"""LLM synthesis: prompt building, response parsing, and report generation."""

from __future__ import annotations

import json
import logging
import re
from abc import ABC, abstractmethod
from typing import Any, ClassVar

import requests
from ollama import Client, ResponseError

from ovs_logs.config.settings import LLMSettings, settings
from ovs_logs.core.analysis.indicators import SuspiciousIndicator
from ovs_logs.core.report import IncidentReport
from ovs_logs.core.report_schema import REPORT_JSON_SCHEMA
from ovs_logs.core.threat_intel import ReputationResult

logger = logging.getLogger(__name__)


class LLMProvider(ABC):
    """Abstract provider for LLM text generation."""

    @abstractmethod
    def generate(self, prompt: str) -> str:
        """Send a prompt and return the generated text."""


class OllamaProvider(LLMProvider):
    """Provider backed by the Ollama Python SDK for a local Ollama server.

    Targets a local Ollama instance (``http://localhost:11434``) and enforces
    structured output via Ollama's ``format`` parameter using
    :data:`REPORT_JSON_SCHEMA`.  Uses ``stream=False`` so the full reply is
    returned in a single response.
    """

    _DEFAULT_TIMEOUT = 300

    def __init__(
        self,
        api_key: str,
        endpoint: str | None = None,
        model: str | None = None,
        timeout: int | None = None,
        *,
        llm_settings: LLMSettings | None = None,
    ) -> None:

        cfg = llm_settings or settings.llm
        self.api_key = api_key
        self.model = model if model is not None else cfg.model
        self.timeout = timeout if timeout is not None else (cfg.timeout if cfg.timeout is not None else self._DEFAULT_TIMEOUT)
        host = endpoint if endpoint is not None else cfg.api_url
        self.host = host
        self._client = Client(host=host, timeout=self.timeout)

    def generate(self, prompt: str) -> str:
        messages = [
            {
                "role": "system",
                "content": "You are a DFIR analyst. Return the result as JSON conforming to the provided schema.",
            },
            {"role": "user", "content": prompt},
        ]
        try:
            response = self._client.chat(
                model=self.model,
                messages=messages,
                stream=False,
                format=REPORT_JSON_SCHEMA,
                options={"temperature": 0},
            )
        except ResponseError:
            logger.debug("Ollama structured output unavailable; retrying without format", exc_info=True)
            response = self._client.chat(
                model=self.model,
                messages=messages,
                stream=False,
            )
        return response["message"]["content"]


class OpenAICompatibleProvider(LLMProvider):
    """Provider that calls an OpenAI-compatible chat completions endpoint."""

    def __init__(
        self,
        api_key: str,
        endpoint: str | None = None,
        model: str | None = None,
        timeout: int | None = None,
        *,
        llm_settings: LLMSettings | None = None,
    ) -> None:
        cfg = llm_settings or settings.llm
        self.api_key = api_key
        self.endpoint = endpoint if endpoint is not None else cfg.api_url
        self.model = model if model is not None else cfg.model
        self.timeout = timeout if timeout is not None else cfg.timeout

    def generate(self, prompt: str) -> str:
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": "You are a DFIR analyst."},
                {"role": "user", "content": prompt},
            ],
        }
        response = requests.post(self.endpoint, headers=headers, json=payload, timeout=self.timeout)
        response.raise_for_status()
        data = response.json()
        return data["choices"][0]["message"]["content"]


_ERR_API_KEY_REQUIRED = "LLM API key is required"
_ERR_ENDPOINT_REQUIRED = "LLM endpoint is required"
_ERR_MODEL_REQUIRED = "LLM model is required"
_ERR_CLOUD_BLOCKED = (
    "Ollama Cloud (ollama.com) is not supported; use a local Ollama endpoint such as http://localhost:11434"
)


def create_llm_provider(
    api_key: str,
    endpoint: str | None = None,
    model: str | None = None,
    timeout: int | None = None,
) -> LLMProvider:
    """Create an LLM provider from explicit parameters.

    Routes to :class:`OllamaProvider` only for a local Ollama server
    (``localhost:11434``).  The Ollama Cloud API (``ollama.com``) is blocked
    because its structured-output support is inconsistent and can return
    unexpected fields.  Any other endpoint uses :class:`OpenAICompatibleProvider`.

    Raises ``ValueError`` if *endpoint* or *model* are explicitly set to an
    empty string, or if *endpoint* targets ``ollama.com``.  ``None`` values are
    passed through to the provider, which falls back to ``settings.llm``
    defaults.  An *api_key* is required by the OpenAI-compatible path;
    Ollama-local may pass an empty placeholder.
    """
    if endpoint == "":
        raise ValueError(_ERR_ENDPOINT_REQUIRED)
    if model == "":
        raise ValueError(_ERR_MODEL_REQUIRED)
    endpoint_key = endpoint or settings.llm.api_url
    if "ollama.com" in endpoint_key:
        raise ValueError(_ERR_CLOUD_BLOCKED)
    if ":11434" in endpoint_key:
        return OllamaProvider(api_key=api_key, endpoint=endpoint, model=model, timeout=timeout)
    if not api_key:
        raise ValueError(_ERR_API_KEY_REQUIRED)
    return OpenAICompatibleProvider(api_key=api_key, endpoint=endpoint, model=model, timeout=timeout)


class PromptBuilder:
    """Builds a prompt that asks the LLM for a structured incident report."""

    def __init__(self, max_sample_events: int = 10) -> None:
        self.max_sample_events = max_sample_events

    def build(
        self,
        indicators: list[SuspiciousIndicator],
        threat_intel: dict[str, ReputationResult] | None = None,
        sample_events: list[dict[str, Any]] | None = None,
    ) -> str:
        sections = [
            "You are a DFIR analyst. Analyze the suspicious indicators below and produce a structured incident report.",
            "Return ONLY a JSON object with these top-level keys: "
            "title, summary, severity (Low/Medium/High), timeline, "
            "mitre_mappings, mitigation (with format, title, content), "
            "indicators, and metadata.",
            "Indicators:",
        ]

        for indicator in indicators:
            sections.append(f"- [{indicator.severity}] {indicator.type}: {indicator.description}")
            sections.append(f"  Evidence: {json.dumps(indicator.evidence, default=str)}")

        if threat_intel:
            sections.append("Threat intelligence:")
            for ip, reputation in threat_intel.items():
                sections.append(
                    f"- {ip}: abuse confidence {reputation.abuse_confidence_score}, reports {reputation.total_reports}"
                )

        if sample_events:
            sections.append("Sample raw events:")
            for event in sample_events[: self.max_sample_events]:
                sections.append(json.dumps(event))

        return "\n\n".join(sections)


class ResponseParser:
    """Extracts a JSON incident report from an LLM response."""

    REQUIRED_FIELDS: ClassVar[set[str]] = {
        "title",
        "summary",
        "severity",
        "timeline",
        "mitre_mappings",
        "mitigation",
    }

    def parse(self, text: str) -> dict[str, Any]:
        """Parse JSON from a raw or markdown-wrapped LLM response."""
        match = re.search(r"```(?:json)?\s*(.*?)\s*```", text, re.DOTALL)
        candidate = match.group(1) if match else text
        candidate = candidate.strip()

        try:
            data = json.loads(candidate)
        except json.JSONDecodeError as exc:
            raise ValueError("LLM response is not valid JSON") from exc

        missing = self.REQUIRED_FIELDS - set(data.keys())
        if missing:
            raise ValueError(f"LLM response missing required fields: {missing}")

        return data


class LLMSynthesizer:
    """Orchestrates prompt -> LLM -> parsed incident report."""

    def __init__(
        self,
        provider: LLMProvider,
        prompt_builder: PromptBuilder | None = None,
        response_parser: ResponseParser | None = None,
    ) -> None:
        self.provider = provider
        self.prompt_builder = prompt_builder or PromptBuilder()
        self.response_parser = response_parser or ResponseParser()

    def synthesize(
        self,
        indicators: list[SuspiciousIndicator],
        threat_intel: dict[str, ReputationResult] | None = None,
        sample_events: list[dict[str, Any]] | None = None,
    ) -> IncidentReport:
        """Generate an incident report from indicators and optional context."""
        prompt = self.prompt_builder.build(indicators, threat_intel, sample_events)
        raw_response = self.provider.generate(prompt)
        parsed = self.response_parser.parse(raw_response)
        return IncidentReport.from_dict(parsed)
