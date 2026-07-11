"""LLM synthesis: prompt building, response parsing, and report generation."""

from __future__ import annotations

import json
import re
from abc import ABC, abstractmethod
from typing import Any, ClassVar

import requests

from ovs_logs.config.settings import LLMSettings, settings
from ovs_logs.core.analysis.indicators import SuspiciousIndicator
from ovs_logs.core.report import IncidentReport
from ovs_logs.core.threat_intel import ReputationResult


class LLMProvider(ABC):
    """Abstract provider for LLM text generation."""

    @abstractmethod
    def generate(self, prompt: str) -> str:
        """Send a prompt and return the generated text."""


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
        self.endpoint = endpoint or cfg.api_url
        self.model = model or cfg.model
        self.timeout = timeout or cfg.timeout

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
        return response.json()["choices"][0]["message"]["content"]


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
