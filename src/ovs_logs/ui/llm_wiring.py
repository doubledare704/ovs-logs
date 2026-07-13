"""Wiring helpers that bridge Streamlit session_state to core LLM / threat-intel construction."""

from __future__ import annotations

from ovs_logs.config.settings import DEFAULT_ENDPOINT_SENTINEL, LLM_PRESETS, settings
from ovs_logs.core.llm import LLMProvider, create_llm_provider
from ovs_logs.core.threat_intel import ThreatIntelClient


class LLMConfig:
    """Resolved LLM configuration from session_state."""

    def __init__(self, session_state: dict) -> None:
        """Extract LLM-related keys from a Streamlit session_state dict."""
        self.api_key: str = session_state.get("LLM_API_KEY", "")
        self.preset: str = session_state.get("LLM_PRESET", "OpenAI")
        self.endpoint: str = session_state.get("LLM_ENDPOINT", "")
        self.model: str = session_state.get("LLM_MODEL", "")

    def resolve_endpoint(self) -> str:
        """Return the effective endpoint.

        Priority:
        1. ``self.endpoint`` (user-entered value, non-empty)
        2. ``settings.llm.api_url`` if the preset uses ``DEFAULT_ENDPOINT_SENTINEL``
        3. Preset endpoint
        4. Empty string (no preset matched)
        """
        if self.endpoint:
            return self.endpoint
        preset_cfg = LLM_PRESETS.get(self.preset)
        if preset_cfg and preset_cfg.endpoint == DEFAULT_ENDPOINT_SENTINEL:
            return settings.llm.api_url
        return preset_cfg.endpoint if preset_cfg else ""

    def resolve_model(self) -> str:
        """Return the effective model name.

        Priority:
        1. ``self.model`` (user-entered value, non-empty)
        2. Preset model
        3. Empty string (no preset matched)
        """
        if self.model:
            return self.model
        preset_cfg = LLM_PRESETS.get(self.preset)
        return preset_cfg.model if preset_cfg else ""


def build_llm_provider(session_state: dict) -> LLMProvider:
    """Build an :class:`LLMProvider` from Streamlit session_state.

    Raises :class:`ValueError` when required parameters (api key, endpoint,
    model) are explicitly empty strings.
    """
    cfg = LLMConfig(session_state)
    return create_llm_provider(
        api_key=cfg.api_key,
        endpoint=cfg.resolve_endpoint(),
        model=cfg.resolve_model(),
    )


def build_threat_intel_client(session_state: dict) -> ThreatIntelClient | None:
    """Build a :class:`ThreatIntelClient` if an AbuseIPDB key is present."""
    api_key = session_state.get("ABUSEIPDB_API_KEY", "")
    if not api_key:
        return None
    return ThreatIntelClient(api_key=api_key)
