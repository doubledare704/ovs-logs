from __future__ import annotations

from ovs_logs.config.settings import LLM_PRESETS, settings
from ovs_logs.core.llm import LLMProvider, create_llm_provider
from ovs_logs.core.threat_intel import ThreatIntelClient


class LLMConfig:
    """Resolved LLM configuration from session_state."""

    def __init__(self, session_state: dict) -> None:
        self.api_key: str = session_state.get("LLM_API_KEY", "")
        self.preset: str = session_state.get("LLM_PRESET", "OpenAI")
        self.endpoint: str = session_state.get("LLM_ENDPOINT", "")
        self.model: str = session_state.get("LLM_MODEL", "")

    def resolve_endpoint(self) -> str:
        preset_cfg = LLM_PRESETS.get(self.preset)
        if preset_cfg and preset_cfg.endpoint == "__default__":
            return settings.llm.api_url
        return self.endpoint or (preset_cfg.endpoint if preset_cfg else self.endpoint)

    def resolve_model(self) -> str:
        preset_cfg = LLM_PRESETS.get(self.preset)
        if preset_cfg and preset_cfg.model:
            return preset_cfg.model
        return self.model


def build_llm_provider(session_state: dict) -> LLMProvider:
    cfg = LLMConfig(session_state)
    return create_llm_provider(
        api_key=cfg.api_key,
        endpoint=cfg.resolve_endpoint(),
        model=cfg.resolve_model(),
    )


def build_threat_intel_client(session_state: dict) -> ThreatIntelClient | None:
    api_key = session_state.get("ABUSEIPDB_API_KEY", "")
    if not api_key:
        return None
    return ThreatIntelClient(api_key=api_key)
