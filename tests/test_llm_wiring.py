"""Tests for the LLM wiring helpers (src/ovs_logs/ui/llm_wiring.py)."""

from __future__ import annotations

from typing import Any

import pytest

from ovs_logs.config.settings import settings
from ovs_logs.core.llm import OpenAICompatibleProvider
from ovs_logs.core.threat_intel import ThreatIntelClient
from ovs_logs.ui.llm_wiring import (
    build_llm_provider,
    build_threat_intel_client,
)


def test_build_llm_provider_with_preset_endpoint() -> None:
    state: dict[str, Any] = {
        "LLM_API_KEY": "test-key",
        "LLM_PRESET": "Ollama-local",
        "LLM_ENDPOINT": "",
        "LLM_MODEL": "",
    }
    provider = build_llm_provider(state)
    assert isinstance(provider, OpenAICompatibleProvider)
    assert provider.endpoint == "http://localhost:11434/v1/chat/completions"
    assert provider.model == "llama3"


def test_build_llm_provider_openai_preset_uses_settings_url() -> None:
    state: dict[str, Any] = {
        "LLM_API_KEY": "test-key",
        "LLM_PRESET": "OpenAI",
        "LLM_ENDPOINT": "",
        "LLM_MODEL": "",
    }
    provider = build_llm_provider(state)
    assert isinstance(provider, OpenAICompatibleProvider)
    assert provider.endpoint == settings.llm.api_url


def test_build_llm_provider_custom_preset_uses_session_state() -> None:
    state: dict[str, Any] = {
        "LLM_API_KEY": "test-key",
        "LLM_PRESET": "Custom",
        "LLM_ENDPOINT": "https://custom.example.com/v1/chat/completions",
        "LLM_MODEL": "my-custom-model",
    }
    provider = build_llm_provider(state)
    assert isinstance(provider, OpenAICompatibleProvider)
    assert provider.endpoint == "https://custom.example.com/v1/chat/completions"
    assert provider.model == "my-custom-model"


def test_build_llm_provider_raises_on_empty_key() -> None:
    state: dict[str, Any] = {
        "LLM_API_KEY": "",
        "LLM_PRESET": "OpenAI",
        "LLM_ENDPOINT": "",
        "LLM_MODEL": "",
    }
    with pytest.raises(ValueError, match="LLM API key is required"):
        build_llm_provider(state)


def test_build_llm_provider_raises_on_empty_endpoint() -> None:
    """Azure preset has empty endpoint; no user override → ValueError."""
    state: dict[str, Any] = {
        "LLM_API_KEY": "test-key",
        "LLM_PRESET": "Azure",
        "LLM_ENDPOINT": "",
        "LLM_MODEL": "",
    }
    with pytest.raises(ValueError, match="LLM endpoint is required"):
        build_llm_provider(state)


def test_build_llm_provider_raises_on_empty_model() -> None:
    """Azure preset has empty model; no user override → ValueError."""
    state: dict[str, Any] = {
        "LLM_API_KEY": "test-key",
        "LLM_PRESET": "Azure",
        "LLM_ENDPOINT": "https://azure.example.com",
        "LLM_MODEL": "",
    }
    with pytest.raises(ValueError, match="LLM model is required"):
        build_llm_provider(state)


def test_build_llm_provider_openai_preset_user_override_wins() -> None:
    """User-entered endpoint/model must take precedence over the OpenAI preset."""
    state: dict[str, Any] = {
        "LLM_API_KEY": "test-key",
        "LLM_PRESET": "OpenAI",
        "LLM_ENDPOINT": "https://my-proxy.example.com/v1/chat/completions",
        "LLM_MODEL": "gpt-4o",
    }
    provider = build_llm_provider(state)
    assert isinstance(provider, OpenAICompatibleProvider)
    assert provider.endpoint == "https://my-proxy.example.com/v1/chat/completions"
    assert provider.endpoint != settings.llm.api_url
    assert provider.model == "gpt-4o"


def test_build_llm_provider_ollama_preset_user_override_wins() -> None:
    """User-entered endpoint/model must take precedence over the Ollama-local preset."""
    state: dict[str, Any] = {
        "LLM_API_KEY": "test-key",
        "LLM_PRESET": "Ollama-local",
        "LLM_ENDPOINT": "https://my-proxy.example.com/v1/chat/completions",
        "LLM_MODEL": "custom-llama",
    }
    provider = build_llm_provider(state)
    assert isinstance(provider, OpenAICompatibleProvider)
    assert provider.endpoint == "https://my-proxy.example.com/v1/chat/completions"
    assert provider.model == "custom-llama"


def test_build_threat_intel_client_returns_none_on_empty_key() -> None:
    assert build_threat_intel_client({"ABUSEIPDB_API_KEY": ""}) is None
    assert build_threat_intel_client({}) is None


def test_build_threat_intel_client_returns_client_on_key() -> None:
    client = build_threat_intel_client({"ABUSEIPDB_API_KEY": "abuse-key"})
    assert isinstance(client, ThreatIntelClient)
