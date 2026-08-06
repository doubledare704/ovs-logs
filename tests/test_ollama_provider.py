"""Tests for OllamaProvider structured-output behavior (mocked client)."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest
from ollama import ResponseError

from ovs_logs.config.settings import OLLAMA_DEFAULT_ENDPOINT
from ovs_logs.core.llm import OllamaProvider, list_ollama_models
from ovs_logs.core.report_schema import REPORT_JSON_SCHEMA


@pytest.fixture
def mock_client(monkeypatch: pytest.MonkeyPatch) -> MagicMock:
    client = MagicMock()
    monkeypatch.setattr("ovs_logs.core.llm.Client", MagicMock(return_value=client))
    return client


def test_generate_sends_schema_and_temperature(mock_client: MagicMock) -> None:
    mock_client.chat.return_value = {"message": {"content": '{"title": "t"}'}}

    provider = OllamaProvider(api_key="", endpoint=OLLAMA_DEFAULT_ENDPOINT, model="qwen3.5:4b")
    provider.generate("prompt")

    assert mock_client.chat.call_count == 1
    kwargs = mock_client.chat.call_args.kwargs
    assert kwargs["format"] == REPORT_JSON_SCHEMA
    assert kwargs["options"] == {"temperature": 0}
    assert kwargs["stream"] is False


def test_generate_falls_back_without_format_on_error(mock_client: MagicMock) -> None:
    mock_client.chat.side_effect = [
        ResponseError("structured output unsupported"),
        {"message": {"content": '{"title": "t"}'}},
    ]

    provider = OllamaProvider(api_key="", endpoint=OLLAMA_DEFAULT_ENDPOINT, model="qwen3.5:4b")
    result = provider.generate("prompt")

    assert mock_client.chat.call_count == 2
    assert "format" in mock_client.chat.call_args_list[0].kwargs
    assert "format" not in mock_client.chat.call_args_list[1].kwargs
    assert result == '{"title": "t"}'


# ---------------------------------------------------------------------------
# list_ollama_models tests
# ---------------------------------------------------------------------------


def _make_model(name: str) -> MagicMock:
    """Return a mock Ollama model with the given name."""
    m = MagicMock()
    m.model = name
    return m


def test_list_ollama_models_returns_sorted(monkeypatch: pytest.MonkeyPatch) -> None:
    client = MagicMock()
    client.list.return_value.models = [
        _make_model("llama3:8b"),
        _make_model("qwen3.5:4b"),
        _make_model("codellama:7b"),
    ]
    monkeypatch.setattr("ovs_logs.core.llm.Client", MagicMock(return_value=client))

    result = list_ollama_models(OLLAMA_DEFAULT_ENDPOINT)

    assert result == ["codellama:7b", "llama3:8b", "qwen3.5:4b"]


def test_list_ollama_models_returns_empty_on_error(monkeypatch: pytest.MonkeyPatch) -> None:
    client = MagicMock()
    client.list.side_effect = ConnectionError("refused")
    monkeypatch.setattr("ovs_logs.core.llm.Client", MagicMock(return_value=client))

    result = list_ollama_models(OLLAMA_DEFAULT_ENDPOINT)

    assert result == []


def test_list_ollama_models_filters_empty_names(monkeypatch: pytest.MonkeyPatch) -> None:
    client = MagicMock()
    client.list.return_value.models = [
        _make_model("llama3:8b"),
        _make_model(""),
        _make_model("qwen3.5:4b"),
    ]
    monkeypatch.setattr("ovs_logs.core.llm.Client", MagicMock(return_value=client))

    result = list_ollama_models(OLLAMA_DEFAULT_ENDPOINT)

    assert result == ["llama3:8b", "qwen3.5:4b"]
