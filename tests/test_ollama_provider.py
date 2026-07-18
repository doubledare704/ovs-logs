"""Tests for OllamaProvider structured-output behavior (mocked client)."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from ovs_logs.core.llm import OllamaProvider
from ovs_logs.core.report_schema import REPORT_JSON_SCHEMA


@pytest.fixture
def mock_client(monkeypatch: pytest.MonkeyPatch) -> MagicMock:
    client = MagicMock()
    monkeypatch.setattr("ovs_logs.core.llm.Client", MagicMock(return_value=client))
    return client


def test_generate_sends_schema_and_temperature(mock_client: MagicMock) -> None:
    mock_client.chat.return_value = {"message": {"content": '{"title": "t"}'}}

    provider = OllamaProvider(api_key="", endpoint="http://localhost:11434", model="qwen3.5:4b")
    provider.generate("prompt")

    assert mock_client.chat.call_count == 1
    kwargs = mock_client.chat.call_args.kwargs
    assert kwargs["format"] == REPORT_JSON_SCHEMA
    assert kwargs["options"] == {"temperature": 0}
    assert kwargs["stream"] is False


def test_generate_falls_back_without_format_on_error(mock_client: MagicMock) -> None:
    mock_client.chat.side_effect = [
        RuntimeError("structured output unsupported"),
        {"message": {"content": '{"title": "t"}'}},
    ]

    provider = OllamaProvider(api_key="", endpoint="http://localhost:11434", model="qwen3.5:4b")
    result = provider.generate("prompt")

    assert mock_client.chat.call_count == 2
    assert "format" in mock_client.chat.call_args_list[0].kwargs
    assert "format" not in mock_client.chat.call_args_list[1].kwargs
    assert result == '{"title": "t"}'
