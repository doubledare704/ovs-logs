"""Tests for the dataclass-based settings module."""

from unittest.mock import patch

from ovs_logs.config.settings import (
    _load_abuseipdb_settings,
    _load_database_settings,
    _load_llm_settings,
    _load_text_parse_settings,
    _load_thresholds,
    settings,
)


def test_singleton_has_expected_defaults() -> None:
    assert settings.abuseipdb.api_url == "https://api.abuseipdb.com/api/v2/check"
    assert settings.abuseipdb.timeout == 10
    assert settings.llm.model == "gpt-4o-mini"
    assert settings.thresholds.top_talkers == 100
    assert settings.database.path == ".ovs_logs/ovs_logs.db"
    assert settings.text_parse.structured is True
    assert settings.text_parse.max_lines_per_file == 0


def test_environment_variables_override_defaults() -> None:
    env = {
        "ABUSEIPDB_API_URL": "https://custom.abuseipdb.com/api/v2/check",
        "ABUSEIPDB_TIMEOUT": "20",
        "ABUSEIPDB_MAX_REQUESTS_PER_MINUTE": "120",
        "ABUSEIPDB_MAX_RETRIES": "5",
        "ABUSEIPDB_BACKOFF_SECONDS": "2",
        "OVS_LOGS_LLM_API_URL": "https://custom.llm.com/v1/chat",
        "OVS_LOGS_LLM_MODEL": "gpt-4",
        "OVS_LOGS_LLM_TIMEOUT": "90",
        "OVS_LOGS_TALKER_THRESHOLD": "500",
        "OVS_LOGS_ERROR_THRESHOLD": "75",
        "OVS_LOGS_EVENT_DISTRIBUTION_THRESHOLD": "200",
        "OVS_LOGS_TEMPORAL_BUCKET_THRESHOLD": "150",
        "OVS_LOGS_DB_PATH": "/tmp/ovs_logs.db",
        "OVS_LOG_STRUCTURED": "false",
        "OVS_LOG_PARSE_LIMIT": "500",
    }

    with patch.dict("os.environ", env, clear=False):
        abuse = _load_abuseipdb_settings()
        llm = _load_llm_settings()
        thresholds = _load_thresholds()
        db = _load_database_settings()
        text_parse = _load_text_parse_settings()

    assert abuse.api_url == env["ABUSEIPDB_API_URL"]
    assert abuse.timeout == 20
    assert abuse.max_requests_per_minute == 120
    assert abuse.max_retries == 5
    assert abuse.backoff_seconds == 2

    assert llm.api_url == env["OVS_LOGS_LLM_API_URL"]
    assert llm.model == env["OVS_LOGS_LLM_MODEL"]
    assert llm.timeout == 90

    assert thresholds.top_talkers == 500
    assert thresholds.error_spikes == 75
    assert thresholds.event_distribution == 200
    assert thresholds.temporal_anomaly == 150

    assert db.path == env["OVS_LOGS_DB_PATH"]

    assert text_parse.structured is False
    assert text_parse.max_lines_per_file == 500
