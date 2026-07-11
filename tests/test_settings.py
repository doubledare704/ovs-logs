"""Tests for the dataclass-based settings module."""

from unittest.mock import patch

from ovs_logs.config.settings import (
    Settings,
    settings,
)

DEFAULT_ABUSEIPDB_TIMEOUT = 10
DEFAULT_TOP_TALKERS = 100


def test_singleton_has_expected_defaults() -> None:
    assert settings.abuseipdb.api_url == "https://api.abuseipdb.com/api/v2/check"
    assert settings.abuseipdb.timeout == DEFAULT_ABUSEIPDB_TIMEOUT
    assert settings.llm.model == "gpt-4o-mini"
    assert settings.thresholds.top_talkers == DEFAULT_TOP_TALKERS
    assert settings.database.path == ".ovs_logs/ovs_logs.db"
    assert settings.text_parse.structured is True
    assert settings.text_parse.max_lines_per_file == 0


ENV_ABUSEIPDB_TIMEOUT = 20
ENV_ABUSEIPDB_MAX_REQUESTS_PER_MINUTE = 120
ENV_ABUSEIPDB_MAX_RETRIES = 5
ENV_ABUSEIPDB_BACKOFF_SECONDS = 2
ENV_LLM_TIMEOUT = 90
ENV_THRESHOLD_TOP_TALKERS = 500
ENV_THRESHOLD_ERROR_SPIKES = 75
ENV_THRESHOLD_EVENT_DISTRIBUTION = 200
ENV_THRESHOLD_TEMPORAL_ANOMALY = 150
ENV_TEXT_PARSE_MAX_LINES_PER_FILE = 500


def test_environment_variables_override_defaults() -> None:
    env = {
        "ABUSEIPDB_API_URL": "https://custom.abuseipdb.com/api/v2/check",
        "ABUSEIPDB_TIMEOUT": str(ENV_ABUSEIPDB_TIMEOUT),
        "ABUSEIPDB_MAX_REQUESTS_PER_MINUTE": str(ENV_ABUSEIPDB_MAX_REQUESTS_PER_MINUTE),
        "ABUSEIPDB_MAX_RETRIES": str(ENV_ABUSEIPDB_MAX_RETRIES),
        "ABUSEIPDB_BACKOFF_SECONDS": str(ENV_ABUSEIPDB_BACKOFF_SECONDS),
        "OVS_LOGS_LLM_API_URL": "https://custom.llm.com/v1/chat",
        "OVS_LOGS_LLM_MODEL": "gpt-4",
        "OVS_LOGS_LLM_TIMEOUT": str(ENV_LLM_TIMEOUT),
        "OVS_LOGS_TALKER_THRESHOLD": str(ENV_THRESHOLD_TOP_TALKERS),
        "OVS_LOGS_ERROR_THRESHOLD": str(ENV_THRESHOLD_ERROR_SPIKES),
        "OVS_LOGS_EVENT_DISTRIBUTION_THRESHOLD": str(ENV_THRESHOLD_EVENT_DISTRIBUTION),
        "OVS_LOGS_TEMPORAL_BUCKET_THRESHOLD": str(ENV_THRESHOLD_TEMPORAL_ANOMALY),
        "OVS_LOGS_DB_PATH": "/tmp/ovs_logs.db",
        "OVS_LOGS_STRUCTURED": "false",
        "OVS_LOGS_PARSE_LIMIT": str(ENV_TEXT_PARSE_MAX_LINES_PER_FILE),
    }

    with patch.dict("os.environ", env, clear=False):
        s = Settings()

    assert s.abuseipdb.api_url == env["ABUSEIPDB_API_URL"]
    assert s.abuseipdb.timeout == ENV_ABUSEIPDB_TIMEOUT
    assert s.abuseipdb.max_requests_per_minute == ENV_ABUSEIPDB_MAX_REQUESTS_PER_MINUTE
    assert s.abuseipdb.max_retries == ENV_ABUSEIPDB_MAX_RETRIES
    assert s.abuseipdb.backoff_seconds == ENV_ABUSEIPDB_BACKOFF_SECONDS

    assert s.llm.api_url == env["OVS_LOGS_LLM_API_URL"]
    assert s.llm.model == env["OVS_LOGS_LLM_MODEL"]
    assert s.llm.timeout == ENV_LLM_TIMEOUT

    assert s.thresholds.top_talkers == ENV_THRESHOLD_TOP_TALKERS
    assert s.thresholds.error_spikes == ENV_THRESHOLD_ERROR_SPIKES
    assert s.thresholds.event_distribution == ENV_THRESHOLD_EVENT_DISTRIBUTION
    assert s.thresholds.temporal_anomaly == ENV_THRESHOLD_TEMPORAL_ANOMALY

    assert s.database.path == env["OVS_LOGS_DB_PATH"]

    assert s.text_parse.structured is False
    assert s.text_parse.max_lines_per_file == ENV_TEXT_PARSE_MAX_LINES_PER_FILE
