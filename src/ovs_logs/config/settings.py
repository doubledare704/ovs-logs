"""Project-wide configuration and default thresholds."""

from __future__ import annotations

import os
from dataclasses import dataclass, field


def _str_env(name: str, default: str) -> str:
    return os.getenv(name, default)


def _int_env(name: str, default: int) -> int:
    value = os.getenv(name)
    return int(value) if value is not None else default


@dataclass(frozen=True)
class AbuseIPDBSettings:
    """AbuseIPDB API client settings."""

    api_url: str = "https://api.abuseipdb.com/api/v2/check"
    timeout: int = 10
    max_requests_per_minute: int = 60
    max_retries: int = 2
    backoff_seconds: int = 1


@dataclass(frozen=True)
class LLMSettings:
    """OpenAI-compatible LLM provider settings."""

    api_url: str = "https://api.openai.com/v1/chat/completions"
    model: str = "gpt-4o-mini"
    timeout: int = 60


@dataclass(frozen=True)
class AnalysisThresholds:
    """Default thresholds for the indicator processing layer."""

    top_talkers: int = 100
    error_spikes: int = 50
    event_distribution: int = 100
    temporal_anomaly: int = 100


@dataclass(frozen=True)
class DatabaseSettings:
    """DuckDB database location."""

    path: str = ".ovs_logs/ovs_logs.db"


def _load_abuseipdb_settings() -> AbuseIPDBSettings:
    return AbuseIPDBSettings(
        api_url=_str_env("ABUSEIPDB_API_URL", AbuseIPDBSettings.api_url),
        timeout=_int_env("ABUSEIPDB_TIMEOUT", AbuseIPDBSettings.timeout),
        max_requests_per_minute=_int_env(
            "ABUSEIPDB_MAX_REQUESTS_PER_MINUTE", AbuseIPDBSettings.max_requests_per_minute
        ),
        max_retries=_int_env("ABUSEIPDB_MAX_RETRIES", AbuseIPDBSettings.max_retries),
        backoff_seconds=_int_env(
            "ABUSEIPDB_BACKOFF_SECONDS", AbuseIPDBSettings.backoff_seconds
        ),
    )


def _load_llm_settings() -> LLMSettings:
    return LLMSettings(
        api_url=_str_env("OVS_LOGS_LLM_API_URL", LLMSettings.api_url),
        model=_str_env("OVS_LOGS_LLM_MODEL", LLMSettings.model),
        timeout=_int_env("OVS_LOGS_LLM_TIMEOUT", LLMSettings.timeout),
    )


def _load_thresholds() -> AnalysisThresholds:
    return AnalysisThresholds(
        top_talkers=_int_env(
            "OVS_LOGS_TALKER_THRESHOLD", AnalysisThresholds.top_talkers
        ),
        error_spikes=_int_env(
            "OVS_LOGS_ERROR_THRESHOLD", AnalysisThresholds.error_spikes
        ),
        event_distribution=_int_env(
            "OVS_LOGS_EVENT_DISTRIBUTION_THRESHOLD",
            AnalysisThresholds.event_distribution,
        ),
        temporal_anomaly=_int_env(
            "OVS_LOGS_TEMPORAL_BUCKET_THRESHOLD", AnalysisThresholds.temporal_anomaly
        ),
    )


def _load_database_settings() -> DatabaseSettings:
    return DatabaseSettings(path=_str_env("OVS_LOGS_DB_PATH", DatabaseSettings.path))


@dataclass(frozen=True)
class TextParseConfig:
    """Runtime tuneables for text-log structured extraction."""

    structured: bool = True
    max_lines_per_file: int = 0


def _load_text_parse_settings() -> TextParseConfig:
    return TextParseConfig(
        structured=_str_env("OVS_LOGS_STRUCTURED", "true").lower() != "false",
        max_lines_per_file=_int_env("OVS_LOGS_PARSE_LIMIT", 0),
    )


@dataclass(frozen=True)
class Settings:
    """Project-wide configuration singleton."""

    abuseipdb: AbuseIPDBSettings = field(default_factory=_load_abuseipdb_settings)
    llm: LLMSettings = field(default_factory=_load_llm_settings)
    thresholds: AnalysisThresholds = field(default_factory=_load_thresholds)
    database: DatabaseSettings = field(default_factory=_load_database_settings)
    text_parse: TextParseConfig = field(default_factory=_load_text_parse_settings)


settings = Settings()
