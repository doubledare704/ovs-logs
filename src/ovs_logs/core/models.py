import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from ovs_logs.config.settings import AbuseIPDBSettings, VirusTotalSettings


@dataclass(frozen=True)
class ReputationResult:
    """Normalized IP reputation data from AbuseIPDB."""

    ip: str
    abuse_confidence_score: int = 0
    country_code: str | None = None
    isp: str | None = None
    domain: str | None = None
    total_reports: int = 0
    last_reported_at: str | None = None
    cached: bool = False


@dataclass(frozen=True)
class VirusTotalResult:
    """Normalized file-hash threat data from VirusTotal API v3."""

    hash: str
    malicious: int = 0
    suspicious: int = 0
    undetected: int = 0
    harmless: int = 0
    detection_ratio: float = 0.0
    cached: bool = False


@dataclass(frozen=True)
class ThreatIntelClientOptions:
    """Configuration options for :class:`ThreatIntelClient`."""

    api_key: str | None = None
    endpoint: str | None = None
    timeout: int | None = None
    max_requests_per_minute: int | None = None
    max_retries: int | None = None
    backoff_seconds: int | None = None
    abuseipdb_settings: AbuseIPDBSettings | None = None


@dataclass(frozen=True)
class VirusTotalClientOptions:
    """Configuration options for :class:`VirusTotalClient`."""

    api_key: str | None = None
    endpoint: str | None = None
    timeout: int | None = None
    max_requests_per_minute: int | None = None
    max_retries: int | None = None
    backoff_seconds: int | None = None
    virustotal_settings: VirusTotalSettings | None = None


@dataclass(frozen=True)
class AllowlistedIndicator:
    """Represents a row in the ``allowlisted_indicators`` table."""

    indicator_id: str
    indicator: str
    indicator_type: str
    description: str | None = None
    metadata: dict[str, Any] | None = None
    created_at: datetime | None = None

    @property
    def json_metadata(self) -> str | None:
        """Return the JSON-encoded metadata string, or ``None`` if no metadata."""
        if self.metadata is None:
            return None
        return json.dumps(self.metadata)


@dataclass(frozen=True)
class IngestOptions:
    db: Path
    file: Path
    file_type: str | None = None
    table: str | None = None
    tool: str | None = None
    force_reanalyze: bool = False
