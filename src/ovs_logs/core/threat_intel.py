"""Threat intelligence clients for IP and file-hash lookups via AbuseIPDB and VirusTotal."""

from __future__ import annotations

import dataclasses
import logging
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

import requests

from ovs_logs.config.settings import AbuseIPDBSettings, VirusTotalSettings, settings
from ovs_logs.core.retry import retry

logger = logging.getLogger(__name__)


class ThreatIntelError(Exception):
    """Raised when a threat-intel lookup fails."""


class ThreatIntelTransientError(ThreatIntelError):
    """Raised for transient HTTP errors (5xx, 429) that may succeed on retry."""


_TRANSIENT_STATUS_MIN = 500
_RATE_LIMIT_STATUS = 429
_SUCCESS_STATUS = 200


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


class RateLimiter:
    """Enforces a minimum interval between consecutive API requests.

    This class is **not** thread-safe.  Use a separate instance per thread
    or wrap ``wait()`` with an external lock when sharing across threads.
    """

    def __init__(
        self,
        max_requests_per_minute: int | None = None,
        time_source: Callable[[], float] | None = None,
        sleep_func: Callable[[float], None] | None = None,
    ) -> None:
        if max_requests_per_minute is None:
            max_requests_per_minute = settings.abuseipdb.max_requests_per_minute
        self.min_interval = 60.0 / max_requests_per_minute if max_requests_per_minute > 0 else 0.0
        self.time_source = time_source or time.monotonic
        self.sleep_func = sleep_func or time.sleep
        self._last_request_time: float | None = None

    def wait(self) -> None:
        """Sleep if the last request happened too recently."""
        if self._last_request_time is not None and self.min_interval > 0:
            elapsed = self.time_source() - self._last_request_time
            if elapsed < self.min_interval:
                self.sleep_func(self.min_interval - elapsed)
        self._last_request_time = self.time_source()


class ThreatIntelClient:
    """Client for querying AbuseIPDB IP reputation data with caching, rate limiting, and retries."""

    def __init__(  # noqa: PLR0913
        self,
        api_key: str | None = None,
        endpoint: str | None = None,
        timeout: int | None = None,
        max_requests_per_minute: int | None = None,
        max_retries: int | None = None,
        backoff_seconds: int | None = None,
        *,
        abuseipdb_settings: AbuseIPDBSettings | None = None,
    ) -> None:
        cfg = abuseipdb_settings or settings.abuseipdb
        self.api_key = api_key
        self.endpoint = endpoint if endpoint is not None else cfg.api_url
        self.timeout = timeout if timeout is not None else cfg.timeout
        retries = max_retries if max_retries is not None else cfg.max_retries
        backoff = backoff_seconds if backoff_seconds is not None else cfg.backoff_seconds
        rate_limit = max_requests_per_minute if max_requests_per_minute is not None else cfg.max_requests_per_minute
        self.rate_limiter = RateLimiter(max_requests_per_minute=rate_limit)
        self._make_request = retry(
            max_retries=retries,
            backoff_seconds=backoff,
            exceptions=(requests.Timeout, ThreatIntelTransientError),
        )(self._make_request_impl)
        self._cache: dict[str, ReputationResult] = {}

    @staticmethod
    def _build_result(ip: str, data: dict[str, Any]) -> ReputationResult:
        return ReputationResult(
            ip=ip,
            abuse_confidence_score=int(data.get("abuseConfidenceScore", 0) or 0),
            country_code=data.get("countryCode") or None,
            isp=data.get("isp") or None,
            domain=data.get("domain") or None,
            total_reports=int(data.get("totalReports", 0) or 0),
            last_reported_at=data.get("lastReportedAt") or None,
            cached=False,
        )

    def _neutral_result(self, ip: str) -> ReputationResult:
        return ReputationResult(
            ip=ip,
            abuse_confidence_score=0,
            country_code=None,
            isp=None,
            domain=None,
            total_reports=0,
            last_reported_at=None,
            cached=False,
        )

    def _is_transient(self, status_code: int) -> bool:
        return status_code >= _TRANSIENT_STATUS_MIN or status_code == _RATE_LIMIT_STATUS

    def _make_request_impl(self, ip: str) -> requests.Response:
        """Make a single rate-limited HTTP request.

        Raises :class:`ThreatIntelTransientError` for status codes that may
        succeed on retry (5xx, 429).  The :meth:`_make_request` wrapper
        (decorated with ``@retry``) handles the backoff and retry logic.
        """
        self.rate_limiter.wait()
        response = requests.get(
            self.endpoint,
            params={"ipAddress": ip, "verbose": "true"},
            headers={
                "Key": self.api_key,
                "Accept": "application/json",
            },
            timeout=self.timeout,
        )
        if self._is_transient(response.status_code):
            raise ThreatIntelTransientError(f"AbuseIPDB lookup for {ip} returned HTTP {response.status_code}")
        return response

    def lookup(self, ip: str) -> ReputationResult:
        """Return reputation data for a single IP, using cache if available."""
        if not self.api_key:
            return self._neutral_result(ip)

        if ip in self._cache:
            return dataclasses.replace(self._cache[ip], cached=True)

        try:
            response = self._make_request(ip)
        except ThreatIntelTransientError as exc:
            raise ThreatIntelError(f"AbuseIPDB lookup failed for {ip} after retries: {exc}") from exc
        except requests.Timeout as exc:
            raise ThreatIntelError(f"AbuseIPDB lookup for {ip} timed out after retries") from exc
        except requests.RequestException as exc:
            raise ThreatIntelError(f"AbuseIPDB lookup for {ip} failed: {exc}") from exc

        if response.status_code == _SUCCESS_STATUS:
            data = response.json().get("data", {})
            result = self._build_result(ip, data)
            self._cache[ip] = result
            return result

        raise ThreatIntelError(f"AbuseIPDB lookup failed for {ip}: HTTP {response.status_code} - {response.text}")

    def lookup_many(self, ips: list[str]) -> dict[str, ReputationResult]:
        """Return reputation data for a list of unique IPs."""
        unique_ips = sorted(set(ips))
        return {ip: self.lookup(ip) for ip in unique_ips}


class VirusTotalClient:
    """Client for querying VirusTotal API v3 file-hash threat intelligence."""

    def __init__(  # noqa: PLR0913
        self,
        api_key: str | None = None,
        endpoint: str | None = None,
        timeout: int | None = None,
        max_requests_per_minute: int | None = None,
        max_retries: int | None = None,
        backoff_seconds: int | None = None,
        *,
        virustotal_settings: VirusTotalSettings | None = None,
    ) -> None:
        cfg = virustotal_settings or settings.virustotal
        self.api_key = api_key if api_key is not None else cfg.api_key
        self.endpoint = endpoint if endpoint is not None else cfg.api_url
        self.timeout = timeout if timeout is not None else cfg.timeout
        retries = max_retries if max_retries is not None else cfg.max_retries
        backoff = backoff_seconds if backoff_seconds is not None else cfg.backoff_seconds
        rate_limit = max_requests_per_minute if max_requests_per_minute is not None else cfg.max_requests_per_minute
        self.rate_limiter = RateLimiter(max_requests_per_minute=rate_limit)
        self._make_request = retry(
            max_retries=retries,
            backoff_seconds=backoff,
            exceptions=(requests.Timeout, ThreatIntelTransientError),
        )(self._make_request_impl)
        self._cache: dict[str, VirusTotalResult] = {}

    @staticmethod
    def _build_result(file_hash: str, attributes: dict[str, Any]) -> VirusTotalResult:
        stats = attributes.get("last_analysis_stats", {})
        malicious = int(stats.get("malicious", 0) or 0)
        suspicious = int(stats.get("suspicious", 0) or 0)
        undetected = int(stats.get("undetected", 0) or 0)
        harmless = int(stats.get("harmless", 0) or 0)
        confirmed_timeout = int(stats.get("confirmed-timeout", 0) or 0)
        failure = int(stats.get("failure", 0) or 0)
        timeout = int(stats.get("timeout", 0) or 0)
        type_unsupported = int(stats.get("type-unsupported", 0) or 0)
        total = (
            malicious + suspicious + undetected + harmless + confirmed_timeout + failure + timeout + type_unsupported
        )
        detection_ratio = malicious / total if total > 0 else 0.0
        return VirusTotalResult(
            hash=file_hash,
            malicious=malicious,
            suspicious=suspicious,
            undetected=undetected,
            harmless=harmless,
            detection_ratio=detection_ratio,
            cached=False,
        )

    def _is_transient(self, status_code: int) -> bool:
        return status_code >= _TRANSIENT_STATUS_MIN or status_code == _RATE_LIMIT_STATUS

    def _make_request_impl(self, file_hash: str) -> requests.Response:
        self.rate_limiter.wait()
        response = requests.get(
            self.endpoint.format(file_hash=file_hash),
            headers={
                "x-apikey": self.api_key,
                "Accept": "application/json",
            },
            timeout=self.timeout,
        )
        if self._is_transient(response.status_code):
            raise ThreatIntelTransientError(f"VirusTotal lookup for {file_hash} returned HTTP {response.status_code}")
        return response

    def lookup(self, file_hash: str) -> VirusTotalResult:
        """Return threat-intel data for a single file hash, using cache if available."""
        if not self.api_key:
            raise ThreatIntelError("VirusTotal API key is required; set VIRUSTOTAL_API_KEY")

        if file_hash in self._cache:
            return dataclasses.replace(self._cache[file_hash], cached=True)

        try:
            response = self._make_request(file_hash)
        except ThreatIntelTransientError as exc:
            raise ThreatIntelError(f"VirusTotal lookup failed for {file_hash} after retries: {exc}") from exc
        except requests.Timeout as exc:
            raise ThreatIntelError(f"VirusTotal lookup for {file_hash} timed out after retries") from exc
        except requests.RequestException as exc:
            raise ThreatIntelError(f"VirusTotal lookup for {file_hash} failed: {exc}") from exc

        if response.status_code == _SUCCESS_STATUS:
            try:
                payload = response.json()
            except ValueError as exc:
                raise ThreatIntelError(f"VirusTotal lookup failed for {file_hash}: malformed JSON: {exc}") from exc
            data = payload.get("data", {})
            if not data:
                raise ThreatIntelError(f"VirusTotal lookup failed for {file_hash}: missing 'data' in response")
            attrs = data.get("attributes", {})
            if not attrs:
                raise ThreatIntelError(
                    f"VirusTotal lookup failed for {file_hash}: missing 'data.attributes' in response",
                )
            result = self._build_result(file_hash, attrs)
            self._cache[file_hash] = result
            return result

        raise ThreatIntelError(
            f"VirusTotal lookup failed for {file_hash}: HTTP {response.status_code} - {response.text}",
        )

    def lookup_many(self, hashes: list[str]) -> dict[str, VirusTotalResult]:
        """Return threat-intel data for a list of unique file hashes."""
        unique_hashes = sorted(set(hashes))
        return {h: self.lookup(h) for h in unique_hashes}
