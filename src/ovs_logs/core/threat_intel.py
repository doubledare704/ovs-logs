"""Threat intelligence client for IP reputation lookups via AbuseIPDB."""

from __future__ import annotations

import dataclasses
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

import requests

from ovs_logs.config.settings import AbuseIPDBSettings, settings


class ThreatIntelError(Exception):
    """Raised when a threat-intel lookup fails."""


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


class RateLimiter:
    """Enforces a minimum interval between consecutive API requests."""

    def __init__(
        self,
        max_requests_per_minute: int = settings.abuseipdb.max_requests_per_minute,
        time_source: Callable[[], float] | None = None,
        sleep_func: Callable[[float], None] | None = None,
    ) -> None:
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
        self.max_retries = max_retries if max_retries is not None else cfg.max_retries
        self.backoff_seconds = backoff_seconds if backoff_seconds is not None else cfg.backoff_seconds
        rate_limit = max_requests_per_minute if max_requests_per_minute is not None else cfg.max_requests_per_minute
        self.rate_limiter = RateLimiter(max_requests_per_minute=rate_limit)
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

    def _execute(self, ip: str) -> requests.Response:
        """Make a single rate-limited HTTP request."""
        self.rate_limiter.wait()
        return requests.get(
            self.endpoint,
            params={"ipAddress": ip, "verbose": "true"},
            headers={
                "Key": self.api_key,
                "Accept": "application/json",
            },
            timeout=self.timeout,
        )

    def lookup(self, ip: str) -> ReputationResult:
        """Return reputation data for a single IP, using cache if available."""
        if not self.api_key:
            return self._neutral_result(ip)

        if ip in self._cache:
            return dataclasses.replace(self._cache[ip], cached=True)

        last_error: Exception | None = None
        for attempt in range(self.max_retries + 1):
            try:
                response = self._execute(ip)
            except requests.Timeout as exc:
                last_error = exc
                if attempt < self.max_retries:
                    time.sleep(self.backoff_seconds * (2**attempt))
                    continue
                raise ThreatIntelError(
                    f"AbuseIPDB lookup for {ip} timed out after {self.max_retries + 1} attempts"
                ) from exc
            except requests.RequestException as exc:
                raise ThreatIntelError(f"AbuseIPDB lookup for {ip} failed: {exc}") from exc

            if response.status_code == _SUCCESS_STATUS:
                data = response.json().get("data", {})
                result = self._build_result(ip, data)
                self._cache[ip] = result
                return result

            if self._is_transient(response.status_code):
                last_error = ThreatIntelError(f"AbuseIPDB lookup for {ip} returned HTTP {response.status_code}")
                if attempt < self.max_retries:
                    time.sleep(self.backoff_seconds * (2**attempt))
                    continue

            raise ThreatIntelError(f"AbuseIPDB lookup failed for {ip}: HTTP {response.status_code} - {response.text}")

        # Exhausted retries on transient errors.
        raise last_error or ThreatIntelError(f"AbuseIPDB lookup failed for {ip} after retries")

    def lookup_many(self, ips: list[str]) -> dict[str, ReputationResult]:
        """Return reputation data for a list of unique IPs."""
        unique_ips = sorted(set(ips))
        return {ip: self.lookup(ip) for ip in unique_ips}
