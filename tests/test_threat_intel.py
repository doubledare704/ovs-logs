"""Tests for the AbuseIPDB threat-intel client."""

from unittest.mock import Mock, patch

import pytest
import requests

from ovs_logs.core.threat_intel import (
    RateLimiter,
    ReputationResult,
    ThreatIntelClient,
    ThreatIntelError,
)


def _success_response() -> Mock:
    response = Mock()
    response.status_code = 200
    response.json.return_value = {
        "data": {
            "ipAddress": "1.2.3.4",
            "abuseConfidenceScore": 75,
            "countryCode": "US",
            "isp": "Example ISP",
            "domain": "example.com",
            "totalReports": 10,
            "lastReportedAt": "2024-01-01T00:00:00",
        }
    }
    return response


def test_explicit_falsy_overrides_are_honored() -> None:
    """Explicit falsy values (0, "") must override settings defaults, not be discarded."""
    client = ThreatIntelClient(
        api_key="test-key",
        endpoint="",
        timeout=0,
        max_retries=0,
        backoff_seconds=0,
        max_requests_per_minute=0,
    )

    assert client.endpoint == ""
    assert client.timeout == 0
    # rate limiter with 0 requests/minute disables throttling (min_interval == 0)
    assert client.rate_limiter.min_interval == 0.0
    # max_retries=0 and backoff_seconds=0 are embedded in the @retry decorator
    # and verified implicitly through the retry behavior tests below.


def test_lookup_success_and_cache() -> None:
    with patch("ovs_logs.core.threat_intel.requests.get", return_value=_success_response()) as mock_get:
        client = ThreatIntelClient(api_key="test-key")
        result = client.lookup("1.2.3.4")

    assert result == ReputationResult(
        ip="1.2.3.4",
        abuse_confidence_score=75,
        country_code="US",
        isp="Example ISP",
        domain="example.com",
        total_reports=10,
        last_reported_at="2024-01-01T00:00:00",
        cached=False,
    )
    mock_get.assert_called_once()

    # Second lookup should be served from cache without another HTTP call.
    cached = client.lookup("1.2.3.4")
    expected_score = 75
    assert cached.cached is True
    assert cached.abuse_confidence_score == expected_score
    assert mock_get.call_count == 1


def test_lookup_many_deduplicates_ips() -> None:
    with patch("ovs_logs.core.threat_intel.requests.get", return_value=_success_response()) as mock_get:
        client = ThreatIntelClient(api_key="test-key")
        results = client.lookup_many(["1.2.3.4", "1.2.3.4", "5.6.7.8"])

    assert set(results.keys()) == {"1.2.3.4", "5.6.7.8"}
    expected_count = 2
    assert mock_get.call_count == expected_count


def test_lookup_without_api_key_returns_neutral_result() -> None:
    client = ThreatIntelClient(api_key=None)
    result = client.lookup("1.2.3.4")

    assert result.abuse_confidence_score == 0
    assert result.country_code is None
    assert result.cached is False


def test_lookup_http_error_raises() -> None:
    response = Mock()
    response.status_code = 429
    response.text = "Too Many Requests"

    with patch("ovs_logs.core.threat_intel.requests.get", return_value=response):
        client = ThreatIntelClient(api_key="test-key", max_retries=0)
        with pytest.raises(ThreatIntelError, match="AbuseIPDB lookup failed"):
            client.lookup("1.2.3.4")


def test_rate_limiter_enforces_delay(monkeypatch) -> None:
    sleeps: list[float] = []
    times = [0.0, 0.5, 0.5]
    monkeypatch.setattr("ovs_logs.core.threat_intel.time.monotonic", lambda: times.pop(0))
    monkeypatch.setattr("ovs_logs.core.threat_intel.time.sleep", sleeps.append)

    limiter = RateLimiter(max_requests_per_minute=2)
    limiter.wait()
    limiter.wait()

    assert sleeps == [29.5]


def test_lookup_retries_on_transient_error() -> None:
    bad = Mock()
    bad.status_code = 500
    bad.text = "Server Error"
    good = _success_response()

    with (
        patch("ovs_logs.core.threat_intel.time.sleep", return_value=None),
        patch("ovs_logs.core.threat_intel.requests.get", side_effect=[bad, good]) as mock_get,
    ):
        client = ThreatIntelClient(api_key="test-key", max_retries=1)
        result = client.lookup("1.2.3.4")

    expected_score = 75
    expected_calls = 2
    assert result.abuse_confidence_score == expected_score
    assert mock_get.call_count == expected_calls


def test_lookup_raises_after_timeout_retries() -> None:
    with (
        patch("ovs_logs.core.threat_intel.time.sleep", return_value=None),
        patch("ovs_logs.core.threat_intel.requests.get", side_effect=requests.Timeout("timeout")) as mock_get,
    ):
        client = ThreatIntelClient(api_key="test-key", max_retries=1)
        with pytest.raises(ThreatIntelError, match="timed out"):
            client.lookup("1.2.3.4")

    expected_calls = 2
    assert mock_get.call_count == expected_calls


def test_lookup_raises_after_rate_limit_retries() -> None:
    response = Mock()
    response.status_code = 429
    response.text = "Too Many Requests"

    with (
        patch("ovs_logs.core.threat_intel.time.sleep", return_value=None),
        patch("ovs_logs.core.threat_intel.requests.get", return_value=response) as mock_get,
    ):
        client = ThreatIntelClient(api_key="test-key", max_retries=1)
        with pytest.raises(ThreatIntelError, match="HTTP 429"):
            client.lookup("1.2.3.4")

    expected_calls = 2
    assert mock_get.call_count == expected_calls
