"""Tests for threat-intel clients (AbuseIPDB and VirusTotal)."""

from unittest.mock import Mock, patch

import pytest
import requests

from ovs_logs.config.settings import AbuseIPDBSettings, Settings, VirusTotalSettings, _load_virustotal_settings
from ovs_logs.core.threat_intel import (
    RateLimiter,
    ReputationResult,
    ThreatIntelClient,
    ThreatIntelError,
    VirusTotalClient,
    VirusTotalResult,
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


def test_rate_limiter_resolves_settings_lazily(monkeypatch) -> None:
    """A no-arg ``RateLimiter()`` must read settings at construction time.

    Reproduces the review-flagged issue where the default was captured at module
    import time, so monkeypatching settings after import had no effect. Construct
    with no args after patching and assert the interval reflects the new value.
    """
    patched = 30
    # Both ``Settings`` and ``AbuseIPDBSettings`` are frozen dataclasses, so
    # construct a fresh ``Settings`` with a patched ``abuseipdb`` and patch the
    # module-level name that ``threat_intel`` references. Because ``RateLimiter``
    # now resolves the value lazily at construction, the new object is read on
    # the next call.
    original = __import__("ovs_logs.config.settings", fromlist=["settings"]).settings
    patched_settings = Settings(
        abuseipdb=AbuseIPDBSettings(max_requests_per_minute=patched),
        llm=original.llm,
        thresholds=original.thresholds,
        database=original.database,
        text_parse=original.text_parse,
        threat_lists=original.threat_lists,
    )
    monkeypatch.setattr("ovs_logs.core.threat_intel.settings", patched_settings)

    limiter = RateLimiter()

    assert limiter.min_interval == 60.0 / patched


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


# ---------------------------------------------------------------------------
# VirusTotal client tests
# ---------------------------------------------------------------------------

_DUMMY_HASH = "dummyhash123"


def _vt_success_response() -> Mock:
    response = Mock()
    response.status_code = 200
    response.json.return_value = {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 5,
                    "suspicious": 2,
                    "undetected": 10,
                    "harmless": 3,
                }
            }
        }
    }
    return response


def test_vt_lookup_success_and_cache(mocker) -> None:
    mock_get = mocker.patch("ovs_logs.core.threat_intel.requests.get", return_value=_vt_success_response())
    client = VirusTotalClient(api_key="test-key")
    result = client.lookup(_DUMMY_HASH)

    assert result == VirusTotalResult(
        hash=_DUMMY_HASH,
        malicious=5,
        suspicious=2,
        undetected=10,
        harmless=3,
        detection_ratio=5.0 / 20.0,
        cached=False,
    )
    mock_get.assert_called_once()

    cached = client.lookup(_DUMMY_HASH)
    assert cached.cached is True
    assert cached.malicious == 5
    assert mock_get.call_count == 1


def test_vt_lookup_without_api_key_raises() -> None:
    client = VirusTotalClient(api_key=None)
    with pytest.raises(ThreatIntelError, match="API key is required"):
        client.lookup(_DUMMY_HASH)


def test_vt_lookup_http_error_raises(mocker) -> None:
    response = Mock()
    response.status_code = 429
    response.text = "Too Many Requests"

    mocker.patch("ovs_logs.core.threat_intel.requests.get", return_value=response)
    client = VirusTotalClient(api_key="test-key", max_retries=0)
    with pytest.raises(ThreatIntelError, match="VirusTotal lookup failed"):
        client.lookup(_DUMMY_HASH)


def test_vt_lookup_retries_on_transient_error(mocker) -> None:
    bad = Mock()
    bad.status_code = 500
    bad.text = "Server Error"
    good = _vt_success_response()

    mocker.patch("ovs_logs.core.threat_intel.time.sleep", return_value=None)
    mock_get = mocker.patch("ovs_logs.core.threat_intel.requests.get", side_effect=[bad, good])
    client = VirusTotalClient(api_key="test-key", max_retries=1)
    result = client.lookup(_DUMMY_HASH)

    expected_ratio = 5.0 / 20.0
    assert result.malicious == 5
    assert result.detection_ratio == expected_ratio
    expected_calls = 2
    assert mock_get.call_count == expected_calls


def test_vt_rate_limiter_resolves_settings_lazily(monkeypatch) -> None:
    patched = 10
    original = __import__("ovs_logs.config.settings", fromlist=["settings"]).settings
    patched_settings = Settings(
        abuseipdb=original.abuseipdb,
        virustotal=VirusTotalSettings(max_requests_per_minute=patched),
        llm=original.llm,
        thresholds=original.thresholds,
        database=original.database,
        text_parse=original.text_parse,
        threat_lists=original.threat_lists,
    )
    monkeypatch.setattr("ovs_logs.core.threat_intel.settings", patched_settings)

    client = VirusTotalClient(api_key="test-key")

    assert client.rate_limiter.min_interval == 60.0 / patched


def test_vt_lookup_many_deduplicates_hashes(mocker) -> None:
    mock_get = mocker.patch("ovs_logs.core.threat_intel.requests.get", return_value=_vt_success_response())
    client = VirusTotalClient(api_key="test-key")
    results = client.lookup_many([_DUMMY_HASH, _DUMMY_HASH, "otherhash"])

    assert set(results.keys()) == {_DUMMY_HASH, "otherhash"}
    expected_calls = 2
    assert mock_get.call_count == expected_calls


def test_vt_lookup_without_api_key_uses_settings(monkeypatch, mocker) -> None:
    original = __import__("ovs_logs.config.settings", fromlist=["settings"]).settings
    patched = Settings(
        abuseipdb=original.abuseipdb,
        virustotal=VirusTotalSettings(api_key="env-key-test"),
        llm=original.llm,
        thresholds=original.thresholds,
        database=original.database,
        text_parse=original.text_parse,
        threat_lists=original.threat_lists,
        evtx_tools=original.evtx_tools,
    )
    monkeypatch.setattr("ovs_logs.core.threat_intel.settings", patched)
    mock_get = mocker.patch("ovs_logs.core.threat_intel.requests.get", return_value=_vt_success_response())
    client = VirusTotalClient()
    result = client.lookup(_DUMMY_HASH)
    assert result.malicious == 5
    mock_get.assert_called_once()


def test_vt_malformed_payload_raises(mocker) -> None:
    response = Mock()
    response.status_code = 200
    response.json.return_value = {}
    mocker.patch("ovs_logs.core.threat_intel.requests.get", return_value=response)
    client = VirusTotalClient(api_key="test-key", max_retries=0)
    with pytest.raises(ThreatIntelError, match="missing 'data'"):
        client.lookup(_DUMMY_HASH)


def test_vt_settings_loads_api_key_from_env(monkeypatch) -> None:
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "env-key-test")
    vt_settings = _load_virustotal_settings()
    assert vt_settings.api_key == "env-key-test"
    client = VirusTotalClient(virustotal_settings=vt_settings)
    assert client.api_key == "env-key-test"


def test_vt_lookup_uses_settings_api_key(monkeypatch, mocker) -> None:
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "env-key-test")
    vt_settings = _load_virustotal_settings()
    mock_get = mocker.patch("ovs_logs.core.threat_intel.requests.get", return_value=_vt_success_response())
    client = VirusTotalClient(api_key=None, virustotal_settings=vt_settings)
    result = client.lookup(_DUMMY_HASH)
    assert result.malicious == 5
    mock_get.assert_called_once()
