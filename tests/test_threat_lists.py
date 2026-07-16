"""Tests for the offline FireHOL IP-list enrichment module."""

from __future__ import annotations

import dataclasses
import json
import os
import time
from pathlib import Path
from unittest.mock import Mock, create_autospec

import pytest
import requests

from ovs_logs.core.analysis.indicators import SuspiciousIndicator, extract_unique_ips
from ovs_logs.core.threat_lists import (
    ThreatListError,
    download_list,
    ensure_cache_dir,
    is_loaded,
    load_networks,
    match_ips,
    netset_path,
    parse_netset,
    stale_lists,
    update_lists,
)

# ---------------------------------------------------------------------------
# parse_netset
# ---------------------------------------------------------------------------


def test_parse_netset_strips_comments_and_blanks(tmp_path: Path) -> None:
    ns = tmp_path / "test.netset"
    ns.write_text(
        "# This is a comment\n1.2.3.0/24\n\n  # another comment\n10.0.0.0/8\n  192.168.0.0/16  \n",
        encoding="utf-8",
    )
    result = parse_netset(ns)
    assert result == ["1.2.3.0/24", "10.0.0.0/8", "192.168.0.0/16"]


def test_parse_netset_missing_file(tmp_path: Path) -> None:
    assert parse_netset(tmp_path / "nonexistent.netset") == []


def test_parse_netset_empty_file(tmp_path: Path) -> None:
    ns = tmp_path / "empty.netset"
    ns.write_text("", encoding="utf-8")
    assert parse_netset(ns) == []


# ---------------------------------------------------------------------------
# match_ips
# ---------------------------------------------------------------------------


def test_match_ips_inside_cidr(tmp_path: Path) -> None:
    cache = tmp_path / "cache"
    cache.mkdir()
    (cache / "test_list.netset").write_text("10.0.0.0/8\n", encoding="utf-8")

    hits = match_ips(["10.0.0.1", "10.255.255.255", "192.168.1.1"], ["test_list"], str(cache))
    assert hits == {
        "10.0.0.1": ["test_list"],
        "10.255.255.255": ["test_list"],
    }
    assert "192.168.1.1" not in hits


def test_match_ips_multiple_lists(tmp_path: Path) -> None:
    cache = tmp_path / "cache"
    cache.mkdir()
    (cache / "list_a.netset").write_text("10.0.0.0/8\n", encoding="utf-8")
    (cache / "list_b.netset").write_text("10.0.0.0/16\n", encoding="utf-8")

    hits = match_ips(["10.0.0.1"], ["list_a", "list_b"], str(cache))
    assert hits == {"10.0.0.1": ["list_a", "list_b"]}


def test_match_ips_ipv6(tmp_path: Path) -> None:
    cache = tmp_path / "cache"
    cache.mkdir()
    (cache / "v6.netset").write_text("2001:db8::/32\n", encoding="utf-8")

    hits = match_ips(["2001:db8::1", "2001:db9::1"], ["v6"], str(cache))
    assert hits == {"2001:db8::1": ["v6"]}
    assert "2001:db9::1" not in hits


def test_match_ips_unparseable_ip_skipped(tmp_path: Path) -> None:
    cache = tmp_path / "cache"
    cache.mkdir()
    (cache / "test.netset").write_text("10.0.0.0/8\n", encoding="utf-8")

    hits = match_ips(["not-an-ip", "", "10.0.0.1"], ["test"], str(cache))
    assert hits == {"10.0.0.1": ["test"]}


def test_match_ips_empty_input(tmp_path: Path) -> None:
    assert match_ips([], ["any"], str(tmp_path)) == {}


def test_match_ips_no_lists_loaded(tmp_path: Path) -> None:
    assert match_ips(["10.0.0.1"], ["nonexistent"], str(tmp_path)) == {}


# ---------------------------------------------------------------------------
# load_networks
# ---------------------------------------------------------------------------


def test_load_networks_skips_invalid_cidrs(tmp_path: Path) -> None:
    cache = tmp_path / "cache"
    cache.mkdir()
    (cache / "test.netset").write_text("10.0.0.0/8\nnot-a-cidr\n", encoding="utf-8")

    networks = load_networks(["test"], str(cache))
    names = {n for n, _, _ in networks}
    cidrs = {c for _, c, _ in networks}
    assert names == {"test"}
    assert "10.0.0.0/8" in cidrs
    assert "not-a-cidr" not in cidrs


# ---------------------------------------------------------------------------
# download_list
# ---------------------------------------------------------------------------


def _make_session(*, status: int = 200, content: bytes = b"", headers: dict | None = None) -> Mock:
    session = create_autospec(requests.Session, instance=True)
    resp = Mock(status_code=status, headers=headers or {}, content=content)
    resp.json.side_effect = ValueError("not json")
    session.get.return_value = resp
    return session


def test_download_list_200_writes_file_and_meta(tmp_path: Path) -> None:
    cache = tmp_path / "cache"
    session = _make_session(
        status=200,
        content=b"10.0.0.0/8\n",
        headers={"ETag": '"abc123"', "Last-Modified": "Mon, 01 Jan 2024 00:00:00 GMT"},
    )

    result = download_list("firehol_level1", str(cache), session=session)
    assert result == "updated"

    ns = netset_path("firehol_level1", str(cache))
    assert ns.read_bytes() == b"10.0.0.0/8\n"

    meta_path = cache / "firehol_level1.netset.meta.json"
    assert meta_path.is_file()
    meta = json.loads(meta_path.read_text(encoding="utf-8"))
    assert meta["etag"] == '"abc123"'
    assert meta["last_modified"] == "Mon, 01 Jan 2024 00:00:00 GMT"
    assert "fetched_at" in meta


def test_download_list_304_refreshes_fetched_at(tmp_path: Path) -> None:
    cache = tmp_path / "cache"
    cache.mkdir()
    # Pre-seed the file and meta
    ns = cache / "test.netset"
    ns.write_text("10.0.0.0/8\n", encoding="utf-8")
    meta_data = {
        "etag": '"abc"',
        "last_modified": "Mon, 01 Jan 2024 00:00:00 GMT",
        "fetched_at": "2024-01-01T00:00:00+00:00",
    }
    meta_path = cache / "test.netset.meta.json"
    meta_path.write_text(json.dumps(meta_data), encoding="utf-8")

    session = _make_session(status=304)

    result = download_list("test", str(cache), session=session)
    assert result == "unchanged"

    # Verify conditional headers were sent
    call_kwargs = session.get.call_args
    assert call_kwargs is not None
    _, kwargs = call_kwargs
    assert kwargs["headers"].get("If-None-Match") == '"abc"'
    assert kwargs["headers"].get("If-Modified-Since") == "Mon, 01 Jan 2024 00:00:00 GMT"

    # fetched_at should be refreshed
    refreshed = json.loads(meta_path.read_text(encoding="utf-8"))
    assert refreshed["fetched_at"] != "2024-01-01T00:00:00+00:00"


def test_download_list_network_error_with_cache_keeps_it(tmp_path: Path) -> None:
    cache = tmp_path / "cache"
    cache.mkdir()
    ns = cache / "test.netset"
    ns.write_text("cached content", encoding="utf-8")

    session = create_autospec(requests.Session, instance=True)
    session.get.side_effect = requests.ConnectionError("network down")

    result = download_list("test", str(cache), session=session)
    assert result == "cached"
    assert ns.read_text(encoding="utf-8") == "cached content"


def test_download_list_network_error_no_cache_raises(tmp_path: Path) -> None:
    cache = tmp_path / "cache"
    session = create_autospec(requests.Session, instance=True)
    session.get.side_effect = requests.ConnectionError("network down")

    with pytest.raises(ThreatListError, match="Failed to download test"):
        download_list("test", str(cache), session=session)


def test_download_list_http_error_with_cache_keeps_it(tmp_path: Path) -> None:
    cache = tmp_path / "cache"
    cache.mkdir()
    ns = cache / "test.netset"
    ns.write_text("cached content", encoding="utf-8")

    session = _make_session(status=500)

    result = download_list("test", str(cache), session=session)
    assert result == "cached"
    assert ns.read_text(encoding="utf-8") == "cached content"


def test_download_list_http_error_no_cache_raises(tmp_path: Path) -> None:
    cache = tmp_path / "cache"
    session = _make_session(status=403)

    with pytest.raises(ThreatListError, match="HTTP 403"):
        download_list("test", str(cache), session=session)


# ---------------------------------------------------------------------------
# update_lists
# ---------------------------------------------------------------------------


def test_update_lists_mixed_results(tmp_path: Path) -> None:
    cache = tmp_path / "cache"
    cache.mkdir()
    # Pre-seed one list that will get a 304
    (cache / "firehol_abusers_30d.netset").write_text("10.0.0.0/8\n", encoding="utf-8")
    meta = cache / "firehol_abusers_30d.netset.meta.json"
    meta_data = {
        "etag": '"x"',
        "last_modified": "Mon, 01 Jan 2024 00:00:00 GMT",
        "fetched_at": "2024-01-01T00:00:00+00:00",
    }
    meta.write_text(json.dumps(meta_data), encoding="utf-8")

    session = create_autospec(requests.Session, instance=True)

    def _get(url: str, **_kwargs: object) -> Mock:
        if "firehol_level1" in url:
            return Mock(status_code=200, headers={}, content=b"1.2.3.0/24\n")
        if "firehol_abusers_30d" in url:
            return Mock(status_code=304, headers={}, content=b"")
        return Mock(status_code=404, headers={}, content=b"")

    session.get.side_effect = _get

    results = update_lists(
        ["firehol_level1", "firehol_abusers_30d"],
        str(cache),
        session=session,
    )
    assert results["firehol_level1"] == "updated"
    assert results["firehol_abusers_30d"] == "unchanged"


def test_update_lists_network_error_to_all_fails(tmp_path: Path) -> None:
    cache = tmp_path / "cache"
    session = create_autospec(requests.Session, instance=True)
    session.get.side_effect = requests.ConnectionError("down")

    results = update_lists(["list_a"], str(cache), session=session)
    assert "error:" in results["list_a"]


def test_update_lists_fallback_to_cached(tmp_path: Path) -> None:
    """When download_list raises a network error but a cached .netset file
    exists, the result is ``"cached"``."""
    cache = tmp_path / "cache"
    cache.mkdir()
    # Pre-seed a cached .netset file
    (cache / "firehol_level1.netset").write_text("10.0.0.0/8\n", encoding="utf-8")

    session = create_autospec(requests.Session, instance=True)
    session.get.side_effect = requests.ConnectionError("network down")

    results = update_lists(["firehol_level1"], str(cache), session=session)
    assert results["firehol_level1"] == "cached"


def test_update_lists_oserror_preserves_other_results(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An OSError from download_list (e.g. a disk-full write) must not abort
    the loop or discard results for already-processed lists."""
    cache = tmp_path / "cache"
    calls: list[str] = []

    def _fake_download(name: str, cache_dir: str, **kwargs: object) -> str:
        calls.append(name)
        if name == "list_a":
            return "updated"
        raise OSError("disk full")

    monkeypatch.setattr("ovs_logs.core.threat_lists.download_list", _fake_download)

    results = update_lists(["list_a", "list_b"], str(cache))
    assert results["list_a"] == "updated"
    assert "error:" in results["list_b"]
    assert set(calls) == {"list_a", "list_b"}


# ---------------------------------------------------------------------------
# is_loaded / stale_lists
# ---------------------------------------------------------------------------


def test_is_loaded_true_when_file_exists(tmp_path: Path) -> None:
    cache = tmp_path / "cache"
    cache.mkdir()
    (cache / "firehol_level1.netset").write_text("10.0.0.0/8\n", encoding="utf-8")
    assert is_loaded(["firehol_level1"], str(cache)) is True


def test_is_loaded_false_when_missing(tmp_path: Path) -> None:
    assert is_loaded(["firehol_level1"], str(tmp_path)) is False


def test_is_loaded_any_one_of_many(tmp_path: Path) -> None:
    cache = tmp_path / "cache"
    cache.mkdir()
    (cache / "list_a.netset").write_text("10.0.0.0/8\n", encoding="utf-8")
    assert is_loaded(["list_a", "list_b"], str(cache)) is True


def test_stale_lists_missing(tmp_path: Path) -> None:
    stale = stale_lists(["a", "b"], str(tmp_path), max_age_hours=1)
    assert stale == ["a", "b"]


def test_stale_lists_fresh_file(tmp_path: Path) -> None:
    cache = tmp_path / "cache"
    cache.mkdir()
    (cache / "fresh.netset").write_text("10.0.0.0/8\n", encoding="utf-8")

    stale = stale_lists(["fresh"], str(cache), max_age_hours=24)
    assert stale == []


def test_stale_lists_old_file(tmp_path: Path) -> None:
    cache = tmp_path / "cache"
    cache.mkdir()
    ns = cache / "old.netset"
    ns.write_text("10.0.0.0/8\n", encoding="utf-8")
    # Set mtime to far in the past
    old_time = time.time() - 48 * 3600
    os.utime(ns, (old_time, old_time))

    stale = stale_lists(["old"], str(cache), max_age_hours=24)
    assert stale == ["old"]


def test_stale_lists_uses_fetched_at_when_available(tmp_path: Path) -> None:
    cache = tmp_path / "cache"
    cache.mkdir()
    (cache / "meta_list.netset").write_text("10.0.0.0/8\n", encoding="utf-8")
    # Sidecar with very old fetched_at
    meta_path = cache / "meta_list.netset.meta.json"
    meta_path.write_text(
        json.dumps({"fetched_at": "2020-01-01T00:00:00+00:00"}),
        encoding="utf-8",
    )

    stale = stale_lists(["meta_list"], str(cache), max_age_hours=24)
    assert stale == ["meta_list"]


# ---------------------------------------------------------------------------
# ensure_cache_dir
# ---------------------------------------------------------------------------


def test_ensure_cache_dir_creates_directory(tmp_path: Path) -> None:
    cache = tmp_path / "deep" / "nested" / "cache"
    assert not cache.exists()
    result = ensure_cache_dir(str(cache))
    assert cache.is_dir()
    assert result == cache


def test_ensure_cache_dir_noop_when_exists(tmp_path: Path) -> None:
    cache = tmp_path / "cache"
    cache.mkdir()
    result = ensure_cache_dir(str(cache))
    assert cache.is_dir()
    assert result == cache


# ---------------------------------------------------------------------------
# Integration: full enrichment pipeline
# ---------------------------------------------------------------------------


def test_enrichment_pipeline_matching_indicators(tmp_path: Path) -> None:
    """Full enrichment pipeline: cache netset, extract IPs, match, attach."""
    cache = tmp_path / "cache"
    cache.mkdir()
    (cache / "firehol_level1.netset").write_text("10.0.0.0/8\n", encoding="utf-8")

    indicators = [
        SuspiciousIndicator(
            type="top_talkers",
            severity="High",
            description="IP 10.0.0.1 generated 100 events",
            evidence={"source_ip": "10.0.0.1", "event_count": 100},
        ),
        SuspiciousIndicator(
            type="top_talkers",
            severity="Medium",
            description="IP 192.168.1.1 generated 50 events",
            evidence={"source_ip": "192.168.1.1", "event_count": 50},
        ),
        SuspiciousIndicator(
            type="error_spikes",
            severity="Low",
            description="No source_ip field",
            evidence={"status_code": 404, "error_count": 5},
        ),
    ]

    # Step 1: Extract unique IPs
    ips = extract_unique_ips(indicators)
    assert ips == ["10.0.0.1", "192.168.1.1"]

    # Step 2: Match against threat lists
    hits = match_ips(ips, ["firehol_level1"], str(cache))
    assert hits == {"10.0.0.1": ["firehol_level1"]}

    # Step 3: Attach threat_lists to matching indicators
    enriched = []
    for ind in indicators:
        ip = ind.evidence.get("source_ip", "")
        if isinstance(ip, str) and ip in hits:
            enriched.append(dataclasses.replace(ind, threat_lists=hits[ip]))
        else:
            enriched.append(ind)

    assert enriched[0].threat_lists == ["firehol_level1"]
    assert enriched[1].threat_lists == []  # not in 10.0.0.0/8
    assert enriched[2].threat_lists == []  # no source_ip


def test_enrichment_pipeline_no_netset_no_matches(tmp_path: Path) -> None:
    """When no netset files exist, enrichment returns nothing."""
    indicators = [
        SuspiciousIndicator(
            type="top_talkers",
            severity="High",
            description="IP 10.0.0.1",
            evidence={"source_ip": "10.0.0.1", "event_count": 1},
        ),
    ]
    ips = extract_unique_ips(indicators)
    hits = match_ips(ips, ["firehol_level1"], str(tmp_path / "empty_cache"))
    assert hits == {}


def test_enrichment_pipeline_multiple_matches_deduplicated(tmp_path: Path) -> None:
    """Same IP in multiple indicators is matched once."""
    cache = tmp_path / "cache"
    cache.mkdir()
    (cache / "blocklist.netset").write_text("10.0.0.0/8\n", encoding="utf-8")

    indicators = [
        SuspiciousIndicator(
            type="top_talkers",
            severity="High",
            description="IP 10.0.0.1",
            evidence={"source_ip": "10.0.0.1", "event_count": 100},
        ),
        SuspiciousIndicator(
            type="error_spikes",
            severity="Medium",
            description="IP 10.0.0.1 errors",
            evidence={"source_ip": "10.0.0.1", "error_count": 50},
        ),
    ]

    ips = extract_unique_ips(indicators)
    assert ips == ["10.0.0.1"]  # deduplicated

    hits = match_ips(ips, ["blocklist"], str(cache))
    enriched = []
    for ind in indicators:
        ip = ind.evidence.get("source_ip", "")
        if isinstance(ip, str) and ip in hits:
            enriched.append(dataclasses.replace(ind, threat_lists=hits[ip]))
        else:
            enriched.append(ind)

    assert all(e.threat_lists == ["blocklist"] for e in enriched)
