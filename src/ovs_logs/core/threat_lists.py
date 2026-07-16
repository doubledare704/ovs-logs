"""Offline FireHOL IP-list enrichment for threat intelligence.

Provides an offline, keyless, analysis-layer enrichment. Suspicious ``source_ip``
values are matched against static CIDR blocklists so the intelligence view shows
a known-bad signal even with no API key.

State is file-based (cached ``.netset`` files + sidecar ``.meta.json``), not in
DuckDB, keeping threat-list state independent of whichever database the user selects.
"""

from __future__ import annotations

import functools
import json
import logging
import os
import time
from datetime import UTC, datetime
from ipaddress import ip_address, ip_network
from pathlib import Path
from typing import Any, Literal

import requests

logger = logging.getLogger(__name__)


class ThreatListError(Exception):
    """Raised when a threat-list operation fails irrecoverably."""


_HTTP_OK = 200
_HTTP_NOT_MODIFIED = 304
_IPV4 = 4
_IPV6 = 6


# ---------------------------------------------------------------------------
# Path helpers
# ---------------------------------------------------------------------------


def netset_path(name: str, cache_dir: str) -> Path:
    """Return the expected ``.netset`` file path for a named list."""
    return Path(cache_dir) / f"{name}.netset"


def _meta_path(name: str, cache_dir: str) -> Path:
    """Return the sidecar ``.meta.json`` path for a named list."""
    return Path(cache_dir) / f"{name}.netset.meta.json"


# ---------------------------------------------------------------------------
# Cache directory management
# ---------------------------------------------------------------------------


def ensure_cache_dir(cache_dir: str) -> Path:
    """Create the threat-list cache directory and return its path.

    No-op if the directory already exists. Raises ``OSError`` if the
    directory cannot be created.
    """
    path = Path(cache_dir)
    path.mkdir(parents=True, exist_ok=True)
    return path


# ---------------------------------------------------------------------------
# Download
# ---------------------------------------------------------------------------


def _read_meta(name: str, cache_dir: str) -> dict[str, Any]:
    """Read the sidecar metadata for a named list, or return an empty dict."""
    meta = _meta_path(name, cache_dir)
    if meta.is_file():
        try:
            return json.loads(meta.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            logger.warning("Corrupt meta file for %s, ignoring", name)
    return {}


def _write_meta(name: str, cache_dir: str, data: dict[str, Any]) -> None:
    """Write sidecar metadata for a named list."""
    meta = _meta_path(name, cache_dir)
    meta.parent.mkdir(parents=True, exist_ok=True)
    meta.write_text(json.dumps(data, indent=2), encoding="utf-8")


def download_list(
    name: str,
    cache_dir: str,
    *,
    session: requests.Session | None = None,
    base_url: str = "https://iplists.firehol.org/files",
    timeout: int = 10,
) -> Literal["updated", "unchanged", "cached"]:
    """Download a FireHOL ``.netset`` file with conditional GET support.

    Args:
        name: List name (e.g. ``"firehol_level1"``).
        cache_dir: Directory to store cached ``.netset`` and ``.meta.json`` files.
        session: Optional ``requests.Session`` for test injection.
        base_url: Base URL for FireHOL IP lists.
        timeout: Request timeout in seconds.

    Returns:
        ``"updated"`` when freshly downloaded (HTTP 200), ``"unchanged"`` on
        304, and ``"cached"`` when a recoverable error occurred but a cached
        copy is kept.

    Raises:
        ThreatListError: When the download fails and no cached copy exists.
    """
    sess = session or requests
    url = f"{base_url}/{name}.netset"
    headers: dict[str, str] = {}

    meta = _read_meta(name, cache_dir)
    etag = meta.get("etag")
    last_modified = meta.get("last_modified")
    if etag:
        headers["If-None-Match"] = etag
    if last_modified:
        headers["If-Modified-Since"] = last_modified

    try:
        response = sess.get(url, headers=headers, timeout=timeout)
    except requests.RequestException as exc:
        # Recoverable network error: keep cached copy if available
        ns_path = netset_path(name, cache_dir)
        if ns_path.is_file():
            logger.warning("Network error downloading %s, keeping cached copy: %s", name, exc)
            return "cached"
        raise ThreatListError(f"Failed to download {name}: {exc}") from exc

    if response.status_code == _HTTP_NOT_MODIFIED:
        # Unchanged — refresh the fetched_at timestamp
        meta["fetched_at"] = datetime.now(UTC).isoformat()
        _write_meta(name, cache_dir, meta)
        ns_path = netset_path(name, cache_dir)
        if ns_path.is_file():
            # Touch the file so mtime-based freshness resets
            os.utime(ns_path, None)
        return "unchanged"

    if response.status_code != _HTTP_OK:
        ns_path = netset_path(name, cache_dir)
        if ns_path.is_file():
            logger.warning("HTTP %d for %s, keeping cached copy", response.status_code, name)
            return "cached"
        raise ThreatListError(f"Failed to download {name}: HTTP {response.status_code}")

    # Success — write netset + sidecar
    ns_path = netset_path(name, cache_dir)
    ns_path.parent.mkdir(parents=True, exist_ok=True)
    ns_path.write_bytes(response.content)

    # Extract etag and last_modified from response headers
    new_etag = response.headers.get("ETag")
    new_last_modified = response.headers.get("Last-Modified")
    _write_meta(
        name,
        cache_dir,
        {
            "etag": new_etag,
            "last_modified": new_last_modified,
            "fetched_at": datetime.now(UTC).isoformat(),
        },
    )
    return "updated"


def update_lists(
    names: list[str],
    cache_dir: str,
    *,
    session: requests.Session | None = None,
    base_url: str = "https://iplists.firehol.org/files",
    timeout: int = 10,
) -> dict[str, str]:
    """Download/refresh multiple threat lists.

    Returns a per-list status mapping: ``"updated"``, ``"unchanged"``,
    ``"cached"`` (kept existing), or ``"error: ..."``.
    """
    results: dict[str, str] = {}
    for name in names:
        try:
            results[name] = download_list(name, cache_dir, session=session, base_url=base_url, timeout=timeout)
        except (ThreatListError, OSError) as exc:
            results[name] = f"error: {exc}"
    return results


# ---------------------------------------------------------------------------
# Parsing & matching
# ---------------------------------------------------------------------------


def parse_netset(path: Path) -> list[str]:
    """Parse a ``.netset`` file into a list of CIDR strings.

    Strips comment lines (``#``) and blank lines.
    """
    if not path.is_file():
        return []
    cidrs: list[str] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        cidrs.append(stripped)
    return cidrs


@functools.lru_cache(maxsize=32)
def _load_networks_cached(path_str: str, mtime: float) -> tuple[tuple[str, str, Any], ...]:
    """Memoized helper that parses a netset file into ``(name, cidr_str, ip_network)`` tuples.

    The cache key includes the file path and modification time so that reruns
    (e.g. Streamlit) avoid re-parsing thousands of CIDRs.
    """
    path = Path(path_str)
    name = path.stem  # e.g. "firehol_level1"
    cidrs = parse_netset(path)
    networks: list[tuple[str, str, Any]] = []
    for cidr in cidrs:
        try:
            networks.append((name, cidr, ip_network(cidr, strict=False)))
        except ValueError:
            logger.debug("Skipping unparseable CIDR in %s: %s", name, cidr)
    return tuple(networks)


def load_networks(names: list[str], cache_dir: str) -> list[tuple[str, str, Any]]:
    """Parse cached netsets into ``(name, cidr_str, ip_network)`` tuples.

    Each network is tagged with its list name. Parsing is memoized by
    ``(path, mtime)``.
    """
    networks: list[tuple[str, str, Any]] = []
    for name in names:
        path = netset_path(name, cache_dir)
        if not path.is_file():
            continue
        try:
            mtime = path.stat().st_mtime
            networks.extend(_load_networks_cached(str(path), mtime))
        except OSError:
            logger.warning("Unable to stat %s, skipping", path)
    return networks


def match_ips(ips: list[str], names: list[str], cache_dir: str) -> dict[str, list[str]]:
    """Match unique IPs against loaded threat-list networks.

    Returns a mapping ``{ip: [sorted unique list names]}`` for IPs that fall
    within at least one network. Un-parseable IPs are silently skipped.
    """
    if not ips or not names:
        return {}

    networks = load_networks(names, cache_dir)
    if not networks:
        return {}

    networks_v4: list[tuple[str, Any]] = []
    networks_v6: list[tuple[str, Any]] = []
    for net_name, _cidr_str, net in networks:
        (networks_v4 if net.version == _IPV4 else networks_v6).append((net_name, net))

    hits: dict[str, set[str]] = {}
    for raw_ip in ips:
        try:
            addr = ip_address(raw_ip)
        except ValueError:
            continue
        matching_names: set[str] = set()
        for net_name, net in networks_v4 if addr.version == _IPV4 else networks_v6:
            if addr in net:
                matching_names.add(net_name)
        if matching_names:
            hits[raw_ip] = matching_names

    return {ip: sorted(matched_names) for ip, matched_names in hits.items()}


# ---------------------------------------------------------------------------
# Cache state helpers
# ---------------------------------------------------------------------------


def is_loaded(names: list[str], cache_dir: str) -> bool:
    """Return ``True`` when at least one enabled list file exists on disk."""
    return any(netset_path(name, cache_dir).is_file() for name in names)


def stale_lists(names: list[str], cache_dir: str, max_age_hours: int = 24) -> list[str]:
    """Return list names that are missing or whose mtime is older than ``max_age_hours``.

    Uses ``fetched_at`` from the sidecar metadata when available, falling back
    to file mtime.
    """
    now = time.time()
    stale: list[str] = []
    for name in names:
        path = netset_path(name, cache_dir)
        if not path.is_file():
            stale.append(name)
            continue

        # Prefer fetched_at from sidecar
        meta = _read_meta(name, cache_dir)
        fetched_at_str = meta.get("fetched_at")
        if fetched_at_str:
            try:
                fetched = datetime.fromisoformat(fetched_at_str).timestamp()
            except (ValueError, TypeError):
                fetched = path.stat().st_mtime
        else:
            fetched = path.stat().st_mtime

        age_seconds = now - fetched
        if age_seconds > max_age_hours * 3600:
            stale.append(name)
    return stale
