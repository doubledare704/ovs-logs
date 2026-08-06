"""Download and install external DFIR tool binaries.

Provides cross-platform detection, GitHub release fetching, archive
extraction, and permission setup for Hayabusa.
"""

from __future__ import annotations

import io
import logging
import platform
import shutil
import stat
import subprocess
import sys
import tempfile
import zipfile
from dataclasses import dataclass
from pathlib import Path

import requests

logger = logging.getLogger(__name__)

HAYABUSA_REPO = "Yamato-Security/hayabusa"
GITHUB_API_BASE = "https://api.github.com/repos"
_DEFAULT_TIMEOUT = 120


@dataclass(frozen=True)
class PlatformInfo:
    """Detected OS and CPU architecture."""

    os_name: str
    """``"darwin"``, ``"linux"``, or ``"windows"``."""

    arch: str
    """``"x64"``, ``"aarch64"``, or ``"x86"``."""

    asset_tag: str
    """Hayabusa release asset suffix, e.g. ``"mac-aarch64"``."""


@dataclass(frozen=True)
class InstallResult:
    """Result of a successful Hayabusa installation."""

    binary_path: Path
    """Path to the installed hayabusa binary."""

    platform: PlatformInfo
    """Platform detected during installation."""

    tag_name: str
    """Release tag that was installed, e.g. ``"v4.0.0"``."""


def detect_platform() -> PlatformInfo:
    """Detect the current OS and CPU architecture.

    Returns:
        A ``PlatformInfo`` matching the current platform.

    Raises:
        ValueError: If the platform or architecture is not supported.
    """
    system = platform.system().lower()
    machine = platform.machine().lower()

    arch_map: dict[str, str] = {
        "x86_64": "x64",
        "amd64": "x64",
        "aarch64": "aarch64",
        "arm64": "aarch64",
        "x86": "x86",
        "i386": "x86",
        "i686": "x86",
    }
    arch = arch_map.get(machine)
    if arch is None:
        raise ValueError(f"Unsupported CPU architecture: {machine}")

    os_asset_map: dict[str, dict[str, str]] = {
        "darwin": {"x64": "mac-x64", "aarch64": "mac-aarch64"},
        "linux": {"x64": "lin-x64-gnu", "aarch64": "lin-aarch64-gnu"},
        "windows": {"x64": "win-x64", "aarch64": "win-aarch64", "x86": "win-x86"},
    }
    os_variants = os_asset_map.get(system)
    if os_variants is None:
        raise ValueError(f"Unsupported operating system: {system}")

    asset_tag = os_variants.get(arch)
    if asset_tag is None:
        raise ValueError(f"Unsupported combination: {system}/{arch}")

    return PlatformInfo(os_name=system, arch=arch, asset_tag=asset_tag)


def fetch_release_meta(
    version: str | None = None,
    *,
    timeout: int = _DEFAULT_TIMEOUT,
) -> dict[str, object]:
    """Fetch GitHub release metadata for Hayabusa.

    Args:
        version: Specific version tag (e.g. ``"4.0.0"``). ``None`` for latest.
        timeout: HTTP request timeout in seconds.

    Returns:
        Parsed JSON release payload as a dict.
    """
    if version:
        url = f"{GITHUB_API_BASE}/{HAYABUSA_REPO}/releases/tags/v{version}"
    else:
        url = f"{GITHUB_API_BASE}/{HAYABUSA_REPO}/releases/latest"

    response = requests.get(url, timeout=timeout)
    response.raise_for_status()
    return response.json()


def _haya_binary_name() -> str:
    """Return the platform-appropriate hayabusa binary name."""
    return "hayabusa.exe" if sys.platform == "win32" else "hayabusa"


def resolve_asset_url(
    release_meta: dict[str, object],
    platform_info: PlatformInfo,
) -> str:
    """Find the download URL for the matching platform asset.

    Args:
        release_meta: Parsed GitHub release JSON.
        platform_info: Current platform detection result.

    Returns:
        The ``browser_download_url`` for the matching asset.

    Raises:
        TypeError: If the release metadata structure is invalid.
        ValueError: If no matching asset is found.
    """
    tag_name = release_meta.get("tag_name", "unknown")
    assets = release_meta.get("assets", [])
    if not isinstance(assets, list):
        raise TypeError(f"Invalid release metadata for {tag_name}")

    suffix = f"{platform_info.asset_tag}.zip"
    for asset in assets:
        if not isinstance(asset, dict):
            continue
        name = asset.get("name", "")
        if isinstance(name, str) and name.endswith(suffix) and "live-response" not in name:
            url = asset.get("browser_download_url")
            if isinstance(url, str):
                return url

    raise ValueError(f"No matching asset found for {platform_info.asset_tag} in release {tag_name}")


def download_bytes(
    url: str,
    *,
    timeout: int = _DEFAULT_TIMEOUT,
) -> bytes:
    """Download content from a URL and return as bytes.

    Args:
        url: The URL to download.
        timeout: HTTP request timeout in seconds.

    Returns:
        The downloaded content as bytes.
    """
    response = requests.get(url, timeout=timeout)
    response.raise_for_status()
    return response.content


def extract_zip_bytes(data: bytes, dest: Path) -> Path:
    """Extract a zip archive from bytes into a destination directory.

    Args:
        data: Raw zip archive bytes.
        dest: Directory to extract into.

    Returns:
        Path to the extracted root directory (the first directory inside the archive).
    """
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        zf.extractall(dest)

    entries = [p for p in dest.iterdir() if p.is_dir()]
    if len(entries) == 1:
        return entries[0]
    return dest


def make_executable(path: Path) -> None:
    """Set the executable bit on Unix. No-op on Windows."""
    if sys.platform == "win32":
        return
    current = path.stat().st_mode
    path.chmod(current | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def get_hayabusa_version(binary: Path) -> str:
    """Run ``hayabusa help`` and return the version string.

    Args:
        binary: Path to the hayabusa binary.

    Returns:
        The version string, e.g. ``"v4.0.0"``.
    """
    result = subprocess.run(
        [str(binary), "help"],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    output = result.stdout.strip() or result.stderr.strip()
    return output.splitlines()[0] if output else ""


def install_hayabusa(
    target_dir: Path,
    *,
    version: str | None = None,
    force: bool = False,
    timeout: int = _DEFAULT_TIMEOUT,
) -> InstallResult:
    """Download, extract, and install Hayabusa into a target directory.

    The binary is placed at ``target_dir/hayabusa`` (or ``hayabusa.exe`` on
    Windows) and the ``rules/`` directory is extracted alongside it.

    Args:
        target_dir: Where to install hayabusa and rules.
        version: Specific version to install. ``None`` for latest.
        force: Re-download even if the binary already exists.
        timeout: HTTP request timeout in seconds.

    Returns:
        An ``InstallResult`` with the binary path, platform, and release tag.
    """
    binary_name = _haya_binary_name()
    binary_path = target_dir / binary_name
    platform_info = detect_platform()

    if binary_path.exists() and not force:
        logger.info("Hayabusa already installed at %s, skipping (use --force to reinstall)", binary_path)
        return InstallResult(binary_path=binary_path, platform=platform_info, tag_name="unknown")

    target_dir.mkdir(parents=True, exist_ok=True)

    release_meta = fetch_release_meta(version=version, timeout=timeout)
    asset_url = resolve_asset_url(release_meta, platform_info)

    tag_name = str(release_meta.get("tag_name", "unknown"))
    logger.info("Downloading Hayabusa %s for %s/%s ...", tag_name, platform_info.os_name, platform_info.arch)

    archive_data = download_bytes(asset_url, timeout=timeout)

    with tempfile.TemporaryDirectory() as tmp_dir:
        extract_zip_bytes(archive_data, Path(tmp_dir))
        extracted = Path(tmp_dir)

        src_binary_candidates = [p for p in extracted.iterdir() if p.is_file()]
        if not src_binary_candidates:
            raise FileNotFoundError("No binary file found in archive")
        src_binary = src_binary_candidates[0]

        src_rules_candidates = [p for p in extracted.iterdir() if p.is_dir() and p.name == "rules"]
        src_rules = src_rules_candidates[0] if src_rules_candidates else None

        if binary_path.exists():
            binary_path.unlink()
        src_binary.rename(binary_path)
        make_executable(binary_path)

        rules_dest = target_dir / "rules"
        if rules_dest.exists():
            shutil.rmtree(rules_dest)
        if src_rules is not None and src_rules.is_dir():
            shutil.move(str(src_rules), str(rules_dest))
        else:
            logger.warning("No rules/ directory found in archive")

    logger.info("Hayabusa installed to %s", binary_path)
    return InstallResult(binary_path=binary_path, platform=platform_info, tag_name=tag_name)
