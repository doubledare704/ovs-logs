"""Tests for the cross-platform Hayabusa downloader."""

from __future__ import annotations

import hashlib
import io
import zipfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from ovs_logs.core.downloader import (
    InstallResult,
    PlatformInfo,
    detect_platform,
    extract_zip_bytes,
    fetch_release_meta,
    find_release_asset,
    get_hayabusa_version,
    install_hayabusa,
    make_executable,
    resolve_asset_url,
    verify_sha256,
)
from ovs_logs.core.errors import IngestionError


def _make_zip_archive(entries: dict[str, bytes]) -> bytes:
    """Create an in-memory zip archive from {filename: content} mapping."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, content in entries.items():
            zf.writestr(name, content)
    return buf.getvalue()


def _make_release_meta(assets: list[dict[str, str]], tag: str = "v4.0.0") -> dict:
    return {"tag_name": tag, "assets": assets}


def _sha256_digest(data: bytes) -> str:
    """Return the ``"sha256:<hex>"`` GitHub-style digest for *data*."""
    return f"sha256:{hashlib.sha256(data).hexdigest()}"


class TestDetectPlatform:
    def test_darwin_arm64(self) -> None:
        with patch("platform.system", return_value="Darwin"), patch("platform.machine", return_value="arm64"):
            result = detect_platform()
        assert result.os_name == "darwin"
        assert result.arch == "aarch64"
        assert result.asset_tag == "mac-aarch64"

    def test_darwin_x86_64(self) -> None:
        with patch("platform.system", return_value="Darwin"), patch("platform.machine", return_value="x86_64"):
            result = detect_platform()
        assert result.os_name == "darwin"
        assert result.arch == "x64"
        assert result.asset_tag == "mac-x64"

    def test_linux_x86_64(self) -> None:
        with patch("platform.system", return_value="Linux"), patch("platform.machine", return_value="x86_64"):
            result = detect_platform()
        assert result.os_name == "linux"
        assert result.arch == "x64"
        assert result.asset_tag == "lin-x64-gnu"

    def test_linux_aarch64(self) -> None:
        with patch("platform.system", return_value="Linux"), patch("platform.machine", return_value="aarch64"):
            result = detect_platform()
        assert result.os_name == "linux"
        assert result.arch == "aarch64"
        assert result.asset_tag == "lin-aarch64-gnu"

    def test_windows_amd64(self) -> None:
        with patch("platform.system", return_value="Windows"), patch("platform.machine", return_value="AMD64"):
            result = detect_platform()
        assert result.os_name == "windows"
        assert result.arch == "x64"
        assert result.asset_tag == "win-x64"

    def test_windows_arm64(self) -> None:
        with patch("platform.system", return_value="Windows"), patch("platform.machine", return_value="arm64"):
            result = detect_platform()
        assert result.os_name == "windows"
        assert result.arch == "aarch64"
        assert result.asset_tag == "win-aarch64"

    def test_unsupported_architecture_raises(self) -> None:
        with (
            patch("platform.system", return_value="Linux"),
            patch("platform.machine", return_value="riscv64"),
            pytest.raises(ValueError, match="Unsupported CPU architecture"),
        ):
            detect_platform()

    def test_unsupported_os_raises(self) -> None:
        with (
            patch("platform.system", return_value="FreeBSD"),
            patch("platform.machine", return_value="x86_64"),
            pytest.raises(ValueError, match="Unsupported operating system"),
        ):
            detect_platform()


class TestResolveAssetUrl:
    def test_finds_matching_asset(self) -> None:
        meta = _make_release_meta(
            [
                {"name": "hayabusa-4.0.0-mac-aarch64.zip", "browser_download_url": "https://example.com/mac-arm.zip"},
                {"name": "hayabusa-4.0.0-mac-x64.zip", "browser_download_url": "https://example.com/mac-x64.zip"},
            ]
        )
        platform = PlatformInfo(os_name="darwin", arch="aarch64", asset_tag="mac-aarch64")
        url = resolve_asset_url(meta, platform)
        assert url == "https://example.com/mac-arm.zip"

    def test_excludes_live_response(self) -> None:
        meta = _make_release_meta(
            [
                {
                    "name": "hayabusa-4.0.0-win-x64-live-response.zip",
                    "browser_download_url": "https://example.com/lr.zip",
                },
                {"name": "hayabusa-4.0.0-win-x64.zip", "browser_download_url": "https://example.com/win.zip"},
            ]
        )
        platform = PlatformInfo(os_name="windows", arch="x64", asset_tag="win-x64")
        url = resolve_asset_url(meta, platform)
        assert url == "https://example.com/win.zip"

    def test_raises_when_no_match(self) -> None:
        meta = _make_release_meta(
            [
                {"name": "hayabusa-4.0.0-mac-x64.zip", "browser_download_url": "https://example.com/mac-x64.zip"},
            ]
        )
        platform = PlatformInfo(os_name="macos", arch="aarch64", asset_tag="mac-aarch64")
        with pytest.raises(ValueError, match="No matching asset"):
            resolve_asset_url(meta, platform)

    def test_handles_empty_assets(self) -> None:
        meta = _make_release_meta([])
        platform = PlatformInfo(os_name="darwin", arch="x64", asset_tag="mac-x64")
        with pytest.raises(ValueError, match="No matching asset"):
            resolve_asset_url(meta, platform)


class TestExtractZipBytes:
    def test_extracts_single_root_directory(self, tmp_path: Path) -> None:
        archive = _make_zip_archive(
            {
                "hayabusa-4.0.0-mac-aarch64/hayabusa": b"binary",
                "hayabusa-4.0.0-mac-aarch64/rules/default/test.yml": b"rule",
            }
        )
        result = extract_zip_bytes(archive, tmp_path)
        assert result.is_dir()
        assert result.name == "hayabusa-4.0.0-mac-aarch64"
        assert (result / "hayabusa").read_bytes() == b"binary"
        assert (result / "rules" / "default" / "test.yml").read_bytes() == b"rule"

    def test_extracts_flat_archive(self, tmp_path: Path) -> None:
        archive = _make_zip_archive({"file.txt": b"content"})
        result = extract_zip_bytes(archive, tmp_path)
        assert result == tmp_path


class TestMakeExecutable:
    def test_sets_executable_bits(self, tmp_path: Path) -> None:
        binary = tmp_path / "hayabusa"
        binary.write_bytes(b"fake")
        binary.chmod(0o644)
        make_executable(binary)
        mode = binary.stat().st_mode
        assert mode & 0o111

    @patch("sys.platform", "win32")
    def test_noop_on_windows(self, tmp_path: Path) -> None:
        binary = tmp_path / "hayabusa.exe"
        binary.write_bytes(b"fake")
        binary.chmod(0o644)
        make_executable(binary)
        assert binary.stat().st_mode & 0o777 == 0o644


class TestGetHayabusaVersion:
    def test_returns_version_string(self, tmp_path: Path) -> None:
        binary = tmp_path / "hayabusa"
        binary.write_text("#!/bin/sh\necho 'Hayabusa v4.0.0'", encoding="utf-8")
        binary.chmod(0o755)
        version = get_hayabusa_version(binary)
        assert "v4.0.0" in version


class TestInstallHayabusa:
    _PLATFORM = PlatformInfo("darwin", "aarch64", "mac-aarch64")
    _RELEASE_META = _make_release_meta(
        [{"name": "hayabusa-4.0.0-mac-aarch64.zip", "browser_download_url": "https://example.com/hayabusa.zip"}]
    )

    def _meta_for_archive(self, archive: bytes) -> dict:
        meta = dict(self._RELEASE_META)
        asset = dict(meta["assets"][0])
        asset["digest"] = _sha256_digest(archive)
        meta["assets"] = [asset]
        return meta

    def test_fresh_install(self, tmp_path: Path) -> None:
        target = tmp_path / "tools"
        archive = _make_zip_archive(
            {
                "hayabusa-4.0.0-mac-aarch64": b"fake-binary",
                "rules/default/test.yml": b"rule-content",
            }
        )

        with (
            patch("ovs_logs.core.downloader.detect_platform", return_value=self._PLATFORM),
            patch("ovs_logs.core.downloader.fetch_release_meta", return_value=self._meta_for_archive(archive)),
            patch("ovs_logs.core.downloader.resolve_asset_url", return_value="https://example.com/hayabusa.zip"),
            patch("ovs_logs.core.downloader.download_bytes", return_value=archive),
        ):
            result = install_hayabusa(target, version="4.0.0")

        assert isinstance(result, InstallResult)
        assert result.binary_path.exists()
        assert result.binary_path.name == "hayabusa"
        assert result.platform == self._PLATFORM
        assert result.tag_name == "v4.0.0"
        assert result.binary_path.read_bytes() == b"fake-binary"
        assert (target / "rules" / "default" / "test.yml").read_bytes() == b"rule-content"

    def test_skip_when_already_installed(self, tmp_path: Path) -> None:
        target = tmp_path / "tools"
        target.mkdir()
        binary = target / "hayabusa"
        binary.write_bytes(b"existing")

        with (
            patch("ovs_logs.core.downloader.detect_platform", return_value=self._PLATFORM),
            patch("ovs_logs.core.downloader.fetch_release_meta") as mock_fetch,
        ):
            result = install_hayabusa(target)

        assert isinstance(result, InstallResult)
        assert result.binary_path == binary
        assert result.platform == self._PLATFORM
        mock_fetch.assert_not_called()

    def test_force_redownloads(self, tmp_path: Path) -> None:
        target = tmp_path / "tools"
        target.mkdir()
        binary = target / "hayabusa"
        binary.write_bytes(b"old")

        archive = _make_zip_archive({"hayabusa-4.0.0-mac-aarch64": b"new-binary"})
        with (
            patch("ovs_logs.core.downloader.detect_platform", return_value=self._PLATFORM),
            patch("ovs_logs.core.downloader.fetch_release_meta", return_value=self._meta_for_archive(archive)),
            patch("ovs_logs.core.downloader.resolve_asset_url", return_value="https://example.com/hayabusa.zip"),
            patch("ovs_logs.core.downloader.download_bytes", return_value=archive),
        ):
            result = install_hayabusa(target, force=True)

        assert isinstance(result, InstallResult)
        assert result.binary_path.read_bytes() == b"new-binary"

    def test_checksum_mismatch_raises(self, tmp_path: Path) -> None:
        target = tmp_path / "tools"
        archive = _make_zip_archive({"hayabusa-4.0.0-mac-aarch64": b"fake-binary"})
        meta = self._meta_for_archive(archive)
        meta["assets"][0]["digest"] = _sha256_digest(b"different-content")

        with (
            patch("ovs_logs.core.downloader.detect_platform", return_value=self._PLATFORM),
            patch("ovs_logs.core.downloader.fetch_release_meta", return_value=meta),
            patch("ovs_logs.core.downloader.resolve_asset_url", return_value="https://example.com/hayabusa.zip"),
            patch("ovs_logs.core.downloader.download_bytes", return_value=archive),
            pytest.raises(IngestionError, match="SHA-256 checksum mismatch"),
        ):
            install_hayabusa(target, version="4.0.0")

        assert not (target / "hayabusa").exists()

    def test_missing_digest_raises(self, tmp_path: Path) -> None:
        target = tmp_path / "tools"
        archive = _make_zip_archive({"hayabusa-4.0.0-mac-aarch64": b"fake-binary"})

        with (
            patch("ovs_logs.core.downloader.detect_platform", return_value=self._PLATFORM),
            patch("ovs_logs.core.downloader.fetch_release_meta", return_value=self._RELEASE_META),
            patch("ovs_logs.core.downloader.resolve_asset_url", return_value="https://example.com/hayabusa.zip"),
            patch("ovs_logs.core.downloader.download_bytes", return_value=archive) as mock_download,
            pytest.raises(IngestionError, match="refusing to install an unverifiable binary"),
        ):
            install_hayabusa(target, version="4.0.0")

        mock_download.assert_not_called()
        assert not (target / "hayabusa").exists()


class TestVerifySha256:
    def test_matches_bare_hex(self) -> None:
        digest = hashlib.sha256(b"payload").hexdigest()
        verify_sha256(b"payload", digest)

    def test_matches_prefixed_hex(self) -> None:
        digest = _sha256_digest(b"payload")
        verify_sha256(b"payload", digest)

    def test_mismatch_raises(self) -> None:
        digest = hashlib.sha256(b"payload").hexdigest()
        with pytest.raises(IngestionError, match="SHA-256 checksum mismatch"):
            verify_sha256(b"tampered", digest)

    def test_invalid_digest_raises(self) -> None:
        with pytest.raises(ValueError, match="Invalid SHA-256 digest"):
            verify_sha256(b"payload", "not-a-digest")


class TestFindReleaseAsset:
    def test_returns_matching_asset_with_digest(self) -> None:
        meta = _make_release_meta(
            [
                {
                    "name": "hayabusa-4.0.0-mac-aarch64.zip",
                    "browser_download_url": "https://example.com/mac.zip",
                    "digest": "sha256:abc123",
                }
            ]
        )
        platform = PlatformInfo(os_name="darwin", arch="aarch64", asset_tag="mac-aarch64")
        asset = find_release_asset(meta, platform)
        assert asset["name"] == "hayabusa-4.0.0-mac-aarch64.zip"
        assert asset["digest"] == "sha256:abc123"


class TestFetchReleaseMeta:
    def test_fetches_latest(self) -> None:
        mock_response = MagicMock()
        mock_response.json.return_value = {"tag_name": "v4.0.0", "assets": []}
        mock_response.raise_for_status = MagicMock()

        with patch("ovs_logs.core.downloader.requests.get", return_value=mock_response) as mock_get:
            result = fetch_release_meta()

        assert result["tag_name"] == "v4.0.0"
        mock_get.assert_called_once()
        call_url = mock_get.call_args[0][0]
        assert call_url.endswith("/releases/latest")

    def test_fetches_specific_version(self) -> None:
        mock_response = MagicMock()
        mock_response.json.return_value = {"tag_name": "v3.0.0", "assets": []}
        mock_response.raise_for_status = MagicMock()

        with patch("ovs_logs.core.downloader.requests.get", return_value=mock_response) as mock_get:
            result = fetch_release_meta(version="3.0.0")

        assert result["tag_name"] == "v3.0.0"
        call_url = mock_get.call_args[0][0]
        assert "tags/v3.0.0" in call_url
