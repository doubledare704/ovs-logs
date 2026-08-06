"""Tests for the setup-hayabusa CLI command."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from typer.testing import CliRunner

from ovs_logs.cli.main import app
from ovs_logs.core.downloader import InstallResult, PlatformInfo

runner = CliRunner()

_DARWIN_ARM = PlatformInfo(os_name="darwin", arch="aarch64", asset_tag="mac-aarch64")


def _make_result(tmp_path: Path, tag: str = "v4.0.0") -> InstallResult:
    binary = tmp_path / "hayabusa"
    binary.write_bytes(b"fake-binary")
    return InstallResult(binary_path=binary, platform=_DARWIN_ARM, tag_name=tag)


def test_setup_hayabusa_success(tmp_path: Path) -> None:
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    (rules_dir / "default").mkdir()
    (rules_dir / "default" / "test.yml").write_text("title: test", encoding="utf-8")

    with (
        patch(
            "ovs_logs.core.downloader.install_hayabusa",
            return_value=_make_result(tmp_path),
        ) as mock_install,
        patch(
            "ovs_logs.core.downloader.get_hayabusa_version",
            return_value="v4.0.0",
        ),
    ):
        result = runner.invoke(app, ["setup-hayabusa", "--target-dir", str(tmp_path)])

    assert result.exit_code == 0
    assert "Hayabusa installed successfully" in result.output
    assert "v4.0.0" in result.output
    assert "1 rule files" in result.output
    mock_install.assert_called_once()


def test_setup_hayabusa_specific_version(tmp_path: Path) -> None:
    with (
        patch(
            "ovs_logs.core.downloader.install_hayabusa",
            return_value=_make_result(tmp_path, tag="v3.0.0"),
        ) as mock_install,
        patch(
            "ovs_logs.core.downloader.get_hayabusa_version",
            return_value="v3.0.0",
        ),
    ):
        result = runner.invoke(
            app,
            ["setup-hayabusa", "--target-dir", str(tmp_path), "--version", "3.0.0"],
        )

    assert result.exit_code == 0
    mock_install.assert_called_once_with(
        tmp_path,
        version="3.0.0",
        force=False,
    )


def test_setup_hayabusa_force_flag(tmp_path: Path) -> None:
    with (
        patch(
            "ovs_logs.core.downloader.install_hayabusa",
            return_value=_make_result(tmp_path),
        ) as mock_install,
        patch(
            "ovs_logs.core.downloader.get_hayabusa_version",
            return_value="v4.0.0",
        ),
    ):
        result = runner.invoke(
            app,
            ["setup-hayabusa", "--target-dir", str(tmp_path), "--force"],
        )

    assert result.exit_code == 0
    mock_install.assert_called_once_with(
        tmp_path,
        version=None,
        force=True,
    )


def test_setup_hayabusa_error_handling(tmp_path: Path) -> None:
    with patch(
        "ovs_logs.core.downloader.detect_platform",
        side_effect=ValueError("Unsupported platform"),
    ):
        result = runner.invoke(app, ["setup-hayabusa", "--target-dir", str(tmp_path)])

    assert result.exit_code != 0
    assert "Unsupported platform" in result.output


def test_setup_hayabusa_no_rules_dir(tmp_path: Path) -> None:
    with (
        patch(
            "ovs_logs.core.downloader.install_hayabusa",
            return_value=_make_result(tmp_path),
        ),
        patch(
            "ovs_logs.core.downloader.get_hayabusa_version",
            return_value="v4.0.0",
        ),
    ):
        result = runner.invoke(app, ["setup-hayabusa", "--target-dir", str(tmp_path)])

    assert result.exit_code == 0
    assert "No rules directory found" in result.output
