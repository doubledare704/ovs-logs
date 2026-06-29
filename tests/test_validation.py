"""Tests for the log file validation module."""

from pathlib import Path

import pytest

from ovs_logs.core.validation import LogFile, validate_log_file


def test_valid_csv(tmp_path: Path) -> None:
    file = tmp_path / "access.csv"
    file.write_text("timestamp,client_ip,status\n2024-01-01T00:00:00,1.2.3.4,200\n")

    log = validate_log_file(file)

    assert isinstance(log, LogFile)
    assert log.path == file
    assert log.format == "csv"
    assert not log.needs_conversion


def test_valid_json(tmp_path: Path) -> None:
    file = tmp_path / "events.json"
    file.write_text('[{"timestamp":"2024-01-01T00:00:00","client_ip":"1.2.3.4"}]')

    log = validate_log_file(file)

    assert log.format == "json"
    assert not log.needs_conversion


def test_valid_txt(tmp_path: Path) -> None:
    file = tmp_path / "notes.txt"
    file.write_text("plain text log line\n")

    log = validate_log_file(file)

    assert log.format == "txt"
    assert not log.needs_conversion


def test_valid_log(tmp_path: Path) -> None:
    file = tmp_path / "access.log"
    file.write_text("2024-01-01T00:00:00 GET /api 200\n")

    log = validate_log_file(file)

    assert log.format == "log"
    assert not log.needs_conversion


def test_valid_evtx_requires_conversion(tmp_path: Path) -> None:
    file = tmp_path / "security.evtx"
    file.write_bytes(b"EVT\x00...")

    log = validate_log_file(file)

    assert log.format == "evtx"
    assert log.needs_conversion


def test_empty_file_raises(tmp_path: Path) -> None:
    file = tmp_path / "empty.log"
    file.write_text("")

    with pytest.raises(ValueError, match="empty"):
        validate_log_file(file)


def test_missing_file_raises(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        validate_log_file(tmp_path / "missing.csv")


def test_unsupported_binary_raises(tmp_path: Path) -> None:
    file = tmp_path / "image.png"
    file.write_bytes(b"\x89PNG\r\n\x1a\n")

    with pytest.raises(ValueError, match="Unsupported"):
        validate_log_file(file)
