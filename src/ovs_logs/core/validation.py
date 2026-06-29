"""Log file validation and format detection for OVS-Log."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

SUPPORTED_FORMATS = {"csv", "json", "txt", "log", "evtx"}

FORMAT_ALIASES = {
    ".csv": "csv",
    ".json": "json",
    ".txt": "txt",
    ".log": "log",
    ".evtx": "evtx",
}


@dataclass(frozen=True)
class LogFile:
    """Descriptor for a validated input log file."""

    path: Path
    format: str
    needs_conversion: bool


def detect_format(path: Path) -> str:
    """Detect the log format from the file extension or content.

    Supported formats are ``csv``, ``json``, ``txt``, ``log``, and ``evtx``.
    Unknown extensions are inspected via a small content sample. Plain text
    files with unknown extensions are treated as ``log``; binary or otherwise
    unrecognizable content is reported as unsupported.
    """
    suffix = path.suffix.lower()
    if suffix in FORMAT_ALIASES:
        return FORMAT_ALIASES[suffix]

    with path.open("rb") as fh:
        sample = fh.read(4096)
    if not sample:
        raise ValueError(f"Cannot determine format for empty file: {path}")

    try:
        text = sample.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError(
            f"Unsupported binary file format for {path}"
        ) from exc

    first_line = text.lstrip().splitlines()[0] if text else ""
    if first_line.startswith(("{", "[")):
        return "json"
    if "," in first_line and first_line[:1].isalnum():
        return "csv"

    return "log"


def validate_log_file(path: str | Path) -> LogFile:
    """Validate a log file path and return a typed ``LogFile`` descriptor.

    Raises:
        FileNotFoundError: If the file does not exist.
        ValueError: If the path is not a file, is empty, or has an unsupported
            format.
        PermissionError: If the file is not readable.
    """
    p = Path(path)

    if not p.exists():
        raise FileNotFoundError(f"Log file not found: {p}")
    if not p.is_file():
        raise ValueError(f"Path is not a file: {p}")
    if not os.access(p, os.R_OK):
        raise PermissionError(f"Log file is not readable: {p}")
    if p.stat().st_size == 0:
        raise ValueError(f"Log file is empty: {p}")

    fmt = detect_format(p)
    if fmt not in SUPPORTED_FORMATS:
        raise ValueError(f"Unsupported log format '{fmt}' for file: {p}")

    return LogFile(path=p, format=fmt, needs_conversion=(fmt == "evtx"))
