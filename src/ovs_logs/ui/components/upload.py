"""File upload, validation, preview, and deduplication helpers.

Extracted from the monolithic ``app.py`` so the upload pipeline can be
understood and tested independently of the rest of the dashboard.
"""

from __future__ import annotations

import hashlib
import logging
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING, Any

import streamlit as st

from ovs_logs.core.constants import KB, MB
from ovs_logs.core.ingestion.adapters import iter_evtx_record_summaries
from ovs_logs.core.validation import validate_log_file
from ovs_logs.ui.state import SessionKeys

if TYPE_CHECKING:
    from streamlit.runtime.uploaded_file_manager import UploadedFile


logger = logging.getLogger(__name__)

SK = SessionKeys()

_MAX_PREVIEW_LINES = 200
_MAX_PREVIEW_BYTES = 64 * KB


def _save_uploaded_file(uploaded_file: UploadedFile) -> tuple[Path, str]:
    """Save an uploaded file to a temporary location and return its path + SHA-256 hash."""
    uploaded_file.seek(0)
    suffix = Path(uploaded_file.name).suffix
    temp_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=suffix or ".tmp") as tmp:
            temp_path = Path(tmp.name)
            hasher = hashlib.sha256()
            while chunk := uploaded_file.read(8192):
                tmp.write(chunk)
                hasher.update(chunk)
    except OSError:
        if temp_path is not None:
            temp_path.unlink(missing_ok=True)
        raise
    if temp_path is None:
        raise RuntimeError("Failed to create temporary file")
    uploaded_file.seek(0)
    return temp_path, hasher.hexdigest()


def _preview_evtx(path: Path, max_records: int = 50) -> str:
    """Render a short readable summary of EVTX records via the core adapter."""
    try:
        summaries = iter_evtx_record_summaries(path, max_records=max_records)
    except Exception as exc:  # pragma: no cover - exercised through parser errors
        logger.warning("Unable to preview EVTX file %s: %s", path, exc)
        return f"Unable to preview EVTX file: {exc}"

    lines = [
        f"#{summary['record_id']} | {summary['timestamp']} | EventID={summary['event_id']} | "
        f"{summary['provider']} | {summary['channel']}"
        for summary in summaries
    ]
    return "\n".join(lines) if lines else "(no records found)"


@st.cache_data(ttl=5)
def _read_preview_lines(path: Path, max_lines: int = _MAX_PREVIEW_LINES) -> str:
    """Read the first *max_lines* from a file for display in the upload preview."""
    if path.suffix.lower() == ".evtx":
        return _preview_evtx(path)

    lines: list[bytes] = []
    bytes_read = 0
    with path.open("rb") as fh:
        for _ in range(max_lines):
            remaining = _MAX_PREVIEW_BYTES - bytes_read
            if remaining <= 0:
                break
            line = fh.readline(remaining + 1)
            if not line:
                break
            lines.append(line[:remaining].rstrip(b"\n"))
            bytes_read += min(len(line), remaining)
            if len(line) > remaining:
                break
    return b"\n".join(lines).decode("utf-8", errors="replace")


def _find_uploaded_file(uploaded_files: list[dict[str, Any]], content_hash: str) -> bool:
    return any(file["content_hash"] == content_hash for file in uploaded_files)


def _format_size(size: int) -> str:
    """Format a byte count into a human-readable string."""
    if size >= MB:
        return f"{size / MB:.1f} MB"
    if size >= KB:
        return f"{size / KB:.1f} KB"
    return f"{size} B"


def register_uploaded_file(uploaded_file: UploadedFile) -> tuple[bool, str | None]:
    """Register a newly uploaded file for the ingest pipeline.

    Saves the file to a temporary location, computes a content hash for
    deduplication, and appends a metadata dict to ``uploaded_files`` in
    session state.  Returns a ``(created, message)`` pair: ``created`` is
    ``True`` when the file was newly registered, ``False`` when it is a
    duplicate or has already been consumed.  *message* contains a warning
    string for duplicates and is ``None`` on success.
    """
    upload_id = f"{uploaded_file.name}:{uploaded_file.size}"
    if upload_id in st.session_state.get(SK.consumed_uploads, set()):
        return False, None

    uploaded_files = st.session_state[SK.uploaded_files]
    if any(f["name"] == uploaded_file.name and f["size"] == uploaded_file.size for f in uploaded_files):
        return False, None

    try:
        temp_path, content_hash = _save_uploaded_file(uploaded_file)
    except OSError as exc:
        return False, f"Unable to save upload {uploaded_file.name}: {exc}"

    if _find_uploaded_file(uploaded_files, content_hash):
        temp_path.unlink(missing_ok=True)
        return False, f"Duplicate file skipped: {uploaded_file.name}"

    uploaded_files.append(
        {
            "name": uploaded_file.name,
            "size": uploaded_file.size,
            "content_hash": content_hash,
            "temp_path": str(temp_path),
            "format": None,
            "validated": False,
            "validation_error": None,
            "status": "pending",
            "preview": None,
            "ingest_table": None,
            "row_count": None,
            "schema": None,
            "normalized_table": None,
            "normalized_row_count": None,
        }
    )
    st.session_state.setdefault(SK.consumed_uploads, set()).add(upload_id)
    return True, None


def validate_uploaded_file(file_state: dict[str, Any]) -> None:
    """Validate a pending uploaded file and update its session state entry."""
    try:
        log_file = validate_log_file(file_state["temp_path"])
        file_state["format"] = log_file.format
        file_state["validated"] = True
        file_state["validation_error"] = None
        file_state["status"] = "ready"
        file_state["preview"] = _read_preview_lines(Path(file_state["temp_path"]))
    except (OSError, ValueError) as exc:
        Path(file_state["temp_path"]).unlink(missing_ok=True)
        file_state["validated"] = False
        file_state["validation_error"] = str(exc)
        file_state["status"] = "invalid"
        file_state["preview"] = None
