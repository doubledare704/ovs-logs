"""Shared display helpers for rendering incident reports in the UI.

Centralizes severity badges and date formatting so the Intelligence and
Mitigation tabs render report metadata consistently.
"""

from __future__ import annotations

_SEVERITY_EMOJI: dict[str, str] = {"High": "🔴", "Medium": "🟡", "Low": "🟢"}


def severity_label(severity: str) -> str:
    """Return ``severity`` prefixed with its emoji indicator."""
    emoji = _SEVERITY_EMOJI.get(severity, "⚪")
    return f"{emoji} {severity}"


def report_date_label(created_at: object) -> str:
    """Render a ``created_at`` value (datetime, date, or str) as ``YYYY-MM-DD``.

    Falls back to ``"unknown"`` for null values so internal tables with partial
    rows never render a literal ``"None"`` label.
    """
    if created_at is None:
        return "unknown"
    return str(created_at)[:10]
