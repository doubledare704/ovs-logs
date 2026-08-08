"""Shared Streamlit preview helpers for the OVS-Log dashboard."""

import json
from collections.abc import Mapping, Sequence
from typing import Any, cast


def _serialize_preview_value(value: Any) -> Any:
    """Convert non-Streamlit-friendly objects into preview-safe values."""
    if isinstance(value, (dict, list, tuple, set)):
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, bytes):
        try:
            return value.decode("utf-8")
        except UnicodeDecodeError:
            return repr(value)
    return value


def serialize_preview_rows(
    rows: Sequence[Mapping[str, Any]] | Sequence[tuple[Any, ...]], columns: Sequence[str] | None = None
) -> list[dict[str, Any]]:
    """Serialize rows into a list of preview-safe dictionaries for Streamlit."""
    if not rows:
        return []

    if columns is not None:
        return [
            {column: _serialize_preview_value(value) for column, value in zip(columns, row, strict=True)}
            for row in rows
        ]

    if isinstance(rows[0], Mapping):
        return [
            {key: _serialize_preview_value(value) for key, value in cast(Mapping[str, Any], row).items()}
            for row in rows
        ]

    raise TypeError("serialize_preview_rows requires a columns list for tuple rows")
