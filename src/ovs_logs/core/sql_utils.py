"""Shared SQL identifier helpers for DuckDB queries."""

from __future__ import annotations


def quote_identifier(identifier: str) -> str:
    """Quote an identifier safely for DuckDB SQL."""
    return '"' + identifier.replace('"', '""') + '"'
