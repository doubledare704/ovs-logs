"""Ingestion adapters for loading raw logs into DuckDB."""

from .adapters import LoadResult, load_csv, load_evtx, load_json, load_text_log

__all__ = [
    "LoadResult",
    "load_csv",
    "load_json",
    "load_text_log",
    "load_evtx",
]
