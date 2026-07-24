"""Ingestion adapters for loading raw logs into DuckDB."""

from .adapters import (
    LoadResult,
    load_csv,
    load_evtx,
    load_evtx_via_evtxecmd,
    load_evtx_via_evtxecmd_json,
    load_evtx_via_hayabusa,
    load_evtx_via_hayabusa_json,
    load_json,
    load_text_log,
)

__all__ = [
    "LoadResult",
    "load_csv",
    "load_evtx",
    "load_evtx_via_evtxecmd",
    "load_evtx_via_evtxecmd_json",
    "load_evtx_via_hayabusa",
    "load_evtx_via_hayabusa_json",
    "load_json",
    "load_text_log",
]
