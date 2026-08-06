"""Ingestion adapters for loading raw logs into DuckDB."""

from .adapters import (
    HybridIngestionPipeline,
    HybridIngestionResult,
    IngestionResult,
    load_csv,
    load_evtx,
    load_evtx_via_hayabusa,
    load_evtx_via_hayabusa_json,
    load_json,
    load_text_log,
)

__all__ = [
    "HybridIngestionPipeline",
    "HybridIngestionResult",
    "IngestionResult",
    "load_csv",
    "load_evtx",
    "load_evtx_via_hayabusa",
    "load_evtx_via_hayabusa_json",
    "load_json",
    "load_text_log",
]
