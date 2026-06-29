"""Analysis engine, SQL templates, and indicator shaping for anomaly detection."""

from .engine import AnalysisEngine
from .indicators import IndicatorProcessor, SuspiciousIndicator
from .templates import SQLTemplate, TEMPLATES

__all__ = [
    "AnalysisEngine",
    "IndicatorProcessor",
    "SQLTemplate",
    "SuspiciousIndicator",
    "TEMPLATES",
]
