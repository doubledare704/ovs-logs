"""Analysis engine, SQL templates, and indicator shaping for anomaly detection."""

from .engine import AnalysisEngine
from .indicators import IndicatorProcessor, SuspiciousIndicator
from .templates import TEMPLATES, SQLTemplate

__all__ = [
    "TEMPLATES",
    "AnalysisEngine",
    "IndicatorProcessor",
    "SQLTemplate",
    "SuspiciousIndicator",
]
