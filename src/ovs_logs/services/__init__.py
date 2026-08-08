"""Service layer: orchestration of core components for CLI and UI clients.

Services encapsulate multi-step workflows (analysis, threat intel, LLM synthesis)
so that both the CLI (``cli/``) and UI (``ui/``) can reuse the same orchestration
logic without duplicating pipeline code or importing core internals directly.
"""

from ..core.models import AnalysisConfig
from .analysis_service import AnalysisService

__all__ = [
    "AnalysisConfig",
    "AnalysisService",
]
