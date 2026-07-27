"""OVS-Log: local AI-powered log tracer and DFIR assistant."""

from .presentation import FormattedContext, FormatterConfig, format_context

__version__ = "0.1.0"

__all__ = [
    "FormattedContext",
    "FormatterConfig",
    "__version__",
    "format_context",
]
