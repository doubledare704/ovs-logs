"""Shared error classification and exit-code mapping for OVS-Log.

Provides a single ``classify_error`` function that both the CLI and UI can
use to map exceptions to consistent exit codes and user-facing messages.
"""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)

# Exit codes used by the CLI
EXIT_SUCCESS = 0
EXIT_FILE_ERROR = 2
EXIT_VALIDATION_ERROR = 3
EXIT_NOT_SUPPORTED = 4
EXIT_UNEXPECTED = 1


class IngestionError(Exception):
    """Raised when an ingestion operation fails."""


class BinaryNotFoundError(IngestionError):
    """Raised when an external binary required for ingestion cannot be found."""


# Ordered classification ladder shared by ``classify_error`` and ``error_category``.
# The first matching entry wins; anything unmatched falls back to the "unexpected"
# defaults. Keeping this single source of truth prevents the exit code and the
# displayed category from drifting apart.
_CLASSIFICATIONS: list[tuple[tuple[type[Exception], ...], int, str]] = [
    ((FileNotFoundError, PermissionError), EXIT_FILE_ERROR, "File error"),
    ((ValueError,), EXIT_VALIDATION_ERROR, "Validation error"),
    ((IngestionError,), EXIT_VALIDATION_ERROR, "Ingestion error"),
    ((NotImplementedError,), EXIT_NOT_SUPPORTED, "Not supported"),
]


def _classify(exc: Exception) -> tuple[int, str]:
    """Return the ``(exit_code, label)`` pair for ``exc`` from the shared ladder."""
    for exc_types, exit_code, label in _CLASSIFICATIONS:
        if isinstance(exc, exc_types):
            return exit_code, label
    return EXIT_UNEXPECTED, "Unexpected error"


def classify_error(exc: Exception) -> int:
    """Map an exception to its corresponding CLI exit code.

    Args:
        exc: The exception to classify.

    Returns:
        One of the ``EXIT_*`` constants defined in this module.
    """
    exit_code, label = _classify(exc)
    logger.error("%s: %s", label, exc)
    return exit_code


def error_category(exc: Exception) -> str:
    """Return a user-friendly category label for an exception.

    Returns one of ``"File error"``, ``"Validation error"``, ``"Not supported"``,
    or ``"Unexpected error"``.
    """
    return _classify(exc)[1]
