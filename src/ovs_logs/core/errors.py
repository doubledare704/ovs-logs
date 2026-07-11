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


def classify_error(exc: Exception) -> int:
    """Map an exception to its corresponding CLI exit code.

    Args:
        exc: The exception to classify.

    Returns:
        One of the ``EXIT_*`` constants defined in this module.
    """
    if isinstance(exc, (FileNotFoundError, PermissionError)):
        logger.error("File error: %s", exc)
        return EXIT_FILE_ERROR
    if isinstance(exc, ValueError):
        logger.error("Validation error: %s", exc)
        return EXIT_VALIDATION_ERROR
    if isinstance(exc, NotImplementedError):
        logger.error("Not supported: %s", exc)
        return EXIT_NOT_SUPPORTED
    logger.error("Unexpected error: %s", exc)
    return EXIT_UNEXPECTED


def error_category(exc: Exception) -> str:
    """Return a user-friendly category label for an exception.

    Returns one of ``"File error"``, ``"Validation error"``, ``"Not supported"``,
    or ``"Unexpected error"``.
    """
    if isinstance(exc, (FileNotFoundError, PermissionError)):
        return "File error"
    if isinstance(exc, ValueError):
        return "Validation error"
    if isinstance(exc, NotImplementedError):
        return "Not supported"
    return "Unexpected error"
