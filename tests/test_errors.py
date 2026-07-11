"""Tests for the shared error classification module."""

from ovs_logs.core.errors import (
    EXIT_FILE_ERROR,
    EXIT_NOT_SUPPORTED,
    EXIT_UNEXPECTED,
    EXIT_VALIDATION_ERROR,
    classify_error,
    error_category,
)


def test_classify_error_exit_codes() -> None:
    assert classify_error(FileNotFoundError("x")) == EXIT_FILE_ERROR
    assert classify_error(PermissionError("x")) == EXIT_FILE_ERROR
    assert classify_error(ValueError("x")) == EXIT_VALIDATION_ERROR
    assert classify_error(NotImplementedError("x")) == EXIT_NOT_SUPPORTED
    assert classify_error(RuntimeError("x")) == EXIT_UNEXPECTED


def test_error_category_labels() -> None:
    assert error_category(FileNotFoundError("x")) == "File error"
    assert error_category(ValueError("x")) == "Validation error"
    assert error_category(NotImplementedError("x")) == "Not supported"
    assert error_category(RuntimeError("x")) == "Unexpected error"


def test_classify_and_category_stay_in_sync() -> None:
    """Both public functions derive from the same ladder, so they must agree."""
    exceptions = [
        FileNotFoundError("x"),
        PermissionError("x"),
        ValueError("x"),
        NotImplementedError("x"),
        RuntimeError("x"),
    ]
    codes = {classify_error(exc) for exc in exceptions}
    labels = {error_category(exc) for exc in exceptions}
    # 4 distinct categories/codes across the 5 exceptions (File error shared by two)
    assert len(codes) == len(labels) == 4
