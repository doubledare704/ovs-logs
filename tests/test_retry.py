"""Tests for the retry decorator with exponential backoff."""

from __future__ import annotations

from unittest.mock import Mock, patch

import pytest

from ovs_logs.core.retry import retry


def test_success_on_first_attempt() -> None:
    """Function succeeds on first try — no retries needed."""
    mock_func = Mock(return_value="ok")

    @retry(max_retries=2)
    def wrapped() -> str:
        return mock_func()

    result = wrapped()

    assert result == "ok"
    assert mock_func.call_count == 1


def test_retry_on_transient_then_success() -> None:
    """Function fails once, then succeeds on retry."""
    call_count = 0

    @retry(max_retries=2, backoff_seconds=0.01)
    def wrapped() -> str:
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            msg = "transient"
            raise ConnectionError(msg)
        return "ok"

    with patch("ovs_logs.core.retry.time.sleep", return_value=None):
        result = wrapped()

    assert result == "ok"
    assert call_count == 2


def test_exhaustion_raises_last_exception() -> None:
    """All retries exhausted — last exception is re-raised."""

    @retry(max_retries=2, backoff_seconds=0.01)
    def wrapped() -> str:
        raise ValueError("persistent")

    with (
        patch("ovs_logs.core.retry.time.sleep", return_value=None),
        pytest.raises(ValueError, match="persistent"),
    ):
        wrapped()


def test_on_retry_callback_invoked() -> None:
    """on_retry callback receives the exception and attempt index."""
    calls: list[tuple[Exception, int]] = []

    def on_retry_cb(exc: Exception, attempt: int) -> None:
        calls.append((exc, attempt))

    @retry(max_retries=2, backoff_seconds=0.01, on_retry=on_retry_cb)
    def wrapped() -> str:
        raise TimeoutError("timeout")

    with (
        patch("ovs_logs.core.retry.time.sleep", return_value=None),
        pytest.raises(TimeoutError),
    ):
        wrapped()

    assert len(calls) == 2
    assert isinstance(calls[0][0], TimeoutError)
    assert calls[0][1] == 0
    assert isinstance(calls[1][0], TimeoutError)
    assert calls[1][1] == 1


def test_exponential_backoff_timing() -> None:
    """Delay is backoff_seconds * 2**attempt for each retry."""
    sleeps: list[float] = []

    @retry(max_retries=3, backoff_seconds=1.0)
    def wrapped() -> str:
        raise RuntimeError("fail")

    with (
        patch("ovs_logs.core.retry.time.sleep", side_effect=sleeps.append),
        pytest.raises(RuntimeError),
    ):
        wrapped()

    assert sleeps == [1.0, 2.0, 4.0]


def test_non_matching_exception_propagates_immediately() -> None:
    """Exceptions not in the retry list propagate immediately without retry."""
    call_count = 0

    @retry(max_retries=2, backoff_seconds=0.01, exceptions=(ValueError,))
    def wrapped() -> str:
        nonlocal call_count
        call_count += 1
        raise TypeError("not retryable")

    with pytest.raises(TypeError, match="not retryable"):
        wrapped()

    assert call_count == 1


def test_no_retry_max_retries_zero() -> None:
    """max_retries=0 means try once, no retry on failure."""

    @retry(max_retries=0, backoff_seconds=0.01)
    def wrapped() -> str:
        raise ValueError("no retry")

    with (
        patch("ovs_logs.core.retry.time.sleep", return_value=None),
        pytest.raises(ValueError, match="no retry"),
    ):
        wrapped()
