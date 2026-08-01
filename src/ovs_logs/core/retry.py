"""Reusable retry decorator with exponential backoff for transient failures."""

import functools
import logging
import time
from collections.abc import Callable
from typing import Protocol

logger = logging.getLogger(__name__)


class _RetryDecorator(Protocol):
    def __call__[**P, R](self, func: Callable[P, R]) -> Callable[P, R]: ...


def retry(
    max_retries: int = 2,
    backoff_seconds: float = 1.0,
    exceptions: tuple[type[Exception], ...] = (Exception,),
    on_retry: Callable[[Exception, int], None] | None = None,
) -> _RetryDecorator:
    """Decorator that retries the wrapped callable on transient exceptions.

    After *max_retries* consecutive failures the last exception is re-raised
    so the caller still receives the original error when the operation is
    genuinely unrecoverable.

    Args:
        max_retries: Maximum number of *retry* attempts (0 = try once, no
            retry).  The total number of calls to *func* is ``max_retries + 1``.
        backoff_seconds: Base delay in seconds.  The actual delay before
            retry ``n`` (0-indexed) is ``backoff_seconds * (2 ** n)``.
        exceptions: Tuple of exception types that should trigger a retry.
            Other exceptions propagate immediately.
        on_retry: Optional callback invoked just before each retry sleep,
            useful for metrics or custom logging.  Receives the exception
            and the zero-based attempt index.

    Example::

        @retry(max_retries=3, backoff_seconds=0.5, exceptions=(requests.Timeout,))
        def fetch_data(url: str) -> bytes:
            return requests.get(url, timeout=5).content
    """

    def decorator[**P, R](func: Callable[P, R]) -> Callable[P, R]:
        @functools.wraps(func)
        def wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
            last_exc: Exception | None = None
            for attempt in range(max_retries + 1):
                try:
                    return func(*args, **kwargs)
                except exceptions as exc:
                    last_exc = exc
                    if attempt < max_retries:
                        delay = backoff_seconds * (2**attempt)
                        if on_retry is not None:
                            on_retry(exc, attempt)

                        logger.debug(
                            "Retrying %s after attempt %d/%d (delay=%.1fs)",
                            func.__name__,
                            attempt + 1,
                            max_retries,
                            delay,
                        )
                        time.sleep(delay)

            if last_exc is not None:
                raise last_exc

            raise RuntimeError("Retry loop exhausted without exceptions.")

        return wrapper

    return decorator
