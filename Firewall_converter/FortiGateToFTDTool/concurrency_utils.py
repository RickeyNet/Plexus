from __future__ import annotations

import random
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Callable, Iterable, TypeVar

T = TypeVar("T")
R = TypeVar("R")

# Common error fragments returned by FTD API wrappers for transient failures.
DEFAULT_TRANSIENT_ERROR_TOKENS = (
    "429",
    "too many",
    "rate limit",
    "timeout",
    "temporarily",
    "503",
    "504",
)


def is_transient_error(error: object, tokens: Iterable[str] = DEFAULT_TRANSIENT_ERROR_TOKENS) -> bool:
    """Return True when an error message suggests a retryable/transient condition."""
    if not error:
        return False
    message = str(error).lower()
    return any(token in message for token in tokens)


def run_with_retry(
    operation: Callable[[], tuple[bool, R]],
    should_retry: Callable[[R], bool],
    max_attempts: int = 4,
    initial_backoff: float = 0.3,
    jitter_max: float = 0.25,
) -> tuple[bool, R]:
    """Run an operation with exponential backoff retries based on callback return values."""
    attempts = max(1, max_attempts)
    backoff = initial_backoff

    for attempt in range(attempts):
        success, result = operation()
        if success:
            return True, result

        last_result = result
        if attempt < attempts - 1 and should_retry(result):
            time.sleep(backoff + random.uniform(0, jitter_max))
            backoff *= 2
            continue

        return False, result

    raise RuntimeError("run_with_retry reached an unreachable state")


def run_thread_pool(items: list[T], max_workers: int, worker: Callable[[int, T], None]) -> None:
    """Execute worker(index, item) for each item using a bounded thread pool."""
    workers = max(1, max_workers)
    with ThreadPoolExecutor(max_workers=workers) as executor:
        for index, item in enumerate(items):
            executor.submit(worker, index, item)
