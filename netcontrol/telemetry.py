"""Shared logging, redaction, and lightweight metrics helpers for Plexus."""

from __future__ import annotations

import logging
import re
import threading
from collections import defaultdict
from typing import Any

_SENSITIVE_FIELD_PATTERN = re.compile(
    r"(password|secret|token|authorization|api[_-]?key)",
    re.IGNORECASE,
)

_SENSITIVE_ASSIGNMENT_PATTERN = re.compile(
    r"((?:password|secret|token|api[_-]?key)\s*[=:]\s*)([^\s,;]+)",
    re.IGNORECASE,
)

_METRICS_LOCK = threading.Lock()
_COUNTERS: dict[str, int] = defaultdict(int)
_TIMINGS: dict[str, list[float]] = defaultdict(list)


class RedactingFilter(logging.Filter):
    """Filter that strips obvious secrets from log messages and args."""

    def filter(self, record: logging.LogRecord) -> bool:
        record.msg = redact_value(record.msg)
        if record.args:
            if isinstance(record.args, dict):
                record.args = {k: redact_value(v) for k, v in record.args.items()}
            else:
                record.args = tuple(redact_value(a) for a in record.args)
        return True


def _redact_string(value: str) -> str:
    return _SENSITIVE_ASSIGNMENT_PATTERN.sub(r"\1***", value)


def redact_value(value: Any) -> Any:
    if isinstance(value, dict):
        redacted: dict[str, Any] = {}
        for key, val in value.items():
            if _SENSITIVE_FIELD_PATTERN.search(str(key)):
                redacted[key] = "***"
            else:
                redacted[key] = redact_value(val)
        return redacted
    if isinstance(value, list):
        return [redact_value(v) for v in value]
    if isinstance(value, tuple):
        return tuple(redact_value(v) for v in value)
    if isinstance(value, str):
        return _redact_string(value)
    return value


def configure_logging(logger_name: str = "plexus") -> logging.Logger:
    logger = logging.getLogger(logger_name)
    if logger.handlers:
        return logger

    logger.setLevel(logging.INFO)
    handler = logging.StreamHandler()
    handler.setFormatter(
        logging.Formatter("%(asctime)s %(levelname)s [%(name)s] %(message)s")
    )
    handler.addFilter(RedactingFilter())
    logger.addHandler(handler)
    logger.propagate = False
    return logger


def increment_metric(name: str, value: int = 1) -> None:
    with _METRICS_LOCK:
        _COUNTERS[name] += value


def observe_timing(name: str, duration_ms: float) -> None:
    with _METRICS_LOCK:
        _TIMINGS[name].append(duration_ms)


def snapshot_metrics() -> dict[str, Any]:
    with _METRICS_LOCK:
        timings_summary: dict[str, dict[str, float]] = {}
        for metric_name, values in _TIMINGS.items():
            if not values:
                continue
            timings_summary[metric_name] = {
                "count": float(len(values)),
                "avg_ms": round(sum(values) / len(values), 2),
                "max_ms": round(max(values), 2),
            }
        return {
            "counters": dict(_COUNTERS),
            "timings": timings_summary,
        }
