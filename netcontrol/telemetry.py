"""Shared logging, redaction, and lightweight metrics helpers for Plexus."""

from __future__ import annotations

import logging
import logging.handlers
import re
import socket
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
_SYSLOG_LOCK = threading.Lock()
_SYSLOG_HANDLER: logging.Handler | None = None
_SYSLOG_CONFIG: dict[str, Any] | None = None
_SYSLOG_MARKER = "_plexus_syslog_handler"

_LOG_LEVELS = {
    "DEBUG": logging.DEBUG,
    "INFO": logging.INFO,
    "WARNING": logging.WARNING,
    "ERROR": logging.ERROR,
    "CRITICAL": logging.CRITICAL,
}

_SYSLOG_FACILITIES = {
    "kern": logging.handlers.SysLogHandler.LOG_KERN,
    "user": logging.handlers.SysLogHandler.LOG_USER,
    "mail": logging.handlers.SysLogHandler.LOG_MAIL,
    "daemon": logging.handlers.SysLogHandler.LOG_DAEMON,
    "auth": logging.handlers.SysLogHandler.LOG_AUTH,
    "syslog": logging.handlers.SysLogHandler.LOG_SYSLOG,
    "lpr": logging.handlers.SysLogHandler.LOG_LPR,
    "news": logging.handlers.SysLogHandler.LOG_NEWS,
    "uucp": logging.handlers.SysLogHandler.LOG_UUCP,
    "cron": logging.handlers.SysLogHandler.LOG_CRON,
    "local0": logging.handlers.SysLogHandler.LOG_LOCAL0,
    "local1": logging.handlers.SysLogHandler.LOG_LOCAL1,
    "local2": logging.handlers.SysLogHandler.LOG_LOCAL2,
    "local3": logging.handlers.SysLogHandler.LOG_LOCAL3,
    "local4": logging.handlers.SysLogHandler.LOG_LOCAL4,
    "local5": logging.handlers.SysLogHandler.LOG_LOCAL5,
    "local6": logging.handlers.SysLogHandler.LOG_LOCAL6,
    "local7": logging.handlers.SysLogHandler.LOG_LOCAL7,
}


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
    if not logger.handlers:
        logger.setLevel(logging.INFO)
        handler = logging.StreamHandler()
        handler.setFormatter(
            logging.Formatter("%(asctime)s %(levelname)s [%(name)s] %(message)s")
        )
        handler.addFilter(RedactingFilter())
        logger.addHandler(handler)
    logger.propagate = False
    _attach_syslog_handler(logger)
    return logger


def _plexus_loggers() -> list[logging.Logger]:
    loggers = [logging.getLogger("plexus")]
    for name, logger_obj in logging.Logger.manager.loggerDict.items():
        if not name.startswith("plexus."):
            continue
        if isinstance(logger_obj, logging.Logger):
            loggers.append(logger_obj)
    return loggers


def _attach_syslog_handler(logger: logging.Logger) -> None:
    if _SYSLOG_HANDLER is None:
        return
    if any(getattr(handler, _SYSLOG_MARKER, False) for handler in logger.handlers):
        return
    logger.addHandler(_SYSLOG_HANDLER)


def _remove_syslog_handlers(logger: logging.Logger) -> None:
    for handler in list(logger.handlers):
        if getattr(handler, _SYSLOG_MARKER, False):
            logger.removeHandler(handler)


def _build_syslog_handler(config: dict[str, Any]) -> logging.Handler:
    protocol = str(config.get("protocol", "udp")).lower()
    socktype = socket.SOCK_STREAM if protocol == "tcp" else socket.SOCK_DGRAM
    host = str(config.get("host", "")).strip()
    port = int(config.get("port", 514))
    facility = _SYSLOG_FACILITIES.get(
        str(config.get("facility", "local0")).lower(),
        logging.handlers.SysLogHandler.LOG_LOCAL0,
    )
    level = _LOG_LEVELS.get(str(config.get("level", "INFO")).upper(), logging.INFO)
    app_name = str(config.get("app_name", "plexus")).strip() or "plexus"
    app_name = "".join(ch for ch in app_name if ch.isalnum() or ch in "._-") or "plexus"

    handler = logging.handlers.SysLogHandler(
        address=(host, port),
        facility=facility,
        socktype=socktype,
    )
    setattr(handler, _SYSLOG_MARKER, True)
    handler.setLevel(level)
    handler.setFormatter(
        logging.Formatter(f"{app_name}[%(process)d]: %(levelname)s %(name)s %(message)s")
    )
    handler.addFilter(RedactingFilter())
    return handler


def configure_syslog_logging(config: dict[str, Any] | None) -> bool:
    """Enable, disable, or refresh outbound syslog logging for Plexus loggers."""
    global _SYSLOG_CONFIG, _SYSLOG_HANDLER

    with _SYSLOG_LOCK:
        requested = dict(config or {})
        if not requested.get("enabled") or not str(requested.get("host", "")).strip():
            old_handler = _SYSLOG_HANDLER
            for logger in _plexus_loggers():
                _remove_syslog_handlers(logger)
            _SYSLOG_HANDLER = None
            _SYSLOG_CONFIG = requested
            if old_handler is not None:
                old_handler.close()
            return True

        try:
            new_handler = _build_syslog_handler(requested)
        except Exception:
            return False

        old_handler = _SYSLOG_HANDLER
        for logger in _plexus_loggers():
            _remove_syslog_handlers(logger)
        _SYSLOG_HANDLER = new_handler
        _SYSLOG_CONFIG = requested
        if old_handler is not None:
            old_handler.close()

        for logger in _plexus_loggers():
            _attach_syslog_handler(logger)
        return True


def syslog_logging_enabled() -> bool:
    return bool(_SYSLOG_CONFIG and _SYSLOG_CONFIG.get("enabled") and _SYSLOG_HANDLER)


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
