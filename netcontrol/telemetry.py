"""Shared logging, redaction, and lightweight metrics helpers for Plexus."""

from __future__ import annotations

import logging
import logging.handlers
import re
import socket
import threading
from collections import defaultdict, deque
from collections.abc import Iterable
from typing import Any

from netcontrol.secret_keys import SECRET_KEY_REGEX, SECRET_KEY_WORDS, should_mask

_MASK = "***"

# A quoted value is read up to this many characters, so a quote that never
# closes costs one bounded scan, not one to the end of the line.
_MAX_QUOTED = 1024

# A secret key name (``netcontrol.secret_keys``), possibly the tail of a
# longer name (``db_password``) and possibly quoted (JSON), then ``=`` or
# ``:`` and the value: a quoted string, or one token with an optional
# scheme (``Authorization: Bearer x``). Nothing may follow the key name
# before the separator, so ``token_count=5`` and ``credential_id: 7`` stay;
# a boolean or null value stays too (``has_password: true``).
_SENSITIVE_ASSIGNMENT_PATTERN = re.compile(
    rf"(?P<p>{SECRET_KEY_REGEX}s?[\"']?[ \t]*+[=:][ \t]*+)"
    r"(?!(?:true|false|none|null)\b)"
    r"(?P<v>(?:(?:bearer|basic|token|digest|negotiate)[ \t]++)?"
    rf"(?:\"[^\"\n]{{0,{_MAX_QUOTED}}}\"|'[^'\n]{{0,{_MAX_QUOTED}}}'|[\"']?[^\s,;&\"'}}\]]+))",
    re.IGNORECASE,
)

# Words that follow "password" or "secret" in a log sentence, not a value.
_NOT_A_VALUE = (
    r"(?:is|was|are|be|been|for|of|to|and|or|not|no|in|on|at|by|with|from|the|a|an|if|as|"
    r"reset|change|changed|changes|expired|expires|expiry|incorrect|invalid|wrong|required|missing|provided|"
    r"supplied|empty|blank|policy|length|must|has|have|had|set|auth|authentication|login|prompt|failed|"
    r"failure|mismatch|too|cannot|update|updated|variables?|manager|operator|peer|field|fields|value|hash|"
    r"stored|rotation|accepted|rejected|ok|error|check|does|did|should|will|ref|reference|id|count|key|keys|"
    r"store|vault|provider|engine|name|names|type|file|path|level|encryption|encrypted|\*\*\*)"
)
# Device configuration style: "password x", "enable secret 5 x".
_SENSITIVE_WORD_PATTERN = re.compile(
    r"(?P<p>\b(?:password|passwd|secret)[ \t]++(?:[0-9][ \t]++)?)"
    rf"(?!{_NOT_A_VALUE}(?![^\s,;]))(?P<v>[^\s,;]+)",
    re.IGNORECASE,
)

# An HTTP credential after its scheme. The value must look like a token (a
# digit, a symbol or mixed case) so "basic authentication" still reads.
_AUTH_SCHEME_PATTERN = re.compile(
    r"(?P<p>\b(?i:bearer|basic)[ \t]++)"
    r"(?P<v>(?=[A-Za-z0-9\-._~+/]*?(?:[0-9\-._~+/=]|[a-z][A-Z]))[A-Za-z0-9\-._~+/]++=*+)"
)

# SNMP communities in configuration text (``netcontrol.mcp.redact`` has the
# full set of device configuration rules).
_COMMUNITY_PATTERN = re.compile(r"(?P<p>\bsnmp(?:-server)?[ \t]++community[ \t]++)(?P<v>[^\s,;]+)", re.IGNORECASE)

# The password of URL userinfo (``scheme://user:password@host``), and the
# whole userinfo of an http(s) URL without one (``https://token@host``, the
# usual way a token is put in a Git remote). The user name stays.
_URL_PASSWORD_PATTERN = re.compile(r"(?P<p>\b[A-Za-z][A-Za-z0-9+.\-]{0,31}://[^\s/?#@:]*+:)(?P<v>[^\s/?#@]++)(?=@)")
_URL_TOKEN_PATTERN = re.compile(r"(?P<p>\bhttps?://)(?P<v>[^\s/?#@:]++)(?=@)", re.IGNORECASE)

_STRING_PATTERNS = (
    _SENSITIVE_ASSIGNMENT_PATTERN,
    _SENSITIVE_WORD_PATTERN,
    _AUTH_SCHEME_PATTERN,
    _COMMUNITY_PATTERN,
    _URL_PASSWORD_PATTERN,
    _URL_TOKEN_PATTERN,
)
# A %-style placeholder of a log format string.
_PLACEHOLDER = re.compile(r"%(?:\(\w+\))?[-#0 +]*\d*(?:\.\d+)?[sdrfixXoeEgGca%]")
# A string holding none of these has nothing the patterns could match.
# The first word of each secret key name stands for it ("bind" for "bind_pw").
_TRIGGERS = (*dict.fromkeys(word.split()[0] for word in SECRET_KEY_WORDS), "bearer", "basic", "snmp", "@")

_METRICS_LOCK = threading.Lock()
_COUNTERS: dict[str, int] = defaultdict(int)
# Bounded window of recent samples per metric: avg/max are computed over this
# window while _TIMING_COUNTS keeps the true lifetime observation count.
_TIMINGS_MAXLEN = 1000
_TIMINGS: dict[str, deque[float]] = defaultdict(lambda: deque(maxlen=_TIMINGS_MAXLEN))
_TIMING_COUNTS: dict[str, int] = defaultdict(int)
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
        if record.args:
            if isinstance(record.args, dict):
                record.args = {k: redact_value(v) for k, v in record.args.items()}
            else:
                record.args = tuple(redact_value(a) for a in record.args)
            if isinstance(record.msg, str):
                # Then the formatted message, so a secret split between the
                # format string and its argument ("password=%s") is seen.
                try:
                    message = record.getMessage()
                except Exception:  # noqa: BLE001 - a bad format string is logging's to report
                    message = None
                if message is not None:
                    record.msg = redact_value(message)
                    record.args = None
                    return True
        record.msg = redact_value(record.msg)
        return True


def _mask_match(match: re.Match[str]) -> str:
    value = match.group("v")
    if _PLACEHOLDER.fullmatch(value.strip("\"'")):
        # A log format string ("password=%s"): the argument is redacted on
        # its own, and masking the placeholder would break the formatting.
        return match.group(0)
    quote = value[:1]
    quoted = len(value) >= 2 and quote in "\"'" and value.endswith(quote)
    return match.group("p") + (f"{quote}{_MASK}{quote}" if quoted else _MASK)


def _redact_string(value: str) -> str:
    lowered = value.lower()
    if not any(trigger in lowered for trigger in _TRIGGERS):
        return value
    for pattern in _STRING_PATTERNS:
        value = pattern.sub(_mask_match, value)
    return value


def redact_value(value: Any) -> Any:
    """A copy of ``value`` with the secrets masked: under a secret key name
    (``netcontrol.secret_keys``) the value is replaced whole, other strings
    lose the secret assignments, credentials and communities they hold."""
    if isinstance(value, dict):
        redacted: dict[str, Any] = {}
        for key, val in value.items():
            if should_mask(key, val):
                redacted[key] = _MASK
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


def mask_values(text: str, secrets: Iterable[str] = ()) -> str:
    """``text`` with each of ``secrets`` replaced by the mask wherever it
    occurs, the longest first so a secret that contains another goes whole."""
    out = text or ""
    for secret in sorted({s for s in secrets if s}, key=len, reverse=True):
        out = out.replace(secret, _MASK)
    return out


def redact_text(text: str, secrets: Iterable[str] = ()) -> str:
    """Text that is kept or returned instead of logged (an exception
    message, a receiver's reply) with the redaction a log line gets, and
    with each of ``secrets``, the values known to be secret here, removed
    by value first (``mask_values``)."""
    return _redact_string(mask_values(text, secrets))


def configure_logging(logger_name: str = "plexus") -> logging.Logger:
    logger = logging.getLogger(logger_name)
    if not logger.handlers:
        logger.setLevel(logging.INFO)
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s [%(name)s] %(message)s"))
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

    # The outbound address guard on the admin-set host (raises when refused,
    # so ``configure_syslog_logging`` answers False). Imported here because
    # net_guard imports this module for its logger.
    from netcontrol.routes.net_guard import validate_outbound_host

    validate_outbound_host(host)
    handler = logging.handlers.SysLogHandler(
        address=(host, port),
        facility=facility,
        socktype=socktype,
    )
    setattr(handler, _SYSLOG_MARKER, True)
    handler.setLevel(level)
    handler.setFormatter(logging.Formatter(f"{app_name}[%(process)d]: %(levelname)s %(name)s %(message)s"))
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
        _TIMING_COUNTS[name] += 1


def snapshot_metrics() -> dict[str, Any]:
    with _METRICS_LOCK:
        timings_summary: dict[str, dict[str, float]] = {}
        for metric_name, values in _TIMINGS.items():
            if not values:
                continue
            timings_summary[metric_name] = {
                "count": float(_TIMING_COUNTS[metric_name]),
                "avg_ms": round(sum(values) / len(values), 2),
                "max_ms": round(max(values), 2),
            }
        return {
            "counters": dict(_COUNTERS),
            "timings": timings_summary,
        }
