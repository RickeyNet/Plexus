"""Single sign-on: the parts every protocol shares, with no FastAPI in it.

Plexus signs a browser in through OpenID Connect (:mod:`netcontrol.oidc`)
or SAML 2.0 (:mod:`netcontrol.saml`). Both end in the same place: an
:class:`SsoIdentity` (a subject bound to the account, a username, a display
name and the IdP's groups) that ``routes/auth.py`` provisions, maps to a
role and access groups, and signs in with the ordinary session cookie.

This module holds what does not depend on the protocol:

- the error type and the fixed codes the login page understands;
- URL and redirect-target rules (``https`` only, same-site return paths);
- log-safe text, username and group-value cleaning;
- the HTTP client used to fetch provider documents (TLS verified, optional
  private CA bundle, no redirects, 10 s timeout) and the outbound SSRF
  guard every provider address passes before a request is sent.
"""

from __future__ import annotations

import re
import ssl
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

import httpx

from netcontrol.routes.outbound_http import OutboundRequestError, guard_url

# Codes a sign-in failure may put in ``/login?sso_error=``. The login page
# maps each to a fixed sentence; nothing else from the provider is echoed.
SSO_ERROR_CODES = ("disabled", "state", "provider", "token", "claims", "account", "denied")

HTTP_TIMEOUT_SECONDS = 10.0
# Provider documents are small; refuse anything that is not, so a
# misbehaving endpoint cannot make us hold megabytes.
MAX_RESPONSE_BYTES = 1_000_000
USERNAME_MAX_LENGTH = 150
DISPLAY_NAME_MAX_LENGTH = 200

_LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "::1"}
CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")
# Long runs of token-alphabet characters (JWTs, codes, secrets, base64 XML)
# in provider text are replaced before it is logged.
_TOKENISH = re.compile(r"[A-Za-z0-9_\-\.~+/=]{24,}")


class SsoError(Exception):
    """A sign-in step failed. ``code`` is one of :data:`SSO_ERROR_CODES`;
    ``step`` is a short description safe to log and audit (it never holds
    a token, an assertion, a code or a secret)."""

    def __init__(self, code: str, step: str):
        super().__init__(step)
        self.code = code if code in SSO_ERROR_CODES else "provider"
        self.step = step


@dataclass(frozen=True)
class SsoIdentity:
    """Who signed in. ``sub`` is the provider's stable subject (the OIDC
    ``sub`` claim, the SAML ``NameID``), bound to the account on its first
    sign-in. ``overage`` is set when the provider signalled that the groups
    did not fit, so they are unknown."""

    sub: str
    username: str
    display_name: str = ""
    groups: list[str] = field(default_factory=list)
    overage: bool = False


# ── Small pure helpers ───────────────────────────────────────────────────────


def is_allowed_url(url: str) -> bool:
    """``https`` URL, or ``http`` on a loopback host (a lab IdP)."""
    try:
        parts = urlsplit(str(url or ""))
    except ValueError:
        return False
    if not parts.netloc or not parts.hostname:
        return False
    if parts.scheme == "https":
        return True
    return parts.scheme == "http" and parts.hostname.lower() in _LOOPBACK_HOSTS


async def guard_provider_url(url: str, error: type[SsoError] = SsoError, code: str = "provider") -> None:
    """The outbound SSRF guard for an identity provider address, the one
    webhooks and notification channels use (``net_guard``): link-local
    addresses such as the cloud instance-metadata endpoint are always
    refused, private and loopback ranges when ``APP_SSRF_BLOCK_PRIVATE`` is
    on. It covers the URL an admin typed and every endpoint a provider
    document names. Raises ``error(code)``."""
    try:
        await guard_url(url)
    except OutboundRequestError as exc:
        raise error(code, f"the identity provider address is not allowed ({exc})") from exc


def safe_next(value: str | None) -> str:
    """A same-site path to return to after sign-in, or ``/``.

    Kept only when it starts with exactly one ``/`` and holds no ``//``,
    backslash or control character, so it can never name another host.
    """
    candidate = str(value or "")
    if not candidate.startswith("/") or len(candidate) > 2048:
        return "/"
    if "//" in candidate or "\\" in candidate or CONTROL_CHARS.search(candidate):
        return "/"
    return candidate


def log_safe(text: Any, limit: int = 200) -> str:
    """Provider-supplied text made safe to log: control characters removed,
    token-like runs redacted, truncated."""
    cleaned = CONTROL_CHARS.sub(" ", str(text or ""))
    cleaned = _TOKENISH.sub("[redacted]", cleaned)
    return cleaned[:limit]


def clean_username(value: Any, what: str, error: type[SsoError] = SsoError) -> str:
    """``value`` trimmed, as a username. Raises ``error("claims")`` when it
    is not a string, is empty, longer than 150 characters or holds a control
    character. ``what`` names the source in the message."""
    if not isinstance(value, str):
        raise error("claims", f"username {what} is missing")
    username = value.strip()
    if not username or len(username) > USERNAME_MAX_LENGTH or CONTROL_CHARS.search(username):
        raise error("claims", f"username {what} is empty, too long or has control characters")
    return username


def clean_display_name(value: Any) -> str:
    return value.strip()[:DISPLAY_NAME_MAX_LENGTH] if isinstance(value, str) else ""


def group_values(value: Any) -> list[str]:
    """A groups value as a list of strings (a single string becomes one
    group; anything else is ignored)."""
    if isinstance(value, str):
        return [value] if value else []
    if isinstance(value, list):
        return [str(v) for v in value if isinstance(v, (str, int)) and str(v)]
    return []


def http_client(
    transport: httpx.AsyncBaseTransport | None,
    ca_cert_file: str = "",
    error: type[SsoError] = SsoError,
) -> httpx.AsyncClient:
    """The client used to talk to an identity provider: TLS verified (with
    ``ca_cert_file`` for a private CA), redirects not followed, 10 s
    timeout. ``transport`` replaces the network in tests."""
    if transport is not None:
        return httpx.AsyncClient(transport=transport, timeout=HTTP_TIMEOUT_SECONDS, follow_redirects=False)
    verify: ssl.SSLContext | bool = True
    if ca_cert_file:
        try:
            verify = ssl.create_default_context(cafile=ca_cert_file)
        except (OSError, ssl.SSLError) as exc:
            raise error("provider", "the CA certificate file could not be loaded") from exc
    return httpx.AsyncClient(verify=verify, timeout=HTTP_TIMEOUT_SECONDS, follow_redirects=False)
