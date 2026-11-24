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

from netcontrol.routes.outbound_http import OutboundRequestError, send_request

# Codes a sign-in failure may put in ``/login?sso_error=``. The login page
# maps each to a fixed sentence; nothing else from the provider is echoed.
SSO_ERROR_CODES = ("disabled", "setup", "state", "provider", "token", "claims", "account", "denied")

HTTP_TIMEOUT_SECONDS = 10.0
# Provider documents are small; refuse anything that is not, so a
# misbehaving endpoint cannot make us hold megabytes.
MAX_RESPONSE_BYTES = 1_000_000
USERNAME_MAX_LENGTH = 150
DISPLAY_NAME_MAX_LENGTH = 200

_LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "::1"}
# C0 and C1 control characters and the Unicode line and paragraph separators:
# everything a log reader or a terminal may take for a line break or a command.
CONTROL_CHARS = re.compile("[\x00-\x1f\x7f-\x9f  ]")
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


def single_line(text: Any, limit: int | None = None) -> str:
    """Text someone else chose (a typed sign-in name, a provider's message)
    made safe for one log line or audit field: every control character and
    line separator becomes a space, and the result is cut to ``limit``."""
    return CONTROL_CHARS.sub(" ", str(text or ""))[:limit]


def log_safe(text: Any, limit: int = 200) -> str:
    """Provider-supplied text made safe to log: control characters removed,
    token-like runs redacted, truncated."""
    return _TOKENISH.sub("[redacted]", single_line(text))[:limit]


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
    """A display name from a provider or a form: on one line, trimmed and
    cut to ``DISPLAY_NAME_MAX_LENGTH``; ``""`` for anything but a string."""
    return single_line(value).strip()[:DISPLAY_NAME_MAX_LENGTH] if isinstance(value, str) else ""


def group_values(value: Any) -> list[str]:
    """A groups value as a list of strings (a single string becomes one
    group; anything else is ignored)."""
    if isinstance(value, str):
        return [value] if value else []
    if isinstance(value, list):
        return [str(v) for v in value if isinstance(v, (str, int)) and str(v)]
    return []


async def provider_request(
    method: str,
    url: str,
    *,
    ca_cert_file: str = "",
    transport: httpx.AsyncBaseTransport | None = None,
    error: type[SsoError] = SsoError,
    code: str = "provider",
    data: dict[str, Any] | None = None,
    headers: dict[str, str] | None = None,
) -> httpx.Response:
    """One request to an identity provider, sent by the shared outbound
    sender (``outbound_http.send_request``), like webhooks and notification
    channels: the address passes the SSRF guard (``net_guard``: link-local
    addresses such as the cloud instance-metadata endpoint are always
    refused, private and loopback ranges when ``APP_SSRF_BLOCK_PRIVATE`` is
    on) and the connection goes to the address the guard approved, so a
    second DNS answer cannot send it elsewhere. This covers the URL an admin
    typed and every endpoint a provider document names.

    TLS is verified (with ``ca_cert_file`` for a private CA), redirects are
    not followed, 10 s timeout. ``transport`` replaces the network in tests.
    Raises ``error(code)`` for a refused address, ``error("provider")`` for
    a CA file that does not load, and the ``httpx`` error on a transport
    failure."""
    verify: ssl.SSLContext | bool = True
    if ca_cert_file and transport is None:
        try:
            verify = ssl.create_default_context(cafile=ca_cert_file)
        except (OSError, ssl.SSLError) as exc:
            raise error("provider", "the CA certificate file could not be loaded") from exc
    try:
        return await send_request(
            method,
            url,
            data=data,
            headers=headers,
            verify=verify,
            timeout_s=HTTP_TIMEOUT_SECONDS,
            transport=transport,
        )
    except OutboundRequestError as exc:
        raise error(code, f"the identity provider address is not allowed ({exc})") from exc
