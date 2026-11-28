"""MCP bearer tokens: generation, hashing, and resolving one into a context.

A token is ``plx_mcp_`` plus 32 random bytes (URL-safe). Only its SHA-256 is
stored (``routes.db.mcp_tokens``). ``resolve_token`` reads the token row, its
owner and the owner's current features on every call, so revoking a token or
narrowing its owner's access takes effect on the next request.

A new token always gets an expiry date (``new_token_expiry``); a row with
none is from before that rule and never expires.
"""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta

import routes.database as db

from netcontrol.object_scope import scope_for_user
from netcontrol.routes.auth import _get_user_features

TOKEN_PREFIX = "plx_mcp_"  # nosec B105 - a public prefix, not a credential
CATEGORIES = ("inventory", "configs", "compliance", "monitoring", "topology", "software", "traffic", "audit")

# Lifetime of a new token in days: what a token created without an expiry
# date gets, and the latest expiry date that is accepted.
TOKEN_DEFAULT_DAYS = 90
TOKEN_MAX_DAYS = 365

_DISPLAY_PREFIX_LEN = 12


@dataclass(frozen=True)
class McpContext:
    """Who is calling: the token and the user it acts as."""

    token_id: int
    token_name: str
    owner_id: int
    owner_username: str
    owner_is_admin: bool
    categories: frozenset[str]  # as stored on the token
    features: frozenset[str]  # the owner's current features
    # The owner is limited to selected inventory groups (object-level
    # permissions): such tokens are refused, since MCP tools do not enforce it.
    object_scoped: bool = False


def hash_token(plaintext: str) -> str:
    return hashlib.sha256(plaintext.encode("utf-8")).hexdigest()


def generate_token() -> tuple[str, str, str]:
    """A new token as ``(plaintext, sha256 hex, display prefix)``."""
    plaintext = TOKEN_PREFIX + secrets.token_urlsafe(32)
    return plaintext, hash_token(plaintext), plaintext[:_DISPLAY_PREFIX_LEN]


def extract_bearer(authorization_header: str) -> str:
    """The token from an ``Authorization: Bearer <token>`` value, or ``""``."""
    parts = (authorization_header or "").split()
    if len(parts) == 2 and parts[0].lower() == "bearer":
        return parts[1]
    return ""


def new_token_expiry(requested: str, today: date | None = None) -> str:
    """The expiry date (``YYYY-MM-DD``, UTC) to store for a new token.

    An empty ``requested`` gets ``TOKEN_DEFAULT_DAYS`` from ``today``. A
    date is accepted from ``today`` up to ``TOKEN_MAX_DAYS`` ahead.

    Raises ``ValueError`` with a message for the admin otherwise.
    """
    today = today or datetime.now(UTC).date()
    requested = (requested or "").strip()
    if not requested:
        return (today + timedelta(days=TOKEN_DEFAULT_DAYS)).isoformat()
    try:
        chosen = datetime.strptime(requested, "%Y-%m-%d").date()
    except ValueError:
        chosen = None
    if chosen is None or chosen.isoformat() != requested:
        raise ValueError("Expiry must be a date in the form YYYY-MM-DD.")
    if chosen < today:
        raise ValueError("The expiry date is in the past. Choose today or a later date.")
    if chosen > today + timedelta(days=TOKEN_MAX_DAYS):
        raise ValueError(f"The expiry date can be at most {TOKEN_MAX_DAYS} days from today.")
    return requested


def is_expired(expires_at: str, now: datetime | None = None) -> bool:
    """``expires_at`` is ``""`` (never: a token created before an expiry
    date was required), ``YYYY-MM-DD`` (valid through that day, UTC) or
    ``YYYY-MM-DD HH:MM:SS``."""
    expires_at = (expires_at or "").strip()
    if not expires_at:
        return False
    now = now or datetime.now(UTC)
    current = now.strftime("%Y-%m-%d" if len(expires_at) <= 10 else "%Y-%m-%d %H:%M:%S")
    return current > expires_at


async def resolve_token(plaintext: str) -> McpContext | None:
    """The call context for a token, or ``None`` when it must be refused:
    wrong prefix, unknown, revoked, expired, or its owner no longer exists
    or is disabled (``users.disabled``: the token stops working with its
    owner's sign-in)."""
    if not plaintext or not plaintext.startswith(TOKEN_PREFIX):
        return None
    token_hash = hash_token(plaintext)
    row = await db.get_mcp_token_by_hash(token_hash)
    if row is None or not secrets.compare_digest(str(row.get("token_hash") or ""), token_hash):
        return None
    if row.get("revoked_at") or is_expired(str(row.get("expires_at") or "")):
        return None
    owner = await db.get_user_by_id(int(row["owner_user_id"]))
    if not owner or owner.get("disabled"):
        return None
    return McpContext(
        token_id=int(row["id"]),
        token_name=str(row["name"]),
        owner_id=int(owner["id"]),
        owner_username=str(owner["username"]),
        owner_is_admin=owner.get("role") == "admin",
        categories=frozenset(row["categories"]) & frozenset(CATEGORIES),
        features=frozenset(await _get_user_features(owner)),
        object_scoped=(await scope_for_user(owner)).restricted,
    )
