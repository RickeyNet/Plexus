"""The remote user directory of a VPN-style source: every user it knows,
connected now or not.

A remote access source (Cato SDP, Appgate SDP, GlobalProtect, AnyConnect on
FMC, OpenVPN on OPNsense) reports the users connected at collection time, and
some also keep a registry of every user or device enrolled. Searching the map
for a user who is not connected right now found nothing, so every snapshot of
such a source carries a directory of all the users it knows:

  - the users connected now (``status`` ``connected``, with their tunnel
    address);
  - the users the source's registry lists but who are not connected
    (``disconnected``);
  - the users an earlier collection saw who appear in neither, carried
    forward by :func:`apply_user_directory` when the snapshot is stored
    (``disconnected``, ``source`` ``history``), for ``HISTORY_DAYS`` after
    they were last seen.

A normaliser puts the directory on its snapshot under ``DIRECTORY_KEY`` as
``{"node_id": <the node that lists users>, "users": [entry, ...]}``, each
entry made with :func:`directory_entry`. The store step merges the history in
and writes the "All users" table onto that node, so the map search (which
reads node sections) finds every user. A disconnected user has no tunnel
address now: the directory is for finding people, never a subnet for path
tracing, and the address shown for one is the last one seen.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from netcontrol.integrations.meraki.normalize import table_section

DIRECTORY_KEY = "remote_user_directory"
SECTION_TITLE = "All users"
COLUMNS = ["User", "Email", "Status", "Last seen", "Last VPN address", "Public IP", "Device", "Known from"]

CONNECTED = "connected"
DISCONNECTED = "disconnected"

# Where an entry came from, as the table names it.
SOURCE_LABELS = {
    "session": "Connected now",
    "registry": "The source's user list",
    "history": "Seen by an earlier collection",
}

# How long a user seen once but no longer reported stays in the directory.
HISTORY_DAYS = 180
# The most users one directory keeps (the newest seen first).
MAX_USERS = 20_000

_FIELDS = ("name", "email", "user_id", "address", "public_ip", "device", "last_seen")


def _text(value: Any) -> str:
    return "" if value is None else str(value).strip()


def directory_entry(
    *,
    name: Any = "",
    email: Any = "",
    user_id: Any = "",
    connected: bool,
    source: str,
    address: Any = "",
    public_ip: Any = "",
    device: Any = "",
    last_seen: Any = "",
) -> dict[str, Any] | None:
    """One user of a directory. ``source`` is ``session`` (connected now) or
    ``registry``. ``last_seen`` is an ISO 8601 time when the source gives one;
    a connected user is seen at the collection time (filled in on store).
    ``None`` for a user with no name, email or ID to find them by."""
    entry = {
        "name": _text(name),
        "email": _text(email),
        "user_id": _text(user_id),
        "status": CONNECTED if connected else DISCONNECTED,
        "address": _text(address),
        "public_ip": _text(public_ip),
        "device": _text(device),
        "last_seen": _text(last_seen),
        "source": source if source in SOURCE_LABELS else "registry",
    }
    if not (entry["name"] or entry["email"] or entry["user_id"]):
        return None
    return entry


def user_key(entry: dict[str, Any]) -> str:
    """What identifies a user across collections: the source's user ID, else
    the email, else the name (case-insensitive)."""
    for field in ("user_id", "email", "name"):
        value = _text(entry.get(field)).lower()
        if value:
            return f"{field}:{value}"
    return ""


def parse_time(value: Any) -> datetime | None:
    text = _text(value)
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def _newer(a: str, b: str) -> str:
    """The later of two ISO times (an unreadable one loses)."""
    ta, tb = parse_time(a), parse_time(b)
    if ta is None:
        return b if tb is not None else a or b
    if tb is None:
        return a
    return a if ta >= tb else b


def merge_users(
    current: list[dict[str, Any]],
    previous: list[dict[str, Any]],
    *,
    now: datetime,
) -> list[dict[str, Any]]:
    """The directory of this collection with the users of the previous one
    folded in. Entries of one user (by :func:`user_key`) are merged: a
    connected entry wins, blanks are filled from the others, and the latest
    ``last_seen`` is kept. A previous user missing from ``current`` is kept as
    disconnected history until ``HISTORY_DAYS`` after it was last seen. The
    newest seen come first, at most ``MAX_USERS``."""
    stamp = now.isoformat(timespec="seconds")
    merged: dict[str, dict[str, Any]] = {}
    for raw in current:
        key = user_key(raw)
        if not key:
            continue
        entry = {**raw}
        if entry.get("status") == CONNECTED:
            entry["last_seen"] = stamp
        have = merged.get(key)
        merged[key] = entry if have is None else _combine(have, entry)

    cutoff = now - timedelta(days=HISTORY_DAYS)
    for raw in previous:
        key = user_key(raw)
        if not key:
            continue
        old = {**raw}
        have = merged.get(key)
        if have is not None:
            # Fill what this collection left blank (a registry has no device
            # or address) from what was seen before.
            merged[key] = _combine(have, {**old, "status": DISCONNECTED, "source": have["source"]})
            continue
        seen = parse_time(old.get("last_seen"))
        if seen is not None and seen < cutoff:
            continue
        old["status"] = DISCONNECTED
        old["source"] = "history"
        merged[key] = old

    def order(entry: dict[str, Any]) -> tuple[int, float, str]:
        seen = parse_time(entry.get("last_seen"))
        return (
            0 if entry.get("status") == CONNECTED else 1,
            -(seen.timestamp() if seen else 0.0),
            (entry.get("name") or entry.get("email") or entry.get("user_id") or "").lower(),
        )

    return sorted(merged.values(), key=order)[:MAX_USERS]


def _combine(a: dict[str, Any], b: dict[str, Any]) -> dict[str, Any]:
    """Two entries of one user as one: ``a``'s values first, a connected
    status and source over a disconnected one, the later ``last_seen``."""
    first, second = (b, a) if b.get("status") == CONNECTED and a.get("status") != CONNECTED else (a, b)
    out = {**first}
    for field in _FIELDS:
        if not _text(out.get(field)):
            out[field] = _text(second.get(field))
    out["last_seen"] = _newer(_text(a.get("last_seen")), _text(b.get("last_seen")))
    if out.get("status") != CONNECTED:
        # A disconnected user has no tunnel now; the address is the last one.
        out["address"] = _text(a.get("address")) or _text(b.get("address"))
    return out


def directory_section(users: list[dict[str, Any]]) -> dict | None:
    """The "All users" table of a directory."""
    rows = [
        [
            u.get("name"),
            u.get("email"),
            u.get("status"),
            u.get("last_seen"),
            u.get("address"),
            u.get("public_ip"),
            u.get("device"),
            SOURCE_LABELS.get(u.get("source") or "", u.get("source")),
        ]
        for u in users
    ]
    return table_section(SECTION_TITLE, COLUMNS, rows)


def apply_user_directory(snapshot: dict[str, Any], previous: dict[str, Any] | None, *, now: datetime) -> int:
    """Merge the previous snapshot's directory into this one's and write the
    "All users" table onto the directory's node, replacing any earlier copy.
    A snapshot whose source collected no users keeps the previous directory
    as history, on the node it names. Returns the number of users listed."""
    directory = snapshot.get(DIRECTORY_KEY)
    found = (previous or {}).get(DIRECTORY_KEY)
    old: dict[str, Any] = found if isinstance(found, dict) else {}
    if not isinstance(directory, dict):
        if not old:
            return 0
        directory = {"node_id": old.get("node_id"), "users": []}
    previous_users = [u for u in old.get("users") or [] if isinstance(u, dict)]
    users = merge_users([u for u in directory.get("users") or [] if isinstance(u, dict)], previous_users, now=now)
    snapshot[DIRECTORY_KEY] = {**directory, "users": users}
    node = next((n for n in snapshot.get("nodes") or [] if n.get("id") == directory.get("node_id")), None)
    if node is None:
        return len(users)
    sections = [s for s in node.get("sections") or [] if s.get("title") != SECTION_TITLE]
    section = directory_section(users)
    if section is not None:
        sections.append(section)
    node["sections"] = sections
    return len(users)
