"""The remote user directory: every user a VPN-style source knows, connected
now or not, with earlier collections carried forward."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from netcontrol.integrations.remote_users import (
    CONNECTED,
    DIRECTORY_KEY,
    DISCONNECTED,
    HISTORY_DAYS,
    SECTION_TITLE,
    apply_user_directory,
    directory_entry,
    merge_users,
    user_key,
)

NOW = datetime(2026, 11, 18, 12, 0, tzinfo=UTC)


def _entry(name, *, connected, source="session", **kw):
    return directory_entry(name=name, connected=connected, source=source, **kw)


def test_entry_needs_something_to_find_the_user_by():
    assert directory_entry(connected=False, source="registry", device="laptop") is None
    entry = _entry("Lee Park", connected=True, address="192.0.2.14")
    assert entry["status"] == CONNECTED and entry["address"] == "192.0.2.14"
    assert directory_entry(name="x", connected=False, source="nonsense")["source"] == "registry"


def test_user_key_prefers_id_then_email_then_name():
    assert user_key({"user_id": "42", "email": "a@example.com", "name": "A"}) == "user_id:42"
    assert user_key({"email": "A@Example.com", "name": "A"}) == "email:a@example.com"
    assert user_key({"name": "Lee Park"}) == "name:lee park"
    assert user_key({}) == ""


def test_connected_and_registry_users_are_both_listed():
    users = merge_users(
        [
            _entry("Lee Park", connected=True, address="192.0.2.14"),
            _entry("Sam Ortiz", connected=False, source="registry", last_seen="2026-11-01T08:00:00Z"),
        ],
        [],
        now=NOW,
    )
    assert [(u["name"], u["status"]) for u in users] == [("Lee Park", CONNECTED), ("Sam Ortiz", DISCONNECTED)]
    assert users[0]["last_seen"] == NOW.isoformat(timespec="seconds")


def test_a_user_seen_before_is_carried_forward_as_disconnected():
    before = merge_users(
        [_entry("Lee Park", connected=True, address="192.0.2.14", public_ip="203.0.113.9", device="LT-01")],
        [],
        now=NOW - timedelta(days=2),
    )
    users = merge_users([_entry("Sam Ortiz", connected=True)], before, now=NOW)
    lee = next(u for u in users if u["name"] == "Lee Park")
    assert lee["status"] == DISCONNECTED and lee["source"] == "history"
    # The last address and device stay, so the user can still be identified.
    assert (lee["address"], lee["public_ip"], lee["device"]) == ("192.0.2.14", "203.0.113.9", "LT-01")


def test_registry_entry_is_filled_from_history_and_reconnect_wins():
    before = merge_users([_entry("Lee Park", connected=True, device="LT-01")], [], now=NOW - timedelta(days=1))
    users = merge_users([_entry("Lee Park", connected=False, source="registry")], before, now=NOW)
    assert len(users) == 1
    assert users[0]["source"] == "registry" and users[0]["device"] == "LT-01"
    again = merge_users([_entry("lee park", connected=True, address="192.0.2.20")], users, now=NOW)
    assert again[0]["status"] == CONNECTED and again[0]["address"] == "192.0.2.20"


def test_history_expires():
    old = [{**_entry("Gone User", connected=False, source="registry"), "last_seen": "2026-01-01T00:00:00+00:00"}]
    assert merge_users([], old, now=NOW) == []
    recent = [{**old[0], "last_seen": (NOW - timedelta(days=HISTORY_DAYS - 1)).isoformat()}]
    assert len(merge_users([], recent, now=NOW)) == 1


def test_apply_writes_the_table_on_the_directory_node():
    previous = {
        DIRECTORY_KEY: {
            "node_id": "users",
            "users": [{**_entry("Lee Park", connected=False), "last_seen": "2026-11-17T09:00:00+00:00"}],
        },
    }
    snapshot = {
        "nodes": [{"id": "users", "sections": [{"title": SECTION_TITLE, "kind": "table", "rows": []}]}],
        DIRECTORY_KEY: {"node_id": "users", "users": [_entry("Sam Ortiz", connected=True)]},
    }
    assert apply_user_directory(snapshot, previous, now=NOW) == 2
    sections = [s for s in snapshot["nodes"][0]["sections"] if s["title"] == SECTION_TITLE]
    assert len(sections) == 1
    assert [row[0] for row in sections[0]["rows"]] == ["Sam Ortiz", "Lee Park"]
    assert sections[0]["rows"][1][7] == "Seen by an earlier collection"


def test_apply_keeps_history_when_users_were_not_collected():
    previous = {DIRECTORY_KEY: {"node_id": "users", "users": [_entry("Lee Park", connected=True)]}}
    snapshot = {"nodes": [{"id": "users", "sections": []}]}
    assert apply_user_directory(snapshot, previous, now=NOW) == 1
    assert snapshot[DIRECTORY_KEY]["users"][0]["status"] == DISCONNECTED
    assert apply_user_directory({"nodes": []}, None, now=NOW) == 0
