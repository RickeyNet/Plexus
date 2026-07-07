"""Regression tests for the empty-password bind guards (auth.py).

RFC 4513 §5.1.2: a simple LDAP bind with an empty password is an
*unauthenticated* bind that many directory servers accept without verifying
anything. The RADIUS path mirrors the guard. Both must reject an empty
password before contacting the server, independent of the API-layer check.
"""

from __future__ import annotations

import netcontrol.routes.auth as auth


def test_radius_rejects_empty_password():
    # The empty-password check precedes the pyrad-availability check, so this
    # holds whether or not the library is installed.
    ok, status = auth._radius_authenticate_sync("alice", "", {"server": "1.2.3.4", "secret": "s"})
    assert ok is False
    assert status == "reject"


def test_ldap_rejects_empty_password(monkeypatch):
    # Force the LDAP_AVAILABLE gate open so we reach the empty-password guard;
    # the guard returns before any python_ldap call, so no server is needed.
    monkeypatch.setattr(auth, "LDAP_AVAILABLE", True)
    ok, status, attrs = auth._ldap_authenticate_sync(
        "alice", "", {"server": "ldap.example.com", "base_dn": "dc=x"}
    )
    assert ok is False
    assert status == "reject"
    assert attrs == {}


def test_ldap_empty_password_does_not_touch_server(monkeypatch):
    # Even with a bogus server that would error on connect, an empty password
    # short-circuits to reject (not error).
    monkeypatch.setattr(auth, "LDAP_AVAILABLE", True)
    ok, status, _ = auth._ldap_authenticate_sync(
        "bob", "", {"server": "203.0.113.9", "port": 389, "base_dn": "dc=x"}
    )
    assert (ok, status) == (False, "reject")
