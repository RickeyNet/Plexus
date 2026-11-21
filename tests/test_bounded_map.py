"""The size-capped tracker maps (login lockout, API rate limits, MCP throttle)."""

from __future__ import annotations

import netcontrol.routes.state as state
import pytest
from netcontrol.bounded_map import BoundedDict, prune_expired


class _Clock:
    def __init__(self, now: float = 1000.0):
        self.now = now

    def __call__(self) -> float:
        return self.now


def _older_than(seconds: float):
    def check(_key, stamp, now):
        return now - stamp > seconds

    return check


def test_cap_evicts_least_recently_written():
    d = BoundedDict(3)
    d["a"] = 1
    d["b"] = 2
    d["c"] = 3
    d["a"] = 10  # rewritten: now the newest
    d["d"] = 4
    assert list(d) == ["c", "a", "d"]
    assert d["a"] == 10


def test_cap_never_exceeded_under_many_keys():
    d = BoundedDict(100)
    for i in range(10_000):
        d[f"198.51.100.{i}"] = [float(i)]
    assert len(d) == 100
    # The newest keys survive.
    assert "198.51.100.9999" in d
    assert "198.51.100.0" not in d


def test_rewriting_existing_key_at_cap_evicts_nothing():
    d = BoundedDict(2)
    d["a"] = 1
    d["b"] = 2
    d["a"] = 3
    assert dict(d) == {"b": 2, "a": 3}


def test_expired_entries_go_before_live_ones():
    clock = _Clock()
    d = BoundedDict(3, _older_than(60), clock=clock)
    d["old-1"] = clock.now - 120
    d["live"] = clock.now - 10
    d["old-2"] = clock.now - 300
    d["new"] = clock.now
    # Both expired entries were pruned; the older live entry was kept.
    assert set(d) == {"live", "new"}


def test_prune_runs_at_most_once_per_interval():
    clock = _Clock()
    calls = []

    def never(key, value, now):
        calls.append(key)
        return False

    d = BoundedDict(2, never, prune_interval=5.0, clock=clock)
    d["a"] = 1
    d["b"] = 2
    d["c"] = 3  # full: prune scan (nothing expired), then evict "a"
    d["d"] = 4  # full again within the interval: evict only
    assert len(calls) == 2
    clock.now += 6
    d["e"] = 5
    assert len(calls) == 4
    assert list(d) == ["d", "e"]


def test_max_entries_must_be_positive():
    with pytest.raises(ValueError):
        BoundedDict(0)


def test_prune_expired_on_plain_dict():
    d = {"a": 0.0, "b": 95.0, "c": 99.0}
    assert prune_expired(d, _older_than(10), now=100.0) == 1
    assert d == {"b": 95.0, "c": 99.0}


def test_state_tracker_maps_are_bounded():
    for tracker in (state.LOGIN_ATTEMPTS, state.LOCKED_OUT, state.API_RATE_LIMIT_TRACKER):
        assert isinstance(tracker, BoundedDict)
        assert tracker.max_entries == state.TRACKER_MAX_ENTRIES


def test_state_expiry_rules(monkeypatch):
    monkeypatch.setattr(state, "LOGIN_RULES", {**state.LOGIN_RULES, "lockout_time": 900, "rate_limit_window": 60})
    monkeypatch.setattr(state, "API_RATE_LIMIT", {**state.API_RATE_LIMIT, "window": 60})
    monkeypatch.setattr(state, "LOCKED_OUT", {"192.0.2.1": 2000.0})
    now = 1000.0

    assert state.lockout_expired("192.0.2.1", 999.0, now)
    assert not state.lockout_expired("192.0.2.1", 1001.0, now)

    # Kept while the address is locked out, however old.
    assert not state.login_attempts_expired("192.0.2.1", [0.0], now)
    assert state.login_attempts_expired("192.0.2.2", [0.0], now)
    assert not state.login_attempts_expired("192.0.2.2", [now - 100], now)
    assert state.login_attempts_expired("192.0.2.2", [], now)

    assert state.rate_limit_entry_expired("192.0.2.3", [now - 61], now)
    assert not state.rate_limit_entry_expired("192.0.2.3", [now - 30], now)
    assert state.rate_limit_entry_expired("192.0.2.3", [], now)
