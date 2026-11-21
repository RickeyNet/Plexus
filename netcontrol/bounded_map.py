"""Size-capped dict for per-client tracker maps.

The login lockout maps and the API rate-limit tracker are keyed by client
address, so their key count follows whatever reaches the server. They use
:class:`BoundedDict`: a plain ``dict`` (callers and tests index, ``pop`` and
iterate it as usual) that never holds more than ``max_entries`` keys. When a
new key would pass the cap it first drops expired entries (at most once per
``prune_interval`` seconds), then the least recently written ones.

:func:`prune_expired` is the same expiry pass, run by the periodic cleanup
loop in ``netcontrol/app.py``.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Hashable, MutableMapping
from typing import Any

# ``is_expired(key, value, now)``: True when the entry no longer matters.
ExpiryCheck = Callable[[Any, Any, float], bool]


def prune_expired(mapping: MutableMapping[Any, Any], is_expired: ExpiryCheck, now: float | None = None) -> int:
    """Drop every entry ``is_expired`` accepts; the number dropped."""
    if now is None:
        now = time.time()
    stale = [key for key, value in list(mapping.items()) if is_expired(key, value, now)]
    for key in stale:
        mapping.pop(key, None)
    return len(stale)


class BoundedDict(dict[Any, Any]):
    """A ``dict`` that holds at most ``max_entries`` keys.

    Writing a key moves it to the end, so eviction drops the entries written
    longest ago. Only item assignment (``d[key] = value``) is bounded: it is
    the only way the tracker maps are filled. ``update`` and ``setdefault``
    go straight to ``dict`` and must not be used on them."""

    def __init__(
        self,
        max_entries: int,
        is_expired: ExpiryCheck | None = None,
        *,
        prune_interval: float = 1.0,
        clock: Callable[[], float] = time.time,
    ) -> None:
        super().__init__()
        if max_entries < 1:
            raise ValueError("max_entries must be at least 1")
        self.max_entries = max_entries
        self.is_expired = is_expired
        self.prune_interval = prune_interval
        self.clock = clock
        self._last_prune = float("-inf")

    def __setitem__(self, key: Hashable, value: Any) -> None:
        if key in self:
            super().__delitem__(key)
        elif len(self) >= self.max_entries:
            self._make_room()
        super().__setitem__(key, value)

    def _make_room(self) -> None:
        now = self.clock()
        if self.is_expired is not None and now - self._last_prune >= self.prune_interval:
            self._last_prune = now
            prune_expired(self, self.is_expired, now)
        while len(self) >= self.max_entries:
            super().__delitem__(next(iter(self)))
