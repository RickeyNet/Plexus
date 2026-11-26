"""Longest-prefix matching over a set of IP networks.

The topology map, IPAM, the aggregate lookup, the path tracer and the Meraki
VPN check all ask which of a set of networks holds an address or a network,
the most specific first. :class:`PrefixIndex` answers that with one dict
probe per distinct prefix length instead of a scan of every network, so it
pays off when built once and asked many times; :func:`longest_prefix_match`
and :func:`longest_prefix_matches` are the one-off forms. IPv4 and IPv6 are
kept apart (an address never matches a network of the other version). Ties
(the same network listed more than once) keep their input order, so the
result does not depend on dict or set ordering.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable

Network = ipaddress.IPv4Network | ipaddress.IPv6Network
Address = ipaddress.IPv4Address | ipaddress.IPv6Address

__all__ = ["PrefixIndex", "longest_prefix_match", "longest_prefix_matches"]


def _as_network(target: Network | Address) -> Network:
    if isinstance(target, ipaddress.IPv4Address | ipaddress.IPv6Address):
        return ipaddress.ip_network(target)
    return target


class PrefixIndex[T]:
    """``(network, item)`` pairs indexed for longest-prefix lookups."""

    def __init__(self, entries: Iterable[tuple[Network, T]]) -> None:
        # IP version -> prefix length -> network address as an int -> items.
        self._tables: dict[int, dict[int, dict[int, list[T]]]] = {4: {}, 6: {}}
        for network, item in entries:
            by_length = self._tables[network.version].setdefault(network.prefixlen, {})
            by_length.setdefault(int(network.network_address), []).append(item)
        self._lengths = {version: sorted(table, reverse=True) for version, table in self._tables.items()}

    def matches(self, target: Network | Address) -> list[T]:
        """The items of the most specific network that holds all of
        ``target`` (an address or a network), in input order; ``[]`` when
        none does."""
        network = _as_network(target)
        width = network.max_prefixlen
        base = int(network.network_address)
        table = self._tables[network.version]
        for length in self._lengths[network.version]:
            if length > network.prefixlen:
                continue
            mask = ((1 << length) - 1) << (width - length)
            items = table[length].get(base & mask)
            if items:
                return list(items)
        return []

    def match(self, target: Network | Address) -> T | None:
        """The first item of :meth:`matches`, else ``None``."""
        found = self.matches(target)
        return found[0] if found else None


def longest_prefix_matches[T](target: Network | Address, entries: Iterable[tuple[Network, T]]) -> list[T]:
    """:meth:`PrefixIndex.matches` over ``entries`` for a single lookup."""
    return PrefixIndex(entries).matches(target)


def longest_prefix_match[T](target: Network | Address, entries: Iterable[tuple[Network, T]]) -> T | None:
    """:meth:`PrefixIndex.match` over ``entries`` for a single lookup."""
    return PrefixIndex(entries).match(target)
