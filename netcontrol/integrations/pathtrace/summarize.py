"""Summarize addresses: the fewest routes that cover a list of addresses.

Routes to a long list of addresses (the hosts of Meraki networks that an
Azure route table must reach, say) are easier to keep as a few aggregates.
``parse_addresses`` reads the typed list, ``summarize`` rolls it up (to a
prefix length, then to at most a number of routes, merging the neighbours
whose common supernet adds the fewest addresses) and ``routes`` reports
each route: the inputs it covers and the collected networks (subnet index
rows, as ``sweep.list_rows`` lists them) it overlaps, so a route that would
also catch another source's network shows up before it is created.

Pure (no I/O): the API handler loads the subnets and picks them with the
sweep's filters.
"""

from __future__ import annotations

import bisect
import ipaddress
import re
from collections.abc import Iterable, Iterator, Sequence
from typing import Any

from netcontrol.integrations.pathtrace.model import Network, net
from netcontrol.integrations.pathtrace.sweep import address_of, overlapping

# Most entries one summary reads.
MAX_ADDRESSES = 5000
RELATIONS = ("equal", "inside", "contains", "overlaps")

_SEPARATORS = re.compile(r"[\s,;]+")
_WIDTH = {4: 32, 6: 128}


def parse_addresses(text: str) -> list[Network]:
    """The IP addresses and networks of ``text``, split on newlines, commas,
    semicolons and spaces (an address is a /32 or /128), repeats included;
    ``ValueError`` names the first entry that is neither."""
    return [address_of(entry) for entry in _SEPARATORS.split(str(text or "")) if entry]


def _order(network: Network) -> tuple[int, int, int]:
    return network.version, int(network.network_address), network.prefixlen


def _collapse(networks: list[Network]) -> list[Network]:
    """``networks`` (one IP version) collapsed: the fewest that hold exactly them."""
    return list(ipaddress.collapse_addresses(networks))  # type: ignore[type-var]


def _common(a: Network, b: Network) -> Network:
    """The smallest network that holds both ``a`` and ``b`` (one IP version)."""
    differ = (int(a.network_address) ^ int(b.network_address)).bit_length()
    return a.supernet(new_prefix=min(a.prefixlen, b.prefixlen, _WIDTH[a.version] - differ))


def _cost(routes: list[Network], i: int) -> tuple[int, int]:
    """How merging ``routes[i]`` and ``routes[i + 1]`` ranks: the longer
    their common supernet the better, then the lower address."""
    return -_common(routes[i], routes[i + 1]).prefixlen, int(routes[i].network_address)


def _sibling(other: Network, route: Network, parent: Network) -> bool:
    """Whether ``other`` is the other half of ``route``'s ``parent``."""
    return other.prefixlen == route.prefixlen and other.subnet_of(parent)  # type: ignore[arg-type]


def _absorb(routes: list[Network], i: int) -> int:
    """Collapse the sorted, disjoint ``routes`` around the new ``routes[i]``:
    drop the neighbours it holds and join it with an equal sibling, again
    until neither applies. Its index after that."""
    while True:
        route = routes[i]
        while i + 1 < len(routes) and routes[i + 1].subnet_of(route):  # type: ignore[arg-type]
            del routes[i + 1]
        while i > 0 and routes[i - 1].subnet_of(route):  # type: ignore[arg-type]
            del routes[i - 1]
            i -= 1
        if route.prefixlen == 0:
            return i
        parent = route.supernet()
        if i + 1 < len(routes) and _sibling(routes[i + 1], route, parent):
            routes[i : i + 2] = [parent]
        elif i > 0 and _sibling(routes[i - 1], route, parent):
            routes[i - 1 : i + 1] = [parent]
            i -= 1
        else:
            return i


def _fewer(routes: list[Network], most: int) -> list[Network]:
    """Merge neighbours of the sorted, collapsed ``routes`` (one IP version)
    until at most ``most`` are left: each time the pair whose common
    supernet is the longest prefix, ties to the lower address."""
    costs = [_cost(routes, k) for k in range(len(routes) - 1)]
    while len(routes) > most:
        j = min(range(len(costs)), key=costs.__getitem__)
        routes[j : j + 2] = [_common(routes[j], routes[j + 1])]
        i = _absorb(routes, j)
        # The routes left of ``i`` and right of it are the ones they were.
        right = len(routes) - i - 2
        tail = costs[len(costs) - right :] if right > 0 else []
        middle = [_cost(routes, k) for k in (i - 1, i) if 0 <= k < len(routes) - 1]
        costs = costs[: max(i - 1, 0)] + middle + tail
    return routes


def summarize(
    networks: Iterable[Network], *, prefix: int | None = None, max_routes: int | None = None
) -> list[Network]:
    """The routes that cover ``networks``, per IP version (a route never
    mixes them): each network rolled up to ``prefix`` when given (one
    already shorter stays as it is), collapsed, then neighbours merged until
    at most ``max_routes`` of each version are left (see ``_fewer``).
    Sorted by version, address and prefix length."""
    if max_routes is not None and max_routes < 1:
        raise ValueError("max_routes must be at least 1")
    if prefix is not None and not 0 <= prefix <= 128:
        raise ValueError("prefix must be from 0 to 32 (IPv4) or 128 (IPv6)")
    summary: list[Network] = []
    given = list(networks)
    for version, width in _WIDTH.items():
        mine = [n for n in given if n.version == version]
        if not mine:
            continue
        if prefix is not None:
            if prefix > width:
                raise ValueError(f"prefix must be from 0 to {width} for IPv{version} addresses")
            mine = [n.supernet(new_prefix=prefix) if n.prefixlen > prefix else n for n in mine]
        collapsed = _collapse(mine)
        if max_routes is not None:
            collapsed = _fewer(collapsed, max_routes)
        summary.extend(collapsed)
    return sorted(summary, key=_order)


def relation(route: Network, collected: Network) -> str:
    """How a ``collected`` network that overlaps ``route`` lies against it:
    ``equal``, ``inside`` it, ``contains`` it, or ``overlaps`` it in part."""
    if collected == route:
        return "equal"
    if collected.subnet_of(route):  # type: ignore[arg-type]
        return "inside"
    if collected.supernet_of(route):  # type: ignore[arg-type]
        return "contains"
    return "overlaps"


def _span(network: Network) -> tuple[int, int, int]:
    return network.version, int(network.network_address), int(network.broadcast_address)


def _matches(summary: Sequence[Network], rows: Iterable[dict[str, Any]]) -> Iterator[tuple[int, dict[str, Any]]]:
    """``(index of the route, row)`` for each route of ``summary`` (sorted,
    disjoint) that the network of each of ``rows`` overlaps, row by row."""
    spans = [_span(route) for route in summary]
    starts = [(version, start) for version, start, _ in spans]
    for row in rows:
        collected = net(row.get("cidr"))
        if collected is None:
            continue
        version, low, high = _span(collected)
        # Only the route starting before the network can reach into it from the left.
        k = max(bisect.bisect_left(starts, (version, low)) - 1, 0)
        while k < len(summary) and starts[k] <= (version, high):
            if overlapping(summary[k], (collected,)):
                yield k, row
            k += 1


def overlapping_rows(summary: Sequence[Network], rows: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    """The ``rows`` whose network overlaps at least one route of ``summary``,
    in their order: the ones ``routes`` reports, to list before it."""
    kept: dict[int, dict[str, Any]] = {}
    for _, row in _matches(summary, rows):
        kept.setdefault(id(row), row)
    return list(kept.values())


def routes(
    networks: Sequence[Network], summary: Sequence[Network], rows: Sequence[dict[str, Any]]
) -> list[dict[str, Any]]:
    """One entry per route of ``summary`` (sorted, disjoint, as ``summarize``
    returns it): its size, the distinct ``networks`` (the inputs) it covers
    and the addresses they hold, and the ``rows`` it overlaps (the
    collected networks as ``sweep.list_rows`` lists them, in that order),
    each with its ``relation`` to the route."""
    starts = [(route.version, int(route.network_address)) for route in summary]
    covered: list[list[Network]] = [[] for _ in summary]
    for each in sorted(set(networks), key=_order):
        k = bisect.bisect_right(starts, (each.version, int(each.network_address))) - 1
        if k >= 0 and summary[k].version == each.version and each.subnet_of(summary[k]):  # type: ignore[arg-type]
            covered[k].append(each)
    found: list[list[dict[str, Any]]] = [[] for _ in summary]
    for k, row in _matches(summary, rows):
        found[k].append({**row, "relation": relation(summary[k], address_of(row["cidr"]))})
    return [
        {
            "cidr": str(route),
            "version": route.version,
            "prefixlen": route.prefixlen,
            "addresses": route.num_addresses,
            "inputs": [str(each) for each in covered[k]],
            "input_count": len(covered[k]),
            "input_addresses": sum(n.num_addresses for n in _collapse(covered[k])),
            "overlaps": found[k],
        }
        for k, route in enumerate(summary)
    ]


def routes_text(entries: Iterable[dict[str, Any]]) -> str:
    """The routes of ``routes``, one CIDR per line, for a copy box."""
    return "\n".join(str(entry["cidr"]) for entry in entries)
