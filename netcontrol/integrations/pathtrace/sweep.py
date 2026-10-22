"""Reachability sweep: one destination, or many, traced from many source networks.

The path trace answers one question at a time: does this flow from this
source reach this destination? A sweep asks it of every network the filters
keep from the whole-map subnet index (``subnet_index`` rows with their
``org_ref`` and ``provider``), so a list such as *the user VLANs of every
branch that cannot reach the file server on tcp/445* comes out in one go.
A matrix sweep picks the destination networks from the same index with a
second set of filters and traces every source network to every destination
network (``pairs``, ``run_matrix``). One typed source (``typed_row``)
takes the place of the source networks in either; ``list_rows`` lists the
networks the filters keep without tracing them.

``parse_filters`` turns the query string into ``Filters``, ``select_rows``
keeps the networks they match and ``sweep`` traces each one with the
``Tracer`` and reports its verdict and what decided it. The sweep adds no
finding of its own: every verdict, summary, deciding item and port set is
the tracer's.

Pure (no I/O): the API handler loads the subnets and builds the tracer.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass, field
from typing import Any

from netcontrol.integrations.pathtrace.engine import PROTOCOLS, Tracer
from netcontrol.integrations.pathtrace.model import (
    ALLOWED,
    BLOCKED,
    PARTIAL,
    UNKNOWN,
    UNREACHABLE,
    Network,
    net,
)

# The networks endpoints live in: VLANs, single LANs, SVIs, Cato site ranges,
# cloud subnets and the connected subnets of a firewall.
DEFAULT_KINDS = ("vlan", "lan", "svi", "range", "subnet", "connected")
KINDS = (*DEFAULT_KINDS, "static", "vpn", "peer", "pool", "host", "user")
VERDICTS = (ALLOWED, BLOCKED, UNREACHABLE, PARTIAL, UNKNOWN)
# Most traces one sweep runs: source networks, or source→destination pairs.
MAX_ROWS = 20000

# The item status that decides each verdict (``verdict_of`` in the model).
_DECIDING = {BLOCKED: BLOCKED, UNREACHABLE: BLOCKED, UNKNOWN: UNKNOWN, PARTIAL: PARTIAL}
# ``VLAN <id> <name>`` (a Meraki VLAN, an SVI) and ``<name> (VLAN <id>)`` (a Cato range).
_VLAN_PREFIX = re.compile(r"^VLAN (\d+)\b")
_VLAN_SUFFIX = re.compile(r"\(VLAN (\d+)\)$")
_TRUE = ("1", "true", "yes", "y")
_FALSE = ("0", "false", "no", "n")


@dataclass(frozen=True)
class Terms:
    """Comma-separated match terms: each a case-insensitive substring, or a
    regular expression when wrapped in ``/.../``. Any term matching is a match."""

    raw: tuple[str, ...] = ()
    patterns: tuple[re.Pattern[str], ...] = ()

    def __bool__(self) -> bool:
        return bool(self.patterns)

    def match(self, text: str) -> bool:
        return any(p.search(text) for p in self.patterns)


@dataclass(frozen=True)
class Filters:
    """Which source networks a sweep traces. Empty means no restriction,
    except ``kinds`` (``DEFAULT_KINDS`` when not given)."""

    sources: frozenset[int] = frozenset()
    providers: frozenset[str] = frozenset()
    kinds: frozenset[str] = frozenset(DEFAULT_KINDS)
    vlans: tuple[tuple[int, int], ...] = ()
    name: Terms = field(default_factory=Terms)
    exclude: Terms = field(default_factory=Terms)
    sites: Terms = field(default_factory=Terms)
    within: tuple[Network, ...] = ()
    overlaps: tuple[Network, ...] = ()
    in_vpn: bool | None = None

    def to_json(self) -> dict[str, Any]:
        """The effective filters, as the response echoes them."""
        return {
            "sources": sorted(self.sources),
            "providers": sorted(self.providers),
            "kinds": [k for k in KINDS if k in self.kinds],
            "vlans": ",".join(str(low) if low == high else f"{low}-{high}" for low, high in self.vlans),
            "name": list(self.name.raw),
            "exclude": list(self.exclude.raw),
            "sites": list(self.sites.raw),
            "within": [str(n) for n in self.within],
            "overlaps": [str(n) for n in self.overlaps],
            "in_vpn": self.in_vpn,
        }


def _parts(text: str | None) -> list[str]:
    return [part.strip() for part in str(text or "").split(",") if part.strip()]


def _terms(text: str | None, what: str) -> Terms:
    """``text`` as ``Terms``. A comma inside ``/.../`` belongs to the
    expression, so pieces are joined back until the closing slash."""
    pieces = str(text or "").split(",")
    raw: list[str] = []
    while pieces:
        term = pieces.pop(0).strip()
        if term.startswith("/") and (len(term) < 2 or not term.endswith("/")):
            while pieces and not (len(term) >= 2 and term.endswith("/")):
                term += "," + pieces.pop(0)
            term = term.strip()
        if term:
            raw.append(term)
    patterns: list[re.Pattern[str]] = []
    for term in raw:
        if len(term) >= 2 and term.startswith("/") and term.endswith("/"):
            try:
                patterns.append(re.compile(term[1:-1], re.IGNORECASE))
            except re.error as exc:
                raise ValueError(f"{what}: {term} is not a valid regular expression ({exc})") from exc
        else:
            patterns.append(re.compile(re.escape(term), re.IGNORECASE))
    return Terms(tuple(raw), tuple(patterns))


def _networks(text: str | None, what: str) -> tuple[Network, ...]:
    """The comma-separated IP networks of ``text``; ``ValueError`` names
    ``what`` and the first part that is not one."""
    networks: list[Network] = []
    for part in _parts(text):
        found = net(part)
        if found is None:
            raise ValueError(f"{what}: {part!r} is not an IP network")
        networks.append(found)
    return tuple(networks)


def _vlans(text: str | None) -> tuple[tuple[int, int], ...]:
    ranges: list[tuple[int, int]] = []
    for part in _parts(text):
        match = re.fullmatch(r"(\d{1,4})(?:\s*-\s*(\d{1,4}))?", part)
        if not match:
            raise ValueError(f"vlans: {part!r} is not a VLAN id or range (such as 100 or 110-120)")
        low, high = int(match.group(1)), int(match.group(2) or match.group(1))
        if low > high or high > 4095:
            raise ValueError(f"vlans: {part!r} is not a VLAN range from 0 to 4095")
        ranges.append((low, high))
    return tuple(ranges)


def parse_flag(text: str | None, what: str) -> bool | None:
    """A yes/no query parameter: ``True`` / ``False``, or ``None`` when empty
    (or ``any``); ``ValueError`` names ``what`` otherwise."""
    wanted = str(text or "").strip().lower()
    if wanted in ("", "any", "all"):
        return None
    if wanted in _TRUE:
        return True
    if wanted in _FALSE:
        return False
    raise ValueError(f"{what} must be 1 or 0")


def parse_filters(
    *,
    sources: str | None = None,
    providers: str | None = None,
    kinds: str | None = None,
    vlans: str | None = None,
    name: str | None = None,
    exclude: str | None = None,
    sites: str | None = None,
    within: str | None = None,
    overlaps: str | None = None,
    in_vpn: str | None = None,
) -> Filters:
    """The ``Filters`` of the sweep's query string; ``ValueError`` names the
    first filter that is not valid."""
    refs: set[int] = set()
    for part in _parts(sources):
        try:
            refs.add(int(part))
        except ValueError as exc:
            raise ValueError(f"sources: {part!r} is not a source id") from exc
    wanted_kinds = {k.lower() for k in _parts(kinds)}
    if "all" in wanted_kinds:
        wanted_kinds = set(KINDS)
    unknown_kinds = sorted(wanted_kinds - set(KINDS))
    if unknown_kinds:
        raise ValueError(f"kinds: {', '.join(unknown_kinds)} is not one of {', '.join(KINDS)}")
    return Filters(
        sources=frozenset(refs),
        providers=frozenset(p.lower() for p in _parts(providers)),
        kinds=frozenset(wanted_kinds or DEFAULT_KINDS),
        vlans=_vlans(vlans),
        name=_terms(name, "name"),
        exclude=_terms(exclude, "exclude"),
        sites=_terms(sites, "sites"),
        within=_networks(within, "within"),
        overlaps=_networks(overlaps, "overlaps"),
        in_vpn=parse_flag(in_vpn, "in_vpn"),
    )


def vlan_of(row: dict[str, Any]) -> int | None:
    """The VLAN id in the name of a ``vlan`` or ``svi`` row (``VLAN <id> ...``)
    or a ``range`` row (``... (VLAN <id>)``); ``None`` for any other row."""
    name = str(row.get("name") or "")
    kind = row.get("kind")
    match = _VLAN_PREFIX.match(name) if kind in ("vlan", "svi") else None
    if kind == "range":
        match = _VLAN_SUFFIX.search(name)
    return int(match.group(1)) if match else None


def _inside(network: Network, outer: tuple[Network, ...]) -> bool:
    return any(o.version == network.version and network.subnet_of(o) for o in outer)  # type: ignore[arg-type]


def overlapping(network: Network, others: Iterable[Network]) -> bool:
    """Whether ``network`` shares any address with one of ``others`` (of
    its IP version): inside one, containing one, or partly over one."""
    return any(o.version == network.version and network.overlaps(o) for o in others)


def address_of(text: str) -> Network:
    """The network of a typed address or network; ``ValueError`` when it is
    neither."""
    found = net(text)
    if found is None:
        raise ValueError(f"{text!r} is not an IP address or network")
    return found


def typed_row(source: str, *, graph_node: Any = None) -> dict[str, Any]:
    """The source row of one typed ``source`` (an IP address or network),
    owned by ``graph_node`` when the page knows it, to trace in place of the
    networks the filters keep. Its result row takes its site and node from
    the trace's source end (see ``_result_row``)."""
    address_of(source)
    return {"cidr": source, "typed": True, "graph_node": graph_node}


def select_rows(rows: list[dict[str, Any]], filters: Filters, destination: str | None) -> list[dict[str, Any]]:
    """The networks of ``rows`` that ``filters`` keep, each once per
    ``(cidr, node_id)``, each with its ``vlan``. With a ``destination``,
    networks of the other IP family are left out, and so is the
    destination's own network: any row whose network overlaps it. Without
    one (the destination networks of a matrix, or its sources before
    ``pairs``), only the filters apply."""
    target = address_of(destination) if destination is not None else None
    kept: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for row in rows:
        network = net(row.get("cidr"))
        if network is None:
            continue
        if target is not None and (network.version != target.version or network.overlaps(target)):
            continue
        key = (str(network), str(row.get("node_id") or ""))
        if key in seen:
            continue
        if filters.sources and row.get("org_ref") not in filters.sources:
            continue
        if filters.providers and str(row.get("provider") or "").lower() not in filters.providers:
            continue
        if row.get("kind") not in filters.kinds:
            continue
        vlan = vlan_of(row)
        if filters.vlans and (vlan is None or not any(low <= vlan <= high for low, high in filters.vlans)):
            continue
        name = str(row.get("name") or "")
        if filters.name and not filters.name.match(name):
            continue
        if filters.exclude and filters.exclude.match(name):
            continue
        if filters.sites and not filters.sites.match(str(row.get("site_name") or "")):
            continue
        if filters.within and not _inside(network, filters.within):
            continue
        if filters.overlaps and not overlapping(network, filters.overlaps):
            continue
        if filters.in_vpn is not None and row.get("in_vpn") is not filters.in_vpn:
            continue
        seen.add(key)
        kept.append({**row, "vlan": vlan})
    return kept


def iter_pairs(
    sources: list[dict[str, Any]], destinations: list[dict[str, Any]]
) -> Iterator[tuple[dict[str, Any], dict[str, Any]]]:
    """Each ``(source row, destination row)`` of a matrix sweep, in order.
    A pair is left out when the two networks are of different IP families or
    overlap (which includes a network paired with itself)."""
    targets = [(row, net(row.get("cidr"))) for row in destinations]
    for source in sources:
        network = net(source.get("cidr"))
        if network is None:
            continue
        for destination, target in targets:
            if target is None or target.version != network.version or network.overlaps(target):
                continue
            yield source, destination


def pairs(
    sources: list[dict[str, Any]], destinations: list[dict[str, Any]]
) -> list[tuple[dict[str, Any], dict[str, Any]]]:
    """The pairs of ``iter_pairs`` as a list, for ``run_matrix``."""
    return list(iter_pairs(sources, destinations))


def traffic_text(protocol: str, port: int | None) -> str:
    """The traffic asked about, the way a trace names it: ``tcp/445``, ``icmp``,
    ``any traffic``."""
    protocol = str(protocol or "").strip().lower()
    protocol = "" if protocol in ("any", "all") else protocol
    if not protocol:
        return "any traffic"
    return protocol + (f"/{port}" if port is not None and protocol in ("tcp", "udp") else "")


def _deciding(result: dict[str, Any]) -> tuple[str, str]:
    """``(hop label, "<where>: <text>")`` of the item that decided a trace's
    verdict, in the direction the verdict is from; empty when allowed or
    when no item decided it (an end that could not be placed)."""
    status = _DECIDING.get(result.get("verdict") or "")
    if status is None:
        return "", ""
    request, reply = result.get("request") or {}, result.get("reply") or {}
    first = request if request.get("verdict") == result.get("verdict") else reply
    for direction in (first, reply if first is request else request):
        for each in direction.get("hops") or []:
            for entry in each.get("items") or []:
                if entry.get("status") == status:
                    where = str(entry.get("where") or "")
                    text = str(entry.get("text") or "")
                    return str(each.get("label") or ""), f"{where}: {text}" if where else text
    return "", ""


def _network_key(site: Any, vlan: Any, cidr: Any) -> tuple:
    network = net(cidr)
    return (
        str(site or "").lower(),
        vlan is None,
        vlan if vlan is not None else 0,
        network.version if network is not None else 0,
        int(network.network_address) if network is not None else 0,
        network.prefixlen if network is not None else 0,
    )


def _sort_key(row: dict[str, Any]) -> tuple:
    """By source site, VLAN and network, then by destination site, VLAN and network."""
    return (
        *_network_key(row.get("site_name"), row.get("vlan"), row["cidr"]),
        *_network_key(row.get("dst_site_name"), row.get("dst_vlan"), row.get("dst_cidr")),
    )


def _protocol(protocol: str) -> str:
    protocol = str(protocol or "").strip().lower()
    if protocol not in ("", "any", "all", *PROTOCOLS):
        raise ValueError(f"protocol must be one of {', '.join(PROTOCOLS)}")
    return protocol


def _node_of(tracer: Tracer, row: dict[str, Any]) -> Any:
    """The graph node that owns a subnet index row's network, if any; a
    typed row's (``typed_row``) is the node it was given."""
    if "graph_node" in row:
        return row["graph_node"]
    return tracer.graph_of.get((int(row.get("org_ref") or 0), str(row.get("node_id") or "")))


def _network_fields(tracer: Tracer, row: dict[str, Any], source_node: Any, start: dict[str, Any]) -> dict[str, Any]:
    """The fields of a result row that name its source network ``row``,
    owned by ``source_node``; ``start`` is the trace's source end (empty when
    nothing was traced), which names the node and, of a typed row, the site."""
    node = start["node"] if start.get("node") is not None else source_node
    return {
        "org_ref": row.get("org_ref"),
        "org_name": str(row.get("org_name") or ""),
        "provider": str(row.get("provider") or ""),
        "site_id": str(row.get("site_id") or ""),
        "site_name": str((start.get("site") if row.get("typed") else row.get("site_name")) or ""),
        "node_id": str(row.get("node_id") or ""),
        # The graph node the trace started at, for tracing the row again.
        "source_node": node,
        "node_label": str(start.get("label") or (tracer.label(node) if node else "")),
        "kind": str(row.get("kind") or ""),
        "vlan": row.get("vlan", vlan_of(row)),
        "cidr": row["cidr"],
        "name": str(row.get("name") or ""),
        "in_vpn": row.get("in_vpn"),
    }


def list_rows(tracer: Tracer, rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """The networks of ``rows`` (as ``select_rows`` keeps them), untraced:
    each one's network fields with the graph node of its owner, sorted by
    site, then VLAN, then network."""
    return sorted((_network_fields(tracer, row, _node_of(tracer, row), {}) for row in rows), key=_sort_key)


def _result_row(
    tracer: Tracer,
    row: dict[str, Any],
    destination: str,
    destination_node: Any,
    target: dict[str, Any] | None,
    protocol: str,
    port: int | None,
    traffic: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Trace from the network of source ``row`` to ``destination`` (owned by
    ``destination_node``; ``target`` is its subnet index row in a matrix):
    the result row and the trace (whose ``source`` / ``destination`` ends
    are missing when the tracer refused it). A typed row (``typed_row``)
    takes its site from the trace's source end."""
    source_node = _node_of(tracer, row)
    try:
        result = tracer.trace(
            row["cidr"],
            destination,
            source_node=source_node,
            destination_node=destination_node,
            protocol=protocol,
            port=port,
        )
    except ValueError as exc:
        result = {"verdict": UNKNOWN, "summary": str(exc), "traffic": traffic}
    decided_at, decided_by = _deciding(result)
    end = result.get("destination") or {}
    found = target or {}
    return {
        **_network_fields(tracer, row, source_node, result.get("source") or {}),
        "dst_cidr": str(found.get("cidr") or destination),
        "dst_name": str(found.get("name") or ""),
        "dst_site_name": str((found.get("site_name") if target is not None else end.get("site")) or ""),
        "dst_org_ref": found.get("org_ref"),
        "dst_org_name": str(found.get("org_name") or ""),
        "dst_provider": str(found.get("provider") or ""),
        "dst_node_id": str(found.get("node_id") or ""),
        "dst_node_label": str(end.get("label") or (tracer.label(destination_node) if destination_node else "")),
        "dst_kind": str(found.get("kind") or ""),
        "dst_vlan": found.get("vlan", vlan_of(found)) if target is not None else None,
        "dst_in_vpn": found.get("in_vpn"),
        # The graph node the trace ended at, for tracing the row again.
        "destination_node": end["node"] if end.get("node") is not None else destination_node,
        "verdict": result.get("verdict") or UNKNOWN,
        "summary": str(result.get("summary") or ""),
        "traffic": str(result.get("traffic") or traffic),
        "decided_at": decided_at,
        "decided_by": decided_by,
        "ports": result.get("ports"),
    }, result


def _report(
    results: list[dict[str, Any]], traffic: str, end: dict[str, Any] | None, start: dict[str, Any] | None
) -> dict[str, Any]:
    results.sort(key=_sort_key)
    counts = {verdict: 0 for verdict in VERDICTS}
    for each in results:
        counts[each["verdict"]] = counts.get(each["verdict"], 0) + 1
    return {"source": start, "destination": end, "traffic": traffic, "rows": results, "counts": counts}


def _typed_start(start: dict[str, Any] | None, row: dict[str, Any], result: dict[str, Any]) -> dict[str, Any] | None:
    """The source end a report names: the first trace's, of a typed row."""
    return start or (result.get("source") if row.get("typed") else None)


def run(
    tracer: Tracer,
    rows: list[dict[str, Any]],
    destination: str,
    *,
    destination_node: Any = None,
    protocol: str = "",
    port: int | None = None,
) -> dict[str, Any]:
    """Trace ``protocol``/``port`` from each of ``rows`` (as ``select_rows``
    keeps them, or the one ``typed_row``) to ``destination``: the result
    rows, the counts by verdict, the traffic, the destination end of the
    first trace and, of a typed row, its source end (``None`` otherwise)."""
    protocol = _protocol(protocol)
    traffic = traffic_text(protocol, port)
    start: dict[str, Any] | None = None
    end: dict[str, Any] | None = None
    results: list[dict[str, Any]] = []
    for row in rows:
        result, trace = _result_row(tracer, row, destination, destination_node, None, protocol, port, traffic)
        start = _typed_start(start, row, trace)
        end = end or trace.get("destination")
        results.append(result)
    return _report(results, traffic, end, start)


def run_matrix(
    tracer: Tracer,
    matrix: Iterable[tuple[dict[str, Any], dict[str, Any]]],
    *,
    protocol: str = "",
    port: int | None = None,
) -> dict[str, Any]:
    """Trace ``protocol``/``port`` for each ``(source row, destination row)``
    of ``matrix`` (as ``pairs`` builds it), from the source network to the
    whole destination network at its owner: the result rows, the counts by
    verdict and the traffic (``destination`` is ``None``; ``source`` is the
    first trace's source end when the source rows are one ``typed_row``)."""
    protocol = _protocol(protocol)
    traffic = traffic_text(protocol, port)
    start: dict[str, Any] | None = None
    results: list[dict[str, Any]] = []
    for row, target in matrix:
        result, trace = _result_row(
            tracer, row, target["cidr"], _node_of(tracer, target), target, protocol, port, traffic
        )
        start = _typed_start(start, row, trace)
        results.append(result)
    return _report(results, traffic, None, start)


def sweep(
    tracer: Tracer,
    rows: list[dict[str, Any]],
    destination: str,
    *,
    destination_node: Any = None,
    protocol: str = "",
    port: int | None = None,
) -> list[dict[str, Any]]:
    """The result row of each source network in ``rows``, sorted by site,
    then VLAN, then network (see ``run``; ``run_matrix`` for many
    destinations)."""
    return run(tracer, rows, destination, destination_node=destination_node, protocol=protocol, port=port)["rows"]


CSV_COLUMNS = (
    "Source",
    "Provider",
    "Site",
    "Network",
    "Kind",
    "VLAN",
    "CIDR",
    "In VPN",
    "Destination site",
    "Destination network",
    "Destination CIDR",
    "Verdict",
    "Decided at",
    "Decided by",
    "Ports",
    "Summary",
)
# The columns of a list of networks (``list_rows``): the source network's.
LIST_COLUMNS = CSV_COLUMNS[:8]
VERDICT_WORDS = {
    ALLOWED: "Allowed",
    BLOCKED: "Blocked",
    UNREACHABLE: "No path",
    PARTIAL: "Allowed in part",
    UNKNOWN: "Check incomplete",
}
SUMMARY_COLUMNS = ("Verdict", "Networks", "Share")


def summary_rows(counts: Mapping[str, int]) -> list[list[Any]]:
    """The summary of a sweep as the rows of ``SUMMARY_COLUMNS``: how many
    networks got each verdict, in ``VERDICTS`` order (a verdict with none has
    its row too), each one's share of the total as ``42%``, then a **Total**
    row. ``counts`` is the sweep's ``counts`` (see ``run``)."""
    total = sum(int(counts.get(verdict) or 0) for verdict in VERDICTS)

    def share(count: int) -> str:
        return f"{count / total:.0%}" if total else ""

    rows: list[list[Any]] = [
        [VERDICT_WORDS[verdict], int(counts.get(verdict) or 0), share(int(counts.get(verdict) or 0))]
        for verdict in VERDICTS
    ]
    rows.append(["Total", total, share(total)])
    return rows


def sheet_row(row: dict[str, Any], columns: tuple[str, ...] = CSV_COLUMNS) -> list[Any]:
    """``csv_row`` with the VLAN id as a number, for a spreadsheet."""
    cells: list[Any] = csv_row(row, columns)
    if row.get("vlan") is not None and "VLAN" in columns:
        cells[columns.index("VLAN")] = int(row["vlan"])
    return cells


def sheet_groups(rows: list[dict[str, Any]], verdict: str | None = None) -> list[tuple[str, list[dict[str, Any]]]]:
    """The tabs of a spreadsheet of result ``rows``: **All**, then one per
    verdict in ``VERDICTS`` order (present even when empty, so the tabs are
    always the same). With ``verdict``, the one tab of that verdict's rows."""
    if verdict:
        return [(VERDICT_WORDS.get(verdict, verdict), [row for row in rows if row.get("verdict") == verdict])]
    groups: list[tuple[str, list[dict[str, Any]]]] = [("All", list(rows))]
    groups.extend((VERDICT_WORDS[each], [row for row in rows if row.get("verdict") == each]) for each in VERDICTS)
    return groups


def csv_row(row: dict[str, Any], columns: tuple[str, ...] = CSV_COLUMNS) -> list[str]:
    """A result row as the cells of ``columns`` (of ``CSV_COLUMNS``, such
    as ``LIST_COLUMNS`` for a ``list_rows`` row). **Ports** is the tracer's
    text of the ports allowed end to end (any traffic asked)."""
    in_vpn = row.get("in_vpn")
    ports = row.get("ports") or {}
    cells = [
        str(row.get("org_name") or row.get("org_ref") or ""),
        str(row.get("provider") or ""),
        str(row.get("site_name") or ""),
        str(row.get("name") or ""),
        str(row.get("kind") or ""),
        "" if row.get("vlan") is None else str(row["vlan"]),
        str(row.get("cidr") or ""),
        "" if in_vpn is None else ("Yes" if in_vpn else "No"),
        str(row.get("dst_site_name") or ""),
        str(row.get("dst_name") or ""),
        str(row.get("dst_cidr") or ""),
        VERDICT_WORDS.get(str(row.get("verdict")), str(row.get("verdict") or "")),
        str(row.get("decided_at") or ""),
        str(row.get("decided_by") or ""),
        str(ports.get("text") or ""),
        str(row.get("summary") or ""),
    ]
    return cells if columns is CSV_COLUMNS else [cells[CSV_COLUMNS.index(column)] for column in columns]
