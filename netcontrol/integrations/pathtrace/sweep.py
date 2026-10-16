"""Reachability sweep: one destination, traced from many source networks.

The path trace answers one question at a time: does this flow from this
source reach this destination? A sweep asks it of every network the filters
keep from the whole-map subnet index (``subnet_index`` rows with their
``org_ref`` and ``provider``), so a list such as *the user VLANs of every
branch that cannot reach the file server on tcp/445* comes out in one go.

``parse_filters`` turns the query string into ``Filters``, ``select_rows``
keeps the source networks they match and ``sweep`` traces each one with the
``Tracer`` and reports its verdict and what decided it. The sweep adds no
finding of its own: every verdict, summary and deciding item is the
tracer's.

Pure (no I/O): the API handler loads the subnets and builds the tracer.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Mapping
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
# Most source networks one sweep traces.
MAX_ROWS = 5000

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


def _in_vpn(text: str | None) -> bool | None:
    wanted = str(text or "").strip().lower()
    if wanted in ("", "any", "all"):
        return None
    if wanted in _TRUE:
        return True
    if wanted in _FALSE:
        return False
    raise ValueError("in_vpn must be 1 or 0")


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
    networks: list[Network] = []
    for part in _parts(within):
        found = net(part)
        if found is None:
            raise ValueError(f"within: {part!r} is not an IP network")
        networks.append(found)
    return Filters(
        sources=frozenset(refs),
        providers=frozenset(p.lower() for p in _parts(providers)),
        kinds=frozenset(wanted_kinds or DEFAULT_KINDS),
        vlans=_vlans(vlans),
        name=_terms(name, "name"),
        exclude=_terms(exclude, "exclude"),
        sites=_terms(sites, "sites"),
        within=tuple(networks),
        in_vpn=_in_vpn(in_vpn),
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


def select_rows(rows: list[dict[str, Any]], filters: Filters, destination: str) -> list[dict[str, Any]]:
    """The source networks of ``rows`` that ``filters`` keep, each once per
    ``(cidr, node_id)``, each with its ``vlan``. Networks of the other IP
    family than ``destination`` are left out, and so is the destination's
    own network: any row whose network overlaps it."""
    target = net(destination)
    if target is None:
        raise ValueError(f"{destination!r} is not an IP address or network")
    kept: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for row in rows:
        network = net(row.get("cidr"))
        if network is None or network.version != target.version or network.overlaps(target):
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
        if filters.in_vpn is not None and row.get("in_vpn") is not filters.in_vpn:
            continue
        seen.add(key)
        kept.append({**row, "vlan": vlan})
    return kept


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


def _sort_key(row: dict[str, Any]) -> tuple:
    network = ipaddress.ip_network(row["cidr"], strict=False)
    vlan = row.get("vlan")
    return (
        str(row.get("site_name") or "").lower(),
        vlan is None,
        vlan if vlan is not None else 0,
        network.version,
        int(network.network_address),
        network.prefixlen,
    )


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
    keeps them) to ``destination``: the result rows, the counts by verdict,
    the traffic and the destination end of the first trace."""
    protocol = str(protocol or "").strip().lower()
    if protocol not in ("", "any", "all", *PROTOCOLS):
        raise ValueError(f"protocol must be one of {', '.join(PROTOCOLS)}")
    traffic = traffic_text(protocol, port)
    end: dict[str, Any] | None = None
    results: list[dict[str, Any]] = []
    for row in rows:
        source_node = tracer.graph_of.get((int(row.get("org_ref") or 0), str(row.get("node_id") or "")))
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
        if end is None and result.get("destination"):
            end = result["destination"]
        decided_at, decided_by = _deciding(result)
        source = result.get("source") or {}
        results.append(
            {
                "org_ref": row.get("org_ref"),
                "org_name": str(row.get("org_name") or ""),
                "provider": str(row.get("provider") or ""),
                "site_id": str(row.get("site_id") or ""),
                "site_name": str(row.get("site_name") or ""),
                "node_id": str(row.get("node_id") or ""),
                # The graph node the trace started at, for tracing the row again.
                "source_node": source.get("node", source_node),
                "node_label": str(source.get("label") or (tracer.label(source_node) if source_node else "")),
                "kind": str(row.get("kind") or ""),
                "vlan": row.get("vlan", vlan_of(row)),
                "cidr": row["cidr"],
                "name": str(row.get("name") or ""),
                "in_vpn": row.get("in_vpn"),
                "verdict": result.get("verdict") or UNKNOWN,
                "summary": str(result.get("summary") or ""),
                "traffic": str(result.get("traffic") or traffic),
                "decided_at": decided_at,
                "decided_by": decided_by,
                "ports": result.get("ports"),
            }
        )
    results.sort(key=_sort_key)
    counts = {verdict: 0 for verdict in VERDICTS}
    for each in results:
        counts[each["verdict"]] = counts.get(each["verdict"], 0) + 1
    return {"destination": end, "traffic": traffic, "rows": results, "counts": counts}


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
    then VLAN, then network (see ``run``)."""
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
    "Verdict",
    "Decided at",
    "Decided by",
    "Summary",
)
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


def sheet_row(row: dict[str, Any]) -> list[Any]:
    """``csv_row`` with the VLAN id as a number, for a spreadsheet."""
    cells: list[Any] = csv_row(row)
    if row.get("vlan") is not None:
        cells[CSV_COLUMNS.index("VLAN")] = int(row["vlan"])
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


def csv_row(row: dict[str, Any]) -> list[str]:
    """A result row as the cells of ``CSV_COLUMNS``."""
    in_vpn = row.get("in_vpn")
    return [
        str(row.get("org_name") or row.get("org_ref") or ""),
        str(row.get("provider") or ""),
        str(row.get("site_name") or ""),
        str(row.get("name") or ""),
        str(row.get("kind") or ""),
        "" if row.get("vlan") is None else str(row["vlan"]),
        str(row.get("cidr") or ""),
        "" if in_vpn is None else ("Yes" if in_vpn else "No"),
        VERDICT_WORDS.get(str(row.get("verdict")), str(row.get("verdict") or "")),
        str(row.get("decided_at") or ""),
        str(row.get("decided_by") or ""),
        str(row.get("summary") or ""),
    ]
