"""Path tracing inside an exported HTML file, and what the server shares with it.

The Topology page's HTML export can carry the path tracer itself: the
Pyodide runtime (Python compiled to WebAssembly), the source of the modules
listed in ``MODULES`` and the trace inputs Plexus gathered over the whole
map when the file was made. The file then traces any two subnets or
addresses offline, from that collected data, with the same engine the
server runs.

This module is the bridge the file's Python calls (``open_session``), and
the server uses the same functions for the traces it embeds itself
(``export_trace``, ``graph_node_id``, ``trace``), so both give the same
result. It and every module it imports use the standard library only.
"""

from __future__ import annotations

import copy
import json
from collections.abc import Callable
from datetime import date, datetime
from decimal import Decimal
from pathlib import Path
from typing import Any

from netcontrol.integrations.aws.reachability import Reachability as AwsReachability
from netcontrol.integrations.azure.reachability import Reachability as AzureReachability
from netcontrol.integrations.gcp.reachability import Reachability as GcpReachability
from netcontrol.integrations.pathtrace.engine import Tracer

# The modules the path tracer imports, relative to the repository root: the
# export carries their source so the file runs the engine the server runs.
MODULES = (
    "netcontrol/__init__.py",
    "netcontrol/integrations/__init__.py",
    "netcontrol/integrations/aws/__init__.py",
    "netcontrol/integrations/aws/normalize.py",
    "netcontrol/integrations/aws/reachability.py",
    "netcontrol/integrations/azure/__init__.py",
    "netcontrol/integrations/azure/normalize.py",
    "netcontrol/integrations/azure/reachability.py",
    "netcontrol/integrations/gcp/__init__.py",
    "netcontrol/integrations/gcp/normalize.py",
    "netcontrol/integrations/gcp/reachability.py",
    "netcontrol/integrations/meraki/__init__.py",
    "netcontrol/integrations/meraki/forwarding.py",
    "netcontrol/integrations/meraki/normalize.py",
    "netcontrol/integrations/meraki/subnets.py",
    "netcontrol/integrations/pathtrace/__init__.py",
    "netcontrol/integrations/pathtrace/cloud.py",
    "netcontrol/integrations/pathtrace/engine.py",
    "netcontrol/integrations/pathtrace/model.py",
    "netcontrol/integrations/pathtrace/offline.py",
    "netcontrol/integrations/pathtrace/ports.py",
)

# Cloud provider -> the routes and filtering rules engine Path Mode asks.
REACHABILITY: dict[str, Callable[[list[dict], list[dict]], Any]] = {
    "aws": AwsReachability,
    "azure": AzureReachability,
    "gcp": GcpReachability,
}

_ROOT = Path(__file__).resolve().parents[3]


def module_sources(root: Path | None = None) -> dict[str, str]:
    """The source of every module in ``MODULES``, read from disk, by path."""
    base = root or _ROOT
    return {name: (base / name).read_text(encoding="utf-8") for name in MODULES}


def graph_node_id(raw: Any) -> Any:
    """A graph node id from text (a query string, the export's own ids): an
    inventory host's id is an int. Anything not text is returned as is."""
    if not isinstance(raw, str):
        return raw
    text = raw.strip()
    if not text:
        return None
    return int(text) if text.lstrip("-").isdigit() else text


def export_ids(snapshot: dict[str, Any]) -> tuple[set[str], dict[str, str]]:
    """The node ids of an exported map, and its edge id by graph edge id."""
    node_ids = {str(n["id"]) for n in snapshot.get("nodes") or []}
    edge_ids: dict[str, str] = {}
    for edge in snapshot.get("edges") or []:
        if edge.get("gid"):
            edge_ids.setdefault(str(edge["gid"]), str(edge["id"]))
    return node_ids, edge_ids


def export_trace(trace: dict[str, Any], node_ids: set[str], edge_ids: dict[str, str]) -> dict[str, Any]:
    """A trace with its graph node and edge ids replaced by the export's
    (``None`` for one not on the exported map); the original is untouched."""
    out = copy.deepcopy(trace)

    def node(gid: Any) -> str | None:
        return str(gid) if gid is not None and str(gid) in node_ids else None

    for end in ("source", "destination"):
        if isinstance(out.get(end), dict):
            out[end]["node"] = node(out[end].get("node"))
    for direction in ("request", "reply"):
        for each in (out.get(direction) or {}).get("hops") or []:
            each["node"] = node(each.get("node"))
            gid = each.get("edge")
            each["edge"] = edge_ids.get(str(gid)) if gid is not None else None
    return out


def trace(
    tracer: Tracer,
    source: str,
    destination: str,
    *,
    source_node: Any = None,
    destination_node: Any = None,
    protocol: str = "",
    port: int | None = None,
    node_ids: set[str],
    edge_ids: dict[str, str],
) -> dict[str, Any]:
    """One direction of a leg as the export carries it: the trace in the
    export's ids, or why there is none."""
    try:
        found = tracer.trace(
            source,
            destination,
            source_node=graph_node_id(source_node),
            destination_node=graph_node_id(destination_node),
            protocol=protocol,
            port=port,
        )
    except ValueError as exc:
        return {"applies": False, "traffic": "", "verdict": "unknown", "summary": str(exc)}
    return export_trace(found, node_ids, edge_ids)


def _plain(value: Any) -> Any:
    """``json.dumps`` ``default`` for the values database rows may hold."""
    if isinstance(value, datetime | date):
        return value.isoformat()
    if isinstance(value, Decimal):
        return int(value) if value == value.to_integral_value() else float(value)
    if isinstance(value, set | frozenset):
        return sorted(value, key=str)
    return str(value)


def inputs(
    graph: dict[str, Any],
    snapshots: dict[int, dict],
    clouds: dict[int, dict[str, Any]],
    host_forwarding: dict[int, dict],
    subnets: list[dict],
    snapshot: dict[str, Any],
) -> dict[str, Any]:
    """Everything ``build`` needs, as JSON-ready data. ``clouds`` holds, per
    cloud ``org_ref``, its ``provider`` and the discovered ``resources`` and
    ``connections`` rows; ``snapshot`` is the exported map, whose own node
    and edge ids the traces are given in."""
    node_ids, edge_ids = export_ids(snapshot)
    return {
        "graph": graph,
        "snapshots": {str(org_ref): snap for org_ref, snap in snapshots.items()},
        "clouds": {
            str(org_ref): {
                "provider": str(cloud.get("provider") or ""),
                "resources": list(cloud.get("resources") or []),
                "connections": list(cloud.get("connections") or []),
            }
            for org_ref, cloud in clouds.items()
        },
        "host_forwarding": {str(host_id): block for host_id, block in host_forwarding.items()},
        "subnets": subnets,
        "export": {"nodes": sorted(node_ids), "edges": edge_ids},
    }


def dumps(data: dict[str, Any]) -> str:
    """``inputs`` as JSON text; rows' dates and decimals become plain values."""
    return json.dumps(data, separators=(",", ":"), ensure_ascii=False, default=_plain)


def build(data: dict[str, Any]) -> Tracer:
    """The ``Tracer`` over ``inputs`` read back from JSON: the int keys JSON
    turned into text are restored, and each cloud's engine is rebuilt from
    its rows."""
    snapshots = {int(org_ref): snap for org_ref, snap in (data.get("snapshots") or {}).items()}
    clouds: dict[int, Any] = {}
    for org_ref, cloud in (data.get("clouds") or {}).items():
        engine = REACHABILITY.get(str(cloud.get("provider") or ""))
        if engine is not None:
            clouds[int(org_ref)] = engine(cloud.get("resources") or [], cloud.get("connections") or [])
    host_forwarding = {int(host_id): block for host_id, block in (data.get("host_forwarding") or {}).items()}
    return Tracer(data.get("graph") or {}, snapshots, clouds, host_forwarding, list(data.get("subnets") or []))


def open_session(path: str) -> Callable[[str], str]:
    """Build the tracer over the inputs JSON at ``path`` and return what the
    file calls for each trace: a request as JSON (``source``, ``destination``,
    ``source_node``, ``destination_node``, ``protocol``, ``port``) in, the
    direction ``trace`` returns as JSON out."""
    with open(path, encoding="utf-8") as handle:
        data = json.load(handle)
    tracer = build(data)
    export = data.get("export") or {}
    node_ids = {str(n) for n in export.get("nodes") or []}
    edge_ids = {str(gid): str(eid) for gid, eid in (export.get("edges") or {}).items()}

    def run(request: str) -> str:
        asked = json.loads(request)
        port = asked.get("port")
        return json.dumps(
            trace(
                tracer,
                str(asked.get("source") or ""),
                str(asked.get("destination") or ""),
                source_node=asked.get("source_node"),
                destination_node=asked.get("destination_node"),
                protocol=str(asked.get("protocol") or ""),
                port=port if isinstance(port, int) and not isinstance(port, bool) else None,
                node_ids=node_ids,
                edge_ids=edge_ids,
            ),
            separators=(",", ":"),
            ensure_ascii=False,
        )

    return run
