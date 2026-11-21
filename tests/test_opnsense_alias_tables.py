"""OPNsense alias tables: the pf tables behind the aliases config.xml cannot
resolve, read by the collection and used by the path trace.

The collector reads ``firewall/alias_util/aliases`` and
``firewall/alias_util/list/{alias}`` for the aliases the trace needs
(``opnsense_config``'s ``table_aliases``), within its bounds; the
collection stores them for the firewall's inventory host
(``opnsense_alias_tables``); the trace resolves URL table, GeoIP and
host-name aliases from them. Every name and address is invented
(documentation ranges, example.com); no firewall is contacted.
"""

from __future__ import annotations

import base64
import copy

import httpx
import pytest
from netcontrol.integrations.opnsense import collector as collector_module
from netcontrol.integrations.opnsense.client import OpnsenseClient
from netcontrol.integrations.opnsense.collector import (
    ALIAS_TABLE_PRIVILEGE,
    PHASE_ALIAS_TABLES,
    collect_opnsense,
    plan_alias_tables,
    table_entries,
    tables_wanted,
)
from netcontrol.integrations.opnsense.normalize import build_snapshot
from netcontrol.integrations.opnsense.sample import (
    SAMPLE_ALIAS_CONFIG_XML,
    SAMPLE_BIG_FEED_TOTAL,
    alias_table_answers,
    build_sample_raw,
    sample_api_answers,
)
from netcontrol.integrations.pathtrace.inventory import forwarding_for_host, subnets_for_host
from netcontrol.integrations.pathtrace.opnsense_config import TABLE_WORDING, parse_config, table_cidrs

from test_opnsense_rules import _ISP_ROUTER, _NODES
from test_path_trace import _tracer

BASE = "https://fw-alias-1.example.com"
KEY, SECRET = "sample-key", "sample-secret"
# Only the parts these tests need: system, firmware, interfaces, config.xml.
ONLY_TABLES = {
    "include_gateways": False,
    "include_vpn": False,
    "include_ha": False,
    "include_routes": False,
    "include_firmware_audit": False,
    "include_clients": False,
    "include_rule_stats": False,
    "include_health": False,
}


class _Firewall:
    """An OPNsense API serving the sample answers and the alias tables."""

    def __init__(self) -> None:
        self.answers = {**sample_api_answers(), **alias_table_answers()}
        self.answers["core/backup/download/this"] = SAMPLE_ALIAS_CONFIG_XML
        self.fail: dict[str, int] = {}
        self.calls: list[httpx.Request] = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.calls.append(request)
        expected = "Basic " + base64.b64encode(f"{KEY}:{SECRET}".encode()).decode()
        assert request.headers.get("Authorization") == expected
        # Read-only: the alias tables are only ever read with GET.
        assert request.method == "GET", request.url
        path = request.url.path.removeprefix("/api/")
        if path in self.fail:
            return httpx.Response(self.fail[path], json={"message": f"refused {path}"})
        if path == "core/backup/download/this":
            return httpx.Response(200, text=self.answers[path])
        if path not in self.answers:
            return httpx.Response(404, json={"errorMessage": "Endpoint not found"})
        return httpx.Response(200, json=copy.deepcopy(self.answers[path]))

    def paths(self) -> list[str]:
        return [r.url.path.removeprefix("/api/") for r in self.calls]


def _client(fake: _Firewall) -> OpnsenseClient:
    return OpnsenseClient(BASE, KEY, SECRET, transport=httpx.MockTransport(fake.handler), requests_per_second=1000)


def _tables(raw: dict) -> dict[str, dict]:
    return {t["name"]: t for t in (raw["alias_tables"] or {}).get("tables") or []}


# ── Reading the tables ───────────────────────────────────────────────────────


def test_negated_entries_are_cut_out_as_the_most_specific_match():
    assert sorted(table_cidrs(["198.51.100.0/30", "!198.51.100.1"])) == ["198.51.100.0/32", "198.51.100.2/31"]
    # A network more specific than a negated one stays; garbage is ignored.
    assert table_cidrs(["192.0.2.0/24", "!192.0.2.0/25", "192.0.2.10", "not-an-address"]) == [
        "192.0.2.128/25",
        "192.0.2.10/32",
    ]
    assert sorted(table_cidrs(["2001:db8::/126", "!2001:db8::3"])) == ["2001:db8::/127", "2001:db8::2/128"]


def test_the_aliases_the_trace_needs_are_the_ones_config_xml_cannot_resolve():
    # WebServers resolves from the configuration; Trusted nests a URL table.
    assert tables_wanted(SAMPLE_ALIAS_CONFIG_XML) == [
        "BlockedCountries",
        "PartnerFeed",
        "UpdateHosts",
        "BigFeed",
        "UnreadFeed",
        "Trusted",
    ]
    assert tables_wanted("not xml") == []


def test_the_plan_skips_the_giants_and_what_pf_has_not_loaded(monkeypatch):
    listed = ["bogons", "bogonsv6", "feed_a", "Feed_B", "feed_c"]
    plan = plan_alias_tables(["bogons", "FEED_A", "feed_b", "gone", "feed_c"], listed)
    assert plan == {"read": ["feed_a", "Feed_B", "feed_c"], "skipped": ["bogons"], "missing": ["gone"], "not_read": []}
    monkeypatch.setattr(collector_module, "ALIAS_TABLES_MAX_READS", 2)
    assert plan_alias_tables(["feed_a", "feed_b", "feed_c"], listed)["not_read"] == ["feed_c"]


def test_table_answers_of_both_shapes():
    assert table_entries({"total": 9, "rows": [{"ip": "192.0.2.1"}, {"ip": "!192.0.2.2"}]}) == (
        ["192.0.2.1", "!192.0.2.2"],
        9,
    )
    # The plain items of an older release, entries or rows.
    assert table_entries({"items": ["192.0.2.1", {"ip": "192.0.2.2"}]}) == (["192.0.2.1", "192.0.2.2"], 2)
    assert table_entries(None) == ([], 0)


@pytest.mark.asyncio
async def test_collect_reads_the_tables_after_config_xml():
    fake = _Firewall()
    phases: list[dict] = []
    async with _client(fake) as client:
        raw = await collect_opnsense(client, ONLY_TABLES, phases.append)
    paths = fake.paths()
    lists = [p for p in paths if p.startswith("firewall/alias_util/list/")]
    assert paths.index("core/backup/download/this") < paths.index("firewall/alias_util/aliases")
    assert lists == [
        "firewall/alias_util/list/BlockedCountries",
        "firewall/alias_util/list/PartnerFeed",
        "firewall/alias_util/list/UpdateHosts",
        "firewall/alias_util/list/BigFeed",
        "firewall/alias_util/list/Trusted",
    ]
    tables = _tables(raw)
    assert tables["PartnerFeed"] == {
        "name": "PartnerFeed",
        "entries": ["198.51.100.0/26", "!198.51.100.7"],
        "total": 2,
        "truncated": False,
    }
    big = tables["BigFeed"]
    assert big["truncated"] is True and big["total"] == SAMPLE_BIG_FEED_TOTAL and len(big["entries"]) == 32
    assert raw["alias_tables"]["missing"] == ["UnreadFeed"] and raw["alias_tables"]["read_at"]
    # The count of calls stays right, and the phase is reported.
    last = phases[-1]
    assert last["phase"] == "collected" and last["calls_done"] == last["calls_total"] == len(paths)
    assert any(p["phase"] == PHASE_ALIAS_TABLES for p in phases)
    (warning,) = raw["errors"]
    assert warning["info"] is True and "BigFeed" in warning["message"] and "UnreadFeed" in warning["message"]


@pytest.mark.asyncio
async def test_collect_bounds_the_entries_per_table_and_over_all(monkeypatch):
    monkeypatch.setattr(collector_module, "ALIAS_TABLE_MAX_ENTRIES", 2)
    monkeypatch.setattr(collector_module, "ALIAS_TABLES_MAX_ENTRIES", 5)
    fake = _Firewall()
    async with _client(fake) as client:
        raw = await collect_opnsense(client, ONLY_TABLES)
    tables = _tables(raw)
    # 2 + 2 + 1 entries, then the budget is spent: the rest is not read.
    assert [len(t["entries"]) for t in tables.values()] == [2, 2, 1]
    assert tables["PartnerFeed"]["truncated"] is False and tables["UpdateHosts"]["truncated"] is True
    assert list(tables) == ["BlockedCountries", "PartnerFeed", "UpdateHosts"]
    assert raw["alias_tables"]["not_read"] == ["BigFeed", "Trusted"]
    assert "firewall/alias_util/list/Trusted" not in fake.paths()

    monkeypatch.setattr(collector_module, "ALIAS_TABLES_MAX_ENTRIES", 100)
    fake = _Firewall()
    async with _client(fake) as client:
        raw = await collect_opnsense(client, ONLY_TABLES)
    tables = _tables(raw)
    # BlockedCountries holds 2 and keeps 2; BigFeed is cut at 2.
    assert tables["BlockedCountries"]["truncated"] is False and tables["BigFeed"]["entries"] == [
        "198.51.100.128",
        "198.51.100.129",
    ]


@pytest.mark.asyncio
async def test_a_refused_table_read_names_the_privilege_and_stops():
    fake = _Firewall()
    fake.fail = {"firewall/alias_util/list/BlockedCountries": 403}
    async with _client(fake) as client:
        raw = await collect_opnsense(client, ONLY_TABLES)
    refused = next(e for e in raw["errors"] if e.get("status") == 403)
    assert ALIAS_TABLE_PRIVILEGE in refused["message"]
    assert [p for p in fake.paths() if p.startswith("firewall/alias_util/list/")] == [
        "firewall/alias_util/list/BlockedCountries"
    ]
    assert raw["alias_tables"]["tables"] == []

    fake = _Firewall()
    fake.fail = {"firewall/alias_util/aliases": 403}
    async with _client(fake) as client:
        raw = await collect_opnsense(client, ONLY_TABLES)
    assert raw["alias_tables"] is None
    assert ALIAS_TABLE_PRIVILEGE in next(e for e in raw["errors"] if e.get("status") == 403)["message"]


@pytest.mark.asyncio
async def test_no_table_is_read_without_config_xml_or_with_the_option_off():
    for options in ({**ONLY_TABLES, "include_alias_tables": False}, {**ONLY_TABLES, "config_backup": False}):
        fake = _Firewall()
        async with _client(fake) as client:
            raw = await collect_opnsense(client, options)
        assert raw["alias_tables"] is None
        assert not any(p.startswith("firewall/alias_util/") for p in fake.paths())
    # A configuration without such aliases: no call, an empty set (stored as such).
    fake = _Firewall()
    fake.answers["core/backup/download/this"] = sample_api_answers()["core/backup/download/this"]
    async with _client(fake) as client:
        raw = await collect_opnsense(client, ONLY_TABLES)
    assert raw["alias_tables"]["tables"] == [] and raw["errors"] == []
    assert not any(p.startswith("firewall/alias_util/") for p in fake.paths())


# ── The trace ────────────────────────────────────────────────────────────────


def _collected_tables() -> dict[str, dict]:
    answers = alias_table_answers()
    found: dict[str, dict] = {}
    for name in ("BlockedCountries", "PartnerFeed", "UpdateHosts", "BigFeed", "Trusted"):
        entries, total = table_entries(answers[f"firewall/alias_util/list/{name}"])
        found[name] = {"entries": entries, "total": total, "truncated": total > len(entries)}
    return found


def _trace(tables: dict | None):
    firewall = forwarding_for_host(
        {"ip_address": "192.0.2.1", "device_type": "opnsense"},
        [],
        None,
        [],
        config_backup={"config_text": SAMPLE_ALIAS_CONFIG_XML},
        alias_tables=tables,
    )
    router = forwarding_for_host(
        {"ip_address": "203.0.113.1", "device_type": "cisco_ios"},
        [],
        None,
        [],
        config_backup={"config_text": _ISP_ROUTER},
    )
    subnets = [*subnets_for_host(_NODES[0], firewall), *subnets_for_host(_NODES[1], router)]
    link = {"id": "lldp:31:32", "from": 31, "to": 32, "protocol": "lldp", "status": "up"}
    return _tracer({}, hosts={31: firewall, 32: router}, extra_nodes=_NODES, extra_edges=[link], subnets=subnets)


def _inbound(tracer, source: str, destination: str, port: int) -> dict:
    return tracer.trace(source, destination, source_node=32, destination_node=31, protocol="tcp", port=port)


def _acl_text(out: dict) -> str:
    hop = next(h for h in out["request"]["hops"] if h["label"] == "fw-lab-1")
    return " ".join(i["text"] for i in hop["items"] if i["stage"] in ("acl", "policy"))


def test_without_tables_the_dynamic_aliases_stay_unknown():
    tracer = _trace(None)
    out = _inbound(tracer, "198.51.100.40", "192.0.2.20", 443)
    assert out["verdict"] == "unknown"
    assert "geoip alias BlockedCountries" in _acl_text(out)


def test_a_geoip_table_blocks_what_it_holds_and_passes_on_the_rest():
    tracer = _trace(_collected_tables())
    blocked = _inbound(tracer, "198.51.100.70", "192.0.2.20", 443)
    assert blocked["verdict"] == "blocked", blocked["summary"]
    text = _acl_text(blocked)
    assert "Block countries" in text and f"alias BlockedCountries {TABLE_WORDING}" in text
    # Not in the complete GeoIP table: the next rule (a URL table) decides.
    allowed = _inbound(tracer, "198.51.100.40", "192.0.2.20", 443)
    assert allowed["verdict"] == "allowed", allowed["summary"]
    assert "Partners to web" in _acl_text(allowed)


def test_a_negated_table_entry_does_not_match():
    tracer = _trace(_collected_tables())
    out = _inbound(tracer, "198.51.100.7", "192.0.2.20", 443)
    assert out["verdict"] == "blocked" and "Default deny" in _acl_text(out)


def test_a_truncated_table_matches_what_it_holds_and_leaves_the_rest_unknown():
    tracer = _trace(_collected_tables())
    held = _inbound(tracer, "198.51.100.130", "192.0.2.30", 22)
    assert held["verdict"] == "allowed", held["summary"]
    # A long table is shortened in the hop text.
    assert "and 24 more" in _acl_text(held)
    other = _inbound(tracer, "198.51.100.180", "192.0.2.30", 22)
    assert other["verdict"] == "unknown"
    assert "of which only 32 were read" in _acl_text(other) and str(SAMPLE_BIG_FEED_TOTAL) in _acl_text(other)


def test_an_alias_without_a_table_stays_unknown():
    tracer = _trace(_collected_tables())
    out = _inbound(tracer, "198.51.100.200", "192.0.2.31", 22)
    assert out["verdict"] == "unknown" and "urltable alias UnreadFeed" in _acl_text(out)


def test_nested_aliases_and_rule_negation():
    tracer = _trace(_collected_tables())
    # Trusted nests the URL table and a host alias: resolved through the nested table.
    assert _inbound(tracer, "198.51.100.40", "192.0.2.33", 8443)["verdict"] == "allowed"
    assert _inbound(tracer, "198.51.100.200", "192.0.2.33", 8443)["verdict"] == "blocked"
    # A negated source stays unresolved, tables or not.
    out = _inbound(tracer, "198.51.100.200", "192.0.2.32", 80)
    assert out["verdict"] == "unknown" and "negated Trusted" in _acl_text(out)


def test_a_host_alias_with_a_host_name_takes_the_complete_table():
    running = parse_config(SAMPLE_ALIAS_CONFIG_XML, "", _collected_tables())
    rule = next(e for e in running.access_lists["lan"] if e.name == "Updates")
    assert rule.dst == ["192.0.2.10/32", "198.51.100.200/32"] and rule.unresolved == []
    assert f"alias UpdateHosts {TABLE_WORDING}" in rule.comment
    before = parse_config(SAMPLE_ALIAS_CONFIG_XML)
    rule = next(e for e in before.access_lists["lan"] if e.name == "Updates")
    assert rule.unresolved == ["alias UpdateHosts (host name updates.example.com)"]


# ── Stored by the collection ─────────────────────────────────────────────────


async def _host(address: str = "192.0.2.1") -> int:
    import routes.database as db

    group_id = await db.create_group(f"Firewalls {address}")
    return await db.add_host(group_id, f"fw-{address}", address, device_type="opnsense")


def _raw_with_tables() -> dict:
    tables = _collected_tables()
    return {
        **build_sample_raw(),
        "alias_tables": {
            "read_at": "2026-11-14T09:00:10+00:00",
            "tables": [{"name": name, **table} for name, table in tables.items()],
            "skipped": [],
            "missing": ["UnreadFeed"],
            "not_read": [],
        },
    }


@pytest.mark.asyncio
async def test_after_collection_replaces_the_tables_of_the_matched_host():
    import routes.database as db
    from netcontrol.routes.opnsense_collection import SECTION_ALIAS_TABLES, after_collection
    from netcontrol.routes.opnsense_rules import alias_tables_for_host

    host_id = await _host()
    raw = _raw_with_tables()
    snapshot = build_snapshot(raw)
    await after_collection(raw, snapshot, 901)
    assert "alias_tables" not in raw
    stored = (await db.get_opnsense_alias_tables([host_id]))[host_id]
    assert stored["read_at"] == "2026-11-14 09:00:10"
    assert stored["tables"]["PartnerFeed"]["entries"] == ["198.51.100.0/26", "!198.51.100.7"]
    assert stored["tables"]["BigFeed"]["truncated"] is True
    assert stored["tables"]["BigFeed"]["total"] == SAMPLE_BIG_FEED_TOTAL
    versions = await db.get_opnsense_alias_table_versions([host_id, host_id + 1000])
    assert list(versions) == [host_id]
    firewall = next(n for n in snapshot["nodes"] if n.get("kind") == "appliance" and n["id"].startswith("d:"))
    section = dict(next(s for s in firewall["sections"] if s["title"] == SECTION_ALIAS_TABLES)["rows"])
    assert section["Result"] == "5 tables stored for the path trace" and section["Truncated"] == "BigFeed"
    # The rule views get the sizes, never the entries.
    view = await alias_tables_for_host(host_id)
    assert view["tables"]["BigFeed"] == {"entry_count": 32, "total": SAMPLE_BIG_FEED_TOTAL, "truncated": True}

    # The trace reads them back the way the stored rows give them.
    block = forwarding_for_host(
        {"ip_address": "192.0.2.1", "device_type": "opnsense"},
        [],
        None,
        [],
        config_backup={"config_text": SAMPLE_ALIAS_CONFIG_XML},
        alias_tables=stored["tables"],
    )
    policy = next(p for p in block["policies"] if p["name"] == "ACL wan in on wan (igb0)")
    countries = next(r for r in policy["rules"] if r["name"] == "Block countries")
    assert countries["src"] == ["198.51.100.64/26"] and not countries["unresolved"]

    # The next collection replaces them as a whole.
    raw = {**_raw_with_tables(), "alias_tables": {"read_at": "2026-11-14T10:00:00+00:00", "tables": []}}
    await after_collection(raw, build_snapshot(raw), 901)
    assert await db.get_opnsense_alias_tables([host_id]) == {}


@pytest.mark.asyncio
async def test_tables_not_read_keep_the_stored_ones_and_go_with_the_host():
    import routes.database as db
    from netcontrol.routes.opnsense_collection import store_alias_tables

    host_id = await _host()
    await db.replace_opnsense_alias_tables(host_id, [{"name": "Feed", "entries": ["192.0.2.9"], "total": 1}], "x")
    raw = build_sample_raw()
    assert await store_alias_tables(raw, build_snapshot(raw)) is None
    assert list((await db.get_opnsense_alias_tables([host_id]))[host_id]["tables"]) == ["Feed"]
    await db.remove_host(host_id)
    assert await db.get_opnsense_alias_tables([host_id]) == {}
