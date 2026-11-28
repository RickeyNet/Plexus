"""Object scope and paging pushed into SQL: every list that now takes its
scope (``object_scope.sql_condition``) or its page in the query returns
exactly what the Python path (``filter_rows`` / ``filter_hosts`` and a
slice) returns for the same data, in the same order, for every kind of
caller: an admin, an unrestricted non-admin, a group-scoped user (a grant
with a sub-group), a tenant-rule user, a user with both and a user with no
access. Plus the server-side bucketing of ``GET /api/metrics/query``."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta

import pytest
import routes.database as db
import routes.db.dcim as dcim_db
import routes.db.object_scope as scope_db
from netcontrol import object_scope
from netcontrol.graphql_api.context import GraphQLContext
from netcontrol.graphql_api.schema import schema
from netcontrol.object_scope import filter_rows, scope_for_user, sql_condition
from netcontrol.routes import metrics_engine, risk_analysis as _registers_risk_model, routing as routing_routes
from starlette.requests import Request

CALLERS = ("admin", "all", "subtree", "tenant_rule", "subtree_rule", "none")


async def _sql(query: str, params: tuple = ()) -> list[dict]:
    conn = await db.get_db()
    try:
        cursor = await conn.execute(query, params)
        rows = db.rows_to_list(await cursor.fetchall()) if cursor.description else []
        await conn.commit()
        return rows
    finally:
        await conn.close()


async def _user(name: str, *, role: str = "user", access: dict | None = None, rules: list[dict] | None = None):
    uid = await db.create_user(name, "hash", "salt", role=role)
    if access is not None:
        gid = await db.create_access_group(f"{name} access", "", ["inventory", "ipam", "routing"], **access)
        if rules:
            await scope_db.set_access_group_scope_rules(gid, rules)
        await db.set_user_groups(uid, [gid])
    return await scope_for_user({"id": uid, "role": role})


async def _world() -> dict:
    """Groups a > a1 (a sub-group), b, c; hosts named so that every group's
    hosts interleave in hostname order; two tenants; scopes of each caller."""
    w: dict = {}
    w["a"] = await db.create_group("grp-a")
    w["a1"] = await db.create_group("grp-a1", parent_id=w["a"])
    w["b"] = await db.create_group("grp-b")
    w["c"] = await db.create_group("grp-c")
    w["t1"] = int((await db.create_tenant(name="tenant-one"))["id"])
    w["t2"] = int((await db.create_tenant(name="tenant-two"))["id"])
    groups = [w["a"], w["a1"], w["b"], w["c"]]
    hosts = []
    for i in range(16):
        group = groups[i % 4]
        hid = await db.add_host(
            group, f"node-{i:02d}", f"192.0.2.{10 + i}", device_type="cisco_ios" if i % 3 else "linux"
        )
        hosts.append(hid)
    # Two hosts share a hostname and address: the id breaks the tie.
    hosts.append(await db.add_host(w["b"], "node-05", "192.0.2.15"))
    await _sql("UPDATE hosts SET status = 'up' WHERE id IN (?, ?, ?, ?)", tuple(hosts[:4]))
    # A host of the sub-group carries tenant two: the subtree reaches it.
    await _sql("UPDATE hosts SET tenant_id = ? WHERE id = ?", (w["t2"], hosts[1]))
    w["hosts"] = hosts
    w["scopes"] = {
        "admin": await _user("boss", role="admin"),
        "all": await _user("viewer", access={"object_scope": "all"}),
        "subtree": await _user(
            "east", access={"object_scope": "groups", "inventory_scopes": [{"inventory_group_id": w["a"]}]}
        ),
        "tenant_rule": await _user(
            "tenanted",
            access={"object_scope": "groups", "inventory_scopes": []},
            rules=[{"model": "*", "attribute": "tenant", "value_id": w["t1"]}],
        ),
        "subtree_rule": await _user(
            "mixed",
            access={"object_scope": "groups", "inventory_scopes": [{"inventory_group_id": w["a1"]}]},
            rules=[{"model": "ipam_allocation", "attribute": "tenant", "value_id": w["t2"]}],
        ),
        "none": await _user("nobody", access={"object_scope": "groups", "inventory_scopes": []}),
    }
    return w


def test_scopes_cover_every_kind_of_caller():
    async def run():
        w = await _world()
        s = w["scopes"]
        assert s["admin"].unrestricted and s["all"].unrestricted
        assert s["subtree"].read_groups == {w["a"], w["a1"]}
        assert s["tenant_rule"].restricted and not s["tenant_rule"].read_groups and s["tenant_rule"].rules
        assert s["none"].restricted and not s["none"].read_groups and not s["none"].rules

    asyncio.run(run())


# ── sql_condition ────────────────────────────────────────────────────────────


def test_sql_condition_refuses_models_with_derived_keys():
    async def run():
        scope = object_scope.ObjectScope(unrestricted=False, read_groups=frozenset({1}))
        for model in ("host_set", "vlan_group", "circuit", "cluster", "virtual_machine", "cable"):
            with pytest.raises(ValueError):
                await sql_condition(model, scope)
        # Unrestricted callers too: a call site is wrong whoever calls it.
        with pytest.raises(ValueError):
            await sql_condition("vlan_group", object_scope.UNRESTRICTED)
        assert await sql_condition("region", scope) == ("(1 = 1)", ())
        assert await sql_condition("host_record", object_scope.NO_ACCESS) == ("1 = 0", ())

    asyncio.run(run())


def test_sql_condition_matches_filter_rows_for_column_models():
    """For each column-keyed model, the rows a query with ``sql_condition``
    returns from a table of every key combination are the rows
    ``filter_rows`` keeps, for read and write."""

    async def run():
        w = await _world()
        await _sql(
            "CREATE TEMP TABLE scope_probe (id INTEGER, group_id INTEGER, host_id INTEGER, tenant_id INTEGER,"
            " site_id INTEGER)"
        )
        host = w["hosts"]
        values = {
            "group_id": [None, w["a"], w["a1"], w["b"]],
            "host_id": [None, host[0], host[1], host[2]],
            "tenant_id": [None, w["t1"], w["t2"]],
            "site_id": [None],
        }
        rows = []
        n = 0
        for g in values["group_id"]:
            for h in values["host_id"]:
                for t in values["tenant_id"]:
                    n += 1
                    rows.append({"id": n, "group_id": g, "host_id": h, "tenant_id": t, "site_id": None})
        conn = await db.get_db()
        try:
            for r in rows:
                await conn.execute(
                    "INSERT INTO scope_probe VALUES (?, ?, ?, ?, ?)",
                    (r["id"], r["group_id"], r["host_id"], r["tenant_id"], r["site_id"]),
                )
            for model in (
                "host",
                "host_record",
                "risk_analysis",
                "ipam_allocation",
                "ipam_prefix",
                "vrf",
                "rack",
                "region",
                "tenant",
                "site",
                "routing_instance",
                "aggregate",
            ):
                spec = object_scope.get_model(model)
                for caller, scope in w["scopes"].items():
                    for write in (False, True):
                        # Map the model's key fields onto the probe columns.
                        probe = [
                            {"probe_id": r["id"], **{fld: r[_probe_column(attr)] for attr, fld in spec.keys.items()}}
                            for r in rows
                        ]
                        expected = [r["probe_id"] for r in await filter_rows(model, probe, scope, write=write)]
                        cond, params = await sql_condition(model, scope, alias="p", write=write)
                        cols = "".join(f", p.{_probe_column(attr)} AS {fld}" for attr, fld in spec.keys.items())
                        where = f" WHERE {cond}" if cond else ""
                        cursor = await conn.execute(
                            f"SELECT probe_id FROM (SELECT p.id AS probe_id{cols} FROM scope_probe p) p{where}"
                            " ORDER BY probe_id",
                            params,
                        )
                        got = [r[0] for r in await cursor.fetchall()]
                        assert got == expected, (model, caller, write)
        finally:
            await conn.close()

    asyncio.run(run())


def _probe_column(attr: str) -> str:
    return {"group": "group_id", "host": "host_id", "tenant": "tenant_id", "site": "site_id"}[attr]


# ── GraphQL ──────────────────────────────────────────────────────────────────


def _gql(query: str, scope) -> dict:
    ctx = GraphQLContext(scope=scope, features=None, max_limit=1000, max_objects=100_000)
    result = asyncio.run(schema.execute(query, context_value=ctx))
    assert result.errors is None, result.errors
    return result.data


def _python_hosts(scope, rows: list[dict], **filters) -> list[dict]:
    """The hosts root list as it was computed before: every host, the scope,
    then each filter in Python."""
    rows = scope.filter_hosts(rows)
    if filters.get("name"):
        rows = [h for h in rows if filters["name"].lower() in (h["hostname"] or "").lower()]
    if filters.get("group_id") is not None:
        rows = [h for h in rows if int(h["group_id"]) == filters["group_id"]]
    if filters.get("device_type"):
        rows = [h for h in rows if (h["device_type"] or "") == filters["device_type"]]
    if filters.get("status"):
        rows = [h for h in rows if (h["status"] or "") == filters["status"]]
    return rows


@pytest.mark.parametrize("caller", CALLERS)
def test_graphql_hosts_page_in_sql_like_the_python_path(caller):
    w = asyncio.run(_world())
    scope = w["scopes"][caller]
    every = asyncio.run(db.get_all_hosts())
    cases = [
        ({}, ""),
        ({"name": "NODE-0"}, 'name: "NODE-0"'),
        ({"group_id": w["a1"]}, f"groupId: {w['a1']}"),
        ({"device_type": "linux"}, 'deviceType: "linux"'),
        ({"status": "up"}, 'status: "up"'),
        ({"name": "node", "device_type": "cisco_ios"}, 'name: "node", deviceType: "cisco_ios"'),
    ]
    for filters, args in cases:
        expected = _python_hosts(scope, every, **filters)
        # Pages of 3, the boundary inside the scoped rows, and past the end.
        for offset in (0, 3, 6, len(expected), len(expected) + 5):
            sep = ", " if args else ""
            data = _gql(f"{{ hosts({args}{sep}limit: 3, offset: {offset}) {{ id }} }}", scope)
            assert [h["id"] for h in data["hosts"]] == [h["id"] for h in expected[offset : offset + 3]], (
                caller,
                filters,
                offset,
            )


def test_graphql_hosts_ip_group_and_tag_filters():
    w = asyncio.run(_world())
    scope = w["scopes"]["subtree"]
    every = scope.filter_hosts(asyncio.run(db.get_all_hosts()))
    data = _gql('{ hosts(ip: "192.0.2.0/28", limit: 100) { id ipAddress } }', scope)
    assert [h["id"] for h in data["hosts"]] == [h["id"] for h in every if int(h["ip_address"].rsplit(".", 1)[1]) < 16]
    data = _gql('{ hosts(group: "grp-a1", limit: 100) { id } }', scope)
    assert [h["id"] for h in data["hosts"]] == [h["id"] for h in every if h["group_id"] == w["a1"]]
    # A group outside the scope matches nothing.
    assert _gql('{ hosts(group: "grp-b", limit: 100) { id } }', scope)["hosts"] == []
    tagged = [w["hosts"][0], w["hosts"][2], w["hosts"][4]]

    async def tag():
        tag_id = int((await db.create_tag(name="core"))["id"])
        for hid in tagged:
            await db.set_object_data("host", str(hid), [tag_id], {})

    asyncio.run(tag())
    data = _gql('{ hosts(tags: ["core"], limit: 100) { id } }', scope)
    assert [h["id"] for h in data["hosts"]] == [h["id"] for h in every if h["id"] in tagged]


def test_graphql_hosts_keep_limit_errors():
    w = asyncio.run(_world())
    ctx = GraphQLContext(scope=w["scopes"]["admin"], features=None, max_limit=5, max_objects=1000)
    result = asyncio.run(schema.execute("{ hosts(limit: 6) { id } }", context_value=ctx))
    assert result.errors and "limit must be between 1 and 5" in result.errors[0].message
    result = asyncio.run(schema.execute('{ hosts(ip: "nope", limit: 6) { id } }', context_value=ctx))
    assert result.errors and "ip must be" in result.errors[0].message


async def _allocations(w: dict) -> None:
    source = await db.create_ipam_source("plexus", "local-a")
    source_id = int(source["id"])
    tenants = [None, w["t1"], w["t2"]]
    vrfs = ["", "BLUE", "RED"]
    for i in range(18):
        await _sql(
            "INSERT INTO ipam_allocations (source_id, prefix_subnet, address, vrf_name, tenant_id) VALUES (?, ?, ?, ?, ?)",
            (source_id, "198.51.100.0/24", f"198.51.100.{40 - i}", vrfs[i % 3], tenants[(i // 3) % 3]),
        )


@pytest.mark.parametrize("caller", CALLERS)
def test_graphql_ip_addresses_page_in_sql_like_the_python_path(caller):
    w = asyncio.run(_world())
    asyncio.run(_allocations(w))
    scope = w["scopes"][caller]
    every = asyncio.run(filter_rows("ipam_allocation", asyncio.run(db.list_ipam_allocation_records()), scope))
    for vrf, args in ((None, ""), ("BLUE", 'vrf: "BLUE", '), ("", 'vrf: " ", '), (None, 'address: "198.51.100.30", ')):
        expected = [r for r in every if vrf is None or r["vrf_name"] == vrf]
        if "address" in args:
            expected = [r for r in expected if r["address"] == "198.51.100.30"]
        for offset in (0, 2, 4, len(expected)):
            data = _gql(f"{{ ipAddresses({args}limit: 2, offset: {offset}) {{ id }} }}", scope)
            assert [r["id"] for r in data["ipAddresses"]] == [r["id"] for r in expected[offset : offset + 2]], (
                caller,
                args,
                offset,
            )


@pytest.mark.parametrize("caller", CALLERS)
def test_graphql_prefix_allocations_loader_is_scoped_in_sql(caller):
    w = asyncio.run(_world())
    asyncio.run(_allocations(w))
    scope = w["scopes"][caller]
    every = asyncio.run(db.list_ipam_allocation_records(prefix_subnets=["198.51.100.0/24"]))
    expected = asyncio.run(filter_rows("ipam_allocation", every, scope))
    got = asyncio.run(
        db.list_ipam_allocation_records(
            prefix_subnets=["198.51.100.0/24"],
            scope_condition=asyncio.run(sql_condition("ipam_allocation", scope, alias="a")),
        )
    )
    assert [r["id"] for r in got] == [r["id"] for r in expected]


@pytest.mark.parametrize("caller", CALLERS)
def test_graphql_host_records_read_the_readable_hosts_past_the_row_cap(caller, monkeypatch):
    w = asyncio.run(_world())

    async def seed():
        for hid in w["hosts"]:
            await _sql("INSERT INTO power_ports (host_id, name) VALUES (?, ?)", (hid, "psu-1"))

    asyncio.run(seed())
    scope = w["scopes"][caller]
    every = asyncio.run(db.list_dcim_records("power_port"))
    expected = asyncio.run(filter_rows("host_record", every, scope))
    # A row cap below the table size: a scoped caller still gets every
    # readable record (read for its hosts), an unrestricted one the cap.
    monkeypatch.setattr(dcim_db, "LIST_MAX", 4)
    data = _gql("{ powerPorts(limit: 100) { id } }", scope)
    if scope.unrestricted:
        assert [r["id"] for r in data["powerPorts"]] == [r["id"] for r in every[:4]]
    else:
        assert [r["id"] for r in data["powerPorts"]] == [r["id"] for r in expected]
        page = _gql("{ powerPorts(limit: 2, offset: 2) { id } }", scope)["powerPorts"]
        assert [r["id"] for r in page] == [r["id"] for r in expected[2:4]]


# ── REST lists converted from filter_rows ───────────────────────────────────


async def _routing(w: dict) -> None:
    asn = await db.create_autonomous_system(asn=64512)
    remote = await db.create_autonomous_system(asn=64513)
    for i, hid in enumerate(w["hosts"]):
        inst = await db.create_routing_instance(
            host_id=hid, values={"name": f"bgp-{i % 2}", "autonomous_system_id": asn["id"]}
        )
        await db.create_bgp_peer_group(routing_instance_id=inst["id"], values={"name": "peers"})
        await db.create_bgp_peering(
            routing_instance_id=inst["id"],
            values={"remote_address": f"203.0.113.{i + 1}", "remote_asn_id": remote["id"]},
        )


async def _graphs(w: dict) -> None:
    template = await db.create_graph_template(name="probe-template")
    template_id = int(template["id"] if isinstance(template, dict) else template)
    for hid in w["hosts"]:
        await db.create_host_graph(hid, template_id, title="cpu")
        await db.create_data_source_profile(hid, profile_name="default")


@pytest.mark.parametrize("caller", CALLERS)
def test_routing_and_graph_lists_scope_in_sql_like_filter_rows(caller):
    w = asyncio.run(_world())
    asyncio.run(_routing(w))
    asyncio.run(_graphs(w))
    scope = w["scopes"][caller]

    async def check():
        ri = await sql_condition("routing_instance", scope, alias="ri")
        for reader in (db.list_routing_instances, db.list_bgp_peer_groups, db.list_bgp_peerings):
            expected = await filter_rows("routing_instance", await reader(), scope)
            assert await reader(scope_condition=ri) == expected, (reader.__name__, caller)
        # Combined with the reader's own filters.
        host = w["hosts"][1]
        expected = await filter_rows("routing_instance", await db.list_bgp_peerings(host_id=host), scope)
        assert await db.list_bgp_peerings(host_id=host, scope_condition=ri) == expected
        hg = await sql_condition("host_record", scope, alias="hg")
        expected = await filter_rows("host_record", await db.list_host_graphs(), scope)
        assert await db.list_host_graphs(scope_condition=hg) == expected
        own = await sql_condition("host_record", scope)
        for host_id in (None, w["hosts"][0], w["hosts"][2]):
            expected = await filter_rows("host_record", await db.list_data_source_profiles(host_id), scope)
            assert await db.list_data_source_profiles(host_id, scope_condition=own) == expected

    asyncio.run(check())


@pytest.mark.parametrize("caller", ("admin", "subtree", "none"))
def test_routing_handlers_answer_the_scoped_rows(caller, monkeypatch):
    w = asyncio.run(_world())
    asyncio.run(_routing(w))
    scope = w["scopes"][caller]

    async def as_scope(_request):
        return scope

    monkeypatch.setattr(object_scope, "request_scope", as_scope)
    monkeypatch.setattr(routing_routes, "request_scope", as_scope)

    async def check():
        request = Request({"type": "http", "method": "GET", "path": "/", "headers": [], "query_string": b""})
        listed = await routing_routes.list_routing_instances(
            request, host_id=None, asn=None, status=None, tenant_id=None, search=None
        )
        expected = await filter_rows("routing_instance", await db.list_routing_instances(), scope)
        assert listed["routing_instances"] == expected
        ases = await routing_routes.list_autonomous_systems(request, tenant_id=None, search=None)
        counts = {a["asn"]: a.get("instance_count") for a in ases["autonomous_systems"]}
        if scope.restricted:
            assert counts[64512] == len(expected)

    asyncio.run(check())


# ── Metrics query bucketing ──────────────────────────────────────────────────


def _stamp(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%d %H:%M:%S")


async def _samples(hosts: list[int], now: datetime, minutes: int) -> list[tuple]:
    rows = []
    for hid in hosts:
        for m in range(minutes):
            rows.append((hid, "cpu_percent", "{}", float((hid * 7 + m * 3) % 97), _stamp(now - timedelta(minutes=m))))
    conn = await db.get_db()
    try:
        await conn.executemany(
            "INSERT INTO metric_samples (host_id, metric_name, labels_json, value, sampled_at) VALUES (?, ?, ?, ?, ?)",
            rows,
        )
        await conn.commit()
    finally:
        await conn.close()
    return rows


def _python_buckets(rows: list[tuple], width: int, start: str) -> dict[tuple[int, str], tuple]:
    out: dict[tuple[int, int], list[float]] = {}
    for hid, _metric, _labels, value, at in rows:
        if at < start:
            continue
        epoch = int(datetime.strptime(at, "%Y-%m-%d %H:%M:%S").replace(tzinfo=UTC).timestamp())
        out.setdefault((hid, epoch // width), []).append(value)
    return {
        (hid, _stamp(datetime.fromtimestamp(b * width, UTC))): (min(v), sum(v) / len(v), max(v), len(v))
        for (hid, b), v in out.items()
    }


def test_bucketed_samples_match_python_buckets():
    w = asyncio.run(_world())
    hosts = w["hosts"][:3]
    now = datetime.now(UTC).replace(microsecond=0)
    rows = asyncio.run(_samples(hosts, now, 180))
    start = _stamp(now - timedelta(hours=2))
    got = asyncio.run(
        db.query_metric_samples("cpu_percent", host_ids=hosts, start=start, limit=10_000, bucket_seconds=600)
    )
    expected = _python_buckets(rows, 600, start)
    assert len(got) == len(expected)
    for row in got:
        lo, avg, hi, n = expected[(row["host_id"], row["sampled_at"])]
        assert row["period_start"] == row["sampled_at"]
        assert (row["val_min"], row["val_max"], row["sample_count"]) == (lo, hi, n)
        assert row["val_avg"] == pytest.approx(avg) and row["value"] == pytest.approx(avg)
    # Newest bucket first, then host.
    keys = [(r["sampled_at"], -r["host_id"]) for r in got]
    assert keys == sorted(keys, reverse=True)


def test_auto_resolution_sizes_buckets_to_range_and_series():
    auto = metrics_engine._auto_resolution
    assert auto(timedelta(hours=1), 1) == ("raw", 60)
    assert auto(timedelta(hours=6), 1) == ("raw", 60)
    assert auto(timedelta(hours=24), 1) == ("raw", 300)
    assert auto(timedelta(days=2), 1) == ("raw", 600)
    assert auto(timedelta(days=7), 1) == ("hourly", 0)
    assert auto(timedelta(days=30), 1) == ("hourly", 0)
    assert auto(timedelta(days=90), 1) == ("daily", 0)
    # Many series: wider buckets, then the coarser rollup.
    assert auto(timedelta(hours=6), 500) == ("raw", 600)
    assert auto(timedelta(days=7), 500) == ("daily", 0)
    for delta in (timedelta(hours=1), timedelta(hours=24), timedelta(days=2)):
        for series in (1, 10, 100, 1000):
            _, width = auto(delta, series)
            assert delta.total_seconds() / width <= metrics_engine._QUERY_TARGET_POINTS


def _query(**kw) -> dict:
    args = {"metric": "cpu_percent", "host": "*", "range": "6h", "step": "auto", "group": None, **kw}
    return asyncio.run(metrics_engine.metrics_query(object(), **args))


def test_metrics_query_auto_buckets_and_raw_stays_raw(monkeypatch):
    w = asyncio.run(_world())
    hosts = w["hosts"][:2]
    now = datetime.now(UTC).replace(microsecond=0)
    asyncio.run(_samples(hosts, now, 120))
    host = ",".join(str(h) for h in hosts)
    auto = _query(host=host, range="6h")
    assert (auto["step"], auto["bucket_seconds"], auto["truncated"]) == ("raw", 60, False)
    assert auto["limit"] == metrics_engine._QUERY_AUTO_CAP
    assert auto["count"] == len(auto["data"]) and all("val_avg" in r and "sample_count" in r for r in auto["data"])
    raw = _query(host=host, range="6h", step="raw")
    assert (raw["step"], raw["bucket_seconds"], raw["truncated"], raw["count"]) == ("raw", 0, False, 240)
    assert raw["limit"] == metrics_engine._QUERY_EXPLICIT_CAP and "id" in raw["data"][0]
    # The cap keeps the newest rows and says so.
    monkeypatch.setattr(metrics_engine, "_QUERY_EXPLICIT_CAP", 50)
    capped = _query(host=host, range="6h", step="raw")
    assert (capped["count"], capped["truncated"], capped["limit"]) == (50, True, 50)
    assert [r["id"] for r in capped["data"]] == [r["id"] for r in raw["data"][:50]]
    monkeypatch.setattr(metrics_engine, "_QUERY_AUTO_CAP", 30)
    monkeypatch.setattr(metrics_engine, "_auto_resolution", lambda delta, series: ("raw", 60))
    small = _query(host=host, range="6h")
    assert small["truncated"] is True and small["count"] == 30
    assert small["data"] == auto["data"][:30]
    # Rollup steps keep their shape.
    hourly = _query(host=host, range="7d", step="hourly")
    assert (hourly["step"], hourly["bucket_seconds"], hourly["count"]) == ("hourly", 0, 0)
