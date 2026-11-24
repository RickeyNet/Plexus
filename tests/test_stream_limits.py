"""Long-lived work is bounded: streams cancel their fan-out when the client
goes, one caller cannot hold more than a few discovery runs or live streams
open, and a discovery request cannot make target expansion do unbounded work.
"""

from __future__ import annotations

import asyncio
import ipaddress
import types

import netcontrol.routes.inventory as inventory
import netcontrol.routes.shared as shared
import netcontrol.routes.topology as topology
import pytest
from fastapi import HTTPException
from netcontrol.routes import background_jobs
from netcontrol.routes.inventory import DiscoveryScanRequest, DiscoverySyncRequest
from pydantic import ValidationError
from starlette.websockets import WebSocket

# ── Fixtures and helpers ─────────────────────────────────────────────────────


@pytest.fixture(autouse=True)
def _fresh_limits(monkeypatch):
    """Empty limiters, and session cookies ``tok-<user_id>`` that verify."""
    shared.DISCOVERY_RUNS.reset()
    shared.LIVE_STREAMS.reset()

    def verify(token):
        if not token or not token.startswith("tok-"):
            return None
        user_id = int(token.removeprefix("tok-"))
        return {"user_id": user_id, "user": f"user{user_id}"}

    monkeypatch.setattr(shared, "_verify_session_token_fn", verify)
    yield
    shared.DISCOVERY_RUNS.reset()
    shared.LIVE_STREAMS.reset()


class _Req:
    """The parts of a Request the routes and the limiter read."""

    def __init__(self, user_id: int | None = 1, *, token: bool = False) -> None:
        self.cookies = {"session": f"tok-{user_id}"} if user_id is not None and not token else {}
        auth = {"auth_mode": "token", "user": "api-token", "user_id": 0} if token else None
        self.state = types.SimpleNamespace(correlation_id="corr-1", auth_session=auth)


class _Hang:
    """A probe that answers at once for ``quick`` addresses and otherwise
    waits forever, counting the waits that were cancelled."""

    def __init__(self, quick: set) -> None:
        self.quick = quick
        self.started = 0
        self.cancelled = 0

    async def __call__(self, key, result):
        if key in self.quick:
            return result
        self.started += 1
        try:
            await asyncio.sleep(3600)
        except asyncio.CancelledError:
            self.cancelled += 1
            raise
        return result


async def _settle() -> None:
    for _ in range(5):
        await asyncio.sleep(0)


def _inventory_stubs(monkeypatch, hang: _Hang) -> None:
    async def group(request, group_id, write=False):
        return {"id": group_id, "name": "lab"}

    async def no_ssh(body, session, **kwargs):
        return None, {}

    async def scan(ip, body, snmp_cfg, semaphore, credential, **_kw):
        return await hang(ip, {"ip_address": ip, "hostname": f"h-{ip}"})

    monkeypatch.setattr(inventory, "require_group", group)
    monkeypatch.setattr(inventory, "_resolve_discovery_ssh", no_ssh)
    monkeypatch.setattr(inventory, "_scan_target", scan)
    monkeypatch.setattr(inventory.state, "_resolve_snmp_discovery_config", lambda _gid: {"enabled": False})


def _scan_body(**values) -> DiscoveryScanRequest:
    return DiscoveryScanRequest(cidrs=["192.0.2.0/29"], use_snmp=False, use_icmp=False, use_ssh=False, **values)


# ── fan_out ──────────────────────────────────────────────────────────────────


async def test_fan_out_cancels_pending_tasks_when_the_consumer_stops_early():
    hang = _Hang(quick={0})
    async with shared.fan_out(hang(i, i) for i in range(5)) as finished:
        for coro in finished:
            assert await coro == 0
            break
    await _settle()
    assert hang.started == 4
    assert hang.cancelled == 4


async def test_fan_out_cancels_pending_tasks_when_the_consumer_fails():
    hang = _Hang(quick=set())

    async def boom():
        raise RuntimeError("probe failed")

    with pytest.raises(RuntimeError):
        async with shared.fan_out([boom(), hang(1, 1), hang(2, 2)]) as finished:
            for coro in finished:
                await coro
    await _settle()
    assert hang.cancelled == 2


# ── Each stream cancels its probes when the client goes ──────────────────────


@pytest.mark.parametrize("route", ["scan", "sync"])
async def test_inventory_discovery_stream_cancels_probes_on_disconnect(monkeypatch, route):
    hang = _Hang(quick={"192.0.2.1"})
    _inventory_stubs(monkeypatch, hang)
    if route == "scan":
        response = await inventory.discovery_scan_stream(1, _scan_body(), _Req())
    else:
        body = DiscoverySyncRequest(cidrs=["192.0.2.0/29"], use_snmp=False, use_icmp=False, use_ssh=False)
        response = await inventory.discovery_sync_stream(1, body, _Req())
    assert shared.DISCOVERY_RUNS.active("user:1") == 1

    events = response.body_iterator
    assert '"type": "start"' in await events.__anext__()
    assert '"ip": "192.0.2.1"' in await events.__anext__()
    await _settle()
    assert hang.started == 5  # the other five hosts of the /29 are still probing
    await events.aclose()  # the client went away
    await _settle()

    assert hang.cancelled == 5
    assert shared.DISCOVERY_RUNS.active() == 0


def _topology_stubs(monkeypatch, hang: _Hang, hosts: list[dict]) -> None:
    async def groups(request):
        return [{"id": 1, "name": "lab"}]

    async def group(group_id):
        return {"id": group_id, "name": "lab"}

    async def group_hosts(group_id):
        return hosts

    async def unrestricted(request):
        return types.SimpleNamespace(restricted=False)

    async def neighbors(host_id, ip, cfg, timeout_seconds=5.0):
        return await hang(host_id, ([], []))

    monkeypatch.setattr(topology, "_discoverable_groups", groups)
    monkeypatch.setattr(topology, "request_scope", unrestricted)
    monkeypatch.setattr(topology.db, "get_group", group)
    monkeypatch.setattr(topology.db, "get_hosts_for_group", group_hosts)
    monkeypatch.setattr(topology, "_snmp_hosts", lambda hs, gid: (hs, {h["id"]: {} for h in hs}))
    monkeypatch.setattr(topology, "_discover_neighbors", neighbors)


@pytest.mark.parametrize("route", ["all", "group"])
async def test_topology_discovery_stream_cancels_walks_on_disconnect(monkeypatch, route):
    hosts = [{"id": i, "hostname": f"sw{i}", "ip_address": f"198.51.100.{i}"} for i in range(1, 6)]
    hang = _Hang(quick={1})
    _topology_stubs(monkeypatch, hang, hosts)
    if route == "all":
        response = await topology.discover_topology_stream(_Req())
    else:
        response = await topology.discover_topology_for_group_stream(1, _Req())
    assert shared.DISCOVERY_RUNS.active("user:1") == 1

    events = response.body_iterator
    assert '"type": "start"' in await events.__anext__()
    assert '"type": "group_start"' in await events.__anext__()
    assert '"type": "host_walked"' in await events.__anext__()
    await _settle()
    assert hang.started == 4
    await events.aclose()
    await _settle()

    assert hang.cancelled == 4
    assert shared.DISCOVERY_RUNS.active() == 0


async def test_slot_response_releases_and_cancels_when_the_client_disconnects():
    """Through Starlette itself: the client disconnects mid-stream."""
    hang = _Hang(quick={0})

    async def events():
        async with shared.fan_out(hang(i, i) for i in range(4)) as finished:
            for coro in finished:
                yield f"data: {await coro}\n\n"

    slot = shared.DISCOVERY_RUNS.claim(_Req(3))
    response = slot.stream(events())
    sent: list[dict] = []
    first_body = asyncio.Event()

    async def send(message):
        sent.append(message)
        if message.get("body"):
            first_body.set()

    async def receive():
        await first_body.wait()
        return {"type": "http.disconnect"}

    await response({"type": "http", "asgi": {"spec_version": "2.0"}}, receive, send)
    await _settle()
    assert hang.cancelled == 3
    assert not slot.held
    assert shared.DISCOVERY_RUNS.active() == 0


# ── The limiter ──────────────────────────────────────────────────────────────


async def test_limiter_refuses_the_next_stream_of_one_user_only(monkeypatch):
    hang = _Hang(quick=set())
    _inventory_stubs(monkeypatch, hang)
    per_user = shared.DISCOVERY_RUNS.per_identity

    streams = [await inventory.discovery_scan_stream(1, _scan_body(), _Req(1)) for _ in range(per_user)]
    with pytest.raises(HTTPException) as refused:
        await inventory.discovery_scan_stream(1, _scan_body(), _Req(1))
    assert refused.value.status_code == 429
    assert "already have" in refused.value.detail

    # Another user, and the API token, are counted on their own.
    other = await inventory.discovery_scan_stream(1, _scan_body(), _Req(2))
    token = await inventory.discovery_scan_stream(1, _scan_body(), _Req(token=True))
    assert shared.DISCOVERY_RUNS.active("user:2") == 1
    assert shared.DISCOVERY_RUNS.active("api-token") == 1

    # Finishing one stream normally frees its slot.
    finished = streams.pop()
    hang.quick.update(f"192.0.2.{i}" for i in range(1, 7))
    chunks = [chunk async for chunk in finished.body_iterator]
    assert '"type": "done"' in chunks[-1]
    assert shared.DISCOVERY_RUNS.active("user:1") == per_user - 1
    replacement = await inventory.discovery_scan_stream(1, _scan_body(), _Req(1))

    # A stream that is cancelled frees its slot too.
    pending = asyncio.ensure_future(replacement.body_iterator.__anext__())
    await _settle()
    pending.cancel()
    await asyncio.gather(pending, return_exceptions=True)
    await replacement.body_iterator.aclose()
    assert shared.DISCOVERY_RUNS.active("user:1") == per_user - 1

    for response in [*streams, other, token]:
        await response.body_iterator.aclose()
    assert shared.DISCOVERY_RUNS.active() == 0


async def test_limiter_global_ceiling_and_token_identity(monkeypatch):
    limit = shared.ActiveLimit("test runs", per_identity=2, total=3)
    a1 = limit.claim(_Req(1))
    a2 = limit.claim(_Req(1))
    t1 = limit.claim(_Req(token=True))
    assert limit.active("api-token") == 1
    with pytest.raises(HTTPException) as full:
        limit.claim(_Req(2))
    assert full.value.status_code == 429
    assert "server" in full.value.detail
    a1.release()
    a1.release()  # idempotent
    b1 = limit.claim(_Req(2))
    for slot in (a2, t1, b1):
        slot.release()
    assert limit.active() == 0


async def test_handler_failure_releases_the_slot(monkeypatch):
    hang = _Hang(quick=set())
    _inventory_stubs(monkeypatch, hang)
    body = DiscoveryScanRequest(cidrs=["not-an-address"], use_snmp=False, use_icmp=False, use_ssh=False)
    with pytest.raises((HTTPException, ValueError)):
        await inventory.discovery_scan_stream(1, body, _Req(1))
    assert shared.DISCOVERY_RUNS.active() == 0


async def test_background_discovery_job_holds_a_slot_until_it_ends(monkeypatch):
    hang = _Hang(quick=set())
    _inventory_stubs(monkeypatch, hang)
    per_user = shared.DISCOVERY_RUNS.per_identity
    jobs: list[asyncio.Task] = []
    monkeypatch.setattr(inventory, "supervise_task", lambda task, label: jobs.append(task))

    launched = [await inventory.discovery_scan(1, _scan_body(), _Req(5)) for _ in range(per_user)]
    with pytest.raises(HTTPException) as refused:
        await inventory.discovery_scan(1, _scan_body(), _Req(5))
    assert refused.value.status_code == 429

    await _settle()
    assert hang.started == 6 * per_user  # every job is probing its /29
    for job in launched:
        assert background_jobs.get_job(job["job_id"]) is not None

    # The jobs end (here: cancelled, as at shutdown): each gives its slot
    # back and cancels the probes it still had running.
    assert len(jobs) == per_user
    for task in jobs:
        task.cancel()
    await _settle()
    assert shared.DISCOVERY_RUNS.active("user:5") == 0
    assert hang.cancelled == hang.started


async def test_utilization_stream_takes_a_live_slot(monkeypatch):
    async def no_scope(request, group_id):
        return None

    async def no_links(group_id):
        return [], {}

    monkeypatch.setattr(topology, "_visible_links", no_scope)
    monkeypatch.setattr(topology, "_get_util_map_and_links", no_links)
    response = await topology.stream_topology_utilization(None, 30, _Req(4))
    assert shared.LIVE_STREAMS.active("user:4") == 1
    assert '"edges"' in await response.body_iterator.__anext__()
    await response.body_iterator.aclose()
    assert shared.LIVE_STREAMS.active() == 0


async def test_websocket_limit_closes_the_extra_socket_with_1013(monkeypatch):
    limit = shared.ActiveLimit("live streams", per_identity=1, total=10)
    release = asyncio.Event()
    handled: list[int] = []

    @shared.limit_websocket(limit)
    async def handler(websocket: WebSocket, job_id: int):
        handled.append(job_id)
        await release.wait()

    def socket(user_id: int | None) -> tuple[WebSocket, list[dict]]:
        sent: list[dict] = []
        headers = [(b"cookie", f"session=tok-{user_id}".encode())] if user_id is not None else []

        async def receive():
            return {"type": "websocket.connect"}

        async def send(message):
            sent.append(message)

        scope = {"type": "websocket", "path": "/ws/jobs/1", "headers": headers, "query_string": b""}
        return WebSocket(scope, receive, send), sent

    first_ws, _ = socket(1)
    first = asyncio.ensure_future(handler(websocket=first_ws, job_id=1))
    await _settle()
    assert limit.active("user:1") == 1

    second_ws, second_sent = socket(1)
    await handler(websocket=second_ws, job_id=2)
    assert second_sent == [{"type": "websocket.close", "code": 1013, "reason": "Too many live streams open"}]
    assert handled == [1]

    # Another user, and a handshake with no session (the handler refuses it), pass.
    other_ws, _ = socket(2)
    other = asyncio.ensure_future(handler(websocket=other_ws, job_id=3))
    anon_ws, _ = socket(None)
    anon = asyncio.ensure_future(handler(websocket=anon_ws, job_id=4))
    await _settle()
    assert handled == [1, 3, 4]
    assert limit.active() == 2

    # Ended normally or cancelled, the socket gives its slot back.
    first.cancel()
    await asyncio.gather(first, return_exceptions=True)
    assert limit.active("user:1") == 0
    release.set()
    await asyncio.gather(other, anon)
    assert limit.active() == 0


# ── Target expansion is bounded ──────────────────────────────────────────────


def _count_walked(monkeypatch) -> dict:
    counts = {"calls": 0, "addresses": 0}
    for cls in (ipaddress.IPv4Network, ipaddress.IPv6Network):
        original = cls.hosts

        def counting(self, _original=original):
            counts["calls"] += 1
            for host in _original(self):
                counts["addresses"] += 1
                yield host

        monkeypatch.setattr(cls, "hosts", counting)
    return counts


def test_cidr_list_length_is_capped():
    DiscoveryScanRequest(cidrs=["192.0.2.1/32"] * inventory.DISCOVERY_MAX_CIDRS)
    with pytest.raises(ValidationError):
        DiscoveryScanRequest(cidrs=["192.0.2.1/32"] * (inventory.DISCOVERY_MAX_CIDRS + 1))
    with pytest.raises(ValidationError):
        DiscoverySyncRequest(cidrs=["192.0.2.1/32"] * (inventory.DISCOVERY_MAX_CIDRS + 1))


def test_repeated_cidr_is_expanded_once(monkeypatch):
    counts = _count_walked(monkeypatch)
    targets = inventory._expand_scan_targets(["198.51.100.0/24"] * inventory.DISCOVERY_MAX_CIDRS, 4096)
    assert len(targets) == 254
    assert counts == {"calls": 1, "addresses": 254}


def _overlapping_cidrs() -> list[str]:
    """2001:db8::/118 and every smaller subnet of it down to /128: 2047
    distinct, heavily overlapping entries over 1024 distinct addresses."""
    base = ipaddress.ip_network("2001:db8::/118")
    cidrs = [str(base)]
    for prefix in range(119, 129):
        cidrs.extend(str(net) for net in base.subnets(new_prefix=prefix))
    return cidrs


def test_overlapping_cidrs_walk_a_bounded_number_of_addresses(monkeypatch):
    cidrs = _overlapping_cidrs()
    assert len(cidrs) <= inventory.DISCOVERY_MAX_CIDRS
    counts = _count_walked(monkeypatch)
    targets = inventory._expand_scan_targets(cidrs, 4096)
    assert len(targets) == 1024
    assert counts["addresses"] <= inventory.DISCOVERY_MAX_EXPANDED_ADDRESSES


def test_overlap_past_the_budget_is_refused_without_walking_further(monkeypatch):
    monkeypatch.setattr(inventory, "DISCOVERY_MAX_EXPANDED_ADDRESSES", 1000)
    counts = _count_walked(monkeypatch)
    # max_hosts 1050: budget max(10500, 1000); the overlaps need more.
    with pytest.raises(ValueError, match="overlaps itself"):
        inventory._expand_scan_targets(_overlapping_cidrs(), 1050)
    # It stops at the first address past the budget.
    assert counts["addresses"] <= 10501


async def test_scan_routes_answer_400_for_an_overlap_heavy_list(monkeypatch):
    monkeypatch.setattr(inventory, "DISCOVERY_MAX_EXPANDED_ADDRESSES", 1000)
    hang = _Hang(quick=set())
    _inventory_stubs(monkeypatch, hang)
    body = DiscoveryScanRequest(cidrs=_overlapping_cidrs(), max_hosts=1050, use_snmp=False, use_icmp=False)
    for call in (
        lambda: inventory.discovery_scan(1, body, _Req(1)),
        lambda: inventory.discovery_scan_stream(1, body, _Req(1)),
    ):
        with pytest.raises(HTTPException) as refused:
            await call()
        assert refused.value.status_code == 400
    assert shared.DISCOVERY_RUNS.active() == 0
    assert hang.started == 0
