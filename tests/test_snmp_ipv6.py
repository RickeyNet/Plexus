"""SNMP over IPv6: the one transport helper every SNMP request uses
(``snmp.snmp_transport_target``), the listener's address normalization
(``listener_sources.canonical_address``: IPv4-mapped sources, IPv6
spellings) and the trap receiver's IPv6 socket.

Addresses are from the documentation ranges (``192.0.2.0/24``,
``2001:db8::/32``) and loopback.
"""

from __future__ import annotations

import asyncio
import socket

import netcontrol.routes.metrics_engine as me
import pytest
import routes.database as db
from netcontrol import listener_sources as ls
from netcontrol.routes import snmp as snmp_module


class _Fake:
    def __init__(self, name: str, created: list) -> None:
        self.name, self.created = name, created

    async def create(self, address, **kwargs):
        self.created.append((self.name, address, kwargs["timeout"], kwargs["retries"]))
        return self.name


@pytest.fixture
def transports(monkeypatch):
    created: list[tuple] = []
    monkeypatch.setattr(snmp_module, "UdpTransportTarget", _Fake("udp", created))
    monkeypatch.setattr(snmp_module, "Udp6TransportTarget", _Fake("udp6", created))
    return created


# ── The transport helper ─────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("address", "kind", "target"),
    [
        ("192.0.2.5", "udp", "192.0.2.5"),
        (" 192.0.2.5 ", "udp", "192.0.2.5"),
        ("edge-sw-01.example.com", "udp", "edge-sw-01.example.com"),  # a name resolves over IPv4, as before
        ("2001:db8::5", "udp6", "2001:db8::5"),
        ("2001:DB8:0:0::5", "udp6", "2001:db8::5"),
        ("::ffff:192.0.2.5", "udp", "192.0.2.5"),
    ],
)
async def test_the_transport_follows_the_address_family(transports, address, kind, target):
    assert await snmp_module.snmp_transport_target(address, 1161, 2.5, 3) == kind
    assert transports == [(kind, (target, 1161), 2.5, 3)]


async def test_a_scoped_address_is_refused(transports):
    with pytest.raises(ValueError, match="scoped"):
        await snmp_module.snmp_transport_target("fe80::1%3", 161, 1, 0)
    assert transports == []


async def test_without_pysnmp_ipv6_cannot_be_polled(monkeypatch):
    monkeypatch.setattr(snmp_module, "Udp6TransportTarget", None)
    with pytest.raises(RuntimeError):
        await snmp_module.snmp_transport_target("2001:db8::5", 161, 1, 0)


async def test_the_real_pysnmp_ipv6_target():
    from pysnmp.hlapi.v3arch.asyncio import Udp6TransportTarget

    target = await snmp_module.snmp_transport_target("2001:db8::7", 161, 2, 1)
    assert isinstance(target, Udp6TransportTarget)
    assert target.transport_address[:2] == ("2001:db8::7", 161)
    assert (target.timeout, target.retries) == (2, 1)


async def test_every_request_builds_its_transport_with_the_helper(monkeypatch, transports):
    """GET, walk and the multi-OID GET: an IPv6 host gets an IPv6 transport."""

    class _Engine:
        def close_dispatcher(self):
            pass

    async def get_cmd(_engine, _auth, transport, _context, *oids):
        return None, 0, 0, [(oid, "value") for oid in oids]

    async def walker(*_args, **_kwargs):
        yield None, 0, 0, [("1.3.6.1.2.1.1.1.0", "value")]

    monkeypatch.setattr(snmp_module, "PYSMNP_AVAILABLE", True)
    monkeypatch.setattr(snmp_module, "SnmpEngine", _Engine)
    monkeypatch.setattr(snmp_module, "ObjectIdentity", lambda oid: oid)
    monkeypatch.setattr(snmp_module, "ObjectType", lambda identity: identity)
    monkeypatch.setattr(snmp_module, "get_cmd", get_cmd)
    monkeypatch.setattr(snmp_module, "bulk_walk_cmd", walker)
    cfg = {"enabled": True, "version": "2c", "community": "example"}
    await snmp_module._snmp_get("2001:db8::10", 1.0, cfg)
    await snmp_module._snmp_walk("2001:db8::11", 1.0, cfg, "1.3.6.1.2.1.1")
    await snmp_module._snmp_get_values("2001:db8::12", 1.0, cfg, ("1.3.6.1.2.1.1.5.0",))
    assert [(kind, address[0]) for kind, address, *_ in transports] == [
        ("udp6", "2001:db8::10"),
        ("udp6", "2001:db8::11"),
        ("udp6", "2001:db8::12"),
    ]


# ── Source addresses ─────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("given", "canonical"),
    [
        ("192.0.2.9", "192.0.2.9"),
        ("::ffff:192.0.2.9", "192.0.2.9"),
        ("::FFFF:192.0.2.9", "192.0.2.9"),
        ("0:0:0:0:0:ffff:c000:209", "192.0.2.9"),
        ("2001:DB8:0000::9", "2001:db8::9"),
        ("fe80::1%eth0", "fe80::1%eth0"),
        ("not an address", "not an address"),
        ("bad::address::", "bad::address::"),
        ("", ""),
    ],
)
def test_canonical_address(given, canonical):
    assert ls.canonical_address(given) == canonical


async def test_the_inventory_set_is_keyed_canonically(monkeypatch):
    async def fake_map(hostnames=None):
        if hostnames is not None:
            hostnames[7] = "edge-rtr-01"
        return {"2001:DB8::0042": 7, "192.0.2.42": 8}

    monkeypatch.setattr(db, "get_exporter_host_map", fake_map)
    monkeypatch.setattr(ls, "INVENTORY_ADDRESSES", {})
    monkeypatch.setattr(ls, "INVENTORY_HOSTNAMES", {})
    assert await ls.refresh_inventory() == 2
    assert ls.inventory_host_id("2001:db8::42") == 7
    assert ls.inventory_host_id("::ffff:192.0.2.42") == 8
    assert ls.source_allowed("2001:db8::42")


async def test_an_ipv6_host_written_in_another_spelling_is_found(monkeypatch):
    await db.init_db()
    group_id = await db.create_group("grp-v6")
    host_id = await db.add_host(group_id, "edge-rtr-02", "2001:DB8::0043", "cisco_ios")
    me._host_ip_cache.clear()
    monkeypatch.setitem(ls.INVENTORY_ADDRESSES, "2001:db8::43", host_id)
    assert await me._resolve_host_id_cached("2001:db8::43") == host_id
    me._host_ip_cache.clear()


# ── The trap receiver on IPv6 ────────────────────────────────────────────────


def _ipv6_loopback() -> bool:
    if not socket.has_ipv6:
        return False
    try:
        with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as sock:
            sock.bind(("::1", 0))
    except OSError:
        return False
    return True


@pytest.fixture
def loopback_trap_receiver(monkeypatch):
    import netcontrol.snmpv3_engine as se

    monkeypatch.setattr(me, "_RECEIVER_BIND_HOST", "127.0.0.1")
    monkeypatch.setitem(ls.CONFIG, "policy", "any")
    se.reset()
    yield
    # The receiver's event loop (the test's) is closed by now.
    for transports in (me._receiver_transports, me._receiver_transports6):
        transport = transports.get("trap")
        transports["trap"] = None
        if transport is not None:
            try:
                transport.close()
            except RuntimeError:
                pass
    me._receiver_ports["trap"] = 0
    se.reset()


async def test_the_trap_receiver_listens_on_ipv6_too(loopback_trap_receiver):
    if not _ipv6_loopback():
        pytest.skip("no IPv6 loopback on this machine")
    await db.init_db()
    assert await me._start_receiver("trap", 0)
    port = me._receiver_transports["trap"].get_extra_info("sockname")[1]
    assert me._receiver_transports6["trap"] is not None
    snapshot = me.event_receiver_snapshot()
    assert snapshot["trap_ipv6_listening"] is True and snapshot["trap_engine_boots"] >= 1
    received = me._RECEIVER_STATS["trap"].received
    with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as sock:
        sock.sendto(b"\x30\x00", ("::1", port))
    for _ in range(150):
        if me._RECEIVER_STATS["trap"].received > received:
            break
        await asyncio.sleep(0.02)
    assert me._RECEIVER_STATS["trap"].received == received + 1
    me._trap_event_buffer.clear()
    assert me._stop_receiver("trap") and me._receiver_transports6["trap"] is None


async def test_a_failed_ipv6_bind_keeps_ipv4(loopback_trap_receiver, monkeypatch, caplog):
    await db.init_db()
    monkeypatch.setattr(me, "_IPV6_BIND_HOSTS", {"127.0.0.1": "2001:db8::dead"})  # not a local address
    assert await me._start_receiver("trap", 0)
    assert me._receiver_transports["trap"] is not None and me._receiver_transports6["trap"] is None
    assert "not listening on IPv6" in caplog.text
    assert me.event_receiver_snapshot()["trap_ipv6_listening"] is False


async def test_another_bind_host_gets_no_ipv6_socket(loopback_trap_receiver, monkeypatch):
    monkeypatch.setattr(me, "_IPV6_BIND_HOSTS", {})
    assert not await me._start_receiver6("trap", 0)


def test_answers_go_out_through_the_socket_of_their_family(monkeypatch):
    sent: list[tuple] = []

    class _Transport:
        def __init__(self, name):
            self.name = name

        def sendto(self, data, addr):
            sent.append((self.name, addr))
            if addr[0] == "192.0.2.99":
                raise OSError("unreachable")

    monkeypatch.setitem(me._receiver_transports, "trap", _Transport("v4"))
    monkeypatch.setitem(me._receiver_transports6, "trap", _Transport("v6"))
    me._send_reply(b"x", ("192.0.2.98", 162))
    me._send_reply(b"x", ("2001:db8::98", 162, 0, 0))
    me._send_reply(b"x", ("192.0.2.99", 162))  # a failed send is not raised
    monkeypatch.setitem(me._receiver_transports6, "trap", None)
    me._send_reply(b"x", ("2001:db8::98", 162, 0, 0))  # no IPv6 socket: nothing sent
    assert sent == [("v4", ("192.0.2.98", 162)), ("v6", ("2001:db8::98", 162, 0, 0)), ("v4", ("192.0.2.99", 162))]
