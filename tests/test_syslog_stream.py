"""Syslog over TCP and TLS: RFC 6587 framing, the listener limits, the
source allowlist and rate limit per message, TLS and mutual TLS on
loopback, the lifecycle through the receiver settings, the transport
stored per message, the switch that stops acting on UDP syslog, and the
certificate API.

Every listener binds a free port on loopback; certificates are generated
here; addresses and names are invented.
"""

from __future__ import annotations

import asyncio
import datetime as dt
import ipaddress
import json
import socket
import ssl

import netcontrol.routes.metrics_engine as me
import netcontrol.routes.state as state
import pytest
import routes.database as db
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from netcontrol import listener_sources as ls, syslog_activity, syslog_rules as sr, syslog_stream, syslog_tls, tls_pem
from netcontrol.syslog_stream import FrameDecoder, FramingError, StreamListener

from mcp_helpers import admin_client, user_client
from test_event_receivers_config import _cfg, _wait_for
from test_syslog_activity import _sql, restore  # noqa: F401 - restore is a fixture
from test_syslog_rules import DOWN, _host, _open, engine  # noqa: F401 - engine is a fixture

CONFIG = "/api/admin/metrics/receivers/config"
TLS = "/api/admin/metrics/receivers/tls"
SERVER_NAME = "syslog.example.com"
CHANGE = "%SYS-5-CONFIG_I: Configured from console by ops on vty0 (192.0.2.50)"


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    """Loopback listeners, every source admitted without a rate limit, no
    inventory refresh, default receiver settings and no TLS material."""
    monkeypatch.setattr(me, "_RECEIVER_BIND_HOST", "127.0.0.1")
    monkeypatch.setattr(ls, "_inventory_loaded_at", float("inf"))

    async def no_refresh() -> int:
        return len(ls.INVENTORY_ADDRESSES)

    monkeypatch.setattr(ls, "refresh_inventory", no_refresh)
    ls.apply_config(ls.sanitize_config({"policy": "any", "syslog_rate_limit": 0}))
    for guard in ls.GUARDS.values():
        guard.reset()
    state.EVENT_RECEIVER_CONFIG.update(state.EVENT_RECEIVER_DEFAULTS)
    syslog_tls.apply(None)
    me._trap_event_buffer.clear()
    yield
    me.stop_receivers()
    me._trap_event_buffer.clear()
    state.EVENT_RECEIVER_CONFIG.update(state.EVENT_RECEIVER_DEFAULTS)
    syslog_tls.apply(None)
    ls.apply_config(ls.sanitize_config(None))
    for guard in ls.GUARDS.values():
        guard.reset()


@pytest.fixture
async def stream_receivers():
    """Stops the receivers a test started through the settings, in the
    test's own event loop."""
    yield
    me.stop_receivers()
    await asyncio.sleep(0)


def _free_tcp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _frames(*chunks: bytes) -> list[bytes]:
    decoder = FrameDecoder()
    out: list[bytes] = []
    for chunk in chunks:
        out.extend(decoder.feed(chunk))
    return out


# ── Framing ──────────────────────────────────────────────────────────────────


def test_non_transparent_frames_end_at_lf_crlf_or_nul():
    assert _frames(b"<13>one\n<13>two\r\n<13>three\x00<13>four") == [b"<13>one", b"<13>two", b"<13>three"]


def test_octet_counted_frames():
    first, second = b"<13>first message", b"<14>second\nwith a newline"
    stream = b"%d %s%d %s" % (len(first), first, len(second), second)
    assert _frames(stream) == [first, second]


def test_both_framings_mixed_in_one_stream():
    counted = b"<13>counted"
    stream = b"<13>line one\n%d %s<13>line two\r\n\n" % (len(counted), counted)
    assert _frames(stream) == [b"<13>line one", counted, b"<13>line two"]


def test_frames_split_across_segments():
    counted = b"<13>counted across segments"
    stream = b"<13>a line split up\r\n%d %s<13>tail\x00" % (len(counted), counted)
    one_byte_at_a_time = [stream[i : i + 1] for i in range(len(stream))]
    assert _frames(*one_byte_at_a_time) == [b"<13>a line split up", counted, b"<13>tail"]


def test_an_incomplete_frame_waits_for_more():
    decoder = FrameDecoder()
    counted = b"<13>partial octet counted"
    head = b"%d " % len(counted)
    assert list(decoder.feed(head + counted[:10])) == []
    assert list(decoder.feed(counted[10:] + b"<13>no end yet")) == [counted]
    assert list(decoder.feed(b" still")) == []
    assert list(decoder.feed(b" none\n")) == [b"<13>no end yet still none"]


@pytest.mark.parametrize(
    "stream",
    [
        b"%d <13>x" % (syslog_stream.MAX_FRAME_BYTES + 1),  # over the limit
        b"0 <13>x",  # zero length
        b"12x <13>bad count",  # not a number
        b"123456789",  # longer than any allowed count, no space
    ],
)
def test_a_bad_octet_count_is_a_framing_error(stream):
    with pytest.raises(FramingError):
        _frames(stream)


def test_an_over_long_line_is_a_framing_error():
    with pytest.raises(FramingError):
        _frames(b"<13>" + b"x" * syslog_stream.MAX_FRAME_BYTES)
    with pytest.raises(FramingError):
        _frames(b"<13>" + b"x" * syslog_stream.MAX_FRAME_BYTES + b"\n")


def test_frames_before_an_error_are_delivered():
    decoder = FrameDecoder()
    got: list[bytes] = []
    with pytest.raises(FramingError):
        for frame in decoder.feed(b"<13>good\n0 bad"):
            got.append(frame)
    assert got == [b"<13>good"]


# ── Listener over TCP ────────────────────────────────────────────────────────


class _Recorder:
    def __init__(self) -> None:
        self.frames: list[tuple[bytes, str]] = []
        self.fail = False

    def __call__(self, frame: bytes, source_ip: str) -> None:
        if self.fail:
            raise ValueError("unparseable")
        self.frames.append((frame, source_ip))


async def _listener(transport: str = "tcp", context: ssl.SSLContext | None = None) -> tuple[StreamListener, _Recorder]:
    recorder = _Recorder()
    listener = StreamListener(transport, recorder, me._ReceiverStats())
    assert await listener.start("127.0.0.1", _free_tcp_port(), context)
    return listener, recorder


async def _closed_by_server(reader: asyncio.StreamReader) -> bool:
    try:
        return await asyncio.wait_for(reader.read(), timeout=3) == b""
    except ConnectionError, ssl.SSLError:
        return True


async def test_tcp_messages_arrive_in_any_framing_and_segmentation():
    listener, recorder = await _listener()
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", listener.port)
        counted = b"<13>octet counted"
        for chunk in (b"<13>first li", b"ne\n%d %s" % (len(counted), counted), b"<13>third\r\n"):
            writer.write(chunk)
            await writer.drain()
            await asyncio.sleep(0.02)
        assert await _wait_for(lambda: len(recorder.frames) == 3)
        assert [f for f, _ in recorder.frames] == [b"<13>first line", counted, b"<13>third"]
        assert {ip for _, ip in recorder.frames} == {"127.0.0.1"}
        assert listener.stats.received == 3 and listener.stats.last_message_at > 0
        assert listener.connections == 1
        writer.close()
        assert await _wait_for(lambda: listener.connections == 0)
    finally:
        listener.stop()


async def test_a_framing_error_closes_the_connection_and_counts_an_error():
    listener, recorder = await _listener()
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", listener.port)
        writer.write(b"<13>kept\n99999 too long")
        await writer.drain()
        assert await _closed_by_server(reader)
        assert await _wait_for(lambda: listener.stats.errors == 1)
        assert [f for f, _ in recorder.frames] == [b"<13>kept"]
        writer.close()
    finally:
        listener.stop()


async def test_a_handler_error_is_counted_and_the_connection_stays():
    listener, recorder = await _listener()
    try:
        _reader, writer = await asyncio.open_connection("127.0.0.1", listener.port)
        recorder.fail = True
        writer.write(b"<13>breaks the parser\n")
        await writer.drain()
        assert await _wait_for(lambda: listener.stats.errors == 1)
        recorder.fail = False
        writer.write(b"<13>parsed\n")
        await writer.drain()
        assert await _wait_for(lambda: len(recorder.frames) == 1)
        assert listener.stats.received == 2
        writer.close()
    finally:
        listener.stop()


async def test_a_refused_source_is_closed_at_accept_and_counted():
    ls.apply_config(ls.sanitize_config(None))  # inventory only: loopback is no host
    listener, recorder = await _listener()
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", listener.port)
        writer.write(b"<13>from a stranger\n")
        assert await _closed_by_server(reader)
        assert await _wait_for(lambda: listener.refused == 1)
        assert ls.guard("syslog").stats()["dropped_source"] == 1
        assert recorder.frames == [] and listener.stats.received == 0
        writer.close()

        # Loopback admitted as an extra network: accepted.
        ls.apply_config(ls.sanitize_config({"extra_cidrs": ["127.0.0.0/8"]}))
        _reader, writer = await asyncio.open_connection("127.0.0.1", listener.port)
        writer.write(b"<13>now allowed\n")
        await writer.drain()
        assert await _wait_for(lambda: len(recorder.frames) == 1)
        writer.close()
    finally:
        listener.stop()


async def test_each_message_passes_the_rate_limit():
    ls.apply_config(ls.sanitize_config({"policy": "any", "syslog_rate_limit": 1}))  # a burst of 2
    listener, recorder = await _listener()
    try:
        _reader, writer = await asyncio.open_connection("127.0.0.1", listener.port)
        writer.write(b"".join(b"<13>message %d\n" % i for i in range(5)))
        await writer.drain()
        assert await _wait_for(lambda: ls.guard("syslog").stats()["dropped_rate"] == 3)
        assert len(recorder.frames) == 2 and listener.stats.received == 2
        assert listener.refused == 0
        writer.close()
    finally:
        listener.stop()


async def test_connections_are_capped_per_source_and_in_total(monkeypatch):
    monkeypatch.setattr(syslog_stream, "MAX_CONNECTIONS_PER_SOURCE", 2)
    listener, _recorder = await _listener()
    writers = []
    try:
        for _ in range(2):
            writers.append((await asyncio.open_connection("127.0.0.1", listener.port))[1])
        assert await _wait_for(lambda: listener.connections == 2)
        reader, writer = await asyncio.open_connection("127.0.0.1", listener.port)
        writers.append(writer)
        assert await _closed_by_server(reader)
        assert listener.refused == 1 and listener.connections == 2

        monkeypatch.setattr(syslog_stream, "MAX_CONNECTIONS_PER_SOURCE", 8)
        monkeypatch.setattr(syslog_stream, "MAX_CONNECTIONS", 2)
        reader, writer = await asyncio.open_connection("127.0.0.1", listener.port)
        writers.append(writer)
        assert await _closed_by_server(reader)
        assert listener.refused == 2
    finally:
        for w in writers:
            w.close()
        listener.stop()


async def test_stop_closes_the_open_connections():
    listener, _recorder = await _listener()
    reader, writer = await asyncio.open_connection("127.0.0.1", listener.port)
    assert await _wait_for(lambda: listener.connections == 1)
    assert listener.stop() is True
    assert listener.stop() is False
    assert await _closed_by_server(reader)
    assert listener.connections == 0 and not listener.running
    writer.close()


async def test_a_port_that_will_not_bind_is_reported():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as busy:
        busy.bind(("127.0.0.1", 0))
        busy.listen()
        port = busy.getsockname()[1]
        listener = StreamListener("tcp", _Recorder(), me._ReceiverStats())
        if await listener.start("127.0.0.1", port):  # pragma: no cover - a platform that shares the port
            listener.stop()
            pytest.skip("this platform lets two sockets listen on one port")
        assert listener.error.startswith(f"Could not listen on TCP port {port}")
        assert not listener.running


# ── TLS ──────────────────────────────────────────────────────────────────────


def _store_generated_certificate() -> str:
    cert_pem, key_pem = syslog_tls.generate_self_signed(SERVER_NAME, [SERVER_NAME, "127.0.0.1"], 30)
    syslog_tls.apply({"cert_pem": cert_pem, "key_pem": key_pem})
    return cert_pem


def _ca() -> tuple[ec.EllipticCurvePrivateKey, x509.Certificate]:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Example Device CA")])
    now = dt.datetime.now(dt.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    return key, cert


def _client_pem(
    ca_key, ca_cert, name: str = "edge-r1.example.com", sans: list[x509.GeneralName] | None = None
) -> tuple[str, str]:
    key = ec.generate_private_key(ec.SECP256R1())
    now = dt.datetime.now(dt.UTC)
    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)]))
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=30))
    )
    if sans:
        builder = builder.add_extension(x509.SubjectAlternativeName(sans), critical=False)
    cert = builder.sign(ca_key, hashes.SHA256())
    key_pem = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    ).decode()
    return cert.public_bytes(serialization.Encoding.PEM).decode(), key_pem


def _client_context(server_cert_pem: str, cert_pem: str = "", key_pem: str = "") -> ssl.SSLContext:
    ctx = ssl.create_default_context(cadata=server_cert_pem)
    if cert_pem:
        tls_pem.load_cert_chain_pem(ctx, cert_pem, key_pem)
    return ctx


async def _tls_connect(port: int, ctx: ssl.SSLContext):
    return await asyncio.open_connection("127.0.0.1", port, ssl=ctx, server_hostname=SERVER_NAME)


async def test_a_tls_round_trip_with_a_generated_certificate():
    server_cert = _store_generated_certificate()
    listener, recorder = await _listener("tls", syslog_tls.server_context(False))
    try:
        _reader, writer = await _tls_connect(listener.port, _client_context(server_cert))
        message = b"<13>over tls"
        writer.write(b"%d %s" % (len(message), message))
        await writer.drain()
        assert await _wait_for(lambda: recorder.frames == [(message, "127.0.0.1")])
        writer.close()
    finally:
        listener.stop()


async def test_mutual_tls_accepts_a_device_certificate_and_refuses_none():
    server_cert = _store_generated_certificate()
    ca_key, ca_cert = _ca()
    syslog_tls.MATERIAL["client_ca_pem"] = ca_cert.public_bytes(serialization.Encoding.PEM).decode()
    listener, recorder = await _listener("tls", syslog_tls.server_context(True))
    try:
        cert_pem, key_pem = _client_pem(ca_key, ca_cert)
        _reader, writer = await _tls_connect(listener.port, _client_context(server_cert, cert_pem, key_pem))
        writer.write(b"<13>from a device with a certificate\n")
        await writer.drain()
        assert await _wait_for(lambda: len(recorder.frames) == 1)
        writer.close()

        # No client certificate: the handshake fails (on the client's
        # connect, or on its first read under TLS 1.3); nothing is received.
        try:
            reader, writer = await _tls_connect(listener.port, _client_context(server_cert))
            writer.write(b"<13>without a certificate\n")
            await writer.drain()
            assert await _closed_by_server(reader)
            writer.close()
        except ssl.SSLError, ConnectionError:
            pass
        assert await _wait_for(lambda: listener.stats.errors == 1)
        assert len(recorder.frames) == 1
    finally:
        listener.stop()


async def test_a_stalled_tls_handshake_times_out(monkeypatch):
    monkeypatch.setattr(syslog_stream, "TLS_HANDSHAKE_TIMEOUT_SECONDS", 0.2)
    _store_generated_certificate()
    listener, _recorder = await _listener("tls", syslog_tls.server_context(False))
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", listener.port)  # plain TCP, no hello
        assert await _closed_by_server(reader)
        assert await _wait_for(lambda: listener.stats.errors == 1 and listener.connections == 0)
        writer.close()
    finally:
        listener.stop()


def test_a_tls_round_trip_on_uvloop():
    """uvicorn runs the app on uvloop where it installs (Linux). uvloop
    reads a new connection's first bytes before the task serving it runs,
    so a listener that upgrades an accepted stream to TLS loses the
    ClientHello there and no handshake ever finishes."""
    uvloop = pytest.importorskip("uvloop")
    server_cert = _store_generated_certificate()

    async def round_trip() -> list[tuple[bytes, str]]:
        listener, recorder = await _listener("tls", syslog_tls.server_context(False))
        try:
            for _ in range(5):
                _reader, writer = await _tls_connect(listener.port, _client_context(server_cert))
                writer.write(b"<13>over tls on uvloop\n")
                await writer.drain()
                writer.close()
            await _wait_for(lambda: len(recorder.frames) == 5)
        finally:
            listener.stop()
            await asyncio.sleep(0)
        return recorder.frames

    loop = uvloop.new_event_loop()
    try:
        frames = loop.run_until_complete(round_trip())
    finally:
        loop.close()
    assert frames == [(b"<13>over tls on uvloop", "127.0.0.1")] * 5


# ── Client certificate names the host ────────────────────────────────────────


def _peercert(cn: str = "", dns: tuple[str, ...] = (), ips: tuple[str, ...] = ()) -> dict:
    """A peer certificate as ``SSLSocket.getpeercert()`` gives it."""
    cert: dict = {"subject": ((("organizationName", "Example"),), (("commonName", cn),)) if cn else ()}
    sans = tuple(("DNS", d) for d in dns) + tuple(("IP Address", i) for i in ips)
    if sans:
        cert["subjectAltName"] = sans
    return cert


@pytest.mark.parametrize(
    ("cert", "source", "hostname"),
    [
        (_peercert(ips=("192.0.2.10",)), "192.0.2.10", ""),  # SAN IP, no inventory host
        (_peercert(ips=("192.0.2.10",)), "::ffff:192.0.2.10", ""),  # IPv4-mapped source
        (_peercert(ips=("2001:DB8:0:0:0:0:0:1",)), "2001:db8::1", ""),  # IPv6 written out
        (_peercert(dns=("core-sw1.example.com",)), "192.0.2.10", "core-sw1.example.com"),
        (_peercert(dns=("CORE-SW1.Example.com.",)), "192.0.2.10", "core-sw1.example.com"),
        (_peercert(cn="core-sw1.example.com"), "192.0.2.10", "core-sw1.example.com"),
        (_peercert(cn="core-sw1"), "192.0.2.10", "core-sw1.example.com"),  # bare name in the certificate
        (_peercert(dns=("core-sw1.example.com",)), "192.0.2.10", "core-sw1"),  # bare inventory hostname
        (_peercert(cn="other", dns=("x.example.com", "core-sw1")), "192.0.2.10", "CORE-SW1"),
        (_peercert(cn="192.0.2.10"), "192.0.2.10", "192.0.2.10"),  # a host named by its address
    ],
)
def test_a_certificate_that_names_the_host_matches(cert, source, hostname):
    assert syslog_tls.peer_mismatch(cert, source, hostname) == ""


@pytest.mark.parametrize(
    ("cert", "source", "hostname", "reason"),
    [
        (_peercert(cn="core-sw2.example.com"), "192.0.2.10", "core-sw1.example.com", "core-sw1.example.com"),
        (_peercert(ips=("192.0.2.11",)), "192.0.2.10", "core-sw1.example.com", "192.0.2.10"),
        (_peercert(dns=("*.example.com",)), "192.0.2.10", "core-sw1.example.com", "match neither"),
        (_peercert(cn="*"), "192.0.2.10", "core-sw1", "match neither"),
        # Both names carry a domain: no first-label match across domains.
        (_peercert(cn="core-sw1.example.net"), "192.0.2.10", "core-sw1.example.com", "match neither"),
        (_peercert(cn="core-sw1"), "192.0.2.10", "core-sw10.example.com", "match neither"),
        # A host named by its address: "192" is not its first label.
        (_peercert(cn="192"), "192.0.2.10", "192.0.2.10", "match neither"),
        # No inventory host at the source: only a SAN IP is accepted.
        (_peercert(cn="core-sw1.example.com", dns=("core-sw1.example.com",)), "198.51.100.7", "", "no inventory host"),
        (None, "192.0.2.10", "core-sw1", "no client certificate"),
        ({}, "192.0.2.10", "core-sw1", "no client certificate"),
    ],
)
def test_a_certificate_that_names_another_host_does_not_match(cert, source, hostname, reason):
    assert reason in syslog_tls.peer_mismatch(cert, source, hostname)


def test_the_names_of_a_peer_certificate():
    cert = _peercert(cn="core-sw1", dns=("core-sw1.example.com",), ips=("192.0.2.10",))
    cert["subjectAltName"] += (("email", "ops@example.com"), ("bad",))
    assert syslog_tls.peer_names(cert) == (["core-sw1.example.com"], ["192.0.2.10"], ["core-sw1"])
    assert syslog_tls.peer_names(None) == ([], [], [])
    assert not syslog_tls.host_name_matches("", "core-sw1") and not syslog_tls.host_name_matches("core-sw1", "")


def test_the_inventory_hostname_of_an_address(monkeypatch):
    monkeypatch.setitem(ls.INVENTORY_ADDRESSES, "192.0.2.10", 41)
    monkeypatch.setitem(ls.INVENTORY_HOSTNAMES, 41, "core-sw1.example.com")
    assert ls.inventory_hostname("192.0.2.10") == "core-sw1.example.com"
    assert ls.inventory_hostname("::ffff:192.0.2.10") == "core-sw1.example.com"
    assert ls.inventory_hostname("198.51.100.7") == ""


def _mutual_tls(monkeypatch, hostname: str = "edge-r1.example.com"):
    """A stored server certificate and client CA; loopback is the inventory
    host ``hostname``. Returns (server cert PEM, CA key, CA cert)."""
    server_cert = _store_generated_certificate()
    ca_key, ca_cert = _ca()
    syslog_tls.MATERIAL["client_ca_pem"] = ca_cert.public_bytes(serialization.Encoding.PEM).decode()
    if hostname:
        monkeypatch.setitem(ls.INVENTORY_ADDRESSES, "127.0.0.1", 41)
        monkeypatch.setitem(ls.INVENTORY_HOSTNAMES, 41, hostname)
    return server_cert, ca_key, ca_cert


async def _checked_listener() -> tuple[StreamListener, _Recorder]:
    recorder = _Recorder()
    listener = StreamListener("tls", recorder, me._ReceiverStats())
    assert await listener.start(
        "127.0.0.1", _free_tcp_port(), syslog_tls.server_context(True), peer_check=me._client_cert_names_host
    )
    return listener, recorder


async def test_a_certificate_naming_the_host_is_accepted(monkeypatch):
    server_cert, ca_key, ca_cert = _mutual_tls(monkeypatch)
    listener, recorder = await _checked_listener()
    try:
        # The bare name in the common name; the inventory has the FQDN.
        cert_pem, key_pem = _client_pem(ca_key, ca_cert, "edge-r1")
        _reader, writer = await _tls_connect(listener.port, _client_context(server_cert, cert_pem, key_pem))
        writer.write(b"<13>from the named host\n")
        await writer.drain()
        assert await _wait_for(lambda: recorder.frames == [(b"<13>from the named host", "127.0.0.1")])
        writer.close()

        # A SAN IP of the source address, whatever the names say.
        cert_pem, key_pem = _client_pem(
            ca_key, ca_cert, "unrelated.example.net", [x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
        )
        _reader, writer = await _tls_connect(listener.port, _client_context(server_cert, cert_pem, key_pem))
        writer.write(b"<13>by address\n")
        await writer.drain()
        assert await _wait_for(lambda: len(recorder.frames) == 2)
        assert listener.cert_refused == 0
        writer.close()
    finally:
        listener.stop()


async def test_a_certificate_naming_another_host_is_closed_unread(monkeypatch):
    server_cert, ca_key, ca_cert = _mutual_tls(monkeypatch)
    listener, recorder = await _checked_listener()
    try:
        cert_pem, key_pem = _client_pem(ca_key, ca_cert, "core-sw2.example.com", [x509.DNSName("core-sw2.example.com")])
        try:
            reader, writer = await _tls_connect(listener.port, _client_context(server_cert, cert_pem, key_pem))
            writer.write(b"<13>sent as another host\n")
            await writer.drain()
            assert await _closed_by_server(reader)
            writer.close()
        except ssl.SSLError, ConnectionError:
            pass
        assert await _wait_for(lambda: listener.cert_refused == 1 and listener.connections == 0)
        assert recorder.frames == [] and listener.stats.received == 0 and listener.stats.errors == 0
    finally:
        listener.stop()


async def test_a_source_that_is_no_inventory_host_needs_a_san_ip(monkeypatch):
    server_cert, ca_key, ca_cert = _mutual_tls(monkeypatch, hostname="")  # policy any: loopback is no host
    listener, recorder = await _checked_listener()
    try:
        cert_pem, key_pem = _client_pem(ca_key, ca_cert, "edge-r1.example.com", [x509.DNSName("edge-r1.example.com")])
        try:
            reader, writer = await _tls_connect(listener.port, _client_context(server_cert, cert_pem, key_pem))
            writer.write(b"<13>no host here\n")
            await writer.drain()
            assert await _closed_by_server(reader)
            writer.close()
        except ssl.SSLError, ConnectionError:
            pass
        assert await _wait_for(lambda: listener.cert_refused == 1)
        assert recorder.frames == []
    finally:
        listener.stop()


def test_the_host_check_on_uvloop(monkeypatch):
    """The peer certificate is read from the connection the same way under
    uvloop (uvicorn's event loop where it installs)."""
    uvloop = pytest.importorskip("uvloop")
    server_cert, ca_key, ca_cert = _mutual_tls(monkeypatch)
    good = _client_pem(ca_key, ca_cert, "edge-r1.example.com")
    bad = _client_pem(ca_key, ca_cert, "core-sw2.example.com")

    async def run() -> tuple[list[tuple[bytes, str]], int]:
        listener, recorder = await _checked_listener()
        try:
            for cert_pem, key_pem in (good, bad):
                try:
                    _reader, writer = await _tls_connect(listener.port, _client_context(server_cert, cert_pem, key_pem))
                    writer.write(b"<13>over tls on uvloop\n")
                    await writer.drain()
                    writer.close()
                except ssl.SSLError, ConnectionError:
                    pass
            await _wait_for(lambda: len(recorder.frames) == 1 and listener.cert_refused == 1)
        finally:
            listener.stop()
            await asyncio.sleep(0)
        return recorder.frames, listener.cert_refused

    loop = uvloop.new_event_loop()
    try:
        frames, refused = loop.run_until_complete(run())
    finally:
        loop.close()
    assert frames == [(b"<13>over tls on uvloop", "127.0.0.1")] and refused == 1


# ── Certificates (netcontrol.syslog_tls) ─────────────────────────────────────


def test_a_generated_certificate_is_described():
    cert_pem, key_pem = syslog_tls.generate_self_signed(SERVER_NAME, ["192.0.2.10", "logs.example.com"], 90)
    assert syslog_tls.validate_server_pair(cert_pem, key_pem)[0] == cert_pem
    view = syslog_tls.public_view({"cert_pem": cert_pem, "key_pem": key_pem, "client_ca_pem": ""})
    cert = view["certificate"]
    assert view["has_certificate"] is True and view["has_client_ca"] is False
    assert cert["subject"] == f"CN={SERVER_NAME}" and cert["issuer"] == cert["subject"]
    assert cert["self_signed"] is True
    assert set(cert["sans"]) == {"192.0.2.10", "logs.example.com", SERVER_NAME}
    assert len(cert["sha256_fingerprint"].split(":")) == 32
    not_before = dt.datetime.fromisoformat(cert["not_before"])
    assert dt.timedelta(days=89) < dt.datetime.fromisoformat(cert["not_after"]) - not_before < dt.timedelta(days=91)
    assert "key_pem" not in view


@pytest.mark.parametrize(
    ("args", "error"),
    [
        (("", [], 30), "common name"),
        (("x" * 65, [], 30), "common name"),
        ((SERVER_NAME, [], 0), "validity"),
        ((SERVER_NAME, [], 3651), "validity"),
        ((SERVER_NAME, ["not a name!"], 30), "not a DNS name"),
        ((SERVER_NAME, [f"h{i}.example.com" for i in range(33)], 30), "At most"),
    ],
)
def test_generate_refuses_bad_input(args, error):
    with pytest.raises(syslog_tls.TlsMaterialError, match=error):
        syslog_tls.generate_self_signed(*args)


def test_a_common_name_that_is_no_host_name_stays_out_of_the_sans():
    cert_pem, _key = syslog_tls.generate_self_signed("Plexus syslog receiver", ["192.0.2.10"], 30)
    view = syslog_tls.public_view({"cert_pem": cert_pem, "key_pem": "", "client_ca_pem": ""})
    assert view["certificate"]["sans"] == ["192.0.2.10"] and view["has_certificate"] is False


def test_validation_refuses_bad_material():
    cert_pem, key_pem = syslog_tls.generate_self_signed(SERVER_NAME, [], 30)
    _other_cert, other_key = syslog_tls.generate_self_signed(SERVER_NAME, [], 30)
    with pytest.raises(syslog_tls.TlsMaterialError, match="does not belong"):
        syslog_tls.validate_server_pair(cert_pem, other_key)
    with pytest.raises(syslog_tls.TlsMaterialError, match="not a PEM certificate"):
        syslog_tls.validate_server_pair("garbage", key_pem)
    with pytest.raises(syslog_tls.TlsMaterialError, match="not a PEM private key"):
        syslog_tls.validate_server_pair(cert_pem, "garbage")
    with pytest.raises(syslog_tls.TlsMaterialError, match="longer than"):
        syslog_tls.validate_server_pair(cert_pem, "x" * (syslog_tls.MAX_KEY_PEM_CHARS + 1))
    with pytest.raises(syslog_tls.TlsMaterialError, match="longer than"):
        syslog_tls.validate_server_pair("x" * (syslog_tls.MAX_CERT_PEM_CHARS + 1), key_pem)
    key = serialization.load_pem_private_key(key_pem.encode(), password=None)
    encrypted = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(b"example-passphrase"),
    ).decode()
    with pytest.raises(syslog_tls.TlsMaterialError, match="encrypted"):
        syslog_tls.validate_server_pair(cert_pem, encrypted)
    with pytest.raises(syslog_tls.TlsMaterialError, match="client CA"):
        syslog_tls.validate_client_ca("not a certificate")
    with pytest.raises(syslog_tls.TlsMaterialError, match="longer than"):
        syslog_tls.validate_client_ca("x" * (syslog_tls.MAX_CA_PEM_CHARS + 1))


def test_an_expired_certificate_is_refused():
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, SERVER_NAME)])
    now = dt.datetime.now(dt.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=60))
        .not_valid_after(now - dt.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    key_pem = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    ).decode()
    with pytest.raises(syslog_tls.TlsMaterialError, match="expired"):
        syslog_tls.validate_server_pair(cert.public_bytes(serialization.Encoding.PEM).decode(), key_pem)


def test_the_server_context_needs_its_material():
    with pytest.raises(syslog_tls.TlsMaterialError, match="No server certificate"):
        syslog_tls.server_context(False)
    _store_generated_certificate()
    with pytest.raises(syslog_tls.TlsMaterialError, match="no client CA"):
        syslog_tls.server_context(True)
    ctx = syslog_tls.server_context(False)
    assert ctx.minimum_version == ssl.TLSVersion.TLSv1_2 and ctx.verify_mode == ssl.CERT_NONE
    _ca_key, ca_cert = _ca()
    syslog_tls.MATERIAL["client_ca_pem"] = ca_cert.public_bytes(serialization.Encoding.PEM).decode()
    assert syslog_tls.server_context(True).verify_mode == ssl.CERT_REQUIRED
    view = syslog_tls.public_view()
    assert view["client_ca"][0]["subject"] == "CN=Example Device CA" and view["client_ca"][0]["not_after"]
    # Unusable stored material: reported, never raised by the view.
    syslog_tls.MATERIAL["key_pem"] = "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"
    with pytest.raises(syslog_tls.TlsMaterialError, match="cannot be used"):
        syslog_tls.server_context(False)
    assert syslog_tls.public_view({"cert_pem": "junk", "key_pem": "", "client_ca_pem": "junk"})["client_ca"] == []


def test_the_material_key_changes_with_the_material_and_mode():
    before = syslog_tls.material_key(False)
    assert syslog_tls.material_key(True) != before
    assert syslog_tls.material_key(True, True) != syslog_tls.material_key(True)
    assert syslog_tls.material_key(False, False) == before
    _store_generated_certificate()
    assert syslog_tls.material_key(False) != before
    assert syslog_tls.sanitize({"cert_pem": 1, "other": "x"}) == {"cert_pem": "", "key_pem": "", "client_ca_pem": ""}


def test_temporary_pem_files_are_removed_even_when_cleanup_fails(monkeypatch):
    cert_pem, key_pem = syslog_tls.generate_self_signed(SERVER_NAME, [], 30)
    removed: list[str] = []

    def failing_unlink(path):
        removed.append(path)
        raise OSError("busy")

    monkeypatch.setattr(tls_pem.os, "unlink", failing_unlink)
    tls_pem.load_cert_chain_pem(ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER), cert_pem, key_pem)
    assert len(removed) == 2
    monkeypatch.undo()
    for path in removed:
        tls_pem.os.unlink(path)


# ── Lifecycle through the receiver settings ──────────────────────────────────


async def test_apply_starts_stops_and_rebinds_the_stream_listeners(stream_receivers):
    tcp1, tcp2, tls_port = _free_tcp_port(), _free_tcp_port(), _free_tcp_port()
    snap = await me.apply_event_receiver_config(_cfg(syslog_tcp_enabled=True, syslog_tcp_port=tcp1))
    assert snap["syslog_tcp_running"] is True and snap["syslog_tcp_listening_port"] == tcp1
    assert snap["syslog_running"] is False and snap["syslog_tls_running"] is False
    # Only TCP runs: the syslog receiver counts as running.
    assert me.receiver_running("syslog") and not me.receiver_running("trap")
    tcp = me._STREAM_LISTENERS["tcp"]
    first = tcp._server

    await me.apply_event_receiver_config(_cfg(syslog_tcp_enabled=True, syslog_tcp_port=tcp1))
    assert tcp._server is first  # unchanged settings: not rebound

    # TLS enabled without a certificate: reported, stopped; TCP untouched.
    snap = await me.apply_event_receiver_config(
        _cfg(syslog_tcp_enabled=True, syslog_tcp_port=tcp1, syslog_tls_enabled=True, syslog_tls_port=tls_port)
    )
    assert snap["syslog_tls_running"] is False and "No server certificate" in snap["syslog_tls_error"]
    assert tcp._server is first

    _store_generated_certificate()
    snap = await me.apply_event_receiver_config(
        _cfg(syslog_tcp_enabled=True, syslog_tcp_port=tcp2, syslog_tls_enabled=True, syslog_tls_port=tls_port)
    )
    assert snap["syslog_tcp_listening_port"] == tcp2 and tcp._server is not first
    assert snap["syslog_tls_running"] is True and snap["syslog_tls_error"] == ""
    tls = me._STREAM_LISTENERS["tls"]
    tls_server = tls._server

    # New TLS material: the TLS listener is rebuilt, TCP is not.
    tcp_server = tcp._server
    _store_generated_certificate()
    await me.apply_event_receiver_config(
        _cfg(syslog_tcp_enabled=True, syslog_tcp_port=tcp2, syslog_tls_enabled=True, syslog_tls_port=tls_port)
    )
    assert tls._server is not tls_server and tcp._server is tcp_server

    snap = await me.apply_event_receiver_config(_cfg(syslog_tls_enabled=True, syslog_tls_port=tls_port))
    assert snap["syslog_tcp_running"] is False and snap["syslog_tls_running"] is True

    me.stop_receivers()
    assert not me.receiver_running("syslog")
    assert me.event_receiver_snapshot()["syslog_tls_running"] is False


async def test_turning_the_host_check_on_or_off_rebuilds_the_tls_listener(stream_receivers, monkeypatch):
    _mutual_tls(monkeypatch)
    port = _free_tcp_port()
    base = {"syslog_tls_enabled": True, "syslog_tls_port": port, "syslog_tls_require_client_cert": True}
    await me.apply_event_receiver_config(_cfg(**base))
    tls = me._STREAM_LISTENERS["tls"]
    first = tls._server
    assert first is not None and tls._peer_check is None

    await me.apply_event_receiver_config(_cfg(**base, syslog_tls_match_client_cert=True))
    second = tls._server
    assert second is not first and tls._peer_check is me._client_cert_names_host

    await me.apply_event_receiver_config(_cfg(**base, syslog_tls_match_client_cert=True))
    assert tls._server is second  # unchanged: not rebuilt

    await me.apply_event_receiver_config(_cfg(**base))
    assert tls._server is not second and tls._peer_check is None


async def test_the_snapshot_reports_each_stream_listener(stream_receivers, monkeypatch):
    port = _free_tcp_port()
    await me.apply_event_receiver_config(_cfg(syslog_tcp_enabled=True, syslog_tcp_port=port))
    _reader, writer = await asyncio.open_connection("127.0.0.1", port)
    writer.write(b"<13>counted\n")
    await writer.drain()
    assert await _wait_for(lambda: me.event_receiver_snapshot()["syslog_tcp_received"] == 1)
    snap = me.event_receiver_snapshot()
    for transport in ("tcp", "tls"):
        for suffix in (
            "running",
            "listening_port",
            "received",
            "errors",
            "last_message_at",
            "started_at",
            "connections",
            "connections_refused",
            "error",
        ):
            assert f"syslog_{transport}_{suffix}" in snap
    assert snap["syslog_tcp_connections"] == 1 and snap["syslog_tcp_connections_refused"] == 0
    # Refused for a client certificate that does not name the host: TLS only.
    assert snap["syslog_tls_connections_cert_refused"] == 0
    assert "syslog_tcp_connections_cert_refused" not in snap
    monkeypatch.setattr(me._STREAM_LISTENERS["tls"], "cert_refused", 3)
    assert me.event_receiver_snapshot()["syslog_tls_connections_cert_refused"] == 3
    assert snap["syslog_tcp_last_message_at"] and snap["syslog_tcp_started_at"]
    # The existing keys are kept.
    for key in ("syslog_running", "syslog_received", "syslog_dropped_source", "trap_running", "events_dropped"):
        assert key in snap
    writer.close()


# ── Transport stored, and the UDP switch ─────────────────────────────────────


async def test_each_message_is_stored_with_its_transport(stream_receivers):
    port = _free_tcp_port()
    await me.apply_event_receiver_config(_cfg(syslog_tcp_enabled=True, syslog_tcp_port=port))
    _reader, writer = await asyncio.open_connection("127.0.0.1", port)
    writer.write(b"<13>sent over tcp\n")
    await writer.drain()
    assert await _wait_for(lambda: len(me._trap_event_buffer) == 1)
    me.handle_syslog_message(b"<13>sent over udp", "192.0.2.10")
    me.handle_syslog_message(b"<11>sent over tls", "192.0.2.11", "tls")
    await me._flush_trap_syslog_batch(me._take_trap_event_batch())
    events = {e["message"]: e for e in await db.get_trap_syslog_events(event_type="syslog", limit=10)}
    assert {m: e["transport"] for m, e in events.items()} == {
        "sent over tcp": "tcp",
        "sent over udp": "udp",
        "sent over tls": "tls",
    }
    assert events["sent over tls"]["severity"] == "warning"
    # A row written without a transport (an older caller) is UDP.
    await db.create_trap_syslog_events_batch([("192.0.2.12", None, "syslog", "", "info", "", "no transport", "")])
    rows = await db.get_trap_syslog_events(event_type="syslog", limit=10)
    assert next(r for r in rows if r["message"] == "no transport")["transport"] == "udp"
    writer.close()


async def test_udp_syslog_is_stored_but_not_acted_on_when_the_switch_is_off(monkeypatch):
    handed: list[list] = []
    recollect: list[list] = []

    async def fake_rules(rows):
        handed.append(list(rows))

    async def fake_recollect(rows):
        recollect.append(list(rows))

    monkeypatch.setattr(sr, "process_syslog_batch", fake_rules)
    monkeypatch.setattr(sr, "process_recollect_batch", fake_recollect)
    rows = [
        ("192.0.2.10", 7, "syslog", "23", "info", "", "over udp", "", "udp"),
        ("192.0.2.10", 7, "syslog", "23", "info", "", "over tcp", "", "tcp"),
        ("192.0.2.10", 7, "syslog", "23", "info", "", "over tls", "", "tls"),
        ("192.0.2.10", 7, "syslog", "23", "info", "", "no transport", ""),
    ]
    await me._evaluate_syslog_rules(rows)
    assert [m for _, m in handed[-1]] == ["over udp", "over tcp", "over tls", "no transport"]

    state.EVENT_RECEIVER_CONFIG["syslog_udp_actions"] = False
    await me._evaluate_syslog_rules(rows)
    assert [m for _, m in handed[-1]] == ["over tcp", "over tls"]
    assert [m for _ip, _h, m in recollect[-1]] == ["over tcp", "over tls"]

    # Stored all the same, through the batch writer.
    handed.clear()
    me.handle_syslog_message(b"<13>stored only", "192.0.2.10")
    await me._flush_trap_syslog_batch(me._take_trap_event_batch())
    assert handed == []
    assert [e["message"] for e in await db.get_trap_syslog_events(event_type="syslog")] == ["stored only"]


async def test_a_udp_link_flap_raises_nothing_while_tcp_still_alerts(engine):  # noqa: F811
    clock, repolls, _changes = engine
    state.EVENT_RECEIVER_CONFIG["syslog_udp_actions"] = False
    _gid, host_id = await _host()
    me._host_ip_cache.clear()
    for transport in ("udp", "tcp"):
        for _ in range(3):
            me.handle_syslog_message(DOWN.encode(), "192.0.2.10", transport)
            await me._flush_trap_syslog_batch(me._take_trap_event_batch())
            clock.t += 10  # two downs closer than 5 seconds count once
        if transport == "udp":
            assert await _open(host_id) == {} and repolls == []
    assert [a["metric"] for a in (await _open(host_id)).values()] == ["syslog_link_flap"]
    assert repolls


async def test_the_restore_skips_udp_messages_when_the_switch_is_off(restore):  # noqa: F811
    _clock, _repolls, changes = restore
    _gid, udp_host = await _host("sw-udp", "192.0.2.21")
    _gid2, tcp_host = await _host("sw-tcp", "192.0.2.22")
    for host_id, ip, transport in ((udp_host, "192.0.2.21", "udp"), (tcp_host, "192.0.2.22", "tcp")):
        await _sql(
            "INSERT INTO trap_syslog_events (source_ip, host_id, event_type, message, transport, received_at) "
            "VALUES (?, ?, 'syslog', ?, ?, datetime('now', '-30 seconds'))",
            (ip, host_id, CHANGE, transport),
        )
    state.EVENT_RECEIVER_CONFIG["syslog_udp_actions"] = False
    assert (await sr.restore_state())["config_changes"] == 1 and changes == [tcp_host]
    changes.clear()
    sr.reset_state()
    state.EVENT_RECEIVER_CONFIG["syslog_udp_actions"] = True
    assert (await sr.restore_state())["config_changes"] == 2 and sorted(changes) == sorted([udp_host, tcp_host])


async def test_the_reader_filters_by_transport():
    for transport in ("udp", "tcp", "tls"):
        await _sql(
            "INSERT INTO trap_syslog_events (source_ip, event_type, message, transport) VALUES (?, 'syslog', ?, ?)",
            ("192.0.2.30", f"via {transport}", transport),
        )
    rows = await db.list_syslog_messages_since(60, transports=("tcp", "tls"))
    assert sorted(r["message"] for r in rows) == ["via tcp", "via tls"]
    assert {r["transport"] for r in await db.list_syslog_messages_since(60)} == {"udp", "tcp", "tls"}
    assert await db.list_syslog_messages_since(60, transports=()) == []


async def test_the_activity_counts_messages_per_transport():
    _gid, host_a = await _host("sw-a", "192.0.2.41")
    _gid2, host_b = await _host("sw-b", "192.0.2.42")
    for host_id, transport in ((host_a, "udp"), (host_a, "udp"), (host_b, "tls"), (host_b, "tcp"), (None, "udp")):
        await _sql(
            "INSERT INTO trap_syslog_events (source_ip, host_id, event_type, message, transport) "
            "VALUES ('192.0.2.40', ?, 'syslog', '<13>routine message', ?)",
            (host_id, transport),
        )
    state.EVENT_RECEIVER_CONFIG["syslog_udp_actions"] = False
    out = await syslog_activity.analyze(24)
    assert out["transports"] == {"udp": 2, "tcp": 1, "tls": 1}
    assert out["udp_hosts"] == 1 and out["udp_actions"] is False
    assert out["unknown_source"] == 1 and out["scanned"] == 5


async def test_the_migration_adds_the_transport_column():
    await db.init_db()
    conn = await db.get_db(read_only=True)
    try:
        cursor = await conn.execute("SELECT version FROM schema_migrations WHERE version = 128")
        assert await cursor.fetchone() is not None
        cursor = await conn.execute(
            "SELECT column_default FROM information_schema.columns "
            "WHERE table_name = 'trap_syslog_events' AND column_name = 'transport'"
        )
        row = await cursor.fetchone()
        assert row is not None and "udp" in str(row[0])
    finally:
        await conn.close()


# ── Admin API ────────────────────────────────────────────────────────────────


def _audit_details(prefix: str) -> list[str]:
    events = asyncio.run(db.get_audit_events(500, "system"))
    return [f"{e['action']} {e.get('detail', '')}" for e in events if str(e["action"]).startswith(prefix)]


def test_the_tls_api_is_admin_only(monkeypatch, request):
    admin = admin_client(monkeypatch, request)
    plain = user_client(admin, "tls-user", features=["monitoring"])
    assert plain.get(TLS).status_code == 403
    assert plain.put(TLS, json={"client_ca_pem": ""}).status_code == 403
    assert plain.post(TLS + "/generate", json={"common_name": SERVER_NAME}).status_code == 403
    assert plain.delete(TLS).status_code == 403


def test_the_receiver_settings_refuse_invalid_combinations(monkeypatch, request):
    admin = admin_client(monkeypatch, request)
    port = _free_tcp_port()
    cases = [
        (
            {"syslog_tcp_enabled": True, "syslog_tls_enabled": True, "syslog_tcp_port": port, "syslog_tls_port": port},
            "same TCP port",
        ),
        ({"syslog_tls_enabled": True}, "server certificate"),
        ({"syslog_tls_require_client_cert": True}, "client CA"),
        ({"syslog_tls_match_client_cert": True}, "Require client certificates before"),
        ({"syslog_udp_actions": False}, "TCP or TLS receiver"),
    ]
    for body, message in cases:
        resp = admin.put(CONFIG, json=body)
        assert resp.status_code == 400, resp.text
        assert message in resp.text
    assert admin.put(CONFIG, json={"syslog_tcp_port": 0}).status_code == 422
    assert admin.put(CONFIG, json={"syslog_tls_port": 70000}).status_code == 422

    resp = admin.put(CONFIG, json={"syslog_tcp_enabled": True, "syslog_tcp_port": port, "syslog_udp_actions": False})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["syslog_tcp_running"] is True and body["syslog_udp_actions"] is False
    saved = asyncio.run(db.get_auth_setting("event_receivers"))
    assert saved["syslog_tcp_enabled"] is True and saved["syslog_udp_actions"] is False
    assert any("syslog_tcp=on" in d and "syslog_udp_actions=False" in d for d in _audit_details("event_receivers"))
    # The TCP receiver cannot go off while UDP actions are off.
    assert admin.put(CONFIG, json={"syslog_tcp_enabled": False}).status_code == 400


def test_the_certificate_api(monkeypatch, request):
    admin = admin_client(monkeypatch, request)
    empty = admin.get(TLS).json()
    assert empty == {
        "has_certificate": False,
        "certificate": None,
        "cert_pem": "",
        "has_client_ca": False,
        "client_ca": [],
        "client_ca_pem": "",
    }

    resp = admin.post(TLS + "/generate", json={"common_name": SERVER_NAME, "sans": ["192.0.2.10"], "days": 365})
    assert resp.status_code == 200, resp.text
    generated = resp.json()
    assert generated["has_certificate"] is True and generated["certificate"]["self_signed"] is True
    assert "192.0.2.10" in generated["certificate"]["sans"]
    for text in (resp.text, admin.get(TLS).text):
        assert "PRIVATE KEY" not in text and "key_pem" not in text

    # The key is encrypted at rest; read back in plain text.
    conn_rows = asyncio.run(_raw_setting("syslog_tls"))
    assert "PRIVATE KEY" not in conn_rows and '"__enc__"' in conn_rows
    stored = asyncio.run(db.get_auth_setting("syslog_tls"))
    assert "PRIVATE KEY" in stored["key_pem"] and stored["cert_pem"] == generated["cert_pem"]

    # A key of another certificate, a certificate alone, garbage: refused.
    cert_pem, key_pem = syslog_tls.generate_self_signed("logs.example.com", [], 30)
    _other, other_key = syslog_tls.generate_self_signed("logs.example.com", [], 30)
    resp = admin.put(TLS, json={"cert_pem": cert_pem, "key_pem": other_key})
    assert resp.status_code == 400 and "does not belong" in resp.text and "PRIVATE KEY" not in resp.text
    assert admin.put(TLS, json={"cert_pem": cert_pem}).status_code == 400
    assert admin.put(TLS, json={"client_ca_pem": "not a certificate"}).status_code == 400
    too_long = admin.put(TLS, json={"cert_pem": cert_pem, "key_pem": "x" * (syslog_tls.MAX_KEY_PEM_CHARS + 1)})
    assert too_long.status_code == 400
    assert admin.get(TLS).json()["cert_pem"] == generated["cert_pem"]  # unchanged
    assert admin.put(TLS, json={}).json()["cert_pem"] == generated["cert_pem"]  # nothing to change

    resp = admin.put(TLS, json={"cert_pem": cert_pem, "key_pem": key_pem})
    assert resp.status_code == 200 and resp.json()["certificate"]["subject"] == "CN=logs.example.com"

    _ca_key, ca_cert = _ca()
    ca_pem = ca_cert.public_bytes(serialization.Encoding.PEM).decode()
    resp = admin.put(TLS, json={"client_ca_pem": ca_pem})
    assert resp.status_code == 200 and resp.json()["has_client_ca"] is True
    assert resp.json()["client_ca"][0]["subject"] == "CN=Example Device CA"

    # Mutual TLS on: the CA cannot be removed; the TLS listener cannot lose its certificate.
    tls_port = _free_tcp_port()
    resp = admin.put(
        CONFIG, json={"syslog_tls_enabled": True, "syslog_tls_port": tls_port, "syslog_tls_require_client_cert": True}
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["syslog_tls_running"] is True
    assert admin.put(TLS, json={"client_ca_pem": ""}).status_code == 400
    assert admin.delete(TLS).status_code == 400
    # A new certificate restarts the running listener.
    listener_server = me._STREAM_LISTENERS["tls"]._server
    assert admin.post(TLS + "/generate", json={"common_name": SERVER_NAME}).status_code == 200
    assert me._STREAM_LISTENERS["tls"]._server is not listener_server
    assert admin.get(CONFIG).json()["syslog_tls_running"] is True

    resp = admin.put(CONFIG, json={"syslog_tls_enabled": False, "syslog_tls_require_client_cert": False})
    assert resp.status_code == 200, resp.text
    assert admin.put(TLS, json={"client_ca_pem": ""}).json()["has_client_ca"] is False
    resp = admin.delete(TLS)
    assert resp.status_code == 200 and resp.json()["has_certificate"] is False

    details = _audit_details("syslog_tls")
    assert {d.split(" ")[0] for d in details} == {"syslog_tls.generated", "syslog_tls.updated", "syslog_tls.deleted"}
    assert not any("PRIVATE KEY" in d for d in details)

    assert admin.post(TLS + "/generate", json={"common_name": SERVER_NAME, "days": 0}).status_code == 422
    assert admin.post(TLS + "/generate", json={"common_name": SERVER_NAME, "sans": ["bad name!"]}).status_code == 400


async def _raw_setting(key: str) -> str:
    conn = await db.get_db(read_only=True)
    try:
        cursor = await conn.execute("SELECT value FROM auth_settings WHERE key = ?", (key,))
        row = await cursor.fetchone()
        return str(row[0]) if row else ""
    finally:
        await conn.close()


def test_the_stored_material_loads_at_startup(monkeypatch, request):
    cert_pem, key_pem = syslog_tls.generate_self_signed(SERVER_NAME, [], 30)
    tls_port = _free_tcp_port()
    asyncio.run(db.set_auth_setting("syslog_tls", {"cert_pem": cert_pem, "key_pem": key_pem, "client_ca_pem": ""}))
    asyncio.run(db.set_auth_setting("event_receivers", {"syslog_tls_enabled": True, "syslog_tls_port": tls_port}))
    admin = admin_client(monkeypatch, request)
    assert admin.get(TLS).json()["cert_pem"] == cert_pem
    body = admin.get(CONFIG).json()
    assert body["syslog_tls_running"] is True and body["syslog_tls_listening_port"] == tls_port
    assert json.loads(json.dumps(body))["syslog_tls_error"] == ""
