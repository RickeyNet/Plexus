"""``outbound_http.send_request`` connects to the address the SSRF guard
approved (``PinnedTransport``): the Host header, TLS server name and
certificate check keep the name, and a later DNS answer cannot move the
request. No socket is opened and no real DNS is asked: the resolver and the
network layer are fakes."""

from __future__ import annotations

import asyncio
import gzip
import socket

import httpx
import pytest
from netcontrol import saml, sso
from netcontrol.routes import net_guard, outbound_http
from netcontrol.routes.outbound_http import (
    DEFAULT_MAX_RESPONSE_BYTES,
    ExchangeTimeoutError,
    OutboundRequestError,
    PinnedTransport,
    ResponseTooLargeError,
    send_request,
)


class _Recorder(httpx.AsyncBaseTransport):
    """Stands in for the network: records each request, answers 204."""

    def __init__(self, *args, **kwargs):
        self.requests: list[httpx.Request] = []
        self.kwargs = kwargs

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        return httpx.Response(204)


def _rebinding_resolver(answers: list[str]):
    """Each lookup returns the next answer: a name that rebinds."""
    calls = {"n": 0}

    def fake(host):
        address = answers[min(calls["n"], len(answers) - 1)]
        calls["n"] += 1
        family = socket.AF_INET6 if ":" in address else socket.AF_INET
        return [(family, socket.SOCK_STREAM, 6, "", (address, 0))]

    fake.calls = calls
    return fake


@pytest.fixture
def network(monkeypatch):
    """The transports ``send_request`` builds, with no real network."""
    built: list[_Recorder] = []

    def factory(*args, **kwargs):
        rec = _Recorder(*args, **kwargs)
        built.append(rec)
        return rec

    monkeypatch.setattr(outbound_http.httpx, "AsyncHTTPTransport", factory)
    monkeypatch.setattr(outbound_http, "_env_proxy_applies", lambda url: False)
    return built


@pytest.mark.asyncio
async def test_request_goes_to_the_checked_address_with_the_name_kept(monkeypatch, network):
    resolver = _rebinding_resolver(["192.0.2.10", "169.254.169.254"])
    monkeypatch.setattr(net_guard, "_getaddrinfo", resolver)

    resp = await send_request("POST", "https://hooks.example.com:8443/in?x=1", json={"a": 1}, verify=False)

    assert resp.status_code == 204
    assert resp.request.url.host == "hooks.example.com"  # the caller sees its own URL
    sent = network[0].requests[0]
    assert sent.url.host == "192.0.2.10" and sent.url.port == 8443 and sent.url.path == "/in"
    assert sent.headers["host"] == "hooks.example.com:8443"
    assert sent.extensions["sni_hostname"] == "hooks.example.com"
    assert network[0].kwargs["verify"] is False
    # The name was resolved once, by the guard; the rebinding answer was never used.
    assert resolver.calls["n"] == 1


@pytest.mark.asyncio
async def test_ipv6_answer_is_pinned_and_plain_http_sets_no_sni(monkeypatch, network):
    monkeypatch.setattr(net_guard, "_getaddrinfo", _rebinding_resolver(["2001:db8::10"]))
    await send_request("GET", "http://hooks.example.com/status")
    sent = network[0].requests[0]
    assert sent.url.host == "2001:db8::10"
    assert sent.headers["host"] == "hooks.example.com"
    assert "sni_hostname" not in sent.extensions


@pytest.mark.asyncio
async def test_a_refused_target_never_reaches_the_network(monkeypatch, network):
    monkeypatch.setattr(net_guard, "_getaddrinfo", _rebinding_resolver(["fd00:ec2::254"]))
    with pytest.raises(OutboundRequestError, match="cloud metadata"):
        await send_request("GET", "https://imds.example.com/")
    assert network == []


@pytest.mark.asyncio
async def test_a_name_that_does_not_resolve_is_not_sent(monkeypatch, network):
    def fail(host):
        raise socket.gaierror(socket.EAI_NONAME, "unknown")

    monkeypatch.setattr(net_guard, "_getaddrinfo", fail)
    with pytest.raises(OutboundRequestError, match="does not resolve"):
        await send_request("GET", "https://gone.example.com/")
    assert network == []


@pytest.mark.asyncio
async def test_pinned_transport_refuses_another_host():
    inner = _Recorder()
    pinned = PinnedTransport("hooks.example.com", [net_guard.ipaddress.ip_address("192.0.2.10")], inner)
    with pytest.raises(OutboundRequestError, match="does not match"):
        await pinned.handle_async_request(httpx.Request("GET", "https://other.example.com/"))
    assert inner.requests == []


class _SomeAddressesDown(_Recorder):
    """Fails with ``error`` for every address in ``down``."""

    def __init__(self, down: set[str], error: type[Exception] = httpx.ConnectError):
        super().__init__()
        self.down = down
        self.error = error
        self.tried: list[str] = []

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        self.tried.append(request.url.host)
        if request.url.host in self.down:
            raise self.error("connect failed")
        return await super().handle_async_request(request)


def _addresses(*texts: str):
    return [net_guard.ipaddress.ip_address(text) for text in texts]


@pytest.mark.asyncio
@pytest.mark.parametrize("error", [httpx.ConnectError, httpx.ConnectTimeout])
async def test_an_unreachable_address_falls_back_to_the_next_approved_one(error):
    inner = _SomeAddressesDown({"2001:db8::10"}, error)
    pinned = PinnedTransport("hooks.example.com", _addresses("2001:db8::10", "192.0.2.10"), inner)
    resp = await pinned.handle_async_request(httpx.Request("POST", "https://hooks.example.com/in", content=b"x"))
    assert resp.status_code == 204
    assert inner.tried == ["2001:db8::10", "192.0.2.10"]
    assert inner.requests[0].headers["host"] == "hooks.example.com"
    assert inner.requests[0].extensions["sni_hostname"] == "hooks.example.com"


@pytest.mark.asyncio
async def test_all_addresses_down_raises_the_connect_error_after_a_bounded_number_of_tries():
    many = [f"192.0.2.{n}" for n in range(1, 9)]
    inner = _SomeAddressesDown(set(many))
    pinned = PinnedTransport("hooks.example.com", _addresses(*many), inner)
    with pytest.raises(httpx.ConnectError):
        await pinned.handle_async_request(httpx.Request("GET", "http://hooks.example.com/"))
    assert inner.tried == many[: outbound_http.MAX_PINNED_ADDRESSES]


@pytest.mark.asyncio
async def test_an_error_after_connecting_is_not_retried_on_another_address():
    inner = _SomeAddressesDown({"192.0.2.10"}, httpx.ReadTimeout)
    pinned = PinnedTransport("hooks.example.com", _addresses("192.0.2.10", "192.0.2.11"), inner)
    with pytest.raises(httpx.ReadTimeout):
        await pinned.handle_async_request(httpx.Request("POST", "http://hooks.example.com/", content=b"x"))
    assert inner.tried == ["192.0.2.10"]


def test_pinned_transport_needs_an_address():
    with pytest.raises(ValueError):
        PinnedTransport("hooks.example.com", [], _Recorder())


@pytest.mark.asyncio
async def test_a_supplied_transport_is_used_as_it_is(network):
    seen: list[httpx.Request] = []
    mock = httpx.MockTransport(lambda r: seen.append(r) or httpx.Response(200))
    await send_request("GET", "https://hooks.example.com/x", transport=mock)
    assert seen[0].url.host == "hooks.example.com"
    assert network == []


def test_environment_proxy_detection(monkeypatch):
    for name in ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(outbound_http.urllib.request, "getproxies", lambda: {})
    assert outbound_http._env_proxy_applies("https://hooks.example.com/") is False
    proxies = {"https": "http://proxy.example.com:3128", "no": "skip.example.com"}
    monkeypatch.setattr(outbound_http.urllib.request, "getproxies", lambda: proxies)
    monkeypatch.setenv("no_proxy", "skip.example.com")
    assert outbound_http._env_proxy_applies("https://hooks.example.com/") is True
    assert outbound_http._env_proxy_applies("https://skip.example.com/") is False
    assert outbound_http._env_proxy_applies("http://hooks.example.com/") is False


# ── Identity providers (SAML metadata import, every OIDC request) ────────────


@pytest.mark.asyncio
async def test_an_identity_provider_request_goes_to_the_checked_address(monkeypatch, network):
    resolver = _rebinding_resolver(["192.0.2.20", "169.254.169.254"])
    monkeypatch.setattr(net_guard, "_getaddrinfo", resolver)

    await sso.provider_request("POST", "https://idp.example.com/token", data={"grant_type": "authorization_code"})

    sent = network[0].requests[0]
    assert sent.url.host == "192.0.2.20" and sent.url.path == "/token"
    assert sent.headers["host"] == "idp.example.com"
    assert sent.extensions["sni_hostname"] == "idp.example.com"
    assert sent.headers["content-type"] == "application/x-www-form-urlencoded"
    assert network[0].kwargs["verify"] is True
    assert resolver.calls["n"] == 1


@pytest.mark.asyncio
async def test_saml_metadata_import_is_pinned(monkeypatch, network):
    resolver = _rebinding_resolver(["192.0.2.21", "169.254.169.254"])
    monkeypatch.setattr(net_guard, "_getaddrinfo", resolver)

    # The stand-in network answers 204, which the import refuses after sending.
    with pytest.raises(saml.SamlError, match="HTTP 204"):
        await saml.fetch_metadata("https://idp.example.com/metadata")

    assert [r.url.host for r in network[0].requests] == ["192.0.2.21"]
    assert resolver.calls["n"] == 1


@pytest.mark.asyncio
async def test_a_refused_identity_provider_address_is_not_sent(monkeypatch, network):
    monkeypatch.setattr(net_guard, "_getaddrinfo", _rebinding_resolver(["169.254.169.254"]))
    with pytest.raises(sso.SsoError, match="not allowed") as refused:
        await sso.provider_request("GET", "https://idp.example.com/userinfo", code="claims")
    assert refused.value.code == "claims"
    assert network == []


# ── Bounded responses (max_bytes, total_timeout_s) ───────────────────────────


def _answering(handler) -> httpx.MockTransport:
    return httpx.MockTransport(handler)


@pytest.mark.asyncio
async def test_bounded_response_within_the_limit_reads_like_a_normal_one(monkeypatch):
    monkeypatch.setattr(net_guard, "_getaddrinfo", _rebinding_resolver(["192.0.2.10"]))
    transport = _answering(lambda request: httpx.Response(200, json={"version": "1.2.3"}))

    resp = await send_request("GET", "https://peer.example.com/api", transport=transport, max_bytes=1024)

    assert resp.status_code == 200
    assert resp.json() == {"version": "1.2.3"}
    assert resp.request.url.host == "peer.example.com"


@pytest.mark.asyncio
async def test_bounded_response_past_the_limit_is_refused_before_it_is_all_read(monkeypatch):
    monkeypatch.setattr(net_guard, "_getaddrinfo", _rebinding_resolver(["192.0.2.10"]))
    sent = {"chunks": 0}

    async def endless():
        while True:
            sent["chunks"] += 1
            yield b"x" * 1024

    transport = _answering(lambda request: httpx.Response(200, content=endless()))

    with pytest.raises(ResponseTooLargeError):
        await send_request("GET", "https://peer.example.com/api", transport=transport, max_bytes=4096)
    assert sent["chunks"] <= 6
    # It is an httpx error, so a caller's transport-failure handling covers it.
    assert issubclass(ResponseTooLargeError, httpx.HTTPError)


@pytest.mark.asyncio
async def test_bounded_response_counts_decoded_bytes(monkeypatch):
    """A small compressed body that inflates past the limit is refused, and
    one within it is returned decoded once."""
    monkeypatch.setattr(net_guard, "_getaddrinfo", _rebinding_resolver(["192.0.2.10"]))

    def gz(payload: bytes):
        return lambda request: httpx.Response(200, content=gzip.compress(payload), headers={"content-encoding": "gzip"})

    with pytest.raises(ResponseTooLargeError):
        await send_request(
            "GET", "https://peer.example.com/api", transport=_answering(gz(b"0" * 500_000)), max_bytes=10_000
        )
    resp = await send_request(
        "GET", "https://peer.example.com/api", transport=_answering(gz(b'{"ok": true}')), max_bytes=10_000
    )
    assert resp.json() == {"ok": True}


@pytest.mark.asyncio
async def test_total_timeout_ends_a_response_that_trickles(monkeypatch):
    monkeypatch.setattr(net_guard, "_getaddrinfo", _rebinding_resolver(["192.0.2.10"]))

    async def trickle():
        while True:
            await asyncio.sleep(0.01)
            yield b"x"

    transport = _answering(lambda request: httpx.Response(200, content=trickle()))

    with pytest.raises(TimeoutError) as ended:
        await send_request(
            "GET", "https://peer.example.com/api", transport=transport, max_bytes=1_000_000, total_timeout_s=0.2
        )
    # Also an httpx timeout, so a caller's transport-failure handling covers it.
    assert isinstance(ended.value, ExchangeTimeoutError)
    assert isinstance(ended.value, httpx.TimeoutException)
    assert ended.value.request.url.host == "peer.example.com"


def _endless(sent: dict, chunk: int = 1024):
    async def body():
        while True:
            sent["chunks"] += 1
            yield b"x" * chunk

    return _answering(lambda request: httpx.Response(200, content=body()))


@pytest.mark.asyncio
async def test_a_caller_that_names_no_limit_gets_the_default_one(monkeypatch):
    monkeypatch.setattr(net_guard, "_getaddrinfo", _rebinding_resolver(["192.0.2.10"]))
    sent = {"chunks": 0}
    chunk = 64 * 1024

    with pytest.raises(ResponseTooLargeError):
        await send_request("POST", "https://hooks.example.com/in", transport=_endless(sent, chunk))

    assert sent["chunks"] <= DEFAULT_MAX_RESPONSE_BYTES // chunk + 2


@pytest.mark.asyncio
async def test_truncate_cuts_a_long_answer_and_keeps_the_status(monkeypatch):
    """A sender that only delivers does not fail a delivered message over
    the size of the answer; it stops reading at the limit."""
    monkeypatch.setattr(net_guard, "_getaddrinfo", _rebinding_resolver(["192.0.2.10"]))
    sent = {"chunks": 0}

    resp = await send_request(
        "POST", "https://hooks.example.com/in", transport=_endless(sent), max_bytes=4096, truncate=True
    )

    assert resp.status_code == 200
    assert resp.content == b"x" * 4096
    assert sent["chunks"] <= 6


@pytest.mark.asyncio
async def test_an_exchange_without_a_deadline_of_its_own_still_ends(monkeypatch):
    monkeypatch.setattr(net_guard, "_getaddrinfo", _rebinding_resolver(["192.0.2.10"]))
    monkeypatch.setattr(outbound_http, "MIN_TOTAL_TIMEOUT_SECONDS", 0.1)
    monkeypatch.setattr(outbound_http, "TOTAL_TIMEOUT_FACTOR", 2)

    async def trickle():
        while True:
            await asyncio.sleep(0.01)
            yield b"x"

    transport = _answering(lambda request: httpx.Response(200, content=trickle()))

    with pytest.raises(ExchangeTimeoutError, match="0.2 seconds"):
        await send_request("GET", "https://hooks.example.com/in", transport=transport, timeout_s=0.1)


@pytest.mark.asyncio
async def test_an_identity_provider_answer_past_the_limit_is_refused(monkeypatch):
    monkeypatch.setattr(net_guard, "_getaddrinfo", _rebinding_resolver(["192.0.2.21"]))
    big = _answering(lambda request: httpx.Response(200, content=b"x" * (sso.MAX_RESPONSE_BYTES + 1)))

    with pytest.raises(sso.SsoError, match="too large") as refused:
        await sso.provider_request("GET", "https://idp.example.com/jwks", transport=big, code="token")
    assert refused.value.code == "token"
