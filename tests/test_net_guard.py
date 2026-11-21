"""The outbound SSRF guard (netcontrol/routes/net_guard.py): which literal
addresses it refuses by default and with ``APP_SSRF_BLOCK_PRIVATE`` on."""

from __future__ import annotations

import socket

import pytest
from netcontrol.routes import net_guard
from netcontrol.routes.net_guard import OutboundRequestError, validate_outbound_host, validate_outbound_url


@pytest.mark.parametrize("host", ["127.0.0.1", "::1", "10.0.0.5", "192.168.1.10", "fd00::10"])
def test_loopback_and_private_addresses_pass_by_default(host):
    # ``::1`` sits in the reserved ``::/8`` block; it is still loopback.
    validate_outbound_host(host, block_private=False)
    with pytest.raises(OutboundRequestError, match="disallowed address"):
        validate_outbound_host(host, block_private=True)


@pytest.mark.parametrize(
    "host",
    ["169.254.169.254", "fe80::1", "::ffff:169.254.169.254", "0.0.0.0", "::", "224.0.0.1", "ff02::1", "240.0.0.1"],
)
def test_link_local_multicast_reserved_and_unspecified_are_always_refused(host):
    with pytest.raises(OutboundRequestError, match="disallowed address"):
        validate_outbound_host(host, block_private=False)


def test_url_form_and_allow_list(monkeypatch):
    validate_outbound_url("http://[::1]:8080/hook", block_private=False)
    with pytest.raises(OutboundRequestError, match="scheme"):
        validate_outbound_url("ftp://192.0.2.10/file")
    with pytest.raises(OutboundRequestError, match="no host"):
        validate_outbound_url("https:///path")
    with pytest.raises(OutboundRequestError, match="disallowed address"):
        validate_outbound_url("https://169.254.169.254/latest/meta-data/")
    monkeypatch.setenv("APP_SSRF_ALLOW", "169.254.10.1, 10.0.0.5")
    validate_outbound_url("https://169.254.10.1/status")
    validate_outbound_host("10.0.0.5", block_private=True)


# ── Always-blocked metadata addresses, fail-closed resolution ────────────────


def _resolver(answers):
    """A fake ``getaddrinfo``: ``answers`` maps a name to its addresses; any
    other name fails to resolve. No real DNS is asked."""

    def fake(host):
        if host not in answers:
            raise socket.gaierror(socket.EAI_NONAME, "Name or service not known")
        return [(socket.AF_INET6 if ":" in a else socket.AF_INET, socket.SOCK_STREAM, 6, "", (a, 0)) for a in answers[host]]

    return fake


@pytest.mark.parametrize(
    "host", ["169.254.169.254", "fd00:ec2::254", "::ffff:169.254.169.254", "169.254.170.2", "fd00:ec2::23"]
)
def test_metadata_addresses_are_refused_even_when_allow_listed(monkeypatch, host):
    monkeypatch.setenv("APP_SSRF_ALLOW", host)
    with pytest.raises(OutboundRequestError, match="cloud metadata address"):
        validate_outbound_host(host, block_private=False)


def test_aws_ipv6_metadata_address_is_refused_by_default():
    # fd00:ec2::254 is unique-local, not link-local: before the explicit
    # list it passed whenever private ranges were allowed.
    with pytest.raises(OutboundRequestError, match="disallowed address"):
        validate_outbound_url("http://[fd00:ec2::254]/latest/meta-data/", block_private=False)


def test_allow_listed_name_resolving_to_metadata_is_refused(monkeypatch):
    monkeypatch.setattr(net_guard, "_getaddrinfo", _resolver({"imds.example.com": ["fd00:ec2::254"]}))
    monkeypatch.setenv("APP_SSRF_ALLOW", "imds.example.com")
    with pytest.raises(OutboundRequestError, match="cloud metadata address"):
        validate_outbound_url("https://imds.example.com/")


def test_a_name_that_does_not_resolve_is_refused(monkeypatch):
    monkeypatch.setattr(net_guard, "_getaddrinfo", _resolver({}))
    with pytest.raises(OutboundRequestError, match="does not resolve"):
        validate_outbound_url("https://nowhere.example.com/hook")


def test_an_allow_listed_name_that_does_not_resolve_passes(monkeypatch):
    monkeypatch.setattr(net_guard, "_getaddrinfo", _resolver({}))
    monkeypatch.setenv("APP_SSRF_ALLOW", "lab-idp.example.com")
    assert validate_outbound_url("https://LAB-IDP.example.com/") == []


def test_validation_returns_the_checked_addresses(monkeypatch):
    monkeypatch.setattr(
        net_guard, "_getaddrinfo", _resolver({"hooks.example.com": ["192.0.2.10", "192.0.2.10", "2001:db8::10"]})
    )
    ips = validate_outbound_url("https://hooks.example.com/x")
    assert [str(ip) for ip in ips] == ["192.0.2.10", "2001:db8::10"]
    assert [str(ip) for ip in validate_outbound_host("203.0.113.5")] == ["203.0.113.5"]


def test_any_blocked_answer_refuses_the_name(monkeypatch):
    # A name with one good and one metadata answer is refused: the connection
    # could go to either.
    monkeypatch.setattr(
        net_guard, "_getaddrinfo", _resolver({"mixed.example.com": ["192.0.2.20", "169.254.169.254"]})
    )
    with pytest.raises(OutboundRequestError, match="disallowed address"):
        validate_outbound_url("https://mixed.example.com/")
