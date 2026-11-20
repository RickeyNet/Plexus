"""The outbound SSRF guard (netcontrol/routes/net_guard.py): which literal
addresses it refuses by default and with ``APP_SSRF_BLOCK_PRIVATE`` on."""

from __future__ import annotations

import pytest
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
    monkeypatch.setenv("APP_SSRF_ALLOW", "169.254.169.254, 10.0.0.5")
    validate_outbound_url("https://169.254.169.254/latest/meta-data/")
    validate_outbound_host("10.0.0.5", block_private=True)
