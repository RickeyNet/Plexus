"""Tests for the Palo Alto Panorama topology integration.

Covers the pipeline with no network access:
  * xml_to_data      - entry / member lists, repeated tags, attributes
  * PanoramaClient   - API key in a header (never in the URL), keygen as a
                       POST, refused credentials not retried, absent config
                       nodes, retries, key renewal, DTD refusal, URL trust
  * collector        - every part of a full read against a fake Panorama
                       serving the bundled sample as XML, best-effort past
                       the device list, secret scrubbing, a disconnected
                       firewall, the device group subtree, the Advanced
                       Routing Engine
  * normalize        - HA pair box, WAN stubs, the detail sections of the
                       contract, template variables, the effective rule
                       order with targets and default rules, NAT, tunnels,
                       GlobalProtect users, the Panorama node
  * subnets / merge  - the subnet index, the merge into the Topology graph,
                       the VM-Series joined to its AWS instance
  * forwarding       - interfaces, routes, IPsec, the security policy, NAT
  * HTTP API         - CRUD (the secret stays write-only), sample, build job,
                       validation, and Path Mode traces through the sample
"""

from __future__ import annotations

import asyncio
import copy
import json
import xml.etree.ElementTree as ElementTree
from urllib.parse import parse_qs

import httpx
import netcontrol.app as app_module
import pytest
from netcontrol.integrations.aws.normalize import build_snapshot as build_aws_snapshot
from netcontrol.integrations.aws.sample import build_sample as build_aws_sample
from netcontrol.integrations.meraki.normalize import VPN_PEER_SITE_ID
from netcontrol.integrations.meraki.subnets import subnet_index
from netcontrol.integrations.meraki.unified import merge_meraki_into_graph, node_details, virtual_appliance_pairs
from netcontrol.integrations.panorama import collector as collector_module
from netcontrol.integrations.panorama.client import (
    PanoramaApiError,
    PanoramaClient,
    validate_base_url,
    xml_to_data,
)
from netcontrol.integrations.panorama.collector import (
    COMMAND_DEVICE_GROUPS,
    COMMAND_DEVICES,
    COMMAND_SYSTEM_INFO,
    COMMAND_TEMPLATE_STACKS,
    COMMAND_TEMPLATES,
    DEFAULT_OPTIONS,
    OBJECT_KINDS,
    PANORAMA_ROOT,
    READONLY_DEVICE_GROUPS,
    STATE_COMMANDS,
    TEMPLATE_PARTS,
    TEMPLATE_STACKS,
    collect_panorama,
    sanitize_options,
    scope_root,
    template_device_xpath,
)
from netcontrol.integrations.panorama.normalize import PANORAMA_NODE_ID, PANORAMA_SITE_ID, build_snapshot
from netcontrol.integrations.panorama.sample import AWS_VM, BRANCH, HQ_1, HQ_2, PARTNER_PEER, build_sample_raw
from netcontrol.integrations.software.versions import snapshot_devices

API_KEY = "LUFRPT1-test-key=="
GENERATED_KEY = "LUFRPT1-generated=="
PSK = "pre-shared-secret-value"

# ── A fake Panorama serving the sample as XML ────────────────────────────────


def _element(tag: str, value) -> ElementTree.Element:
    """The XML ``xml_to_data`` reads back as ``value``."""
    element = ElementTree.Element(tag)
    if isinstance(value, dict):
        for key, child in value.items():
            if key.startswith("@"):
                element.set(key[1:], str(child))
            elif key == "#text":
                element.text = str(child)
            elif key in ("entry", "member") and isinstance(child, list):
                for item in child:
                    element.append(_element(key, item))
            elif isinstance(child, list):
                element.append(_list(key, child))
            elif child is not None:
                element.append(_element(key, child))
    elif isinstance(value, list):
        return _list(tag, value)
    elif value is not None:
        element.text = str(value)
    return element


def _list(tag: str, items: list) -> ElementTree.Element:
    element = ElementTree.Element(tag)
    for item in items:
        if isinstance(item, dict):
            element.append(_element("entry", item))
        else:
            ElementTree.SubElement(element, "member").text = str(item)
    return element


def _response(result=None, *, leaf: str = "", status: str = "success", code: str = "", msg: str = "") -> bytes:
    root = ElementTree.Element("response", {"status": status, **({"code": code} if code else {})})
    if msg:
        ElementTree.SubElement(ElementTree.SubElement(root, "msg"), "line").text = msg
    holder = ElementTree.SubElement(root, "result")
    if result in (None, "", [], {}):
        pass
    elif leaf:
        holder.append(_element(leaf, result))
    elif isinstance(result, list):
        for item in result:
            holder.append(_element("entry", item))
    else:
        for child in _element("result", result):
            holder.append(child)
    return ElementTree.tostring(root)


def _xml(content: bytes, status: int = 200) -> httpx.Response:
    return httpx.Response(status, content=content, headers={"Content-Type": "application/xml"})


class _FakePanorama:
    """A Panorama serving the sample data, with knobs for failure cases."""

    def __init__(self) -> None:
        self.raw = build_sample_raw()
        self.key = API_KEY
        self.keygens = 0
        self.calls: list[dict[str, str]] = []
        self.urls: list[str] = []
        self.fail: dict[str, int] = {}  # cmd / xpath fragment -> HTTP status
        self.refuse: dict[str, str] = {}  # fragment -> PAN-OS error message (HTTP 200, status error)
        self.advanced_routing: set[str] = set()
        self.expire_key_once = False

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.urls.append(str(request.url))
        if request.method == "POST":
            form = {k: v[0] for k, v in parse_qs(request.content.decode()).items()}
            assert form["type"] == "keygen"
            if (form.get("user"), form.get("password")) != ("plexus", "s3cret"):
                return _xml(_response(status="error", code="403", msg="Invalid Credential"), 403)
            self.keygens += 1
            self.key = GENERATED_KEY + str(self.keygens)
            return _xml(_response({"key": self.key}))
        params = dict(request.url.params)
        self.calls.append(params)
        if request.headers.get("X-PAN-KEY") != self.key or self.expire_key_once:
            self.expire_key_once = False
            detail = "API key expired" if self.keygens else "Invalid Credential"
            return _xml(_response(status="error", code="403", msg=detail), 403)
        what = params.get("cmd") or params.get("xpath") or ""
        for fragment, status in self.fail.items():
            if fragment in what:
                return _xml(_response(status="error", msg=f"Refused {fragment}"), status)
        for fragment, message in self.refuse.items():
            if fragment in what:
                return _xml(_response(status="error", code="17", msg=message))
        if params["type"] == "version":
            return _xml(
                _response(
                    {"sw-version": "11.1.4-h7", "multi-vsys": "off", "model": "Panorama", "serial": "000710000301"}
                )
            )
        if params["type"] == "op":
            return self._op(params["cmd"], params.get("target", ""))
        assert params["type"] == "config" and params["action"] == "show"
        return self._config(params["xpath"])

    def _op(self, cmd: str, target: str) -> httpx.Response:
        raw = self.raw
        if not target:
            simple = {
                COMMAND_SYSTEM_INFO: ({"hostname": "panorama-01", "ip-address": "10.210.2.30"}, "system"),
                COMMAND_DEVICES: (raw["devices"], "devices"),
                COMMAND_DEVICE_GROUPS: (raw["device_groups"], "devicegroups"),
                COMMAND_TEMPLATES: (raw["templates"], "templates"),
                COMMAND_TEMPLATE_STACKS: (raw["template_stacks"], "template-stack"),
            }
            result, leaf = simple[cmd]
            return _xml(_response(result, leaf=leaf))
        key = next(k for k, c, _o in STATE_COMMANDS if c == cmd)
        if key == "routes" and target in self.advanced_routing:
            return _xml(
                _response(status="error", msg="Advanced routing engine is enabled; use show advanced-routing commands")
            )
        value = raw["state"][target].get(key)
        return _xml(_response(value))

    def _config_paths(self) -> dict[str, tuple[object, str]]:
        raw = self.raw
        paths: dict[str, tuple[object, str]] = {
            READONLY_DEVICE_GROUPS: (
                [{"@name": g, **({"parent-dg": p} if p else {})} for g, p in raw["dg_parents"].items()],
                "",
            ),
            TEMPLATE_STACKS: (raw["stack_config"], "template-stack"),
        }
        for scope, kinds in raw["objects"].items():
            for kind in OBJECT_KINDS:
                paths[f"{scope_root(scope)}/{kind}"] = (kinds.get(kind), kind)
        for scope, bases in raw["security_rules"].items():
            for base, rules in bases.items():
                paths[f"{scope_root(scope)}/{base}-rulebase/security/rules"] = (rules, "rules")
        for scope, rules in raw["default_rules"].items():
            paths[f"{scope_root(scope)}/post-rulebase/default-security-rules/rules"] = (rules, "rules")
        for scope, bases in raw["nat_rules"].items():
            for base, rules in bases.items():
                paths[f"{scope_root(scope)}/{base}-rulebase/nat/rules"] = (rules, "rules")
        for name, config in raw["template_config"].items():
            paths[f"{PANORAMA_ROOT}/template/entry[@name='{name}']/variable"] = (config["variable"], "variable")
            for key, path, _option, _phase in TEMPLATE_PARTS:
                value = copy.deepcopy(config[key])
                if key == "ike-gateway":
                    # A real Panorama answers with the pre-shared key; it must never be kept.
                    for gateway in value:
                        gateway["authentication"] = {"pre-shared-key": {"key": PSK}}
                paths[f"{template_device_xpath(name)}/{path}"] = (value, path.rsplit("/", 1)[-1])
        return paths

    def _config(self, xpath: str) -> httpx.Response:
        found = self._config_paths().get(xpath)
        if found is None:
            return _xml(_response(status="error", code="7", msg="No such node"))
        value, leaf = found
        return _xml(_response(value, leaf=leaf))


def _client(fake: _FakePanorama, **kwargs) -> PanoramaClient:
    kwargs.setdefault("requests_per_second", 1000)
    kwargs.setdefault("api_key", API_KEY)
    return PanoramaClient("https://panorama.example.com", transport=httpx.MockTransport(fake.handler), **kwargs)


def _section(entity: dict, title: str) -> dict:
    return next(s for s in entity["sections"] if s["title"] == title)


def _titles(entity: dict) -> list[str]:
    return [s["title"] for s in entity["sections"]]


def _node(snapshot: dict, node_id: str) -> dict:
    return next(n for n in snapshot["nodes"] if n["id"] == node_id)


def _kv(entity: dict, title: str) -> dict[str, str]:
    return dict(_section(entity, title)["rows"])


def _table(entity: dict, title: str) -> list[dict[str, str]]:
    section = _section(entity, title)
    return [dict(zip(section["columns"], row, strict=False)) for row in section["rows"]]


# ── XML and client ───────────────────────────────────────────────────────────


def test_xml_to_data_reads_entries_members_and_attributes():
    element = ElementTree.fromstring(
        b"""<rules>
              <entry name="a" uuid="1" admin="me"><from><member>trust</member></from><action>allow</action></entry>
              <entry name="b"><target><devices><entry name="0001"/></devices><negate>no</negate></target></entry>
            </rules>"""
    )
    assert xml_to_data(element) == [
        {"@name": "a", "@uuid": "1", "from": ["trust"], "action": "allow"},
        {"@name": "b", "target": {"devices": [{"@name": "0001"}], "negate": "no"}},
    ]
    mixed = ElementTree.fromstring(b"<r><flags>A</flags><entry><d>x</d></entry><ip>1</ip><ip>2</ip><e/></r>")
    assert xml_to_data(mixed) == {"flags": "A", "entry": [{"d": "x"}], "ip": ["1", "2"], "e": ""}
    assert xml_to_data(ElementTree.fromstring(b'<m loc="shared">x</m>')) == {"@loc": "shared", "#text": "x"}


@pytest.mark.asyncio
async def test_client_sends_the_key_in_a_header_never_in_the_url():
    fake = _FakePanorama()
    async with _client(fake) as client:
        await client.login()
        devices = await client.op(COMMAND_DEVICES)
    assert [d["hostname"] for d in devices] == ["hq-fw-01", "hq-fw-02", "branch-fw-01", "aws-vm-fw-01"]
    assert client.info["sw-version"] == "11.1.4-h7"
    assert fake.keygens == 0 and fake.urls and not any(API_KEY in url or "key=" in url for url in fake.urls)


@pytest.mark.asyncio
async def test_client_generates_a_key_with_a_post_and_never_sends_the_password_in_the_url():
    fake = _FakePanorama()
    async with _client(fake, api_key="", username="plexus", password="s3cret") as client:
        info = await client.version()
        await client.op(COMMAND_DEVICES)
    assert info["model"] == "Panorama" and fake.keygens == 1
    assert not any("s3cret" in url or "password" in url for url in fake.urls)


@pytest.mark.asyncio
async def test_client_rejected_credentials_are_not_retried():
    fake = _FakePanorama()
    client = _client(fake, api_key="", username="plexus", password="wrong")
    with pytest.raises(PanoramaApiError) as excinfo:
        await client.login()
    assert excinfo.value.status_code == 403 and "Invalid Credential" in excinfo.value.detail
    assert len(fake.urls) == 1
    bad_key = _client(_FakePanorama(), api_key="not-the-key")
    with pytest.raises(PanoramaApiError) as excinfo:
        await bad_key.login()
    assert excinfo.value.status_code == 403


@pytest.mark.asyncio
async def test_client_renews_an_expired_key_once_when_it_knows_the_user():
    fake = _FakePanorama()
    async with _client(fake, api_key="", username="plexus", password="s3cret") as client:
        await client.login()
        fake.expire_key_once = True
        assert await client.op(COMMAND_DEVICES)
    assert fake.keygens == 2


@pytest.mark.asyncio
async def test_client_absent_config_is_none_and_other_errors_raise():
    fake = _FakePanorama()
    async with _client(fake) as client:
        assert await client.config_show("/config/shared/no-such-thing") is None
        fake.refuse = {"devicegroups": "Command is not supported"}
        with pytest.raises(PanoramaApiError) as excinfo:
            await client.op(COMMAND_DEVICE_GROUPS)
    assert excinfo.value.code == "17" and excinfo.value.status_code is None
    assert excinfo.value.detail == "Command is not supported"


@pytest.mark.asyncio
async def test_client_retries_server_errors_then_succeeds(monkeypatch):
    import netcontrol.integrations.panorama.client as client_module

    async def _no_sleep(_seconds):
        return None

    monkeypatch.setattr(client_module.asyncio, "sleep", _no_sleep)
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] == 2:
            return httpx.Response(503)
        if calls["n"] == 3:
            return httpx.Response(429, headers={"Retry-After": "1"})
        return _xml(_response({"sw-version": "11.1.4", "model": "Panorama"}))

    client = PanoramaClient(
        "https://panorama.example.com",
        api_key=API_KEY,
        transport=httpx.MockTransport(handler),
        requests_per_second=1000,
    )
    await client.login()
    assert await client.op("<show><x/></show>") == {"sw-version": "11.1.4", "model": "Panorama"}
    assert client.stats["retries"] == 2 and client.stats["rate_limited"] == 1


@pytest.mark.asyncio
async def test_client_refuses_a_document_type_declaration():
    def handler(_request: httpx.Request) -> httpx.Response:
        body = b'<?xml version="1.0"?><!DOCTYPE r [<!ENTITY a "aaaa">]><response status="success"><result/></response>'
        return _xml(body)

    client = PanoramaClient("https://p.example.com", api_key=API_KEY, transport=httpx.MockTransport(handler))
    with pytest.raises(PanoramaApiError) as excinfo:
        await client.login()
    assert "document type" in str(excinfo.value)


def test_base_url_must_be_the_https_panorama_host():
    assert validate_base_url("panorama.example.com") == "https://panorama.example.com"
    assert validate_base_url("https://10.1.1.5:8443/") == "https://10.1.1.5:8443"
    for bad in (
        "",
        "http://p.example.com",
        "https://u:pw@p.example.com",
        "https://p.example.com/api/",
        "https://p?x=1",
    ):
        with pytest.raises(ValueError):
            validate_base_url(bad)


def test_sanitize_options_defaults_and_coerces():
    opts = sanitize_options({"username": " ro ", "include_nat": 0, "device_name_contains": " hq ", "bogus": 1})
    assert opts["username"] == "ro" and opts["include_nat"] is False and opts["verify_tls"] is True
    assert opts["device_name_contains"] == "hq" and "bogus" not in opts
    assert set(collector_module._BOOL_OPTIONS) == {k for k, v in DEFAULT_OPTIONS.items() if isinstance(v, bool)}
    assert all(sanitize_options(None)[k] is True for k in collector_module._BOOL_OPTIONS)


# ── Collector ────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_collect_panorama_reads_every_part():
    fake = _FakePanorama()
    progress: list[dict] = []
    async with _client(fake) as client:
        raw = await collect_panorama(client, "", None, progress.append)
    sample = build_sample_raw()
    assert raw["errors"] == [] and raw["unsupported"] == [] and raw["state_skipped"] == {}
    assert raw["panorama"]["version"] == "11.1.4-h7" and raw["panorama"]["hostname"] == "panorama-01"
    assert raw["on_map"] == sample["on_map"] and raw["dg_parents"] == sample["dg_parents"]
    assert raw["objects"] == sample["objects"] and raw["security_rules"] == sample["security_rules"]
    assert raw["nat_rules"] == sample["nat_rules"] and raw["default_rules"] == sample["default_rules"]
    assert raw["stack_config"] == sample["stack_config"]
    # The injected pre-shared key leaves an empty authentication behind.
    for config in raw["template_config"].values():
        for gateway in config["ike-gateway"]:
            assert gateway.pop("authentication") == {}
    assert raw["template_config"] == sample["template_config"]
    assert raw["state"] == sample["state"]
    assert progress[-1]["phase"] == "collected" and progress[-1]["calls_done"] == progress[-1]["calls_total"]
    assert list(dict.fromkeys(p["phase"] for p in progress)) == [
        "panorama login",
        "panorama devices",
        "panorama device groups",
        "panorama templates",
        "panorama objects",
        "panorama policies",
        "panorama nat",
        "panorama network",
        "panorama vpn",
        "panorama global protect",
        "panorama device state",
        "collected",
    ]
    # The operational commands go to each firewall through Panorama.
    targets = {c.get("target") for c in fake.calls if c.get("target")}
    assert targets == {HQ_1, HQ_2, BRANCH, AWS_VM}
    # The collected Panorama builds the same map as the bundled sample it was served from.
    assert build_snapshot(raw)["summary"] == build_snapshot(sample)["summary"]


@pytest.mark.asyncio
async def test_collect_panorama_never_keeps_a_pre_shared_key():
    fake = _FakePanorama()
    async with _client(fake) as client:
        raw = await collect_panorama(client, "", None)
    assert PSK not in json.dumps(raw)
    gateway = raw["template_config"]["HQ-Network"]["ike-gateway"][0]
    assert gateway["authentication"] == {} and gateway["peer-address"] == {"ip": "198.51.100.134"}


@pytest.mark.asyncio
async def test_collect_panorama_is_best_effort_past_the_device_list():
    fake = _FakePanorama()
    fake.fail = {"Corporate']/pre-rulebase/security": 500, "<show><vpn><flow/></vpn></show>": 500}
    async with _client(fake, max_retries=0) as client:
        raw = await collect_panorama(client, "", {"include_global_protect": False})
    paths = sorted(e["path"] for e in raw["errors"])
    assert paths[0] == "/device-group/entry[@name='Corporate']/pre-rulebase/security/rules"
    assert paths.count("<show><vpn><flow/></vpn></show>") == 4 and len(paths) == 5
    assert raw["security_rules"]["Corporate"]["pre"] == [] and "gp_users" not in raw["state"][HQ_1]
    snapshot = build_snapshot(raw)
    assert len(snapshot["collection"]["errors"]) == 5 and snapshot["summary"]["devices"] == 4
    # Without the flow table the IPsec SAs still tell the tunnels' state.
    hq = _node(snapshot, f"d:{HQ_1}")
    states = {r["Tunnel"]: r["State"] for r in _table(hq, "IPsec tunnels")}
    assert states == {"tun-branch": "up", "tun-partner": "down"}


@pytest.mark.asyncio
async def test_collect_panorama_fails_when_devices_unreadable():
    fake = _FakePanorama()
    fake.fail = {"<all/>": 403}
    async with _client(fake, max_retries=0) as client:
        with pytest.raises(PanoramaApiError) as excinfo:
            await collect_panorama(client, "")
    assert excinfo.value.status_code == 403
    with pytest.raises(PanoramaApiError) as excinfo:
        async with _client(_FakePanorama()) as client:
            await collect_panorama(client, "NoSuchGroup")
    assert "Corporate" in excinfo.value.detail


@pytest.mark.asyncio
async def test_collect_panorama_skips_the_state_of_a_disconnected_firewall():
    fake = _FakePanorama()
    fake.raw["devices"][2]["connected"] = "no"
    async with _client(fake) as client:
        raw = await collect_panorama(client, "", None)
    assert raw["state_skipped"] == {BRANCH: "not connected to Panorama"} and BRANCH not in raw["state"]
    assert not any(c.get("target") == BRANCH for c in fake.calls)
    snapshot = build_snapshot(raw)
    branch = _node(snapshot, f"d:{BRANCH}")
    assert branch["status"] == "offline"
    assert _kv(branch, "Overview")["Device state"] == "not read: not connected to Panorama"
    # The templates still give the branch its interfaces and its static routes.
    assert {r["Interface"]: r["IP address"] for r in _table(branch, "Firewall interfaces")}["ethernet1/1"] == (
        "198.51.100.134"
    )
    assert any(r["prefix"] == "10.150.0.0/16" and r["kind"] == "static" for r in branch["forwarding"]["routes"])


@pytest.mark.asyncio
async def test_collect_panorama_limits_to_a_device_group_subtree_and_a_name():
    fake = _FakePanorama()
    async with _client(fake) as client:
        raw = await collect_panorama(client, "branches", None)
    assert raw["on_map"] == [BRANCH] and raw["panorama"]["device_group"] == "Branches"
    # The objects and rules of the ancestors are read: the branch inherits them.
    assert set(raw["objects"]) == {"shared", "Branches", "Corporate"}
    assert set(raw["template_config"]) == {"Branch-Network", "Global-Base"}
    assert {c.get("target") for c in fake.calls if c.get("target")} == {BRANCH}
    async with _client(_FakePanorama()) as client:
        by_name = await collect_panorama(client, "", {"device_name_contains": "hq-fw-01"})
    # An HA member brings its peer: the pair is one box.
    assert by_name["on_map"] == [HQ_1, HQ_2]
    snapshot = build_snapshot(by_name)
    assert snapshot["summary"]["sites"] == 1 and snapshot["summary"]["devices"] == 2


@pytest.mark.asyncio
async def test_collect_panorama_lists_the_advanced_routing_engine_as_unsupported():
    fake = _FakePanorama()
    fake.advanced_routing = {AWS_VM}
    async with _client(fake) as client:
        raw = await collect_panorama(client, "", None)
    assert raw["errors"] == [] and raw["unsupported"] == ["advanced routing engine (aws-vm-fw-01)"]
    assert "routes" not in raw["state"][AWS_VM] and "bgp_peers" not in raw["state"][AWS_VM]
    vm = _node(build_snapshot(raw), f"d:{AWS_VM}")
    # The configured static routes stand in for the routing table.
    assert "Routing table" not in _titles(vm)
    assert {r["Destination"] for r in _table(vm, "Static routes")} == {"default", "to-vpcs"}


# ── Normalize ────────────────────────────────────────────────────────────────


@pytest.fixture(scope="module")
def snapshot() -> dict:
    return build_snapshot(build_sample_raw())


def test_snapshot_summary_counts_every_part(snapshot):
    summary = snapshot["summary"]
    assert snapshot["provider"] == "panorama" and snapshot["collection"]["sources"] == ["Palo Alto Panorama XML API"]
    assert summary["sites"] == 3 and summary["devices"] == 4 and summary["ha_pairs"] == 1
    assert summary["vpn_tunnels"] == 2 and summary["wan_uplinks"] == 4 and summary["remote_users"] == 3
    assert summary["device_groups"] == 2 and summary["security_rules"] == 13 and summary["nat_rules"] == 5


def test_snapshot_draws_the_ha_pair_as_one_box_active_first(snapshot):
    site = next(s for s in snapshot["sites"] if s["id"] == f"ha:{HQ_1}")
    assert site["name"] == "hq-fw-01 / hq-fw-02" and site["tags"] == ["ha"] and site["device_count"] == 2
    ha = next(e for e in snapshot["edges"] if e["kind"] == "stack")
    assert (ha["a"], ha["b"], ha["label"], ha["status"]) == (f"d:{HQ_1}", f"d:{HQ_2}", "HA", "active")
    assert (ha["a_port"], ha["b_port"]) == ("active", "passive")
    passive = _node(snapshot, f"d:{HQ_2}")
    assert _kv(passive, "Overview")["HA state"] == "passive" and _kv(passive, "Overview")["HA peer"] == "hq-fw-01"
    # The passive member forwards nothing: the active one owns the subnets.
    assert "Connected subnets" not in _titles(passive) and "Connected subnets (note)" in _titles(passive)
    assert passive["forwarding"] == _node(snapshot, f"d:{HQ_1}")["forwarding"]
    managed = [e for e in snapshot["edges"] if e["kind"] == "manage"]
    assert {e["b"] for e in managed} == {f"d:{s}" for s in (HQ_1, HQ_2, BRANCH, AWS_VM)}
    assert all(e["a"] == PANORAMA_NODE_ID for e in managed)
    assert _node(snapshot, PANORAMA_NODE_ID)["site"] == PANORAMA_SITE_ID


def test_snapshot_outside_interfaces_are_wan_stubs(snapshot):
    wans = {n["id"]: n for n in snapshot["nodes"] if n["kind"] == "wan"}
    assert set(wans) == {
        f"w:{HQ_1}:ethernet1/1",
        f"w:{HQ_2}:ethernet1/1",
        f"w:{BRANCH}:ethernet1/1",
        f"w:{AWS_VM}:ethernet1/1",
    }
    # The stack variable wins over the template's own value.
    assert wans[f"w:{HQ_1}:ethernet1/1"]["ip"] == "203.0.113.131"
    hq = _kv(wans[f"w:{HQ_1}:ethernet1/1"], "WAN interface")
    assert hq["GlobalProtect gateway"] == "GP-HQ-Gateway" and hq["Default route via"] == "203.0.113.129"
    # A private outside interface is outside because the default route leaves by it.
    assert _kv(wans[f"w:{AWS_VM}:ethernet1/1"], "WAN interface")["Default route via"] == "10.210.0.1"
    assert wans[f"w:{HQ_2}:ethernet1/1"]["status"] == "offline"


def test_snapshot_firewall_sections_follow_the_contract(snapshot):
    hq = _node(snapshot, f"d:{HQ_1}")
    titles = _titles(hq)
    for title in (
        "Overview",
        "Firewall interfaces",
        "Zones",
        "Connected subnets",
        "Static routes",
        "Routing table",
        "Virtual routers",
        "BGP",
        "BGP peers",
        "IKE gateways",
        "IPsec tunnels",
        "GlobalProtect gateways",
        "Security policy",
        "Security rules",
        "NAT rules",
    ):
        assert title in titles, title
    interfaces = {r["Interface"]: r for r in _table(hq, "Firewall interfaces")}
    assert interfaces["ethernet1/2"]["Zone"] == "trust" and interfaces["ethernet1/2"]["Subnet"] == "10.150.10.0/24"
    assert interfaces["tunnel.1"]["Type"] == "Tunnel" and interfaces["ethernet1/1"]["Source"] == "firewall"
    zones = {r["Zone"]: r for r in _table(hq, "Zones")}
    assert zones["vpn"]["Interfaces"] == "tunnel.1, tunnel.2" and zones["trust"]["Vsys"] == "vsys1"
    connected = _section(hq, "Connected subnets")
    assert connected["columns"] == ["Subnet", "Interface", "Name", "Zone", "Virtual router"]
    statics = _section(hq, "Static routes")
    assert statics["columns"][:2] == ["Destination", "Subnet"]
    assert ["to-branch", "10.151.0.0/16", "tunnel.1", "", "10", "default", "Yes", "No"] in statics["rows"]
    table = {r["Destination"]: r for r in _table(hq, "Routing table")}
    assert table["198.18.0.0/15"]["Protocol"] == "BGP" and table["0.0.0.0/0"]["Protocol"] == "Static"
    assert _kv(hq, "BGP")["Local AS"] == "65150"
    assert _table(hq, "BGP peers")[0] | {} == {
        "Peer": "isp-a",
        "Peer group": "ISP",
        "Peer address": "203.0.113.129",
        "Remote AS": "64500",
        "Local address": "203.0.113.131",
        "Virtual router": "default",
        "Enabled": "Yes",
        "State": "Established",
        "For (s)": "864000",
    }
    overview = _kv(hq, "Overview")
    assert overview["Software"] == "11.1.4-h7" and overview["Device group chain"] == "Shared > Corporate"
    assert overview["Template stack"] == "HQ-Stack" and overview["Templates"] == "HQ-Network, Global-Base"
    branch = _node(snapshot, f"d:{BRANCH}")
    assert _kv(branch, "Overview")["Device group chain"] == "Shared > Corporate > Branches"
    guest = {r["Interface"]: r for r in _table(branch, "Firewall interfaces")}["ethernet1/2.30"]
    assert (guest["Type"], guest["Tag"], guest["Zone"]) == ("Sub-interface", "30", "guest")


def test_snapshot_effective_rule_order_targets_and_default_rules(snapshot):
    branch = [(r["Name"], r["Rulebase"]) for r in _table(_node(snapshot, f"d:{BRANCH}"), "Security rules")]
    assert branch == [
        ("Block-Known-Bad", "Shared pre"),
        ("Allow-HQ-to-Branch", "Corporate pre"),
        ("Allow-Branch-to-HQ", "Corporate pre"),
        ("Allow-Trust-DMZ-HTTPS", "Corporate pre"),
        ("Users-Internet", "Corporate pre"),
        ("Legacy-FTP", "Corporate pre"),
        ("GP-Users-to-HQ", "Corporate pre"),
        ("Guest-Quarantine", "Branches pre"),
        ("Branch-Guest-Internet", "Branches pre"),
        ("Branch-Allow-HQ-In", "Branches pre"),
        ("Branch-Deny-Guest-to-LAN", "Branches post"),
        ("Deny-Telnet", "Corporate post"),
        ("intrazone-default", "default (Shared)"),
        ("interzone-default", "default (Shared)"),
    ]
    hq_rules = _table(_node(snapshot, f"d:{HQ_1}"), "Security rules")
    web = next(r for r in hq_rules if r["Name"] == "Allow-DMZ-Web")
    assert web["Service"] == "application-default" and web["Application"] == "Web-Apps"
    assert web["Destination"] == "web-public (203.0.113.132), web-server (10.150.50.10)"
    assert next(r for r in hq_rules if r["Name"] == "Legacy-FTP")["Enabled"] == "No"
    assert hq_rules[-1]["Log"] == "end" and hq_rules[-1]["Action"] == "deny"
    policy = _kv(_node(snapshot, f"d:{BRANCH}"), "Security policy")
    assert policy["Rules targeting other firewalls"] == "1" and policy["Disabled rules"] == "1"
    assert policy["Interzone default"] == "deny (Shared)" and policy["Local rules"].startswith("not collected")


def test_snapshot_nat_rules(snapshot):
    rows = {r["Name"]: r for r in _table(_node(snapshot, f"d:{HQ_1}"), "NAT rules")}
    assert list(rows) == ["No-NAT-VPN", "Web-DNAT", "Mail-Static", "Outbound-PAT"]
    assert rows["Web-DNAT"]["Destination translation"] == "web-server port 443"
    assert rows["Mail-Static"]["Source translation"] == "static IP mail-public, bi-directional"
    assert rows["Outbound-PAT"]["Source translation"] == "dynamic IP and port, interface ethernet1/1"
    assert rows["Web-DNAT"]["Service"] == "service-https (tcp/443)"
    branch = [r["Name"] for r in _table(_node(snapshot, f"d:{BRANCH}"), "NAT rules")]
    assert branch == ["No-NAT-VPN", "Outbound-PAT", "Branch-Outbound-PAT"]


def test_snapshot_tunnels_between_firewalls_and_to_a_peer(snapshot):
    vpn = next(e for e in snapshot["edges"] if e["kind"] == "vpn" and e.get("label") == "Site-to-site VPN")
    assert {vpn["a"], vpn["b"]} == {f"d:{HQ_1}", f"d:{BRANCH}"} and vpn["status"] == "reachable"
    assert {vpn["a_port"], vpn["b_port"]} == {"tunnel.1"}
    ipsec = next(e for e in snapshot["edges"] if e["kind"] == "vpn3p")
    assert (ipsec["a"], ipsec["b"], ipsec["status"]) == (f"d:{HQ_1}", f"p:{PARTNER_PEER}", "unreachable")
    peer = _node(snapshot, f"p:{PARTNER_PEER}")
    assert peer["site"] == VPN_PEER_SITE_ID and _kv(peer, "Site-to-site VPN peer")["Protected networks"] == (
        "172.16.40.0/24"
    )
    hq = _node(snapshot, f"d:{HQ_1}")
    tunnels = {r["Tunnel"]: r for r in _table(hq, "IPsec tunnels")}
    assert tunnels["tun-branch"]["Peer"] == "branch-fw-01" and tunnels["tun-partner"]["State"] == "down"
    assert tunnels["tun-partner"]["Proxy IDs"] == "10.150.10.0/24 > 172.16.40.0/24"
    assert {r["Gateway"]: r["Version"] for r in _table(hq, "IKE gateways")} == {
        "gw-branch": "IKEv2",
        "gw-partner": "IKEv1",
    }
    assert hq["endpoint_ips"] == ["203.0.113.131"] and "alias_ips" not in hq


def test_snapshot_globalprotect_users_and_pools(snapshot):
    users = _node(snapshot, f"u:{HQ_1}")
    assert users["label"] == "GlobalProtect users (3)" and users["kind"] == "users"
    assert [r["User"] for r in _table(users, "Connected users")] == ["alex.kim", "dana.reyes", "sam.okafor"]
    assert _node(snapshot, f"u:{HQ_2}")["label"] == "GlobalProtect users (0)"
    gateway = _table(_node(snapshot, f"d:{HQ_1}"), "GlobalProtect gateways")[0]
    assert gateway["Tunnel interface"] == "tunnel.10" and gateway["Address pools"] == "10.252.0.0/22"
    assert gateway["Connected users"] == "3" and gateway["Address"] == "203.0.113.131"
    site = next(s for s in snapshot["sites"] if s["id"] == f"ha:{HQ_1}")
    assert _section(site, "VPN address pools")["rows"] == [
        ["10.252.0.0/22", "10.252.0.0/22", "10.252.0.0/22", "GP-HQ-Gateway"]
    ]


def test_snapshot_panorama_node_lists_the_whole_panorama(snapshot):
    panorama = _node(snapshot, PANORAMA_NODE_ID)
    assert panorama["kind"] == "cloud" and panorama["ip"] == "10.210.2.30"
    info = _kv(panorama, "Palo Alto Panorama")
    assert info["Version"] == "11.1.4-h7" and info["Firewalls managed"] == "4" and info["HA pairs"] == "1"
    assert info["Device groups"] == "2" and info["Firewalls pending push"] == "1"
    for title in (
        "Managed firewalls",
        "High availability pairs",
        "Device groups",
        "Templates",
        "Template stacks",
        "Address objects",
        "Address groups",
        "Services",
        "Service groups",
        "Pending push",
    ):
        assert title in _titles(panorama), title
    assert _table(panorama, "Pending push") == [
        {
            "Firewall": "aws-vm-fw-01",
            "Device group": "Corporate",
            "Template stack": "AWS-Stack",
            "Out of sync": "shared policy",
            "Shared policy": "Out of Sync",
            "Template": "In Sync",
        }
    ]
    groups = {r["Device group"]: r for r in _table(panorama, "Device groups")}
    assert groups["Branches"]["Parent"] == "Corporate" and groups["Corporate"]["Parent"] == "Shared"
    addresses = {r["Name"]: r for r in _table(panorama, "Address objects")}
    assert addresses["Blocked-Range"]["Location"] == "Shared" and addresses["HQ-LAN"]["Location"] == "Corporate"
    dynamic = next(r for r in _table(panorama, "Address groups") if r["Name"] == "Quarantined-Hosts")
    assert dynamic["Type"] == "Dynamic" and dynamic["Members / filter"] == "'quarantine'"
    stacks = {r["Template stack"]: r for r in _table(panorama, "Template stacks")}
    assert stacks["HQ-Stack"]["Firewalls"] == "hq-fw-01, hq-fw-02"


def test_software_tracker_reads_pan_os_and_panorama(snapshot):
    devices = {d["name"]: d for d in snapshot_devices(snapshot, "panorama")}
    assert devices["hq-fw-01"]["platform"] == "pan-os" and devices["hq-fw-01"]["version"]
    assert devices["Panorama panorama-01"]["platform"] == "panorama"
    assert len(devices) == 5


# ── Subnets and merge ────────────────────────────────────────────────────────


def test_subnet_index_lists_connected_subnets_routes_and_pools(snapshot):
    index = {(s["cidr"], s["node_id"]): s for s in subnet_index(snapshot)}
    trust = index[("10.150.10.0/24", f"d:{HQ_1}")]
    assert trust["kind"] == "connected" and trust["name"] == "Corporate LAN (trust)"
    assert not any(node == f"d:{HQ_2}" for _cidr, node in index)
    assert index[("10.151.0.0/16", f"d:{HQ_1}")]["name"] == "Static route to-branch"
    assert index[("10.252.0.0/22", f"d:{HQ_1}")]["kind"] == "pool"
    assert index[("10.151.30.0/24", f"d:{BRANCH}")]["name"] == "Guest Wi-Fi (guest)"
    assert not any(s["site_id"] in (PANORAMA_SITE_ID, VPN_PEER_SITE_ID) for s in index.values())


def test_merge_marks_panorama_nodes_and_links(snapshot):
    nodes: dict = {}
    edges: list[dict] = []
    merge_meraki_into_graph(nodes, edges, [(9, snapshot)], host_node=lambda _id: None, resolve_external=lambda *_: None)
    firewall = nodes[f"meraki:9:d:{HQ_1}"]
    assert firewall["device_type"] == "panorama" and firewall["device_category"] == "firewall"
    assert firewall["meraki"]["provider"] == "panorama"
    assert nodes[f"meraki:9:{PANORAMA_NODE_ID}"]["meraki"]["kind"] == "cloud"
    assert {"management", "stack", "vpn", "vpn-ipsec", "wan"} <= {e["protocol"] for e in edges}
    managed = next(e for e in edges if e["from"] == f"meraki:9:{PANORAMA_NODE_ID}")
    assert managed["protocol"] == "management"
    details = node_details(snapshot, f"d:{HQ_1}")
    assert details["provider"] == "panorama" and [s["title"] for s in details["site_addressing"]] == [
        "VPN address pools"
    ]


def test_merge_joins_the_vm_series_to_its_aws_instance(snapshot):
    resources, connections = build_aws_sample()
    aws = build_aws_snapshot([{"id": 1, "name": "AWS", "account_identifier": "sample"}], resources, connections, None)
    pairs = virtual_appliance_pairs([(9, snapshot), (-1, aws)])
    assert pairs[(-1, "i:i-0f9a001")] == (9, f"d:{AWS_VM}")
    nodes: dict = {}
    edges: list[dict] = []
    merge_meraki_into_graph(
        nodes, edges, [(9, snapshot), (-1, aws)], host_node=lambda _id: None, resolve_external=lambda *_: None
    )
    assert "meraki:-1:i:i-0f9a001" not in nodes
    vm = nodes[f"meraki:9:d:{AWS_VM}"]
    assert any(e["from"] == vm["id"] and e["protocol"] == "cloud" for e in edges)


# ── Forwarding ───────────────────────────────────────────────────────────────


def test_forwarding_block_of_the_hq_firewall(snapshot):
    block = _node(snapshot, f"d:{HQ_1}")["forwarding"]
    interfaces = {i["name"]: i for i in block["interfaces"]}
    assert interfaces["ethernet1/1"]["kind"] == "wan" and interfaces["tunnel.1"]["kind"] == "tunnel"
    assert interfaces["ethernet1/2"]["zone"] == "trust" and interfaces["ethernet1/2"]["vrf"] == ""
    routes = {r["prefix"]: r for r in block["routes"]}
    assert routes["0.0.0.0/0"]["kind"] == "default" and routes["0.0.0.0/0"]["next_hop"] == "203.0.113.129"
    assert routes["10.151.0.0/16"]["peer"] == {"org_node": f"d:{BRANCH}"} and routes["10.151.0.0/16"]["next_hop"] == ""
    assert routes["172.16.40.0/24"]["peer"] == {"org_node": f"p:{PARTNER_PEER}"}
    assert routes["198.18.0.0/15"]["kind"] == "dynamic" and routes["10.150.10.0/24"]["kind"] == "connected"
    vpn = {v["name"]: v for v in block["vpn"]}
    assert vpn["tun-branch"] | {} == {
        "name": "tun-branch",
        "interface": "tunnel.1",
        "local": ["any"],
        "remote": ["10.151.0.0/16"],
        "peer": {"org_node": f"d:{BRANCH}"},
        "status": "up",
    }
    assert vpn["tun-partner"]["local"] == ["10.150.10.0/24"] and vpn["tun-partner"]["status"] == "down"
    [policy] = block["policies"]
    assert (policy["name"], policy["kind"], policy["applies"], policy["default"]) == (
        "Security policy",
        "firewall",
        "any",
        "deny",
    )
    rules = policy["rules"]
    web = next(r for r in rules if r["name"] == "Allow-DMZ-Web")
    # Matched before destination NAT on the firewall; after it in the tracer.
    assert web["dst"] == ["203.0.113.132/32", "10.150.50.10/32"]
    assert "application Web-Apps" in web["unresolved"] and "application-default ports" in web["unresolved"]
    https = next(r for r in rules if r["name"] == "Allow-Trust-DMZ-HTTPS")
    assert (https["protocol"], https["dst_ports"], https["unresolved"]) == ("tcp", "443", [])
    assert next(r for r in rules if r["name"] == "Legacy-FTP")["enabled"] is False
    bad = next(r for r in rules if r["name"] == "Block-Known-Bad")
    assert bad["action"] == "deny" and bad["dst"] == ["192.0.2.66/32", "192.0.2.192/27"] and bad["unresolved"] == []
    assert [r["name"] for r in rules[-6:]] == ["intrazone-default"] * 5 + ["interzone-default"]
    assert rules[-1]["action"] == "deny" and rules[-2]["action"] == "allow" and rules[-2]["src_zones"] == ["vpn"]
    assert "Local firewall rules" in block["not_collected"]
    nat = block["nat"]
    pat = [n for n in nat if n["name"] == "Outbound-PAT"]
    assert {(n["src_interface"], n["dst_interface"]) for n in pat} == {("trust", "untrust"), ("dmz", "untrust")}
    assert pat[0]["translated_src"] == ["interface"] and pat[0]["kind"] == "pre_rule"
    dnat = next(n for n in nat if n["name"] == "Web-DNAT")
    assert dnat["original_dst"] == ["203.0.113.132/32"] and dnat["translated_dst"] == ["10.150.50.10/32"]
    assert dnat["protocol"] == "tcp" and dnat["original_port"] == "443" and dnat["translated_port"] == "443"
    reverse = next(n for n in nat if n["name"] == "Mail-Static (bi-directional)")
    assert reverse["original_dst"] == ["203.0.113.133/32"] and reverse["translated_dst"] == ["10.150.50.25/32"]
    assert reverse["src_interface"] == "untrust"
    exempt = next(n for n in nat if n["name"] == "No-NAT-VPN")
    assert exempt["translated_src"] == exempt["original_src"] == ["any"]


def test_forwarding_without_the_routing_table_uses_static_routes_and_notes_bgp():
    raw = build_sample_raw()
    for state in raw["state"].values():
        state.pop("routes", None)
    block = _node(build_snapshot(raw), f"d:{HQ_1}")["forwarding"]
    assert "Routes learned by BGP" in block["not_collected"]
    routes = {r["prefix"]: r for r in block["routes"]}
    assert routes["10.151.0.0/16"]["source"] == "Static route to-branch"
    assert routes["10.151.0.0/16"]["peer"] == {"org_node": f"d:{BRANCH}"}
    raw["security_rules"] = None
    raw["nat_rules"] = None
    block = _node(build_snapshot(raw), f"d:{BRANCH}")["forwarding"]
    assert {"Security rules", "NAT rules"} <= set(block["not_collected"]) and block["policies"] == []


def test_forwarding_tells_apart_zones_named_alike_in_two_vsys():
    raw = build_sample_raw()
    raw["devices"][2]["vsys"] = [{"@name": "vsys1"}, {"@name": "vsys2"}]
    vsys = raw["template_config"]["Branch-Network"]["vsys"]
    vsys[0]["zone"] = [z for z in vsys[0]["zone"] if z["@name"] != "guest"]
    vsys.append(
        {
            "@name": "vsys2",
            "zone": [{"@name": "trust", "network": {"layer3": ["ethernet1/2.30"]}}],
            "import": {"network": {"interface": ["ethernet1/2.30"]}},
        }
    )
    raw["state"][BRANCH]["interfaces"]["ifnet"][2].update(zone="trust", vsys="2")
    block = _node(build_snapshot(raw), f"d:{BRANCH}")["forwarding"]
    zones = {i["name"]: i["zone"] for i in block["interfaces"]}
    assert zones["ethernet1/2"] == "vsys1/trust" and zones["ethernet1/2.30"] == "vsys2/trust"
    assert zones["ethernet1/1"] == "untrust"
    rule = next(r for r in block["policies"][0]["rules"] if r["name"] == "Branch-Allow-HQ-In")
    assert rule["dst_zones"] == ["vsys1/trust", "vsys2/trust"]


# ── HTTP API ─────────────────────────────────────────────────────────────────


class _CsrfClient:
    def __init__(self, client, csrf):
        self._c, self._headers = client, {"X-CSRF-Token": csrf}

    def get(self, url, **kw):
        return self._c.get(url, **kw)

    def post(self, url, **kw):
        return self._c.post(url, headers=self._headers, **kw)

    def put(self, url, **kw):
        return self._c.put(url, headers=self._headers, **kw)

    def delete(self, url, **kw):
        return self._c.delete(url, headers=self._headers, **kw)


@pytest.fixture
def api(monkeypatch, request):
    monkeypatch.setenv("APP_SECRET_KEY", "test-secret-key-panorama")
    monkeypatch.setenv("APP_API_TOKEN", "")
    monkeypatch.setenv("APP_REQUIRE_API_TOKEN", "false")
    monkeypatch.setenv("PLEXUS_DEV_BOOTSTRAP", "1")
    monkeypatch.setattr(app_module, "APP_API_TOKEN", "")
    import netcontrol.routes.meraki_topology as routes_module
    from netcontrol.routes.topology import invalidate_topology_cache

    def forget() -> None:
        # The samples must not leak into the next test's map.
        routes_module._SNAPSHOT_CACHE.clear()
        routes_module._HOST_FORWARDING.clear()
        invalidate_topology_cache()

    forget()
    request.addfinalizer(forget)

    from starlette.testclient import TestClient

    client = TestClient(app_module.app, raise_server_exceptions=False)
    client.__enter__()
    request.addfinalizer(lambda: client.__exit__(None, None, None))
    resp = client.post("/api/auth/login", json={"username": "admin", "password": "netcontrol"})
    return _CsrfClient(client, resp.json().get("csrf_token", ""))


def _wait(api, job_id: str) -> dict:
    job: dict = {}
    for _ in range(400):
        job = api.get(f"/api/meraki/builds/{job_id}").json()
        if job["status"] != "running":
            break
    return job


def test_api_panorama_crud_keeps_the_secret_write_only(api):
    listing = api.get("/api/meraki/orgs").json()
    assert listing["panorama_default_options"] == DEFAULT_OPTIONS and "fmc_default_options" in listing
    body = {
        "name": "Prod Panorama",
        "provider": "panorama",
        "org_id": "Branches",
        "base_url": "panorama.example.com",
        "api_key": "super-secret-api-key",
        "options": {"verify_tls": False, "include_nat": 0},
    }
    created = api.post("/api/meraki/orgs", json=body)
    assert created.status_code == 201, created.text
    org = created.json()["org"]
    assert org["provider"] == "panorama" and org["has_api_key"] is True
    assert org["base_url"] == "https://panorama.example.com" and org["org_id"] == "Branches"
    assert org["options"] == {**DEFAULT_OPTIONS, "verify_tls": False, "include_nat": False}
    assert "super-secret-api-key" not in created.text
    assert "super-secret-api-key" not in api.get("/api/meraki/orgs").text

    bad = {"name": "Evil", "provider": "panorama", "base_url": "http://panorama.example.com"}
    assert api.post("/api/meraki/orgs", json=bad).status_code == 400
    bad["base_url"] = "https://panorama.example.com/api/"
    assert api.post("/api/meraki/orgs", json=bad).status_code == 400
    unknown = api.post("/api/meraki/orgs", json={"name": "X", "provider": "fortinet"})
    assert unknown.status_code == 400 and "meraki, cato, fmc, panorama or appgate" in unknown.text

    updated = api.put(f"/api/meraki/orgs/{org['id']}", json={"options": {"username": "ro", "include_vpn": False}})
    assert updated.status_code == 200
    assert updated.json()["org"]["options"]["username"] == "ro" and updated.json()["org"]["has_api_key"] is True
    assert api.delete(f"/api/meraki/orgs/{org['id']}").status_code == 200


def test_api_panorama_sample_is_merged_into_the_topology(api):
    built = api.post("/api/meraki/sample?provider=panorama")
    assert built.status_code == 201, built.text
    assert built.json()["summary"]["ha_pairs"] == 1 and built.json()["summary"]["remote_users"] == 3
    org_ref = built.json()["org_ref"]
    org = next(o for o in api.get("/api/meraki/orgs").json()["orgs"] if o["id"] == org_ref)
    assert org["name"] == "Sample Palo Alto Panorama (demo data)" and org["base_url"] == "https://10.210.2.30"
    assert org["options"]["username"] == "plexus-readonly"

    graph = api.get("/api/topology").json()
    ours = [n for n in graph["nodes"] if (n.get("meraki") or {}).get("provider") == "panorama"]
    assert {n["meraki"]["kind"] for n in ours} == {"appliance", "wan", "cloud", "users", "vpn_peer"}
    assert any(n["label"] == "GlobalProtect users (3)" for n in ours)
    assert any(n["label"] == "Sample Palo Alto Panorama (demo data)" for n in ours)
    protocols = {e["protocol"] for e in graph["edges"] if e.get("provider") == "panorama"}
    assert {"management", "stack", "vpn", "vpn-ipsec", "wan"} <= protocols

    details = api.get(f"/api/meraki/nodes?org_ref={org_ref}&node_id=d:{BRANCH}").json()
    assert details["provider"] == "panorama" and "Security rules" in [s["title"] for s in details["sections"]]
    subnets = api.get("/api/meraki/subnets").json()["subnets"]
    lan = next(s for s in subnets if s["cidr"] == "10.151.10.0/24")
    assert lan["provider"] == "panorama" and lan["kind"] == "connected" and lan["node_id"] == f"d:{BRANCH}"
    assert any(s["cidr"] == "10.252.0.0/22" and s["kind"] == "pool" for s in subnets)
    hits = api.get("/api/topology/search/deep?q=dana.reyes").json()["results"]
    assert [(h["org_ref"], h["node_id"]) for h in hits] == [(org_ref, f"u:{HQ_1}")]
    source = next(s for s in api.get("/api/topology/sources").json()["sources"] if s["type"] == "panorama")
    assert source["demo"] and not source["can_collect"] and source["status"] == "success"
    export = api.get("/api/topology/export.html")
    assert export.status_code == 200 and "GlobalProtect users (3)" in export.text
    # Rebuilding refreshes the same entry.
    assert api.post("/api/meraki/sample?provider=panorama").json()["org_ref"] == org_ref


def test_api_panorama_build_job_runs_the_collector(api, monkeypatch):
    import netcontrol.routes.meraki_topology as routes_module

    async def _fake_collect(client, device_group, options, progress):
        assert client.base_url == "https://panorama.example.com:8443" and device_group == "Corporate"
        assert options["username"] == "" and options["include_device_state"] is True
        progress({"phase": "panorama devices"})
        return build_sample_raw()

    monkeypatch.setattr(routes_module, "collect_panorama", _fake_collect)
    body = {
        "name": "Prod Panorama",
        "provider": "panorama",
        "org_id": "Corporate",
        "base_url": "https://panorama.example.com:8443",
        "api_key": API_KEY,
    }
    org = api.post("/api/meraki/orgs", json=body).json()["org"]
    started = api.post(f"/api/meraki/orgs/{org['id']}/build")
    assert started.status_code == 202, started.text
    job = _wait(api, started.json()["job_id"])
    assert job["status"] == "completed", job
    snapshot = api.get(f"/api/meraki/snapshots/{job['result']['snapshot_id']}/data").json()
    assert snapshot["provider"] == "panorama" and snapshot["org"]["name"] == "Prod Panorama"


def test_api_panorama_build_against_the_fake_is_partial_on_a_failed_resource(api, monkeypatch):
    import netcontrol.routes.meraki_topology as routes_module

    fake = _FakePanorama()
    fake.fail = {"/nat/rules": 500}
    real_client = routes_module.PanoramaClient

    def _client_factory(base_url, **kwargs):
        # A username in the options: the secret is that admin's password, never used as a key.
        assert kwargs["username"] == "plexus" and "api_key" not in kwargs
        kwargs.update(transport=httpx.MockTransport(fake.handler), requests_per_second=1000, max_retries=0)
        return real_client(base_url, **kwargs)

    monkeypatch.setattr(routes_module, "PanoramaClient", _client_factory)
    body = {
        "name": "Lab Panorama",
        "provider": "panorama",
        "base_url": "https://panorama.example.com",
        "api_key": "s3cret",
        "options": {"username": "plexus"},
    }
    org = api.post("/api/meraki/orgs", json=body).json()["org"]
    job = _wait(api, api.post(f"/api/meraki/orgs/{org['id']}/build").json()["job_id"])
    assert job["status"] == "partial", job
    assert job["result"]["warning_count"] == 6 and job["result"]["summary"]["devices"] == 4
    warnings = api.get(f"/api/meraki/snapshots/{job['result']['snapshot_id']}/warnings").json()
    assert "nat/rules" in json.dumps(warnings)
    stored = api.get(f"/api/meraki/snapshots/{job['result']['snapshot_id']}/data").text
    assert PSK not in stored and "s3cret" not in stored and GENERATED_KEY not in stored

    checked = api.post(f"/api/meraki/orgs/{org['id']}/validate").json()
    assert checked["ok"] is True and checked["message"].startswith("Signed in to Panorama panorama-01 (11.1.4-h7)")
    assert [o["name"] for o in checked["organizations"]] == ["Branches", "Corporate"]
    api.put(f"/api/meraki/orgs/{org['id']}", json={"org_id": "Nope"})
    checked = api.post(f"/api/meraki/orgs/{org['id']}/validate").json()
    assert checked["ok"] is False and "no device group Nope" in checked["message"]
    api.put(f"/api/meraki/orgs/{org['id']}", json={"api_key": "wrong"})
    checked = api.post(f"/api/meraki/orgs/{org['id']}/validate").json()
    assert checked["ok"] is False and checked["message"].startswith("Panorama rejected the credentials (HTTP 403)")


def _labels(direction: dict) -> list[str]:
    return [h["label"] for h in direction["hops"]]


def test_api_traces_flows_through_the_panorama_sample(api):
    assert api.post("/api/meraki/sample?provider=panorama").status_code == 201
    graph = api.get("/api/topology").json()["nodes"]
    label = {(n.get("meraki") or {}).get("node_id"): n["label"] for n in graph}
    hq, branch = label[f"d:{HQ_1}"], label[f"d:{BRANCH}"]

    # HQ's LAN to the branch LAN: allowed by the HQ and the branch security rules, over the tunnel.
    allowed = api.get("/api/topology/path?source=10.150.10.0/24&destination=10.151.10.0/24&protocol=tcp&port=443")
    assert allowed.status_code == 200, allowed.text
    body = allowed.json()
    assert body["verdict"] == "allowed", body["summary"]
    assert _labels(body["request"]) == [hq, branch] and _labels(body["reply"]) == [branch, hq]
    assert body["asymmetric"]["status"] == "no"
    first, second = body["request"]["hops"]
    policy = [i for i in first["items"] if i["where"] == "Security policy"]
    assert policy[-1]["status"] == "ok" and "Allow-HQ-to-Branch" in policy[-1]["text"]
    assert any(i["where"] == "Site-to-site VPN tun-branch" and i["status"] == "ok" for i in first["items"])
    assert any("Branch-Allow-HQ-In" in i["text"] for i in second["items"] if i["where"] == "Security policy")
    assert "Local firewall rules" in body["summary"]

    # HQ's LAN to the mail server in the DMZ over SSH: no rule allows it, the interzone default denies it.
    denied = api.get("/api/topology/path?source=10.150.10.0/24&destination=10.150.50.25&protocol=tcp&port=22").json()
    assert denied["verdict"] == "blocked", denied["summary"]
    [hop] = denied["request"]["hops"]
    blocked = next(i for i in hop["items"] if i["status"] == "blocked")
    assert blocked["where"] == "Security policy" and "interzone-default" in blocked["text"]

    # The same flow on 443 is allowed by Allow-Trust-DMZ-HTTPS.
    https = api.get("/api/topology/path?source=10.150.10.0/24&destination=10.150.50.25&protocol=tcp&port=443").json()
    assert https["verdict"] == "allowed", https["summary"]
