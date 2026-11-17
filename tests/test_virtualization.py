"""Virtualization (``/api/virtualization``): cluster types, groups, clusters
with member hosts, virtual machines and VM interfaces; uniqueness, value
validation, 409 on deleting what is in use, the change log, permissions, and
the cloud sync that mirrors AWS, Azure and GCP compute instances (from the
integrations' sample data) as virtual machines."""

from __future__ import annotations

import asyncio

import pytest
import routes.database as db
from netcontrol import virtualization as rules
from netcontrol.custom_fields import CustomFieldError
from netcontrol.integrations.aws.sample import build_sample as aws_sample
from netcontrol.integrations.azure.sample import build_sample as azure_sample
from netcontrol.integrations.gcp.sample import build_sample as gcp_sample
from netcontrol.routes import state
from netcontrol.routes.virtualization import sync_cloud_virtual_machines

from mcp_helpers import CsrfClient, admin_client, user_client

API = "/api/virtualization"
SAMPLES = {"aws": aws_sample, "azure": azure_sample, "gcp": gcp_sample}
COMPUTE = {"aws": "instance", "azure": "vm", "gcp": "instance"}


@pytest.fixture(autouse=True)
def _fresh_limits(monkeypatch):
    monkeypatch.setattr(state, "API_RATE_LIMIT_TRACKER", {})


@pytest.fixture
def admin(monkeypatch, request) -> CsrfClient:
    return admin_client(monkeypatch, request)


def _ok(resp, status: int = 200) -> dict:
    assert resp.status_code == status, resp.text
    return resp.json()


def _type(admin: CsrfClient, name: str = "VMware vSphere") -> int:
    return int(_ok(admin.post(f"{API}/cluster-types", json={"name": name}), 201)["id"])


def _cluster(admin: CsrfClient, name: str = "cl-east", type_id: int | None = None, **extra) -> int:
    type_id = type_id or _type(admin, f"type-for-{name}")
    body = {"name": name, "cluster_type_id": type_id, **extra}
    return int(_ok(admin.post(f"{API}/clusters", json=body), 201)["id"])


def _vm(admin: CsrfClient, cluster_id: int, name: str = "web-01", **extra) -> dict:
    return _ok(admin.post(f"{API}/virtual-machines", json={"name": name, "cluster_id": cluster_id, **extra}), 201)


def _host(admin: CsrfClient, name: str = "esx-01.example.com", ip: str = "192.0.2.21") -> int:
    gid = int(_ok(admin.post("/api/inventory", json={"name": f"grp-{name}"}), 201)["id"])
    body = {"hostname": name, "ip_address": ip, "device_type": "linux"}
    return int(_ok(admin.post(f"/api/inventory/{gid}/hosts", json=body), 201)["id"])


def _sql(statement: str, params: tuple = ()) -> int:
    async def run() -> int:
        conn = await db.get_db()
        try:
            cursor = await conn.execute(statement, params)
            await conn.commit()
            return int(cursor.lastrowid or 0)
        finally:
            await conn.close()

    return asyncio.run(run())


# ── Rules ────────────────────────────────────────────────────────────────────


def test_value_rules():
    assert rules.clean_mac("AA-BB-CC-00-11-22") == "aa:bb:cc:00:11:22"
    assert rules.clean_mac("aabb.cc00.1122") == "aa:bb:cc:00:11:22"
    assert rules.clean_mac("") == ""
    for bad in ("aa:bb:cc:dd:ee", "gg:bb:cc:dd:ee:ff", "aa:bb-cc:dd:ee:ff"):
        with pytest.raises(CustomFieldError):
            rules.clean_mac(bad)
    assert rules.clean_interface_address("192.0.2.10/24") == "192.0.2.10/24"
    assert rules.clean_interface_address("2001:DB8::1/64") == "2001:db8::1/64"
    assert rules.clean_interface_address("198.51.100.7") == "198.51.100.7/32"
    with pytest.raises(CustomFieldError):
        rules.clean_interface_address("192.0.2.300/24")
    with pytest.raises(CustomFieldError):
        rules.clean_interface_addresses(["192.0.2.1/24", "192.0.2.1/24"])
    assert rules.clean_primary_ip("2001:db8::0:1", 6) == "2001:db8::1"
    with pytest.raises(CustomFieldError):
        rules.clean_primary_ip("2001:db8::1", 4)
    assert rules.cloud_status("RUNNING") == "active"
    assert rules.cloud_status("stopped") == "offline"
    assert rules.cloud_status("pending") == "staged"
    assert rules.cloud_status("") == "active"


def test_more_value_rules_and_cloud_edge_cases():
    assert rules.clean_count(None, "vCPUs", 8) is None
    assert rules.clean_mtu(None) is None
    for bad in (lambda: rules.clean_count(True, "vCPUs", 8), lambda: rules.clean_mode("trunk")):
        with pytest.raises(CustomFieldError):
            bad()
    assert rules.clean_primary_ip("", 4) == ""
    with pytest.raises(CustomFieldError):
        rules.clean_primary_ip("not-an-ip", 4)
    with pytest.raises(CustomFieldError):
        rules.clean_interface_address("")
    assert rules.clean_interface_addresses(None) == []
    with pytest.raises(CustomFieldError):
        rules.clean_interface_addresses("192.0.2.1/24")
    with pytest.raises(CustomFieldError):
        rules.clean_interface_addresses([f"192.0.2.{i}/32" for i in range(rules.ADDRESSES_MAX + 1)])
    assert rules.cloud_cluster_name("aws", "demo", "") == "AWS demo global"
    assert rules.cloud_cluster_key("gcp", 3, "") == "gcp:3:global"
    assert rules.decoded_metadata({"metadata_json": "{bad"})["metadata"] == {}
    assert rules.decoded_metadata({"metadata_json": "[1]"})["metadata"] == {}
    resource = {
        "resource_uid": "aws:instance:i-0example",
        "name": "",
        "status": "stopped",
        "metadata": {
            "private_ip": "2001:db8::5",
            "interfaces": [
                "junk",
                {"device_index": 0, "mac": "zz", "subnet_id": "s1", "private_ips": ["2001:db8::5", "bad"]},
                {"device_index": 0, "private_ips": []},
            ],
        },
    }
    spec = rules.vm_from_resource("aws", resource, {"s1": "not-a-cidr"})
    assert spec["name"] == "i-0example" and spec["status"] == "offline"
    assert spec["primary_ip6"] == "2001:db8::5" and spec["primary_ip4"] == ""
    assert [i["name"] for i in spec["interfaces"]] == ["eth0"]
    assert spec["interfaces"][0]["mac_address"] == "" and spec["interfaces"][0]["addresses"] == ["2001:db8::5/128"]
    assert (
        rules.vm_from_resource("azure", {"resource_uid": "azure:vm:x", "metadata": None}, {})["description"]
        == "Azure VM"
    )
    assert rules.vm_from_resource("gcp", {"resource_uid": "gcp:instance:y", "metadata": {}}, {})[
        "description"
    ].startswith("Compute Engine")


@pytest.mark.parametrize("provider", ["aws", "azure", "gcp"])
def test_vm_from_sample_resource(provider):
    resources, _ = SAMPLES[provider]()
    subnets = rules.subnet_cidrs(provider, resources)
    instance = next(r for r in resources if r["resource_type"] == COMPUTE[provider])
    spec = rules.vm_from_resource(provider, instance, subnets)
    assert spec["name"] == instance["name"]
    assert spec["status"] == "active"
    assert spec["primary_ip4"] == instance["metadata"]["private_ip"]
    assert spec["interfaces"]
    first = spec["interfaces"][0]
    # The private address carries the subnet's prefix length.
    assert first["addresses"][0].startswith(f"{instance['metadata']['interfaces'][0]['private_ips'][0]}/")
    assert not first["addresses"][0].endswith("/32")


# ── CRUD, uniqueness, validation ─────────────────────────────────────────────


def test_cluster_type_and_group_crud_and_uniqueness(admin):
    tid = _type(admin, "Proxmox")
    assert _ok(admin.post(f"{API}/cluster-types", json={"name": "proxmox"}), 409)
    assert admin.post(f"{API}/cluster-types", json={"name": "  "}).status_code == 422
    updated = _ok(admin.put(f"{API}/cluster-types/{tid}", json={"description": "PVE"}))
    assert updated["description"] == "PVE" and updated["name"] == "Proxmox"
    gid = int(_ok(admin.post(f"{API}/cluster-groups", json={"name": "Production"}), 201)["id"])
    assert admin.post(f"{API}/cluster-groups", json={"name": "PRODUCTION"}).status_code == 409
    other = int(_ok(admin.post(f"{API}/cluster-groups", json={"name": "Lab"}), 201)["id"])
    assert admin.put(f"{API}/cluster-groups/{other}", json={"name": "production"}).status_code == 409
    groups = _ok(admin.get(f"{API}/cluster-groups"))["cluster_groups"]
    assert [g["name"] for g in groups] == ["Lab", "Production"]
    assert admin.get(f"{API}/cluster-types/999999").status_code == 404
    assert _ok(admin.delete(f"{API}/cluster-groups/{gid}"))["ok"]
    assert admin.delete(f"{API}/cluster-groups/{gid}").status_code == 404


def test_cluster_crud_filters_and_in_use_409(admin):
    tid = _type(admin, "VMware vSphere")
    gid = int(_ok(admin.post(f"{API}/cluster-groups", json={"name": "Prod"}), 201)["id"])
    site_id = _sql("INSERT INTO geo_sites (name) VALUES (?) RETURNING id", ("virt-site-a",))
    tenant_id = _sql("INSERT INTO tenants (name) VALUES (?) RETURNING id", ("Tenant One",))
    cid = _cluster(admin, "cl-prod", tid, cluster_group_id=gid, site_id=site_id, tenant_id=tenant_id)
    _cluster(admin, "cl-lab", tid)
    assert admin.post(f"{API}/clusters", json={"name": "CL-PROD", "cluster_type_id": tid}).status_code == 409
    bad = admin.post(f"{API}/clusters", json={"name": "x", "cluster_type_id": 999999, "site_id": 999999})
    assert bad.status_code == 422 and set(bad.json()["detail"]["fields"]) == {"cluster_type_id", "site_id"}
    row = _ok(admin.get(f"{API}/clusters/{cid}"))
    assert row["cluster_type_name"] == "VMware vSphere" and row["cluster_group_name"] == "Prod"
    assert row["site_name"] == "virt-site-a" and row["tenant_name"] == "Tenant One"
    for query, names in (
        (f"cluster_group_id={gid}", ["cl-prod"]),
        (f"site_id={site_id}", ["cl-prod"]),
        (f"tenant_id={tenant_id}", ["cl-prod"]),
        (f"cluster_type_id={tid}", ["cl-lab", "cl-prod"]),
        ("search=LAB", ["cl-lab"]),
    ):
        assert [c["name"] for c in _ok(admin.get(f"{API}/clusters?{query}"))["clusters"]] == names
    # A type and a group in use, and a cluster holding a VM, cannot be deleted.
    assert admin.delete(f"{API}/cluster-types/{tid}").status_code == 409
    assert admin.delete(f"{API}/cluster-groups/{gid}").status_code == 409
    vm = _vm(admin, cid)
    assert admin.delete(f"{API}/clusters/{cid}").status_code == 409
    _ok(admin.delete(f"{API}/virtual-machines/{vm['id']}"))
    _ok(admin.delete(f"{API}/clusters/{cid}"))
    _ok(admin.delete(f"{API}/cluster-groups/{gid}"))
    # Clearing a link with null; the type cannot be cleared.
    lab = _ok(admin.get(f"{API}/clusters?search=lab"))["clusters"][0]
    assert admin.put(f"{API}/clusters/{lab['id']}", json={"cluster_type_id": None}).status_code == 422
    assert _ok(admin.put(f"{API}/clusters/{lab['id']}", json={"site_id": None}))["site_id"] is None


def test_cluster_member_hosts(admin):
    cid = _cluster(admin)
    host = _host(admin)
    added = _ok(admin.post(f"{API}/clusters/{cid}/hosts", json={"host_id": host}), 201)
    assert [h["id"] for h in added["hosts"]] == [host]
    assert admin.post(f"{API}/clusters/{cid}/hosts", json={"host_id": host}).status_code == 409
    assert admin.post(f"{API}/clusters/{cid}/hosts", json={"host_id": 999999}).status_code == 422
    assert _ok(admin.get(f"{API}/clusters/{cid}"))["host_count"] == 1
    assert [c["id"] for c in _ok(admin.get(f"{API}/hosts/{host}/clusters"))["clusters"]] == [cid]
    _ok(admin.delete(f"{API}/clusters/{cid}/hosts/{host}"))
    assert admin.delete(f"{API}/clusters/{cid}/hosts/{host}").status_code == 404
    assert _ok(admin.get(f"{API}/hosts/{host}/clusters"))["clusters"] == []


def test_vm_crud_validation_and_filters(admin):
    cid = _cluster(admin, "cl-a")
    other = _cluster(admin, "cl-b")
    role = _ok(admin.post("/api/dcim/roles", json={"name": "virt-app"}), 201)
    vm = _vm(
        admin,
        cid,
        "web-01",
        status="planned",
        role_id=role["id"],
        vcpus=4,
        memory_mb=8192,
        disk_gb=80,
        primary_ip4="192.0.2.10",
        primary_ip6="2001:db8::10",
        platform="Ubuntu 24.04",
    )
    assert vm["origin"] == "manual" and vm["cluster_name"] == "cl-a" and vm["role_name"] == "virt-app"
    # Unique per cluster ignoring case; the same name in another cluster is fine.
    assert admin.post(f"{API}/virtual-machines", json={"name": "WEB-01", "cluster_id": cid}).status_code == 409
    _vm(admin, other, "web-01", status="offline")
    bad = admin.post(
        f"{API}/virtual-machines",
        json={
            "name": "x",
            "cluster_id": cid,
            "status": "running",
            "primary_ip4": "2001:db8::1",
            "vcpus": -1,
        },
    )
    assert bad.status_code == 422
    assert set(bad.json()["detail"]["fields"]) == {"status", "primary_ip4", "vcpus"}
    assert admin.post(f"{API}/virtual-machines", json={"name": "x", "cluster_id": 999999}).status_code == 422

    def names(query: str) -> list[str]:
        return [v["cluster_name"] for v in _ok(admin.get(f"{API}/virtual-machines?{query}"))["virtual_machines"]]

    assert names(f"cluster_id={cid}") == ["cl-a"]
    assert names("status=offline") == ["cl-b"]
    assert names(f"role_id={role['id']}") == ["cl-a"]
    assert names("search=2001:db8::10") == ["cl-a"]
    assert names("search=ubuntu") == ["cl-a"]
    assert admin.get(f"{API}/virtual-machines?status=bogus").status_code == 422
    moved = _ok(admin.put(f"{API}/virtual-machines/{vm['id']}", json={"cluster_id": other, "name": "web-02"}))
    assert moved["cluster_id"] == other and moved["name"] == "web-02"
    assert admin.put(f"{API}/virtual-machines/{vm['id']}", json={"name": "WEB-01"}).status_code == 409
    assert admin.put(f"{API}/virtual-machines/{vm['id']}", json={"extra": 1}).status_code == 422
    cleared = _ok(admin.put(f"{API}/virtual-machines/{vm['id']}", json={"role_id": None, "vcpus": None}))
    assert cleared["role_id"] is None and cleared["vcpus"] is None
    assert admin.get(f"{API}/virtual-machines/999999").status_code == 404


def test_vm_interfaces_addresses_and_mac(admin):
    cid = _cluster(admin)
    vm = _vm(admin, cid)
    vrf = _ok(admin.post("/api/ipam/vrfs", json={"name": "virt-blue"}), 201)
    vlan = _ok(admin.post("/api/ipam/vlans", json={"vid": 210, "name": "virt-apps"}), 201)
    base = f"{API}/virtual-machines/{vm['id']}/interfaces"
    body = {
        "name": "eth0",
        "mac_address": "00-50-56-AA-BB-01",
        "mtu": 9000,
        "mode": "access",
        "untagged_vlan_id": vlan["id"],
        "vrf_id": vrf["id"],
        "addresses": ["192.0.2.10/24", "2001:db8::10/64"],
    }
    iface = _ok(admin.post(base, json=body), 201)
    assert iface["mac_address"] == "00:50:56:aa:bb:01"
    assert iface["addresses"] == ["192.0.2.10/24", "2001:db8::10/64"]
    assert iface["vrf_name"] == "virt-blue" and iface["untagged_vlan_vid"] == 210
    assert admin.post(base, json={"name": "ETH0"}).status_code == 409
    bad = admin.post(base, json={"name": "eth1", "mac_address": "00:50:56", "mtu": 10, "addresses": ["nope"]})
    assert bad.status_code == 422
    assert set(bad.json()["detail"]["fields"]) == {"mac_address", "mtu", "addresses"}
    dup = admin.post(base, json={"name": "eth1", "addresses": ["192.0.2.11/24", "192.0.2.11/24"]})
    assert dup.status_code == 422
    no_mode = admin.post(base, json={"name": "eth1", "untagged_vlan_id": vlan["id"]})
    assert no_mode.status_code == 422 and "untagged_vlan_id" in no_mode.json()["detail"]["fields"]
    assert admin.post(base, json={"name": "eth1", "mode": "trunk"}).status_code == 422
    changed = _ok(admin.put(f"{base}/{iface['id']}", json={"addresses": ["198.51.100.5/25"], "enabled": False}))
    assert changed["addresses"] == ["198.51.100.5/25"] and changed["enabled"] is False
    detail = _ok(admin.get(f"{API}/virtual-machines/{vm['id']}"))
    assert [i["name"] for i in detail["interfaces"]] == ["eth0"] and detail["interface_count"] == 1
    # An interface of another VM is not reachable through this one.
    other = _vm(admin, cid, "web-02")
    assert admin.put(f"{API}/virtual-machines/{other['id']}/interfaces/{iface['id']}", json={}).status_code == 404
    _ok(admin.delete(f"{base}/{iface['id']}"))
    assert _ok(admin.get(base))["interfaces"] == []


def test_change_log_entries(admin):
    tid = _type(admin, "Hyper-V")
    gid = int(_ok(admin.post(f"{API}/cluster-groups", json={"name": "grp"}), 201)["id"])
    cid = _cluster(admin, "cl-log", tid)
    vm = _vm(admin, cid, "app-01")
    _ok(admin.put(f"{API}/virtual-machines/{vm['id']}", json={"status": "failed"}))
    iface = _ok(admin.post(f"{API}/virtual-machines/{vm['id']}/interfaces", json={"name": "eth0"}), 201)
    _ok(admin.delete(f"{API}/cluster-groups/{gid}"))

    def actions(object_type: str, object_id: int) -> list[str]:
        changes = _ok(admin.get(f"/api/changes/{object_type}/{object_id}"))["changes"]
        return sorted(c["action"] for c in changes)

    assert actions("cluster_type", tid) == ["create"]
    assert actions("cluster_group", gid) == ["create", "delete"]
    assert actions("cluster", cid) == ["create"]
    assert actions("virtual_machine", vm["id"]) == ["create", "update"]
    assert actions("vm_interface", iface["id"]) == ["create"]
    update = next(
        c for c in _ok(admin.get(f"/api/changes/virtual_machine/{vm['id']}"))["changes"] if c["action"] == "update"
    )
    assert update["changes"]["status"] == {"before": "active", "after": "failed"}
    assert update["object_label"] == "app-01" and update["user"] == "admin"


def test_feature_gate(admin):
    cid = _cluster(admin)
    reader = user_client(admin, "virt-reader", features=["virtualization"])
    assert reader.get(f"{API}/clusters").status_code == 200
    assert reader.post(f"{API}/virtual-machines", json={"name": "x", "cluster_id": cid}).status_code == 403
    assert reader.post(f"{API}/sync-cloud", json={}).status_code == 403
    writer = user_client(admin, "virt-writer", features=["virtualization", "virtualization.write"])
    assert writer.post(f"{API}/virtual-machines", json={"name": "x", "cluster_id": cid}).status_code == 201
    outsider = user_client(admin, "virt-outsider", features=["inventory"])
    assert outsider.get(f"{API}/virtual-machines").status_code == 403
    # Change log entries of virtualization types are for holders of the feature.
    assert outsider.get("/api/changes?object_type=cluster").status_code == 403
    assert reader.get("/api/changes?object_type=cluster").json()["changes"]


# ── Cloud sync ───────────────────────────────────────────────────────────────


async def _account(provider: str, resources: list[dict] | None = None) -> int:
    account = await db.create_cloud_account(provider=provider, name=f"{provider}-demo", auth_type="sample")
    assert account is not None
    if resources is None:
        resources, _ = SAMPLES[provider]()
    await db.replace_cloud_discovery_snapshot(int(account["id"]), resources=resources)
    return int(account["id"])


def _instances(provider: str) -> list[dict]:
    resources, _ = SAMPLES[provider]()
    return [r for r in resources if r["resource_type"] == COMPUTE[provider]]


@pytest.mark.parametrize("provider", ["aws", "azure", "gcp"])
async def test_cloud_sync_create_rerun_manual_and_vanished(provider):
    await db.init_db()
    account_id = await _account(provider)
    instances = _instances(provider)
    first = await sync_cloud_virtual_machines(account_id)
    assert first["created"] == len(instances) and first["failed"] == 0
    vms = await db.list_virtual_machines(origin="discovered")
    assert len(vms) == len(instances)
    assert all(v["cloud_provider"] == provider and v["cloud_resource_id"] for v in vms)
    clusters = {v["cluster_name"] for v in vms}
    regions = {r["region"] for r in instances}
    assert len(clusters) == len(regions)
    assert {v["cluster_type_name"] for v in vms} == {rules.CLOUD_CLUSTER_TYPES[provider]}
    sample = next(v for v in vms if v["name"] == instances[0]["name"])
    interfaces = await db.list_vm_interfaces(int(sample["id"]))
    assert len(interfaces) == len(instances[0]["metadata"]["interfaces"])
    assert any(a.startswith(instances[0]["metadata"]["private_ip"] + "/") for i in interfaces for a in i["addresses"])

    # Idempotent: the same snapshot again changes nothing.
    second = await sync_cloud_virtual_machines(account_id)
    assert second["created"] == 0 and second["updated"] == 0 and second["unchanged"] == len(instances)

    # A person's edit is kept, even across a new discovery snapshot.
    await db.update_virtual_machine(int(sample["id"]), {"name": "renamed", "origin": "manual"}, "admin")
    await db.replace_cloud_discovery_snapshot(account_id, resources=SAMPLES[provider]()[0])
    third = await sync_cloud_virtual_machines(account_id)
    assert third["kept_manual"] == 1 and third["created"] == 0
    kept = await db.get_virtual_machine(int(sample["id"]))
    assert kept["name"] == "renamed" and kept["cloud_resource_id"] is not None

    # An instance gone from the snapshot: offline, not deleted; manual VMs untouched.
    gone = instances[1]
    remaining = [r for r in SAMPLES[provider]()[0] if r["resource_uid"] not in {gone["resource_uid"]}]
    await db.replace_cloud_discovery_snapshot(account_id, resources=remaining)
    fourth = await sync_cloud_virtual_machines(account_id)
    assert fourth["offline"] == 1
    vanished = next(v for v in await db.list_virtual_machines() if v["cloud_resource_uid"] == gone["resource_uid"])
    assert vanished["status"] == "offline" and vanished["cloud_resource_id"] is None
    assert len(await db.list_virtual_machines()) == len(instances)
    # It comes back: active again.
    await db.replace_cloud_discovery_snapshot(account_id, resources=SAMPLES[provider]()[0])
    await sync_cloud_virtual_machines(account_id)
    back = await db.get_virtual_machine(int(vanished["id"]))
    assert back["status"] == "active" and back["cloud_resource_id"] is not None


def test_sync_endpoint_and_discovery_hook(admin):
    account_ids = {p: asyncio.run(_account(p)) for p in ("aws", "azure", "gcp")}
    result = _ok(admin.post(f"{API}/sync-cloud", json={}))
    expected = sum(len(_instances(p)) for p in account_ids)
    assert result["ok"] and result["accounts"] == 3 and result["created"] == expected
    assert admin.post(f"{API}/sync-cloud", json={"account_id": 999999}).status_code == 404
    types = {t["name"] for t in _ok(admin.get(f"{API}/cluster-types"))["cluster_types"]}
    assert {"AWS EC2", "Azure", "GCP"} <= types
    # A VM linked to a cloud resource shows it; a non-compute resource is refused.
    vm = _ok(admin.get(f"{API}/virtual-machines?origin=discovered"))["virtual_machines"][0]
    assert vm["cloud_resource_type"] in {"instance", "vm"} and vm["cloud_account_name"].endswith("-demo")
    subnet = next(
        r for r in asyncio.run(db.get_cloud_resources(account_id=account_ids["aws"])) if r["resource_type"] == "subnet"
    )
    manual = _vm(admin, int(vm["cluster_id"]), "linked")
    refused = admin.put(f"{API}/virtual-machines/{manual['id']}", json={"cloud_resource_id": subnet["id"]})
    assert refused.status_code == 422
    taken = admin.put(f"{API}/virtual-machines/{manual['id']}", json={"cloud_resource_id": vm["cloud_resource_id"]})
    assert taken.status_code == 409

    # A new discovery runs the sync: delete the AWS VMs, discover again.
    for row in _ok(admin.get(f"{API}/virtual-machines?origin=discovered"))["virtual_machines"]:
        if row["cloud_provider"] == "aws":
            _ok(admin.delete(f"{API}/virtual-machines/{row['id']}"))
    _ok(admin.post(f"/api/cloud/accounts/{account_ids['aws']}/discover", json={"mode": "sample"}))
    aws_vms = [
        v
        for v in _ok(admin.get(f"{API}/virtual-machines?origin=discovered"))["virtual_machines"]
        if v["cloud_provider"] == "aws"
    ]
    assert len(aws_vms) == len(_instances("aws"))

    # An edit through the API makes the VM manual.
    edited = _ok(admin.put(f"{API}/virtual-machines/{aws_vms[0]['id']}", json={"description": "kept"}))
    assert edited["origin"] == "manual"

    # Deleting the account leaves its discovered VMs offline.
    _sql("DELETE FROM cloud_accounts WHERE id = ?", (account_ids["gcp"],))
    after = _ok(admin.post(f"{API}/sync-cloud", json={}))
    assert after["offline"] == len(_instances("gcp"))
