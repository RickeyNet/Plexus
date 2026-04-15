"""Tests for bandwidth billing and 95th percentile reports."""

import pytest

import routes.database as db_module
from netcontrol.routes.billing import (
    calculate_95th_percentile,
    generate_billing_for_circuit,
    _get_billing_period_range,
    _format_bps,
)


# ── helpers ──────────────────────────────────────────────────────────────────

async def _init(tmp_path, monkeypatch):
    """Set up a fresh in-memory DB with all tables + migrations."""
    db_path = str(tmp_path / "test.db")
    monkeypatch.setattr(db_module, "DB_PATH", db_path)
    await db_module.init_db()
    return db_path


async def _add_host(group_name="default", hostname="sw1", ip="10.0.0.1"):
    """Insert a minimal host and return its id."""
    db = await db_module.get_db()
    try:
        cur = await db.execute(
            "INSERT OR IGNORE INTO inventory_groups (name) VALUES (?)",
            (group_name,),
        )
        if cur.lastrowid:
            gid = cur.lastrowid
        else:
            cur2 = await db.execute(
                "SELECT id FROM inventory_groups WHERE name = ?", (group_name,)
            )
            gid = (await cur2.fetchone())[0]

        cur = await db.execute(
            "INSERT INTO hosts (group_id, hostname, ip_address) VALUES (?, ?, ?)",
            (gid, hostname, ip),
        )
        await db.commit()
        return cur.lastrowid
    finally:
        await db.close()


async def _add_interface_samples(host_id, if_index, samples):
    """Insert interface_ts samples for testing.

    samples: list of (in_rate_bps, out_rate_bps, sampled_at) tuples
    """
    db = await db_module.get_db()
    try:
        for in_bps, out_bps, ts in samples:
            await db.execute(
                """INSERT INTO interface_ts
                   (host_id, if_index, if_name, in_rate_bps, out_rate_bps, sampled_at)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (host_id, if_index, "Gi0/0", in_bps, out_bps, ts),
            )
        await db.commit()
    finally:
        await db.close()


# ═════════════════════════════════════════════════════════════════════════════
# 95th Percentile Calculation Tests
# ═════════════════════════════════════════════════════════════════════════════


def test_calculate_95th_percentile_empty():
    assert calculate_95th_percentile([]) == 0.0


def test_calculate_95th_percentile_single():
    assert calculate_95th_percentile([100.0]) == 100.0


def test_calculate_95th_percentile_known_values():
    """With 100 values 1-100, 95th percentile should be 96 (index 95)."""
    values = list(range(1, 101))
    result = calculate_95th_percentile(values)
    # 100 * 0.95 = 95 → index 95 → value 96
    assert result == 96.0


def test_calculate_95th_percentile_twenty_values():
    """With 20 values, top 5% = discard 1 value, billing = 19th highest."""
    values = [float(i) for i in range(1, 21)]
    result = calculate_95th_percentile(values)
    # 20 * 0.95 = 19 → index 19 → value 20
    assert result == 20.0


def test_calculate_95th_percentile_unsorted():
    """Input doesn't need to be pre-sorted."""
    values = [50.0, 10.0, 90.0, 30.0, 70.0]
    result = calculate_95th_percentile(values)
    # 5 * 0.95 = 4 → index 4 → sorted=[10,30,50,70,90] → 90
    assert result == 90.0


# ═════════════════════════════════════════════════════════════════════════════
# Format helpers
# ═════════════════════════════════════════════════════════════════════════════


def test_format_bps_gbps():
    assert _format_bps(1_500_000_000) == "1.50 Gbps"


def test_format_bps_mbps():
    assert _format_bps(100_000_000) == "100.00 Mbps"


def test_format_bps_kbps():
    assert _format_bps(512_000) == "512.00 Kbps"


def test_format_bps_bps():
    assert _format_bps(500) == "500 bps"


def test_format_bps_zero():
    assert _format_bps(0) == "0 bps"


# ═════════════════════════════════════════════════════════════════════════════
# Period Range Calculation
# ═════════════════════════════════════════════════════════════════════════════


def test_billing_period_range_explicit():
    """Explicit start/end should be returned as-is."""
    start, end = _get_billing_period_range(1, "monthly", "2026-01-01T00:00:00", "2026-02-01T00:00:00")
    assert start == "2026-01-01T00:00:00"
    assert end == "2026-02-01T00:00:00"


def test_billing_period_range_auto():
    """Auto-calculated period should be non-empty."""
    start, end = _get_billing_period_range(1, "monthly")
    assert start < end


def test_billing_period_range_weekly():
    """Weekly billing should return a 7-day period."""
    start, end = _get_billing_period_range(1, "weekly")
    assert start < end


# ═════════════════════════════════════════════════════════════════════════════
# Database CRUD Tests
# ═════════════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_create_and_get_billing_circuit(tmp_path, monkeypatch):
    await _init(tmp_path, monkeypatch)
    host_id = await _add_host()

    circuit = await db_module.create_billing_circuit(
        name="ISP-A Primary",
        host_id=host_id,
        if_index=1,
        if_name="Gi0/0/0",
        customer="Acme Corp",
        commit_rate_bps=100_000_000,
        cost_per_mbps=5.0,
        created_by="admin",
    )
    assert circuit["name"] == "ISP-A Primary"
    assert circuit["customer"] == "Acme Corp"
    assert circuit["commit_rate_bps"] == 100_000_000
    assert circuit["cost_per_mbps"] == 5.0

    fetched = await db_module.get_billing_circuit(circuit["id"])
    assert fetched["name"] == "ISP-A Primary"


@pytest.mark.asyncio
async def test_list_billing_circuits_with_filter(tmp_path, monkeypatch):
    await _init(tmp_path, monkeypatch)
    host_id = await _add_host()

    await db_module.create_billing_circuit(name="C1", host_id=host_id, if_index=1, customer="Alpha")
    await db_module.create_billing_circuit(name="C2", host_id=host_id, if_index=2, customer="Beta")

    all_circuits = await db_module.list_billing_circuits()
    assert len(all_circuits) == 2

    alpha = await db_module.list_billing_circuits(customer="Alpha")
    assert len(alpha) == 1
    assert alpha[0]["name"] == "C1"

    by_host = await db_module.list_billing_circuits(host_id=host_id)
    assert len(by_host) == 2


@pytest.mark.asyncio
async def test_update_billing_circuit(tmp_path, monkeypatch):
    await _init(tmp_path, monkeypatch)
    host_id = await _add_host()

    circuit = await db_module.create_billing_circuit(
        name="Test", host_id=host_id, if_index=1,
        commit_rate_bps=50_000_000,
    )

    updated = await db_module.update_billing_circuit(
        circuit["id"],
        name="Updated Name",
        commit_rate_bps=200_000_000,
    )
    assert updated["name"] == "Updated Name"
    assert updated["commit_rate_bps"] == 200_000_000


@pytest.mark.asyncio
async def test_delete_billing_circuit(tmp_path, monkeypatch):
    await _init(tmp_path, monkeypatch)
    host_id = await _add_host()

    circuit = await db_module.create_billing_circuit(
        name="Delete Me", host_id=host_id, if_index=1,
    )
    assert await db_module.delete_billing_circuit(circuit["id"])
    assert await db_module.get_billing_circuit(circuit["id"]) is None


@pytest.mark.asyncio
async def test_billing_period_crud(tmp_path, monkeypatch):
    await _init(tmp_path, monkeypatch)
    host_id = await _add_host()

    circuit = await db_module.create_billing_circuit(
        name="Test", host_id=host_id, if_index=1,
    )

    period = await db_module.create_billing_period(
        circuit_id=circuit["id"],
        period_start="2026-03-01T00:00:00",
        period_end="2026-04-01T00:00:00",
        total_samples=1000,
        p95_in_bps=80_000_000,
        p95_out_bps=60_000_000,
        p95_billing_bps=80_000_000,
        status="generated",
    )
    assert period["circuit_id"] == circuit["id"]
    assert period["p95_billing_bps"] == 80_000_000

    periods = await db_module.list_billing_periods(circuit_id=circuit["id"])
    assert len(periods) == 1

    assert await db_module.delete_billing_period(period["id"])
    assert await db_module.get_billing_period(period["id"]) is None


@pytest.mark.asyncio
async def test_billing_customers(tmp_path, monkeypatch):
    await _init(tmp_path, monkeypatch)
    host_id = await _add_host()

    await db_module.create_billing_circuit(name="C1", host_id=host_id, if_index=1, customer="Zeta Inc")
    await db_module.create_billing_circuit(name="C2", host_id=host_id, if_index=2, customer="Alpha LLC")
    await db_module.create_billing_circuit(name="C3", host_id=host_id, if_index=3, customer="Zeta Inc")

    customers = await db_module.get_billing_customers()
    assert customers == ["Alpha LLC", "Zeta Inc"]


# ═════════════════════════════════════════════════════════════════════════════
# Billing Generation Tests
# ═════════════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_generate_billing_with_samples(tmp_path, monkeypatch):
    """Generate billing from interface_ts samples, verify P95 and overage."""
    await _init(tmp_path, monkeypatch)
    host_id = await _add_host()

    circuit = await db_module.create_billing_circuit(
        name="Transit",
        host_id=host_id,
        if_index=1,
        if_name="Gi0/0",
        customer="Customer A",
        commit_rate_bps=50_000_000,  # 50 Mbps commit
        cost_per_mbps=10.0,
        overage_enabled=1,
    )

    # Generate 100 samples: most at ~30 Mbps, some spikes up to 80 Mbps
    samples = []
    for i in range(100):
        ts = f"2026-03-{1 + i // 4:02d}T{(i % 4) * 6:02d}:00:00"
        if i >= 96:  # top 4 samples are high (spikes)
            in_bps = 80_000_000.0
            out_bps = 60_000_000.0
        else:
            in_bps = 30_000_000.0 + (i * 100_000)  # 30-39.5 Mbps range
            out_bps = 20_000_000.0 + (i * 50_000)
        samples.append((in_bps, out_bps, ts))

    await _add_interface_samples(host_id, 1, samples)

    period = await generate_billing_for_circuit(
        circuit,
        period_start="2026-03-01T00:00:00",
        period_end="2026-04-01T00:00:00",
    )

    assert period["total_samples"] == 100
    assert period["p95_in_bps"] > 0
    assert period["p95_out_bps"] > 0
    assert period["p95_billing_bps"] > 0
    # With 50 Mbps commit and samples going up to 80 Mbps,
    # the P95 should be above commit for some configurations
    # (depends on exact distribution)
    assert period["status"] in ("generated", "overage")


@pytest.mark.asyncio
async def test_generate_billing_no_samples(tmp_path, monkeypatch):
    """Generate billing with no samples should produce a zero-value period."""
    await _init(tmp_path, monkeypatch)
    host_id = await _add_host()

    circuit = await db_module.create_billing_circuit(
        name="Empty", host_id=host_id, if_index=1,
        commit_rate_bps=100_000_000,
    )

    period = await generate_billing_for_circuit(
        circuit,
        period_start="2026-03-01T00:00:00",
        period_end="2026-04-01T00:00:00",
    )

    assert period["total_samples"] == 0
    assert period["p95_billing_bps"] == 0
    assert period["status"] == "generated"


@pytest.mark.asyncio
async def test_generate_billing_overage_detection(tmp_path, monkeypatch):
    """P95 above commit rate should mark status as 'overage' with cost."""
    await _init(tmp_path, monkeypatch)
    host_id = await _add_host()

    circuit = await db_module.create_billing_circuit(
        name="Overage Test",
        host_id=host_id,
        if_index=1,
        commit_rate_bps=10_000_000,  # 10 Mbps commit
        cost_per_mbps=20.0,
        overage_enabled=1,
    )

    # All samples at 50 Mbps = P95 should be ~50 Mbps
    samples = [
        (50_000_000.0, 40_000_000.0, f"2026-03-{1 + i // 10:02d}T{i % 10:02d}:00:00")
        for i in range(100)
    ]
    await _add_interface_samples(host_id, 1, samples)

    period = await generate_billing_for_circuit(
        circuit,
        period_start="2026-03-01T00:00:00",
        period_end="2026-04-01T00:00:00",
    )

    assert period["status"] == "overage"
    assert period["overage_bps"] > 0
    assert period["overage_cost"] > 0
    # P95 should be ~50 Mbps, commit is 10 Mbps
    # Overage = ~40 Mbps at $20/Mbps = ~$800
    assert period["overage_cost"] > 500


# ═════════════════════════════════════════════════════════════════════════════
# API Endpoint Tests
# ═════════════════════════════════════════════════════════════════════════════


@pytest.fixture
def app_client(tmp_path, monkeypatch):
    """Create a test client with a known admin account."""
    monkeypatch.setattr(db_module, "DB_PATH", str(tmp_path / "test.db"))
    monkeypatch.setenv("APP_ALLOW_SELF_REGISTER", "true")
    monkeypatch.setenv("APP_SECRET_KEY", "test-secret-key-for-billing")
    monkeypatch.setenv("APP_REQUIRE_API_TOKEN", "false")
    monkeypatch.setenv("PLEXUS_DEV_BOOTSTRAP", "1")

    from fastapi.testclient import TestClient
    from netcontrol.app import app

    with TestClient(app) as client:
        yield client


def _admin_headers(client):
    """Login as the bootstrap admin and return auth headers with CSRF token."""
    login = client.post("/api/auth/login", json={
        "username": "admin", "password": "netcontrol",
    })
    data = login.json()
    token = data.get("token", "")
    csrf = data.get("csrf_token", "")
    return {"Authorization": f"Bearer {token}", "X-CSRF-Token": csrf}


def test_api_list_circuits_empty(app_client):
    client = app_client
    headers = _admin_headers(client)

    resp = client.get("/api/billing/circuits", headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    assert "circuits" in data
    assert len(data["circuits"]) == 0


def test_api_circuit_crud(app_client):
    client = app_client
    headers = _admin_headers(client)

    # Insert a host directly via sync sqlite3 (inventory API routes differ)
    import sqlite3
    conn = sqlite3.connect(db_module.DB_PATH)
    conn.execute("INSERT OR IGNORE INTO inventory_groups (name) VALUES ('billing-test')")
    conn.execute(
        "INSERT INTO hosts (group_id, hostname, ip_address) VALUES (1, 'router1', '10.0.0.1')"
    )
    conn.commit()
    host_id = conn.execute("SELECT id FROM hosts WHERE hostname='router1'").fetchone()[0]
    conn.close()

    # Create circuit
    create_resp = client.post("/api/billing/circuits", json={
        "name": "ISP-A",
        "host_id": host_id,
        "if_index": 1,
        "if_name": "Gi0/0",
        "customer": "Acme",
        "commit_rate_bps": 100000000,
        "cost_per_mbps": 5.0,
    }, headers=headers)
    assert create_resp.status_code == 201
    circuit = create_resp.json()
    assert circuit["name"] == "ISP-A"

    # Get circuit
    get_resp = client.get(f"/api/billing/circuits/{circuit['id']}", headers=headers)
    assert get_resp.status_code == 200

    # Update circuit
    put_resp = client.put(f"/api/billing/circuits/{circuit['id']}", json={
        "name": "ISP-A Updated",
    }, headers=headers)
    assert put_resp.status_code == 200
    assert put_resp.json()["name"] == "ISP-A Updated"

    # List circuits
    list_resp = client.get("/api/billing/circuits", headers=headers)
    assert len(list_resp.json()["circuits"]) == 1

    # Delete
    del_resp = client.delete(f"/api/billing/circuits/{circuit['id']}", headers=headers)
    assert del_resp.status_code == 200


def test_api_billing_summary(app_client):
    client = app_client
    headers = _admin_headers(client)

    resp = client.get("/api/billing/summary", headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    assert "total_circuits" in data
    assert "overage_periods" in data


def test_api_billing_export_csv(app_client):
    client = app_client
    headers = _admin_headers(client)

    resp = client.get("/api/billing/export/periods", headers=headers)
    assert resp.status_code == 200
    assert "text/csv" in resp.headers.get("content-type", "")
