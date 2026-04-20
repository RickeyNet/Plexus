"""
federation.py -- Multi-instance federation APIs.

Provides:
  - Federation peer CRUD (register/edit/remove remote Plexus instances)
  - Peer connectivity testing
  - Manual and automatic sync of aggregate data from peers
  - Federated overview endpoint aggregating metrics across all peers
"""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime
from urllib.parse import urlparse

import httpx
import routes.database as db
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from routes.crypto import decrypt, encrypt
from netcontrol.routes.shared import _audit, _corr_id, _get_session
from netcontrol.telemetry import configure_logging

router = APIRouter()
LOGGER = configure_logging("plexus.federation")

_require_admin = None

# Background sync defaults
_SYNC_INTERVAL_SECONDS = 300  # 5 minutes
_HTTP_TIMEOUT_SECONDS = 30


# ── Late-binding init ────────────────────────────────────────────────────────

def init_federation(require_admin):
    global _require_admin
    _require_admin = require_admin


async def _require_admin_dep(request: Request):
    if _require_admin is None:
        raise HTTPException(status_code=500, detail="Authorization subsystem not initialized")
    return await _require_admin(request)


# ── Pydantic models ─────────────────────────────────────────────────────────

class PeerCreate(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    url: str = Field(min_length=1, max_length=2000)
    api_token: str = ""
    description: str = ""
    enabled: bool = True


class PeerUpdate(BaseModel):
    name: str | None = None
    url: str | None = None
    api_token: str | None = None
    description: str | None = None
    enabled: bool | None = None


# ── Helpers ──────────────────────────────────────────────────────────────────

def _validate_url(url: str) -> str:
    """Validate and normalize a peer URL."""
    url = url.strip().rstrip("/")
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise HTTPException(status_code=422, detail="Peer URL must use http or https scheme")
    if not parsed.hostname:
        raise HTTPException(status_code=422, detail="Peer URL must include a hostname")
    return url


def _peer_row_to_dict(row) -> dict:
    """Convert a DB row to a peer dict (never expose encrypted token)."""
    d = dict(row) if not isinstance(row, dict) else row
    d.pop("api_token_enc", None)
    has_token = bool(row["api_token_enc"]) if "api_token_enc" in (row.keys() if hasattr(row, "keys") else row) else False
    d["has_token"] = has_token
    return d


def _is_missing_federation_table_error(exc: Exception) -> bool:
    """Return True when the backing federation tables are not available yet."""
    message = str(exc).lower()
    return (
        "federation_" in message
        and (
            "no such table" in message
            or "does not exist" in message
            or "undefined table" in message
        )
    )


async def _get_peer_or_404(peer_id: int) -> dict:
    """Fetch a peer by ID or raise 404."""
    cur = await db.get_db()
    try:
        c = await cur.execute(
            "SELECT * FROM federation_peers WHERE id = ?", (peer_id,)
        )
        row = await c.fetchone()
    finally:
        await cur.close()
    if not row:
        raise HTTPException(status_code=404, detail="Peer not found")
    return row


def _build_headers(api_token_enc: str) -> dict:
    """Build request headers for a remote peer, including decrypted API token."""
    headers = {"Accept": "application/json"}
    if api_token_enc:
        try:
            token = decrypt(api_token_enc)
            if token:
                headers["X-API-Token"] = token
        except Exception:
            LOGGER.warning("Failed to decrypt peer API token")
    return headers


async def _fetch_peer_data(url: str, api_token_enc: str) -> dict:
    """Fetch aggregate data from a remote Plexus peer."""
    headers = _build_headers(api_token_enc)
    base = url.rstrip("/")
    result = {
        "devices": {"total": 0, "up": 0, "down": 0, "groups": 0},
        "alerts": {"active": 0, "critical": 0, "warning": 0},
        "compliance": {"total_profiles": 0, "compliant_pct": 0},
        "version": "",
    }
    async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT_SECONDS, verify=False) as client:
        # Fetch inventory summary
        try:
            resp = await client.get(f"{base}/api/inventory/groups", headers=headers)
            if resp.status_code == 200:
                groups = resp.json()
                result["devices"]["groups"] = len(groups) if isinstance(groups, list) else 0
        except Exception as exc:
            LOGGER.debug("Federation: inventory/groups fetch failed: %s", exc)

        # Fetch hosts
        try:
            resp = await client.get(f"{base}/api/inventory/hosts", headers=headers)
            if resp.status_code == 200:
                hosts = resp.json()
                if isinstance(hosts, list):
                    result["devices"]["total"] = len(hosts)
                    result["devices"]["up"] = sum(1 for h in hosts if h.get("status") == "up")
                    result["devices"]["down"] = sum(1 for h in hosts if h.get("status") == "down")
        except Exception as exc:
            LOGGER.debug("Federation: inventory/hosts fetch failed: %s", exc)

        # Fetch active alerts
        try:
            resp = await client.get(f"{base}/api/monitoring/alerts", headers=headers)
            if resp.status_code == 200:
                data = resp.json()
                alerts = data if isinstance(data, list) else data.get("alerts", [])
                active = [a for a in alerts if a.get("state") == "active"]
                result["alerts"]["active"] = len(active)
                result["alerts"]["critical"] = sum(
                    1 for a in active if a.get("severity") == "critical"
                )
                result["alerts"]["warning"] = sum(
                    1 for a in active if a.get("severity") == "warning"
                )
        except Exception as exc:
            LOGGER.debug("Federation: alerts fetch failed: %s", exc)

        # Fetch compliance summary
        try:
            resp = await client.get(f"{base}/api/compliance/profiles", headers=headers)
            if resp.status_code == 200:
                profiles = resp.json()
                if isinstance(profiles, list):
                    result["compliance"]["total_profiles"] = len(profiles)
        except Exception as exc:
            LOGGER.debug("Federation: compliance fetch failed: %s", exc)

        # Fetch version
        try:
            resp = await client.get(f"{base}/api/admin/capabilities", headers=headers)
            if resp.status_code == 200:
                caps = resp.json()
                result["version"] = caps.get("version", "")
        except Exception as exc:
            LOGGER.debug("Federation: capabilities fetch failed: %s", exc)

    return result


# ── CRUD Routes ──────────────────────────────────────────────────────────────

@router.get("/api/federation/peers")
async def list_peers(request: Request, _user=Depends(_require_admin_dep)):
    """List all registered federation peers."""
    cur = await db.get_db()
    try:
        c = await cur.execute(
            "SELECT * FROM federation_peers ORDER BY name"
        )
        rows = await c.fetchall()
    finally:
        await cur.close()
    return [_peer_row_to_dict(r) for r in rows]


@router.post("/api/federation/peers", status_code=201)
async def create_peer(
    body: PeerCreate,
    request: Request,
    _user=Depends(_require_admin_dep),
):
    """Register a new federation peer."""
    url = _validate_url(body.url)
    token_enc = encrypt(body.api_token) if body.api_token else ""
    session = _get_session(request)
    username = session.get("user", "") if session else ""

    cur = await db.get_db()
    try:
        c = await cur.execute(
            """INSERT INTO federation_peers
                   (name, url, api_token_enc, description, enabled, created_by)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (body.name, url, token_enc, body.description, int(body.enabled), username),
        )
        await cur.commit()
        new_id = c.lastrowid
    finally:
        await cur.close()

    await _audit("federation", "peer_created", user=username,
                 detail=f"Peer '{body.name}' ({url}) id={new_id}",
                 correlation_id=_corr_id(request))

    peer = await _get_peer_or_404(new_id)
    return _peer_row_to_dict(peer)


@router.get("/api/federation/peers/{peer_id}")
async def get_peer(peer_id: int, request: Request, _user=Depends(_require_admin_dep)):
    """Get a single federation peer."""
    peer = await _get_peer_or_404(peer_id)
    return _peer_row_to_dict(peer)


@router.put("/api/federation/peers/{peer_id}")
async def update_peer(
    peer_id: int,
    body: PeerUpdate,
    request: Request,
    _user=Depends(_require_admin_dep),
):
    """Update a federation peer."""
    existing = await _get_peer_or_404(peer_id)
    updates = {}
    if body.name is not None:
        updates["name"] = body.name
    if body.url is not None:
        updates["url"] = _validate_url(body.url)
    if body.api_token is not None:
        updates["api_token_enc"] = encrypt(body.api_token) if body.api_token else ""
    if body.description is not None:
        updates["description"] = body.description
    if body.enabled is not None:
        updates["enabled"] = int(body.enabled)

    if not updates:
        return _peer_row_to_dict(existing)

    updates["updated_at"] = datetime.now(UTC).isoformat()
    set_clause = ", ".join(f"{k} = ?" for k in updates)
    values = list(updates.values()) + [peer_id]

    cur = await db.get_db()
    try:
        await cur.execute(
            f"UPDATE federation_peers SET {set_clause} WHERE id = ?",  # noqa: S608
            tuple(values),
        )
        await cur.commit()
    finally:
        await cur.close()

    session = _get_session(request)
    username = session.get("user", "") if session else ""
    await _audit("federation", "peer_updated", user=username,
                 detail=f"Peer id={peer_id} updated fields={list(updates.keys())}",
                 correlation_id=_corr_id(request))

    peer = await _get_peer_or_404(peer_id)
    return _peer_row_to_dict(peer)


@router.delete("/api/federation/peers/{peer_id}")
async def delete_peer(peer_id: int, request: Request, _user=Depends(_require_admin_dep)):
    """Remove a federation peer and its cached snapshots."""
    await _get_peer_or_404(peer_id)

    cur = await db.get_db()
    try:
        await cur.execute("DELETE FROM federation_snapshots WHERE peer_id = ?", (peer_id,))
        await cur.execute("DELETE FROM federation_peers WHERE id = ?", (peer_id,))
        await cur.commit()
    finally:
        await cur.close()

    session = _get_session(request)
    username = session.get("user", "") if session else ""
    await _audit("federation", "peer_deleted", user=username,
                 detail=f"Peer id={peer_id} deleted",
                 correlation_id=_corr_id(request))
    return {"status": "deleted", "id": peer_id}


# ── Connectivity & Sync ─────────────────────────────────────────────────────

@router.post("/api/federation/peers/{peer_id}/test")
async def test_peer(peer_id: int, request: Request, _user=Depends(_require_admin_dep)):
    """Test connectivity to a remote peer."""
    peer = await _get_peer_or_404(peer_id)
    url = peer["url"].rstrip("/")
    headers = _build_headers(peer["api_token_enc"])

    try:
        async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT_SECONDS, verify=False) as client:
            resp = await client.get(f"{url}/api/admin/capabilities", headers=headers)
        if resp.status_code == 200:
            caps = resp.json()
            return {
                "status": "ok",
                "remote_version": caps.get("version", "unknown"),
                "response_code": resp.status_code,
            }
        return {
            "status": "error",
            "message": f"Remote returned HTTP {resp.status_code}",
            "response_code": resp.status_code,
        }
    except httpx.ConnectError:
        return {"status": "error", "message": "Connection refused or unreachable"}
    except httpx.TimeoutException:
        return {"status": "error", "message": "Connection timed out"}
    except Exception:
        LOGGER.exception("Federation test failed for peer %d", peer_id)
        return {"status": "error", "message": "Unexpected error during connectivity test"}


@router.post("/api/federation/peers/{peer_id}/sync")
async def sync_peer(peer_id: int, request: Request, _user=Depends(_require_admin_dep)):
    """Manually trigger a full sync from a remote peer."""
    peer = await _get_peer_or_404(peer_id)
    now = datetime.now(UTC).isoformat()

    try:
        data = await _fetch_peer_data(peer["url"], peer["api_token_enc"])
    except Exception:
        LOGGER.exception("Federation sync failed for peer %d", peer_id)
        cur = await db.get_db()
        try:
            await cur.execute(
                "UPDATE federation_peers SET last_sync_at = ?, last_sync_status = ?, last_sync_message = ? WHERE id = ?",
                (now, "error", "Sync failed — check logs", peer_id),
            )
            await cur.commit()
        finally:
            await cur.close()
        raise HTTPException(status_code=502, detail="Failed to sync with remote peer")

    # Persist snapshot
    cur = await db.get_db()
    try:
        # Upsert snapshots by category
        for category in ("devices", "alerts", "compliance"):
            cat_data = data.get(category, {})
            # Delete old snapshot for this peer+category
            await cur.execute(
                "DELETE FROM federation_snapshots WHERE peer_id = ? AND category = ?",
                (peer_id, category),
            )
            await cur.execute(
                "INSERT INTO federation_snapshots (peer_id, category, data_json, captured_at) VALUES (?, ?, ?, ?)",
                (peer_id, category, json.dumps(cat_data), now),
            )

        # Store version as metadata snapshot
        await cur.execute(
            "DELETE FROM federation_snapshots WHERE peer_id = ? AND category = ?",
            (peer_id, "metadata"),
        )
        await cur.execute(
            "INSERT INTO federation_snapshots (peer_id, category, data_json, captured_at) VALUES (?, ?, ?, ?)",
            (peer_id, "metadata", json.dumps({"version": data.get("version", "")}), now),
        )

        # Update peer sync status
        await cur.execute(
            "UPDATE federation_peers SET last_sync_at = ?, last_sync_status = ?, last_sync_message = ?, updated_at = ? WHERE id = ?",
            (now, "ok", "", now, peer_id),
        )
        await cur.commit()
    finally:
        await cur.close()

    session = _get_session(request)
    username = session.get("user", "") if session else ""
    await _audit("federation", "peer_synced", user=username,
                 detail=f"Peer id={peer_id} synced",
                 correlation_id=_corr_id(request))

    return {"status": "ok", "peer_id": peer_id, "data": data}


# ── Federated Overview ───────────────────────────────────────────────────────

@router.get("/api/federation/overview")
async def federation_overview(request: Request, _user=Depends(_require_admin_dep)):
    """Aggregated overview across all federation peers."""
    cur = await db.get_db()
    try:
        c = await cur.execute(
            "SELECT * FROM federation_peers WHERE enabled = 1 ORDER BY name"
        )
        peers = await c.fetchall()

        # Load latest snapshots
        c = await cur.execute(
            "SELECT * FROM federation_snapshots ORDER BY captured_at DESC"
        )
        all_snapshots = await c.fetchall()
    finally:
        await cur.close()

    # Build per-peer summary
    snap_by_peer: dict[int, dict[str, dict]] = {}
    for s in all_snapshots:
        pid = s["peer_id"]
        cat = s["category"]
        if pid not in snap_by_peer:
            snap_by_peer[pid] = {}
        if cat not in snap_by_peer[pid]:
            try:
                snap_by_peer[pid][cat] = json.loads(s["data_json"])
            except (json.JSONDecodeError, TypeError):
                snap_by_peer[pid][cat] = {}

    totals = {
        "total_peers": len(peers),
        "healthy_peers": sum(1 for p in peers if p["last_sync_status"] == "ok"),
        "total_devices": 0,
        "devices_up": 0,
        "devices_down": 0,
        "total_alerts": 0,
        "critical_alerts": 0,
    }
    peer_summaries = []
    for p in peers:
        pid = p["id"]
        snap = snap_by_peer.get(pid, {})
        devices = snap.get("devices", {})
        alerts = snap.get("alerts", {})
        meta = snap.get("metadata", {})

        totals["total_devices"] += devices.get("total", 0)
        totals["devices_up"] += devices.get("up", 0)
        totals["devices_down"] += devices.get("down", 0)
        totals["total_alerts"] += alerts.get("active", 0)
        totals["critical_alerts"] += alerts.get("critical", 0)

        peer_summaries.append({
            "id": pid,
            "name": p["name"],
            "url": p["url"],
            "enabled": bool(p["enabled"]),
            "last_sync_at": p["last_sync_at"],
            "last_sync_status": p["last_sync_status"],
            "version": meta.get("version", ""),
            "devices": devices,
            "alerts": alerts,
            "compliance": snap.get("compliance", {}),
        })

    return {"totals": totals, "peers": peer_summaries}


# ── Background sync loop (launched from app.py lifespan) ─────────────────────

async def federation_sync_loop() -> None:
    """Periodically sync data from all enabled federation peers."""
    missing_tables_logged = False
    while True:
        try:
            await asyncio.sleep(_SYNC_INTERVAL_SECONDS)
            cur = await db.get_db()
            try:
                c = await cur.execute(
                    "SELECT * FROM federation_peers WHERE enabled = 1"
                )
                peers = await c.fetchall()
            finally:
                await cur.close()

            for peer in peers:
                try:
                    data = await _fetch_peer_data(peer["url"], peer["api_token_enc"])
                    now = datetime.now(UTC).isoformat()
                    cur = await db.get_db()
                    try:
                        for category in ("devices", "alerts", "compliance"):
                            await cur.execute(
                                "DELETE FROM federation_snapshots WHERE peer_id = ? AND category = ?",
                                (peer["id"], category),
                            )
                            await cur.execute(
                                "INSERT INTO federation_snapshots (peer_id, category, data_json, captured_at) VALUES (?, ?, ?, ?)",
                                (peer["id"], category, json.dumps(data.get(category, {})), now),
                            )
                        await cur.execute(
                            "DELETE FROM federation_snapshots WHERE peer_id = ? AND category = ?",
                            (peer["id"], "metadata"),
                        )
                        await cur.execute(
                            "INSERT INTO federation_snapshots (peer_id, category, data_json, captured_at) VALUES (?, ?, ?, ?)",
                            (peer["id"], "metadata", json.dumps({"version": data.get("version", "")}), now),
                        )
                        await cur.execute(
                            "UPDATE federation_peers SET last_sync_at = ?, last_sync_status = ?, last_sync_message = '', updated_at = ? WHERE id = ?",
                            (now, "ok", now, peer["id"]),
                        )
                        await cur.commit()
                    finally:
                        await cur.close()
                except Exception:
                    LOGGER.warning("Federation background sync failed for peer %d", peer["id"])
                    now = datetime.now(UTC).isoformat()
                    try:
                        cur2 = await db.get_db()
                        try:
                            await cur2.execute(
                                "UPDATE federation_peers SET last_sync_at = ?, last_sync_status = ?, last_sync_message = ? WHERE id = ?",
                                (now, "error", "Background sync failed", peer["id"]),
                            )
                            await cur2.commit()
                        finally:
                            await cur2.close()
                    except Exception:
                        LOGGER.warning("Failed to update sync status for peer %d", peer["id"])
            missing_tables_logged = False
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            if _is_missing_federation_table_error(exc):
                if not missing_tables_logged:
                    LOGGER.warning("Federation sync loop waiting for federation tables to be available")
                    missing_tables_logged = True
                continue
            missing_tables_logged = False
            LOGGER.warning("Federation sync loop iteration failed: %s", exc, exc_info=True)
