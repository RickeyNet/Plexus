"""Cloud persistence helpers.

Split out of routes/database.py; star re-exported there so the
``routes.database`` facade keeps its full public surface.
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import ipaddress
import json
import os
import re
from datetime import UTC, datetime, timedelta

import aiosqlite

import routes.database as _dbcore
from routes.database import (
    _LOGGER,
    _is_unique_violation,
    _safe_dynamic_update,
    row_to_dict,
    rows_to_list,
)

__all__ = [
    "create_cloud_account",
    "get_cloud_account",
    "list_cloud_accounts",
    "update_cloud_account",
    "delete_cloud_account",
    "reencrypt_legacy_cloud_auth_configs",
    "set_cloud_account_sync_status",
    "replace_cloud_discovery_snapshot",
    "get_cloud_policy_rules",
    "get_cloud_policy_effective_views",
    "get_cloud_resources",
    "get_cloud_connections",
    "get_cloud_hybrid_links",
    "get_cloud_topology_snapshot",
    "get_cloud_flow_sync_cursor",
    "upsert_cloud_flow_sync_cursor",
    "list_cloud_flow_sync_cursors",
    "get_cloud_traffic_metric_sync_cursor",
    "upsert_cloud_traffic_metric_sync_cursor",
    "list_cloud_traffic_metric_sync_cursors",
    "create_cloud_traffic_metrics_batch",
    "cleanup_old_cloud_traffic_metrics",
    "get_cloud_traffic_metric_summary",
    "get_cloud_traffic_metric_timeline",
    "get_cloud_traffic_metric_top_resources",
]

# ═════════════════════════════════════════════════════════════════════════════
# Cloud Visibility – Accounts, Resources, and Hybrid Connectivity
# ═════════════════════════════════════════════════════════════════════════════


def _cloud_json_text(value, default: str = "{}") -> str:
    if value is None:
        return default
    if isinstance(value, str):
        stripped = value.strip()
        return stripped or default
    try:
        return json.dumps(value, separators=(",", ":"), sort_keys=True)
    except Exception:
        return default


def _looks_encrypted(value: str) -> bool:
    """Heuristic test for whether a stored auth_config string is ciphertext
    (AES-256-GCM ``0x02`` prefix or legacy Fernet ``gAAAAA``) rather than a
    legacy plaintext-JSON row written before at-rest encryption."""
    if not value or value[:1] in "{[":
        return False
    if value.startswith("gAAAAA"):
        return True
    try:
        raw = base64.urlsafe_b64decode(value.encode())
    except Exception:
        return False
    return raw[:1] == b"\x02"


def _cloud_auth_encrypt(value) -> str:
    """Serialize and encrypt an auth_config blob for at-rest storage.

    Cloud account secrets (AWS ``secret_access_key``, Azure ``client_secret``,
    GCP key material) were previously stored as plaintext JSON. Encrypt them
    with the shared AES-256-GCM key, matching the IPAM/DHCP source pattern.
    """
    text = _cloud_json_text(value, default="")
    if not text or text == "{}":
        return ""
    from routes.crypto import encrypt as _enc
    return _enc(text)


async def reencrypt_legacy_cloud_auth_configs() -> int:
    """One-time startup pass: re-encrypt legacy plaintext auth_config rows.

    Accounts created before at-rest encryption keep cleartext credentials in
    the DB until their next save; run this at startup so they don't linger.
    Returns the number of rows rewritten.
    """
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute("SELECT id, auth_config_json FROM cloud_accounts")
        rows = await cursor.fetchall()
        fixed = 0
        for row in rows:
            stored = str(row["auth_config_json"] or "")
            if not stored or stored == "{}" or _looks_encrypted(stored):
                continue
            await db.execute(
                "UPDATE cloud_accounts SET auth_config_json = ? WHERE id = ?",
                (_cloud_auth_encrypt(stored), row["id"]),
            )
            fixed += 1
        if fixed:
            await db.commit()
        return fixed
    finally:
        await db.close()


def _cloud_auth_decrypt(stored) -> str:
    """Return plaintext JSON for a stored auth_config, transparently handling
    both new ciphertext and legacy plaintext rows so existing accounts keep
    working without a migration step."""
    if not stored:
        return "{}"
    if _looks_encrypted(stored):
        from routes.crypto import decrypt as _dec
        try:
            return _dec(stored) or "{}"
        except Exception:
            _LOGGER.warning("cloud: could not decrypt stored auth_config; treating as empty")
            return "{}"
    return stored


async def create_cloud_account(
    provider: str,
    name: str,
    account_identifier: str = "",
    region_scope: str = "",
    auth_type: str = "manual",
    auth_config_json: dict | list | str | None = None,
    notes: str = "",
    enabled: int = 1,
    created_by: str = "",
) -> dict | None:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            """INSERT INTO cloud_accounts
               (provider, name, account_identifier, region_scope, auth_type,
                auth_config_json, notes, enabled, created_by)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                provider,
                name,
                account_identifier,
                region_scope,
                auth_type,
                _cloud_auth_encrypt(auth_config_json),
                notes,
                int(bool(enabled)),
                created_by,
            ),
        )
        await db.commit()
        return await get_cloud_account(cursor.lastrowid)
    finally:
        await db.close()


async def get_cloud_account(account_id: int) -> dict | None:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            """SELECT ca.*,
                      (SELECT COUNT(*) FROM cloud_resources cr WHERE cr.account_id = ca.id) AS resource_count,
                      (SELECT COUNT(*) FROM cloud_connections cc WHERE cc.account_id = ca.id) AS connection_count,
                      (SELECT COUNT(*) FROM cloud_hybrid_links chl WHERE chl.account_id = ca.id) AS hybrid_link_count
               FROM cloud_accounts ca
               WHERE ca.id = ?""",
            (account_id,),
        )
        row = await cursor.fetchone()
        if not row:
            return None
        account = dict(row)
        # Decrypt for internal callers (collectors read auth_config_json off the
        # account dict). API responses strip this via _serialize_account.
        account["auth_config_json"] = _cloud_auth_decrypt(account.get("auth_config_json"))
        return account
    finally:
        await db.close()


async def list_cloud_accounts(
    provider: str | None = None,
    enabled_only: bool = False,
) -> list[dict]:
    db = await _dbcore.get_db()
    try:
        clauses: list[str] = []
        params: list = []
        if provider:
            clauses.append("ca.provider = ?")
            params.append(provider)
        if enabled_only:
            clauses.append("ca.enabled = 1")
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        cursor = await db.execute(
            f"""SELECT ca.*,
                       (SELECT COUNT(*) FROM cloud_resources cr WHERE cr.account_id = ca.id) AS resource_count,
                       (SELECT COUNT(*) FROM cloud_connections cc WHERE cc.account_id = ca.id) AS connection_count,
                       (SELECT COUNT(*) FROM cloud_hybrid_links chl WHERE chl.account_id = ca.id) AS hybrid_link_count
                FROM cloud_accounts ca
                {where}
                ORDER BY ca.provider ASC, ca.name ASC""",
            tuple(params),
        )
        accounts = rows_to_list(await cursor.fetchall())
        for account in accounts:
            account["auth_config_json"] = _cloud_auth_decrypt(account.get("auth_config_json"))
        return accounts
    finally:
        await db.close()


async def update_cloud_account(account_id: int, **kwargs) -> dict | None:
    db = await _dbcore.get_db()
    try:
        allowed = {
            "provider",
            "name",
            "account_identifier",
            "region_scope",
            "auth_type",
            "auth_config_json",
            "notes",
            "enabled",
            "last_sync_at",
            "last_sync_status",
            "last_sync_message",
        }
        sets: list[str] = []
        vals: list = []
        for key, value in kwargs.items():
            if key not in allowed or value is None:
                continue
            if key == "auth_config_json":
                value = _cloud_auth_encrypt(value)
            if key == "enabled":
                value = int(bool(value))
            sets.append(f"{key} = ?")
            vals.append(value)
        if not sets:
            return await get_cloud_account(account_id)
        sets.append("updated_at = NOW()" if _dbcore.DB_ENGINE == "postgres" else "updated_at = datetime('now')")
        sql, sql_params = _safe_dynamic_update("cloud_accounts", sets, vals, "id = ?", account_id)
        await db.execute(sql, sql_params)
        await db.commit()
        return await get_cloud_account(account_id)
    finally:
        await db.close()


async def delete_cloud_account(account_id: int) -> bool:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute("DELETE FROM cloud_accounts WHERE id = ?", (account_id,))
        await db.commit()
        return cursor.rowcount > 0
    finally:
        await db.close()


async def set_cloud_account_sync_status(
    account_id: int,
    *,
    status: str,
    message: str = "",
    last_sync_at: str | None = None,
) -> dict | None:
    sync_time = last_sync_at or datetime.now(UTC).isoformat()
    return await update_cloud_account(
        account_id,
        last_sync_status=status,
        last_sync_message=message,
        last_sync_at=sync_time,
    )


async def replace_cloud_discovery_snapshot(
    account_id: int,
    *,
    resources: list[dict] | None = None,
    connections: list[dict] | None = None,
    hybrid_links: list[dict] | None = None,
    sync_status: str = "success",
    sync_message: str = "",
) -> dict:
    resources = resources or []
    connections = connections or []
    hybrid_links = hybrid_links or []
    now_iso = datetime.now(UTC).isoformat()

    def _extract_policy_rules(resource_item: dict) -> list[dict]:
        metadata = resource_item.get("metadata")
        if metadata is None and resource_item.get("metadata_json"):
            try:
                metadata = json.loads(str(resource_item.get("metadata_json") or "{}"))
            except Exception:
                metadata = {}
        if not isinstance(metadata, dict):
            return []
        rules = metadata.get("policy_rules")
        return rules if isinstance(rules, list) else []

    def _normalize_policy_rule(resource_item: dict, rule: dict, index: int, provider_name: str) -> dict | None:
        resource_uid = str(resource_item.get("resource_uid") or resource_item.get("id") or "").strip()
        if not resource_uid or not isinstance(rule, dict):
            return None
        rule_name = str(rule.get("rule_name") or rule.get("name") or "").strip()
        direction = str(rule.get("direction") or "").strip().lower()
        if direction == "ingress":
            direction = "inbound"
        elif direction == "egress":
            direction = "outbound"
        action = str(rule.get("action") or "").strip().lower()
        protocol = str(rule.get("protocol") or "all").strip().lower() or "all"
        source_selector = str(rule.get("source_selector") or rule.get("source") or "").strip()
        destination_selector = str(rule.get("destination_selector") or rule.get("destination") or "").strip()
        port_expression = str(rule.get("port_expression") or rule.get("ports") or "").strip()
        raw_priority = rule.get("priority")
        priority = None
        if raw_priority not in (None, ""):
            try:
                priority = int(raw_priority)
            except Exception:
                priority = None
        raw_uid = str(rule.get("rule_uid") or rule.get("id") or "").strip()
        rule_uid = raw_uid or f"{resource_uid}:rule:{index + 1}:{direction or 'any'}:{action or 'any'}:{rule_name or 'unnamed'}"
        metadata = rule.get("metadata") if isinstance(rule.get("metadata"), dict) else {}
        return {
            "provider": str(resource_item.get("provider") or provider_name or "").strip(),
            "resource_uid": resource_uid,
            "rule_uid": rule_uid,
            "rule_name": rule_name,
            "direction": direction,
            "action": action,
            "protocol": protocol,
            "source_selector": source_selector,
            "destination_selector": destination_selector,
            "port_expression": port_expression,
            "priority": priority,
            "metadata_json": _cloud_json_text(metadata),
            "discovered_at": str(rule.get("discovered_at") or now_iso),
        }

    db = await _dbcore.get_db()
    try:
        account_row = await db.execute(
            "SELECT id, provider FROM cloud_accounts WHERE id = ?",
            (account_id,),
        )
        account = await account_row.fetchone()
        if not account:
            return {"ok": False, "resources": 0, "connections": 0, "hybrid_links": 0}
        provider = str(account["provider"])

        await db.execute("DELETE FROM cloud_resources WHERE account_id = ?", (account_id,))
        await db.execute("DELETE FROM cloud_connections WHERE account_id = ?", (account_id,))
        await db.execute("DELETE FROM cloud_hybrid_links WHERE account_id = ?", (account_id,))
        await db.execute("DELETE FROM cloud_policy_rules WHERE account_id = ?", (account_id,))

        resource_seen: dict[str, dict] = {}
        policy_rule_seen: dict[str, dict] = {}
        for item in resources:
            uid = str(item.get("resource_uid") or item.get("id") or "").strip()
            if not uid:
                continue
            resource_seen[uid] = {
                "provider": str(item.get("provider") or provider or "").strip(),
                "resource_uid": uid,
                "resource_type": str(item.get("resource_type") or "resource").strip(),
                "name": str(item.get("name") or "").strip(),
                "region": str(item.get("region") or "").strip(),
                "cidr": str(item.get("cidr") or "").strip(),
                "status": str(item.get("status") or "").strip(),
                "metadata_json": _cloud_json_text(item.get("metadata") or item.get("metadata_json")),
                "discovered_at": str(item.get("discovered_at") or now_iso),
                "updated_at": str(item.get("updated_at") or now_iso),
            }
            for index, raw_rule in enumerate(_extract_policy_rules(item)):
                normalized_rule = _normalize_policy_rule(item, raw_rule, index, provider)
                if not normalized_rule:
                    continue
                policy_rule_seen[normalized_rule["rule_uid"]] = normalized_rule

        for item in resource_seen.values():
            await db.execute(
                """INSERT INTO cloud_resources
                   (account_id, provider, resource_uid, resource_type, name, region, cidr,
                    status, metadata_json, discovered_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    account_id,
                    item["provider"],
                    item["resource_uid"],
                    item["resource_type"],
                    item["name"],
                    item["region"],
                    item["cidr"],
                    item["status"],
                    item["metadata_json"],
                    item["discovered_at"],
                    item["updated_at"],
                ),
            )

        connection_seen: dict[str, dict] = {}
        for item in connections:
            src = str(item.get("source_resource_uid") or item.get("source") or "").strip()
            dst = str(item.get("target_resource_uid") or item.get("target") or "").strip()
            ctype = str(item.get("connection_type") or "peering").strip()
            if not src or not dst:
                continue
            key = f"{src}|{dst}|{ctype}"
            connection_seen[key] = {
                "provider": str(item.get("provider") or provider or "").strip(),
                "source_resource_uid": src,
                "target_resource_uid": dst,
                "connection_type": ctype,
                "state": str(item.get("state") or "").strip(),
                "metadata_json": _cloud_json_text(item.get("metadata") or item.get("metadata_json")),
                "discovered_at": str(item.get("discovered_at") or now_iso),
            }

        for item in connection_seen.values():
            await db.execute(
                """INSERT INTO cloud_connections
                   (account_id, provider, source_resource_uid, target_resource_uid,
                    connection_type, state, metadata_json, discovered_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    account_id,
                    item["provider"],
                    item["source_resource_uid"],
                    item["target_resource_uid"],
                    item["connection_type"],
                    item["state"],
                    item["metadata_json"],
                    item["discovered_at"],
                ),
            )

        hybrid_seen: dict[str, dict] = {}
        for item in hybrid_links:
            cloud_uid = str(item.get("cloud_resource_uid") or item.get("target_resource_uid") or "").strip()
            ctype = str(item.get("connection_type") or "vpn").strip()
            host_id_raw = item.get("host_id")
            host_id = None
            if host_id_raw not in (None, ""):
                try:
                    host_id = int(host_id_raw)
                except Exception:
                    host_id = None
            host_label = str(item.get("host_label") or item.get("hostname") or "").strip()
            if not cloud_uid:
                continue
            key = f"{host_id}|{host_label}|{cloud_uid}|{ctype}"
            hybrid_seen[key] = {
                "provider": str(item.get("provider") or provider or "").strip(),
                "host_id": host_id,
                "host_label": host_label,
                "cloud_resource_uid": cloud_uid,
                "connection_type": ctype,
                "state": str(item.get("state") or "").strip(),
                "metadata_json": _cloud_json_text(item.get("metadata") or item.get("metadata_json")),
                "discovered_at": str(item.get("discovered_at") or now_iso),
            }

        for item in hybrid_seen.values():
            await db.execute(
                """INSERT INTO cloud_hybrid_links
                   (account_id, provider, host_id, host_label, cloud_resource_uid,
                    connection_type, state, metadata_json, discovered_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    account_id,
                    item["provider"],
                    item["host_id"],
                    item["host_label"],
                    item["cloud_resource_uid"],
                    item["connection_type"],
                    item["state"],
                    item["metadata_json"],
                    item["discovered_at"],
                ),
            )

        for item in policy_rule_seen.values():
            await db.execute(
                """INSERT INTO cloud_policy_rules
                   (account_id, provider, resource_uid, rule_uid, rule_name, direction,
                    action, protocol, source_selector, destination_selector,
                    port_expression, priority, metadata_json, discovered_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    account_id,
                    item["provider"],
                    item["resource_uid"],
                    item["rule_uid"],
                    item["rule_name"],
                    item["direction"],
                    item["action"],
                    item["protocol"],
                    item["source_selector"],
                    item["destination_selector"],
                    item["port_expression"],
                    item["priority"],
                    item["metadata_json"],
                    item["discovered_at"],
                ),
            )

        await db.execute(
            """UPDATE cloud_accounts
               SET last_sync_at = ?,
                   last_sync_status = ?,
                   last_sync_message = ?,
                   updated_at = ?"""
            + ("::timestamptz" if _dbcore.DB_ENGINE == "postgres" else "")
            + " WHERE id = ?",
            (now_iso, sync_status, sync_message, now_iso, account_id),
        )
        await db.commit()

        return {
            "ok": True,
            "resources": len(resource_seen),
            "connections": len(connection_seen),
            "hybrid_links": len(hybrid_seen),
            "policy_rules": len(policy_rule_seen),
        }
    finally:
        await db.close()


async def get_cloud_policy_rules(
    account_id: int | None = None,
    provider: str | None = None,
    resource_uid: str | None = None,
    direction: str | None = None,
    action: str | None = None,
    limit: int = 500,
) -> list[dict]:
    db = await _dbcore.get_db()
    try:
        clauses: list[str] = []
        params: list = []
        if account_id is not None:
            clauses.append("pr.account_id = ?")
            params.append(account_id)
        if provider:
            clauses.append("pr.provider = ?")
            params.append(provider)
        if resource_uid:
            clauses.append("pr.resource_uid = ?")
            params.append(resource_uid)
        if direction:
            clauses.append("LOWER(pr.direction) = ?")
            params.append(direction.lower())
        if action:
            clauses.append("LOWER(pr.action) = ?")
            params.append(action.lower())
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        params.append(max(1, min(int(limit), 2000)))
        cursor = await db.execute(
            f"""SELECT pr.*, ca.name AS account_name,
                       cr.name AS resource_name,
                       cr.resource_type,
                       cr.region AS resource_region
                FROM cloud_policy_rules pr
                JOIN cloud_accounts ca ON ca.id = pr.account_id
                LEFT JOIN cloud_resources cr
                  ON cr.account_id = pr.account_id
                 AND cr.resource_uid = pr.resource_uid
                {where}
                ORDER BY pr.provider,
                         COALESCE(cr.name, pr.resource_uid),
                         pr.direction,
                         CASE WHEN pr.priority IS NULL THEN 2147483647 ELSE pr.priority END,
                         pr.rule_name,
                         pr.rule_uid
                LIMIT ?""",
            tuple(params),
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def get_cloud_policy_effective_views(
    account_id: int | None = None,
    provider: str | None = None,
) -> list[dict]:
    db = await _dbcore.get_db()
    try:
        clauses = [
            "cr.resource_type IN ('security_group', 'network_security_group', 'firewall_policy')",
        ]
        params: list = []
        if account_id is not None:
            clauses.append("cr.account_id = ?")
            params.append(account_id)
        if provider:
            clauses.append("cr.provider = ?")
            params.append(provider)
        where = " AND ".join(clauses)
        cursor = await db.execute(
            f"""SELECT cr.account_id,
                       ca.name AS account_name,
                       cr.provider,
                       cr.resource_uid,
                       cr.resource_type,
                       cr.name AS resource_name,
                       cr.region,
                       COUNT(pr.id) AS rule_count,
                       COALESCE(SUM(CASE WHEN LOWER(COALESCE(pr.direction, '')) = 'inbound'
                                             AND LOWER(COALESCE(pr.action, '')) = 'allow'
                                        THEN 1 ELSE 0 END), 0) AS inbound_allow_count,
                       COALESCE(SUM(CASE WHEN LOWER(COALESCE(pr.direction, '')) = 'outbound'
                                             AND LOWER(COALESCE(pr.action, '')) = 'allow'
                                        THEN 1 ELSE 0 END), 0) AS outbound_allow_count,
                       COALESCE(SUM(CASE WHEN LOWER(COALESCE(pr.action, '')) = 'deny'
                                        THEN 1 ELSE 0 END), 0) AS deny_count,
                       COALESCE(SUM(CASE WHEN LOWER(COALESCE(pr.direction, '')) = 'inbound'
                                             AND LOWER(COALESCE(pr.action, '')) = 'allow'
                                             AND (
                                                 pr.source_selector LIKE '%0.0.0.0/0%'
                                                 OR pr.source_selector LIKE '%::/0%'
                                                 OR pr.source_selector = '*'
                                                 OR LOWER(pr.source_selector) = 'any'
                                             )
                                        THEN 1 ELSE 0 END), 0) AS public_ingress_count,
                       COALESCE(SUM(CASE WHEN LOWER(COALESCE(pr.direction, '')) = 'outbound'
                                             AND LOWER(COALESCE(pr.action, '')) = 'allow'
                                             AND (
                                                 pr.destination_selector LIKE '%0.0.0.0/0%'
                                                 OR pr.destination_selector LIKE '%::/0%'
                                                 OR pr.destination_selector = '*'
                                                 OR LOWER(pr.destination_selector) = 'any'
                                             )
                                        THEN 1 ELSE 0 END), 0) AS open_egress_count
                FROM cloud_resources cr
                JOIN cloud_accounts ca ON ca.id = cr.account_id
                LEFT JOIN cloud_policy_rules pr
                  ON pr.account_id = cr.account_id
                 AND pr.resource_uid = cr.resource_uid
                WHERE {where}
                GROUP BY cr.account_id, ca.name, cr.provider, cr.resource_uid, cr.resource_type, cr.name, cr.region
                ORDER BY public_ingress_count DESC, rule_count DESC, cr.provider, cr.name, cr.resource_uid""",
            tuple(params),
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def get_cloud_resources(
    account_id: int | None = None,
    provider: str | None = None,
    resource_type: str | None = None,
) -> list[dict]:
    db = await _dbcore.get_db()
    try:
        clauses: list[str] = []
        params: list = []
        if account_id is not None:
            clauses.append("cr.account_id = ?")
            params.append(account_id)
        if provider:
            clauses.append("cr.provider = ?")
            params.append(provider)
        if resource_type:
            clauses.append("cr.resource_type = ?")
            params.append(resource_type)
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        cursor = await db.execute(
            f"""SELECT cr.*, ca.name AS account_name, ca.account_identifier
                FROM cloud_resources cr
                JOIN cloud_accounts ca ON ca.id = cr.account_id
                {where}
                ORDER BY cr.provider, cr.resource_type, cr.name, cr.resource_uid""",
            tuple(params),
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def get_cloud_connections(
    account_id: int | None = None,
    provider: str | None = None,
) -> list[dict]:
    db = await _dbcore.get_db()
    try:
        clauses: list[str] = []
        params: list = []
        if account_id is not None:
            clauses.append("cc.account_id = ?")
            params.append(account_id)
        if provider:
            clauses.append("cc.provider = ?")
            params.append(provider)
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        cursor = await db.execute(
            f"""SELECT cc.*,
                       ca.name AS account_name,
                       src.name AS source_name,
                       src.resource_type AS source_type,
                       dst.name AS target_name,
                       dst.resource_type AS target_type
                FROM cloud_connections cc
                JOIN cloud_accounts ca ON ca.id = cc.account_id
                LEFT JOIN cloud_resources src
                  ON src.account_id = cc.account_id
                 AND src.resource_uid = cc.source_resource_uid
                LEFT JOIN cloud_resources dst
                  ON dst.account_id = cc.account_id
                 AND dst.resource_uid = cc.target_resource_uid
                {where}
                ORDER BY cc.provider, cc.connection_type, cc.source_resource_uid, cc.target_resource_uid""",
            tuple(params),
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def get_cloud_hybrid_links(
    account_id: int | None = None,
    provider: str | None = None,
) -> list[dict]:
    db = await _dbcore.get_db()
    try:
        clauses: list[str] = []
        params: list = []
        if account_id is not None:
            clauses.append("chl.account_id = ?")
            params.append(account_id)
        if provider:
            clauses.append("chl.provider = ?")
            params.append(provider)
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        cursor = await db.execute(
            f"""SELECT chl.*,
                       ca.name AS account_name,
                       h.hostname AS host_hostname,
                       h.ip_address AS host_ip_address,
                       cr.name AS cloud_resource_name,
                       cr.resource_type AS cloud_resource_type
                FROM cloud_hybrid_links chl
                JOIN cloud_accounts ca ON ca.id = chl.account_id
                LEFT JOIN hosts h ON h.id = chl.host_id
                LEFT JOIN cloud_resources cr
                  ON cr.account_id = chl.account_id
                 AND cr.resource_uid = chl.cloud_resource_uid
                {where}
                ORDER BY chl.provider, COALESCE(h.hostname, chl.host_label), chl.cloud_resource_uid""",
            tuple(params),
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def get_cloud_topology_snapshot(
    account_id: int | None = None,
    provider: str | None = None,
) -> dict:
    if account_id is not None:
        account = await get_cloud_account(account_id)
        accounts = [account] if account else []
    else:
        accounts = await list_cloud_accounts(provider=provider)
    resources = await get_cloud_resources(account_id=account_id, provider=provider)
    connections = await get_cloud_connections(account_id=account_id, provider=provider)
    hybrid_links = await get_cloud_hybrid_links(account_id=account_id, provider=provider)

    return {
        "accounts": accounts,
        "resources": resources,
        "connections": connections,
        "hybrid_links": hybrid_links,
        "summary": {
            "account_count": len(accounts),
            "resource_count": len(resources),
            "connection_count": len(connections),
            "hybrid_link_count": len(hybrid_links),
        },
    }


# ═════════════════════════════════════════════════════════════════════════════
# Cloud Flow Sync Cursors
# ═════════════════════════════════════════════════════════════════════════════


async def get_cloud_flow_sync_cursor(account_id: int) -> dict | None:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            "SELECT * FROM cloud_flow_sync_cursors WHERE account_id = ?",
            (account_id,),
        )
        row = await cursor.fetchone()
        return dict(row) if row else None
    finally:
        await db.close()


async def upsert_cloud_flow_sync_cursor(
    account_id: int,
    *,
    last_pull_end: str,
    extra_json: dict | None = None,
) -> None:
    db = await _dbcore.get_db()
    try:
        extra_text = _cloud_json_text(extra_json) if extra_json else "{}"
        now_iso = datetime.now(UTC).isoformat()
        await db.execute(
            """INSERT INTO cloud_flow_sync_cursors (account_id, last_pull_end, extra_json, updated_at)
               VALUES (?, ?, ?, ?)
               ON CONFLICT(account_id) DO UPDATE SET
                   last_pull_end = excluded.last_pull_end,
                   extra_json = excluded.extra_json,
                   updated_at = excluded.updated_at""",
            (account_id, last_pull_end, extra_text, now_iso),
        )
        await db.commit()
    finally:
        await db.close()


async def list_cloud_flow_sync_cursors() -> list[dict]:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            """SELECT c.*, ca.provider, ca.name AS account_name
               FROM cloud_flow_sync_cursors c
               JOIN cloud_accounts ca ON ca.id = c.account_id
               ORDER BY c.account_id""",
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def get_cloud_traffic_metric_sync_cursor(account_id: int) -> dict | None:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            "SELECT * FROM cloud_traffic_metric_sync_cursors WHERE account_id = ?",
            (account_id,),
        )
        row = await cursor.fetchone()
        return dict(row) if row else None
    finally:
        await db.close()


async def upsert_cloud_traffic_metric_sync_cursor(
    account_id: int,
    *,
    last_pull_end: str,
    extra_json: dict | None = None,
) -> None:
    db = await _dbcore.get_db()
    try:
        extra_text = _cloud_json_text(extra_json) if extra_json else "{}"
        now_iso = datetime.now(UTC).isoformat()
        await db.execute(
            """INSERT INTO cloud_traffic_metric_sync_cursors (account_id, last_pull_end, extra_json, updated_at)
               VALUES (?, ?, ?, ?)
               ON CONFLICT(account_id) DO UPDATE SET
                   last_pull_end = excluded.last_pull_end,
                   extra_json = excluded.extra_json,
                   updated_at = excluded.updated_at""",
            (account_id, last_pull_end, extra_text, now_iso),
        )
        await db.commit()
    finally:
        await db.close()


async def list_cloud_traffic_metric_sync_cursors() -> list[dict]:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            """SELECT c.*, ca.provider, ca.name AS account_name
               FROM cloud_traffic_metric_sync_cursors c
               JOIN cloud_accounts ca ON ca.id = c.account_id
               ORDER BY c.account_id""",
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def create_cloud_traffic_metrics_batch(rows: list[tuple]) -> int:
    """Batch insert normalized cloud traffic metric rows.

    Each tuple:
      (account_id, provider, metric_name, metric_namespace, resource_uid,
       direction, statistic, unit, metric_value, interval_start, interval_end,
       metadata_json, source)
    """
    if not rows:
        return 0
    db = await _dbcore.get_db()
    try:
        # OR IGNORE + the unique sample-identity index (migration 0059) makes
        # ingestion idempotent: overlapping manual/scheduled pull windows
        # re-submit the same samples instead of double counting them.
        cursor = await db.executemany(
            """INSERT OR IGNORE INTO cloud_traffic_metrics
               (account_id, provider, metric_name, metric_namespace, resource_uid,
                direction, statistic, unit, metric_value, interval_start, interval_end,
                metadata_json, source)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            rows,
        )
        await db.commit()
        inserted = getattr(cursor, "rowcount", -1) if cursor is not None else -1
        return inserted if isinstance(inserted, int) and inserted >= 0 else len(rows)
    finally:
        await db.close()


async def cleanup_old_cloud_traffic_metrics(hours: int = 168) -> int:
    """Delete cloud traffic metric samples older than ``hours``.

    Without this the table grows without bound (up to 10k rows per account
    per sync cycle); it is called from the traffic-metric sync loop.
    """
    cutoff = _cloud_metric_window_cutoff(hours)
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            "DELETE FROM cloud_traffic_metrics WHERE interval_end < ?",
            (cutoff,),
        )
        await db.commit()
        return cursor.rowcount
    finally:
        await db.close()


def _cloud_metric_window_cutoff(hours: int) -> str:
    """Return the lookback cutoff as an ISO-8601 UTC string.

    cloud_traffic_metrics interval timestamps are written via Python's
    ``datetime.isoformat()`` ('T' separator, '+00:00' offset). Comparing them
    lexically against SQLite's ``datetime('now', ...)`` output
    ('YYYY-MM-DD HH:MM:SS', space separator) is wrong at the cutoff-day
    boundary because 'T' sorts after ' ', so compute the cutoff in Python in
    the same format the rows are stored in. This is also engine-agnostic
    (works identically on SQLite and Postgres).
    """
    return (datetime.now(UTC) - timedelta(hours=max(1, int(hours)))).isoformat()


async def get_cloud_traffic_metric_summary(
    account_id: int | None = None,
    provider: str | None = None,
    hours: int = 24,
) -> dict:
    db = await _dbcore.get_db()
    try:
        clauses = [
            "interval_end >= ?",
        ]
        params: list = [_cloud_metric_window_cutoff(hours)]
        if account_id is not None:
            clauses.append("account_id = ?")
            params.append(account_id)
        if provider:
            clauses.append("provider = ?")
            params.append(provider)
        where = " AND ".join(clauses)
        cursor = await db.execute(
            f"""SELECT COUNT(*) as sample_count,
                       COUNT(DISTINCT metric_name) as metric_count,
                       COUNT(DISTINCT resource_uid) as resource_count,
                       COALESCE(SUM(metric_value), 0) as total_value,
                       COALESCE(AVG(metric_value), 0) as avg_value,
                       COALESCE(MIN(metric_value), 0) as min_value,
                       COALESCE(MAX(metric_value), 0) as max_value,
                       MIN(interval_start) as first_seen,
                       MAX(interval_end) as last_seen
                FROM cloud_traffic_metrics
                WHERE {where}""",
            tuple(params),
        )
        return row_to_dict(await cursor.fetchone()) or {
            "sample_count": 0,
            "metric_count": 0,
            "resource_count": 0,
            "total_value": 0,
            "avg_value": 0,
            "min_value": 0,
            "max_value": 0,
            "first_seen": None,
            "last_seen": None,
        }
    finally:
        await db.close()


async def get_cloud_traffic_metric_timeline(
    account_id: int | None = None,
    provider: str | None = None,
    metric_name: str | None = None,
    hours: int = 24,
    bucket_minutes: int = 5,
) -> list[dict]:
    bucket_minutes = max(1, min(int(bucket_minutes), 60))
    db = await _dbcore.get_db()
    try:
        clauses = [
            "interval_end >= ?",
        ]
        params: list = [_cloud_metric_window_cutoff(hours)]
        if account_id is not None:
            clauses.append("account_id = ?")
            params.append(account_id)
        if provider:
            clauses.append("provider = ?")
            params.append(provider)
        if metric_name:
            clauses.append("metric_name = ?")
            params.append(metric_name)
        where = " AND ".join(clauses)
        bucket_expr = _dbcore._minute_bucket_expr("interval_end", bucket_minutes)
        cursor = await db.execute(
            f"""SELECT
                   {bucket_expr} as bucket,
                   COUNT(*) as sample_count,
                   COALESCE(SUM(metric_value), 0) as total_value,
                   COALESCE(AVG(metric_value), 0) as avg_value,
                   COALESCE(MAX(metric_value), 0) as max_value
               FROM cloud_traffic_metrics
               WHERE {where}
               GROUP BY bucket
               ORDER BY bucket""",
            tuple(params),
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def get_cloud_traffic_metric_top_resources(
    account_id: int | None = None,
    provider: str | None = None,
    metric_name: str | None = None,
    hours: int = 24,
    limit: int = 20,
) -> list[dict]:
    db = await _dbcore.get_db()
    try:
        clauses = [
            "interval_end >= ?",
        ]
        params: list = [_cloud_metric_window_cutoff(hours)]
        if account_id is not None:
            clauses.append("account_id = ?")
            params.append(account_id)
        if provider:
            clauses.append("provider = ?")
            params.append(provider)
        if metric_name:
            clauses.append("metric_name = ?")
            params.append(metric_name)
        params.append(max(1, min(int(limit), 200)))
        where = " AND ".join(clauses)
        cursor = await db.execute(
            f"""SELECT
                   resource_uid,
                   COUNT(*) as sample_count,
                   COALESCE(SUM(metric_value), 0) as total_value,
                   COALESCE(AVG(metric_value), 0) as avg_value,
                   COALESCE(MAX(metric_value), 0) as max_value
               FROM cloud_traffic_metrics
               WHERE {where}
               GROUP BY resource_uid
               ORDER BY total_value DESC
               LIMIT ?""",
            tuple(params),
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


