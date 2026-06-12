"""Graphs persistence helpers.

Split out of routes/database.py; star re-exported there so the
``routes.database`` facade keeps its full public surface.
"""
from __future__ import annotations

import asyncio
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
    "list_graph_templates",
    "get_graph_template",
    "create_graph_template",
    "update_graph_template",
    "delete_graph_template",
    "create_graph_template_item",
    "update_graph_template_item",
    "delete_graph_template_item",
    "list_host_templates",
    "get_host_template",
    "create_host_template",
    "update_host_template",
    "delete_host_template",
    "link_graph_template_to_host_template",
    "unlink_graph_template_from_host_template",
    "list_host_graphs",
    "get_host_graph",
    "create_host_graph",
    "update_host_graph",
    "delete_host_graph",
    "apply_graph_templates_to_host",
    "apply_interface_graph_templates_to_host",
    "list_graph_trees",
    "get_graph_tree",
    "create_graph_tree",
    "update_graph_tree",
    "delete_graph_tree",
    "create_graph_tree_node",
    "update_graph_tree_node",
    "delete_graph_tree_node",
    "list_data_source_profiles",
    "get_data_source_profile",
    "create_data_source_profile",
    "update_data_source_profile",
    "delete_data_source_profile",
    "BUILT_IN_GRAPH_TEMPLATES",
    "seed_built_in_graph_templates",
    "list_snmp_data_sources",
    "get_snmp_data_source",
    "upsert_snmp_data_source",
    "update_snmp_data_source",
    "delete_snmp_data_source",
    "delete_snmp_data_sources_for_host",
    "BUILT_IN_CDEFS",
    "list_cdef_definitions",
    "get_cdef_definition",
    "create_cdef_definition",
    "update_cdef_definition",
    "delete_cdef_definition",
    "seed_built_in_cdefs",
]

# ═════════════════════════════════════════════════════════════════════════════
# Graph Templates (Cacti-parity)
# ═════════════════════════════════════════════════════════════════════════════

async def list_graph_templates(
    category: str | None = None, scope: str | None = None, built_in: bool | None = None,
) -> list[dict]:
    db = await _dbcore.get_db()
    try:
        clauses: list[str] = []
        params: list = []
        if category:
            clauses.append("category = ?")
            params.append(category)
        if scope:
            clauses.append("scope = ?")
            params.append(scope)
        if built_in is not None:
            clauses.append("built_in = ?")
            params.append(1 if built_in else 0)
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        cursor = await db.execute(
            f"SELECT * FROM graph_templates{where} ORDER BY category, name", tuple(params),
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def get_graph_template(template_id: int) -> dict | None:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute("SELECT * FROM graph_templates WHERE id = ?", (template_id,))
        row = await cursor.fetchone()
        if not row:
            return None
        tpl = dict(row)
        cursor2 = await db.execute(
            "SELECT * FROM graph_template_items WHERE template_id = ? ORDER BY sort_order",
            (template_id,),
        )
        tpl["items"] = rows_to_list(await cursor2.fetchall())
        return tpl
    finally:
        await db.close()


async def create_graph_template(
    name: str, description: str = "", graph_type: str = "line",
    category: str = "system", scope: str = "device",
    title_format: str = "", y_axis_label: str = "",
    y_min: float | None = None, y_max: float | None = None,
    stacked: bool = False, area_fill: bool = True,
    grid_w: int = 6, grid_h: int = 4, options_json: str = "{}",
    built_in: bool = False, created_by: str = "",
) -> dict:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            """INSERT INTO graph_templates
               (name, description, graph_type, category, scope, title_format,
                y_axis_label, y_min, y_max, stacked, area_fill, grid_w, grid_h,
                options_json, built_in, created_by)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (name, description, graph_type, category, scope, title_format,
             y_axis_label, y_min, y_max, int(stacked), int(area_fill),
             grid_w, grid_h, options_json, int(built_in), created_by),
        )
        await db.commit()
        new_id = cursor.lastrowid
        cursor2 = await db.execute("SELECT * FROM graph_templates WHERE id = ?", (new_id,))
        return dict(await cursor2.fetchone())
    finally:
        await db.close()


async def update_graph_template(template_id: int, **kwargs) -> dict | None:
    allowed = {
        "name", "description", "graph_type", "category", "scope", "title_format",
        "y_axis_label", "y_min", "y_max", "stacked", "area_fill", "grid_w", "grid_h",
        "options_json",
    }
    updates = {k: v for k, v in kwargs.items() if k in allowed and v is not None}
    if not updates:
        return await get_graph_template(template_id)
    for bkey in ("stacked", "area_fill"):
        if bkey in updates:
            updates[bkey] = int(updates[bkey])
    set_exprs = [f"{k} = ?" for k in updates]
    set_exprs.append("updated_at = datetime('now')")
    sql, sql_params = _safe_dynamic_update("graph_templates", set_exprs, list(updates.values()), "id = ?", template_id)
    db = await _dbcore.get_db()
    try:
        await db.execute(sql, sql_params)
        await db.commit()
        return await get_graph_template(template_id)
    finally:
        await db.close()


async def delete_graph_template(template_id: int) -> bool:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute("DELETE FROM graph_templates WHERE id = ?", (template_id,))
        await db.commit()
        return cursor.rowcount > 0
    finally:
        await db.close()


# ── Graph Template Items ───────────────────────────────────────────────────

async def create_graph_template_item(
    template_id: int, sort_order: int = 0, metric_name: str = "",
    label: str = "", color: str = "", line_type: str = "area",
    cdef_expression: str = "", consolidation: str = "avg",
    transform: str = "", legend_format: str = "",
) -> dict:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            """INSERT INTO graph_template_items
               (template_id, sort_order, metric_name, label, color, line_type,
                cdef_expression, consolidation, transform, legend_format)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (template_id, sort_order, metric_name, label, color, line_type,
             cdef_expression, consolidation, transform, legend_format),
        )
        await db.commit()
        new_id = cursor.lastrowid
        cursor2 = await db.execute("SELECT * FROM graph_template_items WHERE id = ?", (new_id,))
        return dict(await cursor2.fetchone())
    finally:
        await db.close()


async def update_graph_template_item(item_id: int, **kwargs) -> dict | None:
    allowed = {
        "sort_order", "metric_name", "label", "color", "line_type",
        "cdef_expression", "consolidation", "transform", "legend_format",
    }
    updates = {k: v for k, v in kwargs.items() if k in allowed and v is not None}
    if not updates:
        return None
    set_exprs = [f"{k} = ?" for k in updates]
    sql, sql_params = _safe_dynamic_update("graph_template_items", set_exprs, list(updates.values()), "id = ?", item_id)
    db = await _dbcore.get_db()
    try:
        await db.execute(sql, sql_params)
        await db.commit()
        cursor = await db.execute("SELECT * FROM graph_template_items WHERE id = ?", (item_id,))
        row = await cursor.fetchone()
        return dict(row) if row else None
    finally:
        await db.close()


async def delete_graph_template_item(item_id: int) -> bool:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute("DELETE FROM graph_template_items WHERE id = ?", (item_id,))
        await db.commit()
        return cursor.rowcount > 0
    finally:
        await db.close()


# ═════════════════════════════════════════════════════════════════════════════
# Host Templates (Cacti-parity)
# ═════════════════════════════════════════════════════════════════════════════

async def list_host_templates() -> list[dict]:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute("SELECT * FROM host_templates ORDER BY name")
        templates = rows_to_list(await cursor.fetchall())
        for tpl in templates:
            cursor2 = await db.execute(
                """SELECT gt.* FROM graph_templates gt
                   JOIN host_template_graph_links htgl ON htgl.graph_template_id = gt.id
                   WHERE htgl.host_template_id = ?
                   ORDER BY gt.category, gt.name""",
                (tpl["id"],),
            )
            tpl["graph_templates"] = rows_to_list(await cursor2.fetchall())
        return templates
    finally:
        await db.close()


async def get_host_template(template_id: int) -> dict | None:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute("SELECT * FROM host_templates WHERE id = ?", (template_id,))
        row = await cursor.fetchone()
        if not row:
            return None
        tpl = dict(row)
        cursor2 = await db.execute(
            """SELECT gt.* FROM graph_templates gt
               JOIN host_template_graph_links htgl ON htgl.graph_template_id = gt.id
               WHERE htgl.host_template_id = ?
               ORDER BY gt.category, gt.name""",
            (template_id,),
        )
        tpl["graph_templates"] = rows_to_list(await cursor2.fetchall())
        return tpl
    finally:
        await db.close()


async def create_host_template(
    name: str, description: str = "", device_types: str = "[]",
    auto_apply: bool = True, poll_interval: int | None = None,
    created_by: str = "",
) -> dict:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            """INSERT INTO host_templates (name, description, device_types, auto_apply, poll_interval, created_by)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (name, description, device_types, int(auto_apply), poll_interval, created_by),
        )
        await db.commit()
        new_id = cursor.lastrowid
        cursor2 = await db.execute("SELECT * FROM host_templates WHERE id = ?", (new_id,))
        return dict(await cursor2.fetchone())
    finally:
        await db.close()


async def update_host_template(template_id: int, **kwargs) -> dict | None:
    allowed = {"name", "description", "device_types", "auto_apply", "poll_interval"}
    updates = {k: v for k, v in kwargs.items() if k in allowed and v is not None}
    if not updates:
        return await get_host_template(template_id)
    if "auto_apply" in updates:
        updates["auto_apply"] = int(updates["auto_apply"])
    set_exprs = [f"{k} = ?" for k in updates]
    set_exprs.append("updated_at = datetime('now')")
    sql, sql_params = _safe_dynamic_update("host_templates", set_exprs, list(updates.values()), "id = ?", template_id)
    db = await _dbcore.get_db()
    try:
        await db.execute(sql, sql_params)
        await db.commit()
        return await get_host_template(template_id)
    finally:
        await db.close()


async def delete_host_template(template_id: int) -> bool:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute("DELETE FROM host_templates WHERE id = ?", (template_id,))
        await db.commit()
        return cursor.rowcount > 0
    finally:
        await db.close()


async def link_graph_template_to_host_template(
    host_template_id: int, graph_template_id: int,
) -> dict:
    db = await _dbcore.get_db()
    try:
        await db.execute(
            """INSERT OR IGNORE INTO host_template_graph_links (host_template_id, graph_template_id)
               VALUES (?, ?)""",
            (host_template_id, graph_template_id),
        )
        await db.commit()
        return {"host_template_id": host_template_id, "graph_template_id": graph_template_id}
    finally:
        await db.close()


async def unlink_graph_template_from_host_template(
    host_template_id: int, graph_template_id: int,
) -> bool:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            """DELETE FROM host_template_graph_links
               WHERE host_template_id = ? AND graph_template_id = ?""",
            (host_template_id, graph_template_id),
        )
        await db.commit()
        return cursor.rowcount > 0
    finally:
        await db.close()


# ═════════════════════════════════════════════════════════════════════════════
# Host Graphs (graph template instances applied to devices)
# ═════════════════════════════════════════════════════════════════════════════

async def list_host_graphs(
    host_id: int | None = None, graph_template_id: int | None = None,
    enabled_only: bool = False,
) -> list[dict]:
    db = await _dbcore.get_db()
    try:
        clauses: list[str] = []
        params: list = []
        if host_id is not None:
            clauses.append("hg.host_id = ?")
            params.append(host_id)
        if graph_template_id is not None:
            clauses.append("hg.graph_template_id = ?")
            params.append(graph_template_id)
        if enabled_only:
            clauses.append("hg.enabled = 1")
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        cursor = await db.execute(
            f"""SELECT hg.*, gt.name AS template_name, gt.graph_type, gt.category,
                       gt.y_axis_label, gt.stacked, gt.area_fill
                FROM host_graphs hg
                JOIN graph_templates gt ON gt.id = hg.graph_template_id
                {where}
                ORDER BY hg.host_id, gt.category, gt.name, hg.instance_key""",
            tuple(params),
        )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def get_host_graph(host_graph_id: int) -> dict | None:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            """SELECT hg.*, gt.name AS template_name, gt.graph_type, gt.category,
                      gt.y_axis_label, gt.stacked, gt.area_fill, gt.options_json AS template_options
               FROM host_graphs hg
               JOIN graph_templates gt ON gt.id = hg.graph_template_id
               WHERE hg.id = ?""",
            (host_graph_id,),
        )
        row = await cursor.fetchone()
        if not row:
            return None
        hg = dict(row)
        cursor2 = await db.execute(
            "SELECT * FROM graph_template_items WHERE template_id = ? ORDER BY sort_order",
            (hg["graph_template_id"],),
        )
        hg["items"] = rows_to_list(await cursor2.fetchall())
        return hg
    finally:
        await db.close()


async def create_host_graph(
    host_id: int, graph_template_id: int, title: str = "",
    instance_key: str = "", instance_label: str = "",
    enabled: bool = True, pinned: bool = False,
    options_json: str = "{}",
) -> dict:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            """INSERT OR IGNORE INTO host_graphs
               (host_id, graph_template_id, title, instance_key, instance_label, enabled, pinned, options_json)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (host_id, graph_template_id, title, instance_key, instance_label,
             int(enabled), int(pinned), options_json),
        )
        await db.commit()
        new_id = cursor.lastrowid
        if new_id:
            cursor2 = await db.execute("SELECT * FROM host_graphs WHERE id = ?", (new_id,))
            return dict(await cursor2.fetchone())
        # Already existed (IGNORE), fetch existing
        cursor3 = await db.execute(
            """SELECT * FROM host_graphs
               WHERE host_id = ? AND graph_template_id = ? AND instance_key = ?""",
            (host_id, graph_template_id, instance_key),
        )
        row = await cursor3.fetchone()
        return dict(row) if row else {}
    finally:
        await db.close()


async def update_host_graph(host_graph_id: int, **kwargs) -> dict | None:
    allowed = {"title", "instance_label", "enabled", "pinned", "options_json"}
    updates = {k: v for k, v in kwargs.items() if k in allowed and v is not None}
    if not updates:
        return await get_host_graph(host_graph_id)
    for bkey in ("enabled", "pinned"):
        if bkey in updates:
            updates[bkey] = int(updates[bkey])
    set_exprs = [f"{k} = ?" for k in updates]
    sql, sql_params = _safe_dynamic_update("host_graphs", set_exprs, list(updates.values()), "id = ?", host_graph_id)
    db = await _dbcore.get_db()
    try:
        await db.execute(sql, sql_params)
        await db.commit()
        return await get_host_graph(host_graph_id)
    finally:
        await db.close()


async def delete_host_graph(host_graph_id: int) -> bool:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute("DELETE FROM host_graphs WHERE id = ?", (host_graph_id,))
        await db.commit()
        return cursor.rowcount > 0
    finally:
        await db.close()


async def apply_graph_templates_to_host(host_id: int) -> list[dict]:
    """Auto-create host_graphs for a device based on matching host templates.

    Matches the host's device_type against host_templates.device_types JSON array.
    Creates host_graph entries for each linked graph_template (scope='device').
    Returns list of newly created host_graph rows.
    """
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute("SELECT * FROM hosts WHERE id = ?", (host_id,))
        host = await cursor.fetchone()
        if not host:
            return []
        host = dict(host)
        device_type = (host.get("device_type") or "").strip().lower()

        cursor2 = await db.execute(
            "SELECT * FROM host_templates WHERE auto_apply = 1"
        )
        htemplates = rows_to_list(await cursor2.fetchall())

        created: list[dict] = []
        for ht in htemplates:
            try:
                dt_list = json.loads(ht.get("device_types", "[]"))
            except (json.JSONDecodeError, TypeError):
                dt_list = []
            # Empty list means "match all devices"
            if dt_list and device_type not in [d.lower() for d in dt_list]:
                continue

            cursor3 = await db.execute(
                """SELECT gt.* FROM graph_templates gt
                   JOIN host_template_graph_links htgl ON htgl.graph_template_id = gt.id
                   WHERE htgl.host_template_id = ? AND gt.scope = 'device'""",
                (ht["id"],),
            )
            graph_templates = rows_to_list(await cursor3.fetchall())
            for gt in graph_templates:
                cursor4 = await db.execute(
                    """INSERT OR IGNORE INTO host_graphs
                       (host_id, graph_template_id, title, instance_key, enabled)
                       VALUES (?, ?, ?, '', 1)""",
                    (host_id, gt["id"], gt.get("title_format") or gt["name"]),
                )
                await db.commit()
                if cursor4.lastrowid:
                    cursor5 = await db.execute(
                        "SELECT * FROM host_graphs WHERE id = ?", (cursor4.lastrowid,)
                    )
                    row = await cursor5.fetchone()
                    if row:
                        created.append(dict(row))
        return created
    finally:
        await db.close()


async def apply_interface_graph_templates_to_host(host_id: int, interfaces: list[dict]) -> list[dict]:
    """Auto-create host_graphs for each interface on a device.

    For graph_templates with scope='interface', creates one host_graph per interface.
    Each interface becomes a unique instance_key (if_index) with instance_label (if_name).
    """
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            "SELECT * FROM graph_templates WHERE scope = 'interface'"
        )
        iface_templates = rows_to_list(await cursor.fetchall())
        if not iface_templates:
            return []

        created: list[dict] = []
        for iface in interfaces:
            if_index = str(iface.get("if_index", iface.get("ifIndex", "")))
            if_name = iface.get("if_name", iface.get("ifDescr", ""))
            if not if_index:
                continue
            for gt in iface_templates:
                title = (gt.get("title_format") or gt["name"]).replace(
                    "$interface", if_name
                ).replace("$ifIndex", if_index)
                cursor2 = await db.execute(
                    """INSERT OR IGNORE INTO host_graphs
                       (host_id, graph_template_id, title, instance_key, instance_label, enabled)
                       VALUES (?, ?, ?, ?, ?, 1)""",
                    (host_id, gt["id"], title, if_index, if_name),
                )
                await db.commit()
                if cursor2.lastrowid:
                    cursor3 = await db.execute(
                        "SELECT * FROM host_graphs WHERE id = ?", (cursor2.lastrowid,)
                    )
                    row = await cursor3.fetchone()
                    if row:
                        created.append(dict(row))
        return created
    finally:
        await db.close()


# ═════════════════════════════════════════════════════════════════════════════
# Graph Trees (hierarchical navigation)
# ═════════════════════════════════════════════════════════════════════════════

async def list_graph_trees() -> list[dict]:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute("SELECT * FROM graph_trees ORDER BY sort_order, name")
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def get_graph_tree(tree_id: int) -> dict | None:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute("SELECT * FROM graph_trees WHERE id = ?", (tree_id,))
        row = await cursor.fetchone()
        if not row:
            return None
        tree = dict(row)
        cursor2 = await db.execute(
            "SELECT * FROM graph_tree_nodes WHERE tree_id = ? ORDER BY sort_order",
            (tree_id,),
        )
        tree["nodes"] = rows_to_list(await cursor2.fetchall())
        return tree
    finally:
        await db.close()


async def create_graph_tree(
    name: str, description: str = "", sort_order: int = 0, created_by: str = "",
) -> dict:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            "INSERT INTO graph_trees (name, description, sort_order, created_by) VALUES (?, ?, ?, ?)",
            (name, description, sort_order, created_by),
        )
        await db.commit()
        new_id = cursor.lastrowid
        cursor2 = await db.execute("SELECT * FROM graph_trees WHERE id = ?", (new_id,))
        return dict(await cursor2.fetchone())
    finally:
        await db.close()


async def update_graph_tree(tree_id: int, **kwargs) -> dict | None:
    allowed = {"name", "description", "sort_order"}
    updates = {k: v for k, v in kwargs.items() if k in allowed and v is not None}
    if not updates:
        return await get_graph_tree(tree_id)
    set_exprs = [f"{k} = ?" for k in updates]
    set_exprs.append("updated_at = datetime('now')")
    sql, sql_params = _safe_dynamic_update("graph_trees", set_exprs, list(updates.values()), "id = ?", tree_id)
    db = await _dbcore.get_db()
    try:
        await db.execute(sql, sql_params)
        await db.commit()
        return await get_graph_tree(tree_id)
    finally:
        await db.close()


async def delete_graph_tree(tree_id: int) -> bool:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute("DELETE FROM graph_trees WHERE id = ?", (tree_id,))
        await db.commit()
        return cursor.rowcount > 0
    finally:
        await db.close()


# ── Graph Tree Nodes ──────────────────────────────────────────────────────

async def create_graph_tree_node(
    tree_id: int, parent_node_id: int | None = None,
    node_type: str = "header", title: str = "",
    sort_order: int = 0, host_id: int | None = None,
    group_id: int | None = None, graph_id: int | None = None,
) -> dict:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            """INSERT INTO graph_tree_nodes
               (tree_id, parent_node_id, node_type, title, sort_order, host_id, group_id, graph_id)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (tree_id, parent_node_id, node_type, title, sort_order, host_id, group_id, graph_id),
        )
        await db.commit()
        new_id = cursor.lastrowid
        cursor2 = await db.execute("SELECT * FROM graph_tree_nodes WHERE id = ?", (new_id,))
        return dict(await cursor2.fetchone())
    finally:
        await db.close()


async def update_graph_tree_node(node_id: int, **kwargs) -> dict | None:
    allowed = {"parent_node_id", "node_type", "title", "sort_order", "host_id", "group_id", "graph_id"}
    updates = {k: v for k, v in kwargs.items() if k in allowed}
    if not updates:
        return None
    set_exprs = [f"{k} = ?" for k in updates]
    sql, sql_params = _safe_dynamic_update("graph_tree_nodes", set_exprs, list(updates.values()), "id = ?", node_id)
    db = await _dbcore.get_db()
    try:
        await db.execute(sql, sql_params)
        await db.commit()
        cursor = await db.execute("SELECT * FROM graph_tree_nodes WHERE id = ?", (node_id,))
        row = await cursor.fetchone()
        return dict(row) if row else None
    finally:
        await db.close()


async def delete_graph_tree_node(node_id: int) -> bool:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute("DELETE FROM graph_tree_nodes WHERE id = ?", (node_id,))
        await db.commit()
        return cursor.rowcount > 0
    finally:
        await db.close()


# ═════════════════════════════════════════════════════════════════════════════
# Data Source Profiles (per-device poll configuration)
# ═════════════════════════════════════════════════════════════════════════════

async def list_data_source_profiles(host_id: int | None = None) -> list[dict]:
    db = await _dbcore.get_db()
    try:
        if host_id is not None:
            cursor = await db.execute(
                "SELECT * FROM data_source_profiles WHERE host_id = ? ORDER BY profile_name",
                (host_id,),
            )
        else:
            cursor = await db.execute(
                "SELECT * FROM data_source_profiles ORDER BY host_id, profile_name"
            )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def get_data_source_profile(profile_id: int) -> dict | None:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute("SELECT * FROM data_source_profiles WHERE id = ?", (profile_id,))
        row = await cursor.fetchone()
        return dict(row) if row else None
    finally:
        await db.close()


async def create_data_source_profile(
    host_id: int, profile_name: str = "default",
    poll_interval: int = 300, oids_json: str = "[]",
    enabled: bool = True,
) -> dict:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            """INSERT OR IGNORE INTO data_source_profiles
               (host_id, profile_name, poll_interval, oids_json, enabled)
               VALUES (?, ?, ?, ?, ?)""",
            (host_id, profile_name, poll_interval, oids_json, int(enabled)),
        )
        await db.commit()
        new_id = cursor.lastrowid
        if new_id:
            cursor2 = await db.execute("SELECT * FROM data_source_profiles WHERE id = ?", (new_id,))
            return dict(await cursor2.fetchone())
        cursor3 = await db.execute(
            "SELECT * FROM data_source_profiles WHERE host_id = ? AND profile_name = ?",
            (host_id, profile_name),
        )
        return dict(await cursor3.fetchone())
    finally:
        await db.close()


async def update_data_source_profile(profile_id: int, **kwargs) -> dict | None:
    allowed = {"profile_name", "poll_interval", "oids_json", "enabled", "last_polled_at"}
    updates = {k: v for k, v in kwargs.items() if k in allowed and v is not None}
    if not updates:
        return await get_data_source_profile(profile_id)
    if "enabled" in updates:
        updates["enabled"] = int(updates["enabled"])
    set_exprs = [f"{k} = ?" for k in updates]
    set_exprs.append("updated_at = datetime('now')")
    sql, sql_params = _safe_dynamic_update("data_source_profiles", set_exprs, list(updates.values()), "id = ?", profile_id)
    db = await _dbcore.get_db()
    try:
        await db.execute(sql, sql_params)
        await db.commit()
        return await get_data_source_profile(profile_id)
    finally:
        await db.close()


async def delete_data_source_profile(profile_id: int) -> bool:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute("DELETE FROM data_source_profiles WHERE id = ?", (profile_id,))
        await db.commit()
        return cursor.rowcount > 0
    finally:
        await db.close()


# ── Built-in Graph Template Seeding ──────────────────────────────────────────

BUILT_IN_GRAPH_TEMPLATES = [
    {
        "name": "CPU Usage",
        "description": "Device CPU utilization over time",
        "graph_type": "line",
        "category": "system",
        "scope": "device",
        "title_format": "CPU Usage",
        "y_axis_label": "Percent",
        "y_min": 0,
        "y_max": 100,
        "stacked": False,
        "area_fill": True,
        "items": [
            {"metric_name": "cpu_usage", "label": "CPU %", "color": "#3B82F6",
             "line_type": "area", "consolidation": "avg", "legend_format": "Avg: {avg} Max: {max}"},
        ],
    },
    {
        "name": "Memory Usage",
        "description": "Device memory utilization over time",
        "graph_type": "line",
        "category": "system",
        "scope": "device",
        "title_format": "Memory Usage",
        "y_axis_label": "Percent",
        "y_min": 0,
        "y_max": 100,
        "stacked": False,
        "area_fill": True,
        "items": [
            {"metric_name": "memory_usage", "label": "Memory %", "color": "#8B5CF6",
             "line_type": "area", "consolidation": "avg", "legend_format": "Avg: {avg} Max: {max}"},
        ],
    },
    {
        "name": "Interface Traffic",
        "description": "Per-interface inbound and outbound traffic in bits per second",
        "graph_type": "line",
        "category": "traffic",
        "scope": "interface",
        "title_format": "Traffic - $interface",
        "y_axis_label": "Bits/sec",
        "y_min": 0,
        "y_max": None,
        "stacked": False,
        "area_fill": True,
        "items": [
            {"sort_order": 0, "metric_name": "if_in_octets", "label": "Inbound",
             "color": "#10B981", "line_type": "area", "consolidation": "avg",
             "transform": "rate,8,*", "legend_format": "In: {avg} bps (peak {max})"},
            {"sort_order": 1, "metric_name": "if_out_octets", "label": "Outbound",
             "color": "#F59E0B", "line_type": "area", "consolidation": "avg",
             "transform": "rate,8,*,negate", "legend_format": "Out: {avg} bps (peak {max})"},
        ],
    },
    {
        "name": "Interface Errors & Discards",
        "description": "Per-interface error and discard counters",
        "graph_type": "line",
        "category": "traffic",
        "scope": "interface",
        "title_format": "Errors - $interface",
        "y_axis_label": "Errors/sec",
        "y_min": 0,
        "y_max": None,
        "stacked": True,
        "area_fill": False,
        "items": [
            {"sort_order": 0, "metric_name": "if_in_errors", "label": "In Errors",
             "color": "#EF4444", "line_type": "line", "consolidation": "avg",
             "transform": "rate"},
            {"sort_order": 1, "metric_name": "if_out_errors", "label": "Out Errors",
             "color": "#F97316", "line_type": "line", "consolidation": "avg",
             "transform": "rate"},
            {"sort_order": 2, "metric_name": "if_in_discards", "label": "In Discards",
             "color": "#A855F7", "line_type": "line", "consolidation": "avg",
             "transform": "rate"},
            {"sort_order": 3, "metric_name": "if_out_discards", "label": "Out Discards",
             "color": "#EC4899", "line_type": "line", "consolidation": "avg",
             "transform": "rate"},
        ],
    },
    {
        "name": "Device Uptime",
        "description": "Device uptime in days (gauge)",
        "graph_type": "gauge",
        "category": "system",
        "scope": "device",
        "title_format": "Uptime",
        "y_axis_label": "Days",
        "y_min": 0,
        "y_max": None,
        "stacked": False,
        "area_fill": False,
        "grid_w": 3,
        "grid_h": 3,
        "items": [
            {"metric_name": "uptime", "label": "Uptime", "color": "#10B981",
             "line_type": "line", "consolidation": "last",
             "transform": "div,8640000", "legend_format": "{last} days"},
        ],
    },
    {
        "name": "Interface Utilization",
        "description": "Per-interface utilization percentage",
        "graph_type": "line",
        "category": "traffic",
        "scope": "interface",
        "title_format": "Utilization - $interface",
        "y_axis_label": "Percent",
        "y_min": 0,
        "y_max": 100,
        "stacked": False,
        "area_fill": True,
        "items": [
            {"sort_order": 0, "metric_name": "if_utilization_in", "label": "In Utilization",
             "color": "#3B82F6", "line_type": "area", "consolidation": "avg",
             "legend_format": "Avg: {avg}% Peak: {max}%"},
            {"sort_order": 1, "metric_name": "if_utilization_out", "label": "Out Utilization",
             "color": "#F59E0B", "line_type": "area", "consolidation": "avg",
             "legend_format": "Avg: {avg}% Peak: {max}%"},
        ],
    },
    {
        "name": "Ping Latency",
        "description": "ICMP round-trip latency over time",
        "graph_type": "line",
        "category": "availability",
        "scope": "device",
        "title_format": "Ping Latency",
        "y_axis_label": "ms",
        "y_min": 0,
        "y_max": None,
        "stacked": False,
        "area_fill": True,
        "items": [
            {"metric_name": "ping_rtt", "label": "RTT", "color": "#06B6D4",
             "line_type": "area", "consolidation": "avg",
             "legend_format": "Avg: {avg}ms Max: {max}ms"},
        ],
    },
    # ── Get-started pack ───────────────────────────────────────────────────
    # The templates below reference metric names the monitoring poller
    # actually emits into metric_samples (see metrics_engine
    # .emit_metric_samples_from_poll), so they plot real data on a fresh
    # install with zero manual setup.
    {
        "name": "Response Time",
        "description": "Polled round-trip response time (SNMP/ICMP) over time",
        "graph_type": "line",
        "category": "availability",
        "scope": "device",
        "title_format": "Response Time",
        "y_axis_label": "ms",
        "y_min": 0,
        "y_max": None,
        "stacked": False,
        "area_fill": True,
        "items": [
            {"metric_name": "response_time_ms", "label": "Response Time",
             "color": "#06B6D4", "line_type": "area", "consolidation": "avg",
             "legend_format": "Avg: {avg}ms Max: {max}ms"},
        ],
    },
    {
        "name": "Packet Loss",
        "description": "Percentage of probe packets lost over time",
        "graph_type": "line",
        "category": "availability",
        "scope": "device",
        "title_format": "Packet Loss",
        "y_axis_label": "Percent",
        "y_min": 0,
        "y_max": 100,
        "stacked": False,
        "area_fill": True,
        "items": [
            {"metric_name": "packet_loss_pct", "label": "Loss %",
             "color": "#EF4444", "line_type": "area", "consolidation": "avg",
             "legend_format": "Avg: {avg}% Max: {max}%"},
        ],
    },
    {
        "name": "System Overview",
        "description": "CPU and memory utilization on one chart for an at-a-glance health view",
        "graph_type": "line",
        "category": "system",
        "scope": "device",
        "title_format": "System Overview",
        "y_axis_label": "Percent",
        "y_min": 0,
        "y_max": 100,
        "stacked": False,
        "area_fill": False,
        "items": [
            {"sort_order": 0, "metric_name": "cpu_percent", "label": "CPU %",
             "color": "#3B82F6", "line_type": "line", "consolidation": "avg",
             "legend_format": "CPU avg: {avg}% peak: {max}%"},
            {"sort_order": 1, "metric_name": "memory_percent", "label": "Memory %",
             "color": "#8B5CF6", "line_type": "line", "consolidation": "avg",
             "legend_format": "Mem avg: {avg}% peak: {max}%"},
        ],
    },
    {
        "name": "Memory (MB)",
        "description": "Absolute memory used versus total in megabytes",
        "graph_type": "line",
        "category": "system",
        "scope": "device",
        "title_format": "Memory (MB)",
        "y_axis_label": "MB",
        "y_min": 0,
        "y_max": None,
        "stacked": False,
        "area_fill": True,
        "items": [
            {"sort_order": 0, "metric_name": "memory_used_mb", "label": "Used",
             "color": "#8B5CF6", "line_type": "area", "consolidation": "avg",
             "legend_format": "Used avg: {avg} MB"},
            {"sort_order": 1, "metric_name": "memory_total_mb", "label": "Total",
             "color": "#64748B", "line_type": "line", "consolidation": "last",
             "legend_format": "Total: {last} MB"},
        ],
    },
    {
        "name": "Interface Up/Down Count",
        "description": "Number of interfaces operationally up vs down on the device",
        "graph_type": "line",
        "category": "availability",
        "scope": "device",
        "title_format": "Interfaces Up / Down",
        "y_axis_label": "Interfaces",
        "y_min": 0,
        "y_max": None,
        "stacked": False,
        "area_fill": False,
        "items": [
            {"sort_order": 0, "metric_name": "if_up_count", "label": "Up",
             "color": "#10B981", "line_type": "line", "consolidation": "avg",
             "legend_format": "Up: {last}"},
            {"sort_order": 1, "metric_name": "if_down_count", "label": "Down",
             "color": "#EF4444", "line_type": "line", "consolidation": "avg",
             "legend_format": "Down: {last}"},
        ],
    },
    {
        "name": "Routing Table Size",
        "description": "Number of routes in the device routing table over time",
        "graph_type": "line",
        "category": "system",
        "scope": "device",
        "title_format": "Routing Table Size",
        "y_axis_label": "Routes",
        "y_min": 0,
        "y_max": None,
        "stacked": False,
        "area_fill": True,
        "items": [
            {"metric_name": "route_count", "label": "Routes",
             "color": "#0EA5E9", "line_type": "area", "consolidation": "avg",
             "legend_format": "Avg: {avg} Max: {max}"},
        ],
    },
    {
        "name": "VPN Tunnels",
        "description": "Count of VPN tunnels up vs down (firewalls / VPN gateways)",
        "graph_type": "line",
        "category": "availability",
        "scope": "device",
        "title_format": "VPN Tunnels",
        "y_axis_label": "Tunnels",
        "y_min": 0,
        "y_max": None,
        "stacked": False,
        "area_fill": False,
        "items": [
            {"sort_order": 0, "metric_name": "vpn_tunnels_up", "label": "Up",
             "color": "#10B981", "line_type": "line", "consolidation": "avg",
             "legend_format": "Up: {last}"},
            {"sort_order": 1, "metric_name": "vpn_tunnels_down", "label": "Down",
             "color": "#EF4444", "line_type": "line", "consolidation": "avg",
             "legend_format": "Down: {last}"},
        ],
    },
    {
        "name": "Device Uptime (Days)",
        "description": "Device uptime trend in days",
        "graph_type": "line",
        "category": "system",
        "scope": "device",
        "title_format": "Uptime (Days)",
        "y_axis_label": "Days",
        "y_min": 0,
        "y_max": None,
        "stacked": False,
        "area_fill": True,
        "items": [
            {"metric_name": "uptime_seconds", "label": "Uptime",
             "color": "#10B981", "line_type": "area", "consolidation": "last",
             "transform": "div,86400", "legend_format": "{last} days"},
        ],
    },
]


async def seed_built_in_graph_templates() -> int:
    """Create built-in graph templates if they don't already exist. Returns count created."""
    db = await _dbcore.get_db()
    try:
        created = 0
        for tpl_def in BUILT_IN_GRAPH_TEMPLATES:
            cursor = await db.execute(
                "SELECT id FROM graph_templates WHERE name = ? AND built_in = 1",
                (tpl_def["name"],),
            )
            if await cursor.fetchone():
                continue
            items = tpl_def.pop("items", [])
            cursor2 = await db.execute(
                """INSERT INTO graph_templates
                   (name, description, graph_type, category, scope, title_format,
                    y_axis_label, y_min, y_max, stacked, area_fill, grid_w, grid_h,
                    options_json, built_in, created_by)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, '{}', 1, 'system')""",
                (tpl_def["name"], tpl_def.get("description", ""),
                 tpl_def.get("graph_type", "line"), tpl_def.get("category", "system"),
                 tpl_def.get("scope", "device"), tpl_def.get("title_format", ""),
                 tpl_def.get("y_axis_label", ""),
                 tpl_def.get("y_min"), tpl_def.get("y_max"),
                 int(tpl_def.get("stacked", False)), int(tpl_def.get("area_fill", True)),
                 tpl_def.get("grid_w", 6), tpl_def.get("grid_h", 4)),
            )
            await db.commit()
            tpl_id = cursor2.lastrowid
            for idx, item in enumerate(items):
                await db.execute(
                    """INSERT INTO graph_template_items
                       (template_id, sort_order, metric_name, label, color, line_type,
                        cdef_expression, consolidation, transform, legend_format)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (tpl_id, item.get("sort_order", idx),
                     item.get("metric_name", ""), item.get("label", ""),
                     item.get("color", ""), item.get("line_type", "area"),
                     item.get("cdef_expression", ""), item.get("consolidation", "avg"),
                     item.get("transform", ""), item.get("legend_format", "")),
                )
            await db.commit()
            tpl_def["items"] = items
            created += 1
            _LOGGER.info("Seeded built-in graph template: %s (id=%s)", tpl_def["name"], tpl_id)

        # Ensure the default host template exists, then (re)link every
        # built-in device-scope graph template into it.  The link backfill
        # runs every startup -- not just on first creation -- so newly
        # added built-ins auto-apply on upgrade, not only on fresh installs.
        # INSERT OR IGNORE keeps it idempotent.
        cursor_ht = await db.execute(
            "SELECT id FROM host_templates WHERE name = 'Default (All Devices)'"
        )
        ht_row = await cursor_ht.fetchone()
        if ht_row:
            ht_id = ht_row[0] if isinstance(ht_row, tuple) else dict(ht_row)["id"]
        else:
            cursor_ht2 = await db.execute(
                """INSERT INTO host_templates (name, description, device_types, auto_apply, created_by)
                   VALUES ('Default (All Devices)', 'Auto-applies system graphs to all discovered devices',
                           '[]', 1, 'system')""",
            )
            await db.commit()
            ht_id = cursor_ht2.lastrowid
            _LOGGER.info("Seeded default host template (id=%s)", ht_id)

        cursor_device_tpls = await db.execute(
            "SELECT id FROM graph_templates WHERE built_in = 1 AND scope = 'device'"
        )
        linked = 0
        for row in await cursor_device_tpls.fetchall():
            gt_id = row[0] if isinstance(row, tuple) else dict(row)["id"]
            link_cur = await db.execute(
                "INSERT OR IGNORE INTO host_template_graph_links (host_template_id, graph_template_id) VALUES (?, ?)",
                (ht_id, gt_id),
            )
            linked += link_cur.rowcount if link_cur.rowcount and link_cur.rowcount > 0 else 0
        await db.commit()
        if linked:
            _LOGGER.info(
                "Linked %s built-in device graph template(s) into the default host template",
                linked,
            )

        return created
    finally:
        await db.close()


# ═════════════════════════════════════════════════════════════════════════════
# SNMP DATA SOURCES  (auto-discovered interfaces as independent data sources)
# ═════════════════════════════════════════════════════════════════════════════


async def list_snmp_data_sources(host_id: int, ds_type: str | None = None) -> list[dict]:
    db = await _dbcore.get_db()
    try:
        if ds_type:
            cursor = await db.execute(
                "SELECT * FROM snmp_data_sources WHERE host_id = ? AND ds_type = ? ORDER BY instance_key",
                (host_id, ds_type),
            )
        else:
            cursor = await db.execute(
                "SELECT * FROM snmp_data_sources WHERE host_id = ? ORDER BY ds_type, instance_key",
                (host_id,),
            )
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def get_snmp_data_source(ds_id: int) -> dict | None:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute("SELECT * FROM snmp_data_sources WHERE id = ?", (ds_id,))
        row = await cursor.fetchone()
        return row_to_dict(row) if row else None
    finally:
        await db.close()


async def upsert_snmp_data_source(
    host_id: int, ds_type: str, instance_key: str, **kwargs
) -> int:
    """Atomic upsert using INSERT ... ON CONFLICT DO UPDATE (SQLite 3.24+)."""
    allowed = {"name", "table_oid", "index_oid", "instance_label",
               "oids_json", "poll_interval", "enabled", "last_polled_at"}
    name = kwargs.get("name", "")
    table_oid = kwargs.get("table_oid", "")
    index_oid = kwargs.get("index_oid", "")
    instance_label = kwargs.get("instance_label", "")
    oids_json = kwargs.get("oids_json", "[]")
    poll_interval = kwargs.get("poll_interval", 300)
    enabled = kwargs.get("enabled", 1)
    # Build SET clause for ON CONFLICT from provided kwargs
    update_sets = []
    for k in kwargs:
        if k in allowed:
            update_sets.append(f"{k} = excluded.{k}")
    if not update_sets:
        # Nothing to update on conflict - no-op SET
        update_sets = ["name = excluded.name"]
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            f"""INSERT INTO snmp_data_sources
                (host_id, ds_type, instance_key, name, table_oid, index_oid,
                 instance_label, oids_json, poll_interval, enabled)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(host_id, ds_type, instance_key) DO UPDATE SET
                {', '.join(update_sets)}
                RETURNING id""",
            (host_id, ds_type, instance_key, name, table_oid, index_oid,
             instance_label, oids_json, poll_interval, enabled),
        )
        row = await cursor.fetchone()
        await db.commit()
        return int(row[0])
    except Exception:
        await db.rollback()
        raise
    finally:
        await db.close()


async def update_snmp_data_source(ds_id: int, **kwargs) -> bool:
    db = await _dbcore.get_db()
    try:
        sets = []
        vals = []
        for k, v in kwargs.items():
            if k in ("name", "poll_interval", "enabled", "oids_json", "last_polled_at"):
                sets.append(f"{k} = ?")
                vals.append(v)
        if not sets:
            return False
        sql, sql_params = _safe_dynamic_update("snmp_data_sources", sets, vals, "id = ?", ds_id)
        await db.execute(sql, sql_params)
        await db.commit()
        return True
    finally:
        await db.close()


async def delete_snmp_data_source(ds_id: int) -> bool:
    db = await _dbcore.get_db()
    try:
        await db.execute("DELETE FROM snmp_data_sources WHERE id = ?", (ds_id,))
        await db.commit()
        return True
    finally:
        await db.close()


async def delete_snmp_data_sources_for_host(host_id: int) -> int:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            "DELETE FROM snmp_data_sources WHERE host_id = ?", (host_id,)
        )
        await db.commit()
        return cursor.rowcount
    finally:
        await db.close()


# ═════════════════════════════════════════════════════════════════════════════
# CDEF DEFINITIONS  (calculated data sources / expressions)
# ═════════════════════════════════════════════════════════════════════════════

BUILT_IN_CDEFS = [
    {
        "name": "Total Bandwidth",
        "description": "Sum of inbound and outbound traffic (in+out)",
        "expression": "a,b,+",
    },
    {
        "name": "95th Percentile",
        "description": "95th percentile of the data series",
        "expression": "PERCENTILE_95",
    },
    {
        "name": "Average",
        "description": "Average of the data series",
        "expression": "AVG",
    },
    {
        "name": "Peak (Max)",
        "description": "Maximum value of the data series",
        "expression": "MAX",
    },
    {
        "name": "Bits to Bytes",
        "description": "Convert bits to bytes (divide by 8)",
        "expression": "a,8,/",
    },
    {
        "name": "Bytes to Bits",
        "description": "Convert bytes to bits (multiply by 8)",
        "expression": "a,8,*",
    },
    {
        "name": "Invert (Negate)",
        "description": "Negate the value (for outbound display below axis)",
        "expression": "a,-1,*",
    },
]


async def list_cdef_definitions() -> list[dict]:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute("SELECT * FROM cdef_definitions ORDER BY built_in DESC, name")
        return rows_to_list(await cursor.fetchall())
    finally:
        await db.close()


async def get_cdef_definition(cdef_id: int) -> dict | None:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute("SELECT * FROM cdef_definitions WHERE id = ?", (cdef_id,))
        row = await cursor.fetchone()
        return row_to_dict(row) if row else None
    finally:
        await db.close()


async def create_cdef_definition(name: str, expression: str, description: str = "",
                                  built_in: int = 0, created_by: str = "") -> int:
    db = await _dbcore.get_db()
    try:
        cursor = await db.execute(
            """INSERT INTO cdef_definitions (name, description, expression, built_in, created_by)
               VALUES (?, ?, ?, ?, ?)""",
            (name, description, expression, built_in, created_by),
        )
        await db.commit()
        return cursor.lastrowid
    finally:
        await db.close()


async def update_cdef_definition(cdef_id: int, **kwargs) -> bool:
    db = await _dbcore.get_db()
    try:
        sets = []
        vals = []
        for k, v in kwargs.items():
            if k in ("name", "description", "expression"):
                sets.append(f"{k} = ?")
                vals.append(v)
        if not sets:
            return False
        sql, sql_params = _safe_dynamic_update("cdef_definitions", sets, vals, "id = ?", cdef_id)
        await db.execute(sql, sql_params)
        await db.commit()
        return True
    finally:
        await db.close()


async def delete_cdef_definition(cdef_id: int) -> bool:
    db = await _dbcore.get_db()
    try:
        await db.execute("DELETE FROM cdef_definitions WHERE id = ?", (cdef_id,))
        await db.commit()
        return True
    finally:
        await db.close()


async def seed_built_in_cdefs() -> int:
    db = await _dbcore.get_db()
    try:
        created = 0
        for cdef in BUILT_IN_CDEFS:
            cursor = await db.execute(
                "SELECT id FROM cdef_definitions WHERE name = ? AND built_in = 1",
                (cdef["name"],),
            )
            if await cursor.fetchone():
                continue
            await db.execute(
                """INSERT INTO cdef_definitions (name, description, expression, built_in, created_by)
                   VALUES (?, ?, ?, 1, 'system')""",
                (cdef["name"], cdef.get("description", ""), cdef["expression"]),
            )
            await db.commit()
            created += 1
        return created
    finally:
        await db.close()


