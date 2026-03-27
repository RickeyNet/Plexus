"""
graph_templates.py -- Cacti-parity graph template system

Provides API endpoints for:
- Graph Templates (reusable chart definitions)
- Graph Template Items (series within a template)
- Host Templates (device type → graph template mappings)
- Host Graphs (template instances applied to specific devices)
- Graph Trees (hierarchical navigation)
- Data Source Profiles (per-device poll configuration)
"""

import routes.database as db
from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel

from netcontrol.telemetry import configure_logging

router = APIRouter()
LOGGER = configure_logging("plexus.graph_templates")


# ═════════════════════════════════════════════════════════════════════════════
# Pydantic Models
# ═════════════════════════════════════════════════════════════════════════════

class GraphTemplateCreate(BaseModel):
    name: str
    description: str = ""
    graph_type: str = "line"
    category: str = "system"
    scope: str = "device"
    title_format: str = ""
    y_axis_label: str = ""
    y_min: float | None = None
    y_max: float | None = None
    stacked: bool = False
    area_fill: bool = True
    grid_w: int = 6
    grid_h: int = 4
    options_json: str = "{}"


class GraphTemplateUpdate(BaseModel):
    name: str | None = None
    description: str | None = None
    graph_type: str | None = None
    category: str | None = None
    scope: str | None = None
    title_format: str | None = None
    y_axis_label: str | None = None
    y_min: float | None = None
    y_max: float | None = None
    stacked: bool | None = None
    area_fill: bool | None = None
    grid_w: int | None = None
    grid_h: int | None = None
    options_json: str | None = None


class GraphTemplateItemCreate(BaseModel):
    sort_order: int = 0
    metric_name: str = ""
    label: str = ""
    color: str = ""
    line_type: str = "area"
    cdef_expression: str = ""
    consolidation: str = "avg"
    transform: str = ""
    legend_format: str = ""


class GraphTemplateItemUpdate(BaseModel):
    sort_order: int | None = None
    metric_name: str | None = None
    label: str | None = None
    color: str | None = None
    line_type: str | None = None
    cdef_expression: str | None = None
    consolidation: str | None = None
    transform: str | None = None
    legend_format: str | None = None


class HostTemplateCreate(BaseModel):
    name: str
    description: str = ""
    device_types: str = "[]"
    auto_apply: bool = True
    poll_interval: int | None = None


class HostTemplateUpdate(BaseModel):
    name: str | None = None
    description: str | None = None
    device_types: str | None = None
    auto_apply: bool | None = None
    poll_interval: int | None = None


class HostGraphCreate(BaseModel):
    host_id: int
    graph_template_id: int
    title: str = ""
    instance_key: str = ""
    instance_label: str = ""
    enabled: bool = True
    pinned: bool = False
    options_json: str = "{}"


class HostGraphUpdate(BaseModel):
    title: str | None = None
    instance_label: str | None = None
    enabled: bool | None = None
    pinned: bool | None = None
    options_json: str | None = None


class GraphTreeCreate(BaseModel):
    name: str
    description: str = ""
    sort_order: int = 0


class GraphTreeUpdate(BaseModel):
    name: str | None = None
    description: str | None = None
    sort_order: int | None = None


class GraphTreeNodeCreate(BaseModel):
    parent_node_id: int | None = None
    node_type: str = "header"
    title: str = ""
    sort_order: int = 0
    host_id: int | None = None
    group_id: int | None = None
    graph_id: int | None = None


class GraphTreeNodeUpdate(BaseModel):
    parent_node_id: int | None = None
    node_type: str | None = None
    title: str | None = None
    sort_order: int | None = None
    host_id: int | None = None
    group_id: int | None = None
    graph_id: int | None = None


class DataSourceProfileCreate(BaseModel):
    host_id: int
    profile_name: str = "default"
    poll_interval: int = 300
    oids_json: str = "[]"
    enabled: bool = True


class DataSourceProfileUpdate(BaseModel):
    profile_name: str | None = None
    poll_interval: int | None = None
    oids_json: str | None = None
    enabled: bool | None = None


# ═════════════════════════════════════════════════════════════════════════════
# Graph Template CRUD
# ═════════════════════════════════════════════════════════════════════════════

@router.get("/api/graph-templates")
async def list_graph_templates_api(
    category: str | None = Query(default=None),
    scope: str | None = Query(default=None),
    built_in: bool | None = Query(default=None),
):
    templates = await db.list_graph_templates(category=category, scope=scope, built_in=built_in)
    return {"graph_templates": templates}


@router.get("/api/graph-templates/{template_id}")
async def get_graph_template_api(template_id: int):
    tpl = await db.get_graph_template(template_id)
    if not tpl:
        raise HTTPException(status_code=404, detail="Graph template not found")
    return tpl


@router.post("/api/graph-templates", status_code=201)
async def create_graph_template_api(payload: GraphTemplateCreate, request: Request):
    user = getattr(request.state, "user", None) or {}
    created_by = user.get("username", "") if isinstance(user, dict) else ""
    tpl = await db.create_graph_template(
        name=payload.name, description=payload.description,
        graph_type=payload.graph_type, category=payload.category,
        scope=payload.scope, title_format=payload.title_format,
        y_axis_label=payload.y_axis_label, y_min=payload.y_min,
        y_max=payload.y_max, stacked=payload.stacked,
        area_fill=payload.area_fill, grid_w=payload.grid_w,
        grid_h=payload.grid_h, options_json=payload.options_json,
        created_by=created_by,
    )
    LOGGER.info("Graph template created: %s (id=%s)", payload.name, tpl.get("id"))
    return tpl


@router.put("/api/graph-templates/{template_id}")
async def update_graph_template_api(template_id: int, payload: GraphTemplateUpdate):
    existing = await db.get_graph_template(template_id)
    if not existing:
        raise HTTPException(status_code=404, detail="Graph template not found")
    if existing.get("built_in"):
        raise HTTPException(status_code=403, detail="Cannot modify built-in templates")
    updated = await db.update_graph_template(template_id, **payload.model_dump(exclude_none=True))
    return updated


@router.delete("/api/graph-templates/{template_id}")
async def delete_graph_template_api(template_id: int):
    existing = await db.get_graph_template(template_id)
    if not existing:
        raise HTTPException(status_code=404, detail="Graph template not found")
    if existing.get("built_in"):
        raise HTTPException(status_code=403, detail="Cannot delete built-in templates")
    deleted = await db.delete_graph_template(template_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Graph template not found")
    return {"status": "deleted"}


# ═════════════════════════════════════════════════════════════════════════════
# Graph Template Items
# ═════════════════════════════════════════════════════════════════════════════

@router.post("/api/graph-templates/{template_id}/items", status_code=201)
async def create_graph_template_item_api(template_id: int, payload: GraphTemplateItemCreate):
    existing = await db.get_graph_template(template_id)
    if not existing:
        raise HTTPException(status_code=404, detail="Graph template not found")
    item = await db.create_graph_template_item(
        template_id=template_id, sort_order=payload.sort_order,
        metric_name=payload.metric_name, label=payload.label,
        color=payload.color, line_type=payload.line_type,
        cdef_expression=payload.cdef_expression,
        consolidation=payload.consolidation,
        transform=payload.transform, legend_format=payload.legend_format,
    )
    return item


@router.put("/api/graph-templates/{template_id}/items/{item_id}")
async def update_graph_template_item_api(template_id: int, item_id: int, payload: GraphTemplateItemUpdate):
    updated = await db.update_graph_template_item(item_id, **payload.model_dump(exclude_none=True))
    if not updated:
        raise HTTPException(status_code=404, detail="Template item not found")
    return updated


@router.delete("/api/graph-templates/{template_id}/items/{item_id}")
async def delete_graph_template_item_api(template_id: int, item_id: int):
    deleted = await db.delete_graph_template_item(item_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Template item not found")
    return {"status": "deleted"}


# ═════════════════════════════════════════════════════════════════════════════
# Host Template CRUD
# ═════════════════════════════════════════════════════════════════════════════

@router.get("/api/host-templates")
async def list_host_templates_api():
    templates = await db.list_host_templates()
    return {"host_templates": templates}


@router.get("/api/host-templates/{template_id}")
async def get_host_template_api(template_id: int):
    tpl = await db.get_host_template(template_id)
    if not tpl:
        raise HTTPException(status_code=404, detail="Host template not found")
    return tpl


@router.post("/api/host-templates", status_code=201)
async def create_host_template_api(payload: HostTemplateCreate, request: Request):
    user = getattr(request.state, "user", None) or {}
    created_by = user.get("username", "") if isinstance(user, dict) else ""
    tpl = await db.create_host_template(
        name=payload.name, description=payload.description,
        device_types=payload.device_types, auto_apply=payload.auto_apply,
        poll_interval=payload.poll_interval, created_by=created_by,
    )
    LOGGER.info("Host template created: %s (id=%s)", payload.name, tpl.get("id"))
    return tpl


@router.put("/api/host-templates/{template_id}")
async def update_host_template_api(template_id: int, payload: HostTemplateUpdate):
    existing = await db.get_host_template(template_id)
    if not existing:
        raise HTTPException(status_code=404, detail="Host template not found")
    updated = await db.update_host_template(template_id, **payload.model_dump(exclude_none=True))
    return updated


@router.delete("/api/host-templates/{template_id}")
async def delete_host_template_api(template_id: int):
    deleted = await db.delete_host_template(template_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Host template not found")
    return {"status": "deleted"}


# ── Host Template ↔ Graph Template Links ─────────────────────────────────

@router.post("/api/host-templates/{template_id}/graph-templates/{graph_template_id}", status_code=201)
async def link_graph_to_host_template_api(template_id: int, graph_template_id: int):
    ht = await db.get_host_template(template_id)
    if not ht:
        raise HTTPException(status_code=404, detail="Host template not found")
    gt = await db.get_graph_template(graph_template_id)
    if not gt:
        raise HTTPException(status_code=404, detail="Graph template not found")
    result = await db.link_graph_template_to_host_template(template_id, graph_template_id)
    return result


@router.delete("/api/host-templates/{template_id}/graph-templates/{graph_template_id}")
async def unlink_graph_from_host_template_api(template_id: int, graph_template_id: int):
    deleted = await db.unlink_graph_template_from_host_template(template_id, graph_template_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Link not found")
    return {"status": "deleted"}


# ═════════════════════════════════════════════════════════════════════════════
# Host Graphs (template instances on devices)
# ═════════════════════════════════════════════════════════════════════════════

@router.get("/api/host-graphs")
async def list_host_graphs_api(
    host_id: int | None = Query(default=None),
    graph_template_id: int | None = Query(default=None),
    enabled_only: bool = Query(default=False),
):
    graphs = await db.list_host_graphs(
        host_id=host_id, graph_template_id=graph_template_id, enabled_only=enabled_only,
    )
    return {"host_graphs": graphs}


@router.get("/api/host-graphs/{host_graph_id}")
async def get_host_graph_api(host_graph_id: int):
    hg = await db.get_host_graph(host_graph_id)
    if not hg:
        raise HTTPException(status_code=404, detail="Host graph not found")
    return hg


@router.post("/api/host-graphs", status_code=201)
async def create_host_graph_api(payload: HostGraphCreate):
    hg = await db.create_host_graph(
        host_id=payload.host_id, graph_template_id=payload.graph_template_id,
        title=payload.title, instance_key=payload.instance_key,
        instance_label=payload.instance_label, enabled=payload.enabled,
        pinned=payload.pinned, options_json=payload.options_json,
    )
    return hg


@router.put("/api/host-graphs/{host_graph_id}")
async def update_host_graph_api(host_graph_id: int, payload: HostGraphUpdate):
    updated = await db.update_host_graph(host_graph_id, **payload.model_dump(exclude_none=True))
    if not updated:
        raise HTTPException(status_code=404, detail="Host graph not found")
    return updated


@router.delete("/api/host-graphs/{host_graph_id}")
async def delete_host_graph_api(host_graph_id: int):
    deleted = await db.delete_host_graph(host_graph_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Host graph not found")
    return {"status": "deleted"}


@router.post("/api/hosts/{host_id}/apply-graph-templates")
async def apply_templates_to_host_api(host_id: int):
    """Auto-apply matching graph templates to a host based on its device type."""
    created = await db.apply_graph_templates_to_host(host_id)
    return {"created": len(created), "host_graphs": created}


# ═════════════════════════════════════════════════════════════════════════════
# Graph Trees
# ═════════════════════════════════════════════════════════════════════════════

@router.get("/api/graph-trees")
async def list_graph_trees_api():
    trees = await db.list_graph_trees()
    return {"graph_trees": trees}


@router.get("/api/graph-trees/{tree_id}")
async def get_graph_tree_api(tree_id: int):
    tree = await db.get_graph_tree(tree_id)
    if not tree:
        raise HTTPException(status_code=404, detail="Graph tree not found")
    return tree


@router.post("/api/graph-trees", status_code=201)
async def create_graph_tree_api(payload: GraphTreeCreate, request: Request):
    user = getattr(request.state, "user", None) or {}
    created_by = user.get("username", "") if isinstance(user, dict) else ""
    tree = await db.create_graph_tree(
        name=payload.name, description=payload.description,
        sort_order=payload.sort_order, created_by=created_by,
    )
    LOGGER.info("Graph tree created: %s (id=%s)", payload.name, tree.get("id"))
    return tree


@router.put("/api/graph-trees/{tree_id}")
async def update_graph_tree_api(tree_id: int, payload: GraphTreeUpdate):
    existing = await db.get_graph_tree(tree_id)
    if not existing:
        raise HTTPException(status_code=404, detail="Graph tree not found")
    updated = await db.update_graph_tree(tree_id, **payload.model_dump(exclude_none=True))
    return updated


@router.delete("/api/graph-trees/{tree_id}")
async def delete_graph_tree_api(tree_id: int):
    deleted = await db.delete_graph_tree(tree_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Graph tree not found")
    return {"status": "deleted"}


# ── Graph Tree Nodes ──────────────────────────────────────────────────────

@router.post("/api/graph-trees/{tree_id}/nodes", status_code=201)
async def create_graph_tree_node_api(tree_id: int, payload: GraphTreeNodeCreate):
    tree = await db.get_graph_tree(tree_id)
    if not tree:
        raise HTTPException(status_code=404, detail="Graph tree not found")
    node = await db.create_graph_tree_node(
        tree_id=tree_id, parent_node_id=payload.parent_node_id,
        node_type=payload.node_type, title=payload.title,
        sort_order=payload.sort_order, host_id=payload.host_id,
        group_id=payload.group_id, graph_id=payload.graph_id,
    )
    return node


@router.put("/api/graph-trees/{tree_id}/nodes/{node_id}")
async def update_graph_tree_node_api(tree_id: int, node_id: int, payload: GraphTreeNodeUpdate):
    updated = await db.update_graph_tree_node(node_id, **payload.model_dump(exclude_none=True))
    if not updated:
        raise HTTPException(status_code=404, detail="Tree node not found")
    return updated


@router.delete("/api/graph-trees/{tree_id}/nodes/{node_id}")
async def delete_graph_tree_node_api(tree_id: int, node_id: int):
    deleted = await db.delete_graph_tree_node(node_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Tree node not found")
    return {"status": "deleted"}


# ═════════════════════════════════════════════════════════════════════════════
# Data Source Profiles
# ═════════════════════════════════════════════════════════════════════════════

@router.get("/api/data-source-profiles")
async def list_data_source_profiles_api(
    host_id: int | None = Query(default=None),
):
    profiles = await db.list_data_source_profiles(host_id=host_id)
    return {"data_source_profiles": profiles}


@router.get("/api/data-source-profiles/{profile_id}")
async def get_data_source_profile_api(profile_id: int):
    profile = await db.get_data_source_profile(profile_id)
    if not profile:
        raise HTTPException(status_code=404, detail="Data source profile not found")
    return profile


@router.post("/api/data-source-profiles", status_code=201)
async def create_data_source_profile_api(payload: DataSourceProfileCreate):
    profile = await db.create_data_source_profile(
        host_id=payload.host_id, profile_name=payload.profile_name,
        poll_interval=payload.poll_interval, oids_json=payload.oids_json,
        enabled=payload.enabled,
    )
    return profile


@router.put("/api/data-source-profiles/{profile_id}")
async def update_data_source_profile_api(profile_id: int, payload: DataSourceProfileUpdate):
    updated = await db.update_data_source_profile(profile_id, **payload.model_dump(exclude_none=True))
    if not updated:
        raise HTTPException(status_code=404, detail="Data source profile not found")
    return updated


@router.delete("/api/data-source-profiles/{profile_id}")
async def delete_data_source_profile_api(profile_id: int):
    deleted = await db.delete_data_source_profile(profile_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Data source profile not found")
    return {"status": "deleted"}
