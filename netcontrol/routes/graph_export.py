"""
graph_export.py -- Graph image export (PNG/SVG direct URLs)

Provides:
  - Server-side ECharts option JSON generation for host graphs
  - Client-triggered export endpoints (return chart config for frontend rendering)
  - Direct URL endpoints for embedding (return self-contained HTML with chart)
  - SVG generation using ECharts config (for non-interactive embedding)
"""

import json
from xml.sax.saxutils import escape as _xml_escape

import routes.database as db
from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse

from netcontrol.telemetry import configure_logging

router = APIRouter()
LOGGER = configure_logging("plexus.graph_export")


# ═════════════════════════════════════════════════════════════════════════════
# Chart Config Builder
# ═════════════════════════════════════════════════════════════════════════════


def _build_echart_option(template: dict, items: list[dict],
                          metric_data: dict, time_range: str = "24h",
                          theme: str = "dark") -> dict:
    """Build an ECharts option object from a graph template + metric data.

    metric_data format: {"series_name": [{"ts": "...", "value": float}, ...]}
    """
    bg_color = "#1a1a2e" if theme == "dark" else "#ffffff"
    text_color = "#e0e0e0" if theme == "dark" else "#333333"
    grid_color = "rgba(255,255,255,0.08)" if theme == "dark" else "rgba(0,0,0,0.08)"

    series = []
    legend_data = []

    for item in sorted(items, key=lambda x: x.get("sort_order", 0)):
        metric_name = item.get("metric_name", "")
        label = item.get("label", metric_name)
        color = item.get("color", "#10B981")
        line_type = item.get("line_type", "line")
        data_points = metric_data.get(metric_name, [])

        legend_data.append(label)

        series_type = "bar" if line_type == "bar" else "line"
        series_item = {
            "name": label,
            "type": series_type,
            "data": [[p.get("ts", ""), p.get("value", 0)] for p in data_points],
            "itemStyle": {"color": color},
            "lineStyle": {"width": 2, "color": color},
            "smooth": True,
            "symbol": "none",
        }

        if line_type in ("area", "stacked_area"):
            series_item["areaStyle"] = {"opacity": 0.3, "color": color}
        if template.get("stacked"):
            series_item["stack"] = "total"

        series.append(series_item)

    option = {
        "backgroundColor": bg_color,
        "title": {
            "text": template.get("title_format", template.get("name", "")),
            "textStyle": {"color": text_color, "fontSize": 14},
            "left": "center",
        },
        "tooltip": {
            "trigger": "axis",
            "backgroundColor": "rgba(30,30,50,0.9)" if theme == "dark" else "rgba(255,255,255,0.95)",
            "textStyle": {"color": text_color},
        },
        "legend": {
            "data": legend_data,
            "textStyle": {"color": text_color, "fontSize": 11},
            "bottom": 5,
        },
        "grid": {
            "left": 60, "right": 20, "top": 50, "bottom": 50,
        },
        "xAxis": {
            "type": "time",
            "axisLabel": {"color": text_color},
            "axisLine": {"lineStyle": {"color": grid_color}},
            "splitLine": {"lineStyle": {"color": grid_color}},
        },
        "yAxis": {
            "type": "value",
            "name": template.get("y_axis_label", ""),
            "nameTextStyle": {"color": text_color},
            "axisLabel": {"color": text_color},
            "axisLine": {"lineStyle": {"color": grid_color}},
            "splitLine": {"lineStyle": {"color": grid_color}},
        },
        "series": series,
    }

    if template.get("y_min") is not None:
        option["yAxis"]["min"] = template["y_min"]
    if template.get("y_max") is not None:
        option["yAxis"]["max"] = template["y_max"]

    return option


# ═════════════════════════════════════════════════════════════════════════════
# Self-contained HTML embed
# ═════════════════════════════════════════════════════════════════════════════

EMBED_HTML_TEMPLATE = """<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>{title}</title>
<style>
body {{ margin: 0; padding: 0; background: {bg}; }}
#chart {{ width: {width}px; height: {height}px; }}
</style>
<script src="https://cdn.jsdelivr.net/npm/echarts@5/dist/echarts.min.js"></script>
</head>
<body>
<div id="chart"></div>
<script>
var chart = echarts.init(document.getElementById('chart'), '{echarts_theme}');
chart.setOption({option_json});
window.addEventListener('resize', function() {{ chart.resize(); }});
</script>
</body>
</html>"""


# ═════════════════════════════════════════════════════════════════════════════
# API Endpoints
# ═════════════════════════════════════════════════════════════════════════════


@router.get("/api/graphs/{host_graph_id}/config")
async def get_graph_config(
    host_graph_id: int,
    range: str = Query("24h"),
    theme: str = Query("dark"),
):
    """Return the ECharts option JSON for a host graph (for client-side rendering/export)."""
    host_graph = await db.get_host_graph(host_graph_id)
    if not host_graph:
        raise HTTPException(404, "Host graph not found")

    template = await db.get_graph_template(host_graph["graph_template_id"])
    if not template:
        raise HTTPException(404, "Graph template not found")

    items = template.get("items", [])

    # Fetch metric data for the time range
    hours = _parse_range_hours(range)
    metric_data = {}
    for item in items:
        metric_name = item.get("metric_name", "")
        if not metric_name:
            continue
        data = await _fetch_metric_data(
            host_graph["host_id"], metric_name,
            host_graph.get("instance_key", ""), hours
        )
        metric_data[metric_name] = data

    option = _build_echart_option(template, items, metric_data, range, theme)
    return option


@router.get("/api/graphs/{host_graph_id}/embed")
async def get_graph_embed(
    host_graph_id: int,
    width: int = Query(800, ge=200, le=2000),
    height: int = Query(400, ge=150, le=1200),
    range: str = Query("24h"),
    theme: str = Query("dark"),
):
    """Return a self-contained HTML page with the chart for iframe embedding."""
    host_graph = await db.get_host_graph(host_graph_id)
    if not host_graph:
        raise HTTPException(404, "Host graph not found")

    template = await db.get_graph_template(host_graph["graph_template_id"])
    if not template:
        raise HTTPException(404, "Graph template not found")

    items = template.get("items", [])

    hours = _parse_range_hours(range)
    metric_data = {}
    for item in items:
        metric_name = item.get("metric_name", "")
        if not metric_name:
            continue
        data = await _fetch_metric_data(
            host_graph["host_id"], metric_name,
            host_graph.get("instance_key", ""), hours
        )
        metric_data[metric_name] = data

    option = _build_echart_option(template, items, metric_data, range, theme)
    bg = "#1a1a2e" if theme == "dark" else "#ffffff"
    echarts_theme = "dark" if theme == "dark" else ""

    # Escape </script> sequences in the JSON to prevent script injection (CWE-79)
    safe_json = json.dumps(option).replace("</", "<\\/")
    html = EMBED_HTML_TEMPLATE.format(
        title=_xml_escape(template.get("name", "Plexus Graph")),
        bg=bg,
        width=width,
        height=height,
        echarts_theme=_xml_escape(echarts_theme),
        option_json=safe_json,
    )
    return HTMLResponse(content=html)


@router.get("/api/graph-image/{host_graph_id}.svg")
async def get_graph_svg_stub(
    host_graph_id: int,
    width: int = Query(800, ge=200, le=2000),
    height: int = Query(400, ge=150, le=1200),
    range: str = Query("24h"),
):
    """Return an SVG placeholder for the graph.

    True server-side SVG rendering requires a headless browser (Playwright/Puppeteer).
    This endpoint returns a minimal SVG with a link to the embed page as a practical fallback.
    For full PNG/SVG rendering, use the /embed endpoint with a screenshotting tool.
    """
    host_graph = await db.get_host_graph(host_graph_id)
    if not host_graph:
        raise HTTPException(404, "Host graph not found")

    template = await db.get_graph_template(host_graph["graph_template_id"])
    title = _xml_escape(template.get("name", "Graph")) if template else "Graph"

    svg = f"""<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">
  <rect width="100%" height="100%" fill="#1a1a2e"/>
  <text x="{width//2}" y="{height//2 - 10}" text-anchor="middle" fill="#e0e0e0" font-size="16">{title}</text>
  <text x="{width//2}" y="{height//2 + 15}" text-anchor="middle" fill="#888" font-size="12">Use /embed endpoint for interactive chart</text>
</svg>"""
    return HTMLResponse(content=svg, media_type="image/svg+xml")


# ═════════════════════════════════════════════════════════════════════════════
# Helpers
# ═════════════════════════════════════════════════════════════════════════════


def _parse_range_hours(range_str: str) -> int:
    """Parse a range string like '1h', '6h', '24h', '7d', '30d' into hours."""
    s = range_str.strip().lower()
    if s.endswith("d"):
        try:
            return int(s[:-1]) * 24
        except ValueError:
            return 24
    if s.endswith("h"):
        try:
            return int(s[:-1])
        except ValueError:
            return 24
    try:
        return int(s)
    except ValueError:
        return 24


async def _fetch_metric_data(host_id: int, metric_name: str,
                               instance_key: str, hours: int) -> list[dict]:
    """Fetch metric time-series data for chart rendering."""
    ddb = await db.get_db()
    try:
        # Try metric_samples first
        cutoff_sql = f"-{hours} hours"
        cursor = await ddb.execute(
            """SELECT value, collected_at as ts FROM metric_samples
               WHERE host_id = ? AND metric_name = ?
                     AND collected_at >= datetime('now', ?)
               ORDER BY collected_at""",
            (host_id, metric_name, cutoff_sql),
        )
        rows = await cursor.fetchall()
        if rows:
            return [{"ts": dict(r)["ts"] if hasattr(r, "keys") else r[1],
                      "value": dict(r)["value"] if hasattr(r, "keys") else r[0]} for r in rows]

        # Try interface_ts for interface-scoped metrics
        if instance_key:
            cursor2 = await ddb.execute(
                """SELECT in_rate_bps, out_rate_bps, collected_at as ts FROM interface_ts
                   WHERE host_id = ? AND if_index = ?
                         AND collected_at >= datetime('now', ?)
                   ORDER BY collected_at""",
                (host_id, int(instance_key) if instance_key.isdigit() else 0, cutoff_sql),
            )
            rows2 = await cursor2.fetchall()
            if rows2:
                # Return the appropriate metric based on name
                data = []
                for r in rows2:
                    rd = dict(r) if hasattr(r, "keys") else {"in_rate_bps": r[0], "out_rate_bps": r[1], "ts": r[2]}
                    if "in" in metric_name.lower():
                        data.append({"ts": rd["ts"], "value": rd.get("in_rate_bps") or 0})
                    else:
                        data.append({"ts": rd["ts"], "value": rd.get("out_rate_bps") or 0})
                return data

        return []
    finally:
        await ddb.close()
