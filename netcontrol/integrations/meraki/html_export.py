"""Render a topology snapshot as one self-contained interactive HTML file.

The export is a single document with the snapshot JSON and the viewer
(pan/zoom canvas map, search, click-through detail panels) inlined - no CDN,
no network requests, no Plexus session. It can be emailed, dropped on a file
share, or opened on an air-gapped laptop.

All snapshot text reaches the DOM through ``textContent`` in the viewer, and
the JSON is embedded in a non-executing ``application/json`` script block with
``<``/``>``/``&`` escaped, so device names or descriptions containing markup
cannot break out of the data block or execute.
"""

from __future__ import annotations

import html
import json
from functools import lru_cache
from pathlib import Path
from typing import Any

from netcontrol.integrations.meraki.subnets import subnet_index

_TEMPLATE_PATH = Path(__file__).with_name("viewer_template.html")
# The Topology page's tidy layout, bundled by the frontend build
# (src/pages/Topology/viewerLayout.ts). Without it (a frontend that was never
# built) the viewer keeps the export's own row packing of the sites.
_LAYOUT_SCRIPT_PATH = Path(__file__).resolve().parents[2] / "static" / "frontend" / "dist" / "viewer-layout.js"
_JSON_PLACEHOLDER = "__TOPOLOGY_JSON__"
_TITLE_PLACEHOLDER = "__TITLE__"
_LAYOUT_PLACEHOLDER = "/*__LAYOUT_JS__*/"

# Policy for the export when Plexus serves it. ``sandbox`` without
# allow-same-origin gives the document an opaque origin, so its inline script
# can never reach the Plexus API or session even though it is served from the
# Plexus host.
EXPORT_CSP = (
    "default-src 'none'; "
    "script-src 'unsafe-inline'; "
    "style-src 'unsafe-inline'; "
    "img-src data:; "
    "sandbox allow-scripts allow-downloads; "
    "frame-ancestors 'none'; "
    "base-uri 'none'; "
    "form-action 'none'"
)


@lru_cache(maxsize=1)
def _template() -> str:
    return _TEMPLATE_PATH.read_text(encoding="utf-8")


def _layout_script() -> str:
    """The bundled layout, safe inside a ``<script>`` block; '' when not built."""
    try:
        script = _LAYOUT_SCRIPT_PATH.read_text(encoding="utf-8")
    except OSError:
        return ""
    return script.replace("</", "<\\/")


def _embed_json(snapshot: dict[str, Any]) -> str:
    """Serialise for a ``<script type="application/json">`` block."""
    text = json.dumps(snapshot, separators=(",", ":"), ensure_ascii=False)
    return (
        text.replace("&", "\\u0026")
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
        .replace(" ", "\\u2028")
        .replace(" ", "\\u2029")
    )


def render_topology_html(snapshot: dict[str, Any]) -> str:
    """Return the complete standalone HTML document for ``snapshot``."""
    org_name = str((snapshot.get("org") or {}).get("name") or "Meraki")
    title = html.escape(f"{org_name} - Network Topology")
    # Title first: the JSON may itself contain the title placeholder text.
    # The viewer picks path endpoints by subnet from this index.
    data = {**snapshot, "subnets": subnet_index(snapshot)}
    return (
        _template()
        .replace(_TITLE_PLACEHOLDER, title, 1)
        .replace(_LAYOUT_PLACEHOLDER, _layout_script(), 1)
        .replace(_JSON_PLACEHOLDER, _embed_json(data), 1)
    )


def export_filename(snapshot: dict[str, Any]) -> str:
    """Filesystem-safe download name, e.g. ``topology-acme-2026-01-01.html``."""
    org_name = str((snapshot.get("org") or {}).get("name") or "org")
    slug = "".join(c.lower() if c.isalnum() else "-" for c in org_name).strip("-")
    while "--" in slug:
        slug = slug.replace("--", "-")
    stamp = str(snapshot.get("generated_at") or "")[:10]
    return f"topology-{slug[:60] or 'org'}{'-' + stamp if stamp else ''}.html"
