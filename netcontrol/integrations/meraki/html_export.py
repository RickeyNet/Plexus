"""Render a topology snapshot as one self-contained interactive HTML file.

The export is a single document with the snapshot JSON and the viewer
(pan/zoom canvas map, search, click-through detail panels) inlined - no CDN,
no network requests, no Plexus session. It can be emailed, dropped on a file
share, or opened on an air-gapped laptop.

All snapshot text reaches the DOM through ``textContent`` in the viewer, and
the JSON is embedded in a non-executing ``application/json`` script block with
``<``/``>``/``&`` escaped, so device names or descriptions containing markup
cannot break out of the data block or execute.

The export can also carry the path tracer (``tracer_payload``): the Pyodide
runtime vendored under ``netcontrol/static/vendor/pyodide`` (fetched by
``scripts/fetch_pyodide.py``; ``PLEXUS_PYODIDE_DIR`` points elsewhere), the
source of the engine's modules and the trace inputs, each gzip-compressed and
base64-encoded in a non-executing ``text/plain`` block. The viewer starts the
runtime from those blocks on the first trace; nothing is fetched.
"""

from __future__ import annotations

import base64
import gzip
import html
import json
import os
from functools import lru_cache
from pathlib import Path
from typing import Any

from netcontrol.integrations.meraki.subnets import subnet_index
from netcontrol.integrations.pathtrace.offline import module_sources

_TEMPLATE_PATH = Path(__file__).with_name("viewer_template.html")
# The loader the viewer starts the path tracer with (in a worker, else on the page).
_TRACER_SCRIPT_PATH = Path(__file__).with_name("viewer_tracer.js")
# The Topology page's tidy layout, bundled by the frontend build
# (src/pages/Topology/viewerLayout.ts). Without it (a frontend that was never
# built) the viewer keeps the export's own row packing of the sites.
_LAYOUT_SCRIPT_PATH = Path(__file__).resolve().parents[2] / "static" / "frontend" / "dist" / "viewer-layout.js"
_JSON_PLACEHOLDER = "__TOPOLOGY_JSON__"
_TITLE_PLACEHOLDER = "__TITLE__"
_CSP_PLACEHOLDER = "__META_CSP__"
_LAYOUT_PLACEHOLDER = "/*__LAYOUT_JS__*/"
_TRACER_PLACEHOLDER = "<!--__TRACER__-->"

# Where the vendored Pyodide runtime lives; ``PLEXUS_PYODIDE_DIR`` overrides it.
PYODIDE_DIR_ENV = "PLEXUS_PYODIDE_DIR"
_PYODIDE_DEFAULT_DIR = Path(__file__).resolve().parents[2] / "static" / "vendor" / "pyodide"
# The runtime files the export carries -> the media type the loader serves each with.
PYODIDE_FILES = {
    "pyodide.mjs": "text/javascript",
    "pyodide.asm.mjs": "text/javascript",
    "pyodide.asm.wasm": "application/wasm",
    "python_stdlib.zip": "application/zip",
    "pyodide-lock.json": "application/json",
}

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
# An export with the path tracer also runs the runtime in a worker made from a
# blob URL, imports its modules from blob URLs and compiles WebAssembly.
# Nothing is fetched: ``connect-src`` stays closed (``default-src 'none'``).
_TRACER_SOURCES = "script-src 'unsafe-inline' blob: 'wasm-unsafe-eval'; worker-src blob:; child-src blob:; "
EXPORT_TRACER_CSP = EXPORT_CSP.replace("script-src 'unsafe-inline'; ", _TRACER_SOURCES, 1)
# The policy the saved file carries itself (a meta tag has no sandbox or frame-ancestors).
_META_CSP = (
    "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src data:; "
    "base-uri 'none'; form-action 'none'"
)
_META_TRACER_CSP = _META_CSP.replace("script-src 'unsafe-inline'; ", _TRACER_SOURCES, 1)

# (directory, version, file sizes and times) -> the packed runtime; one entry.
_RUNTIME_CACHE: dict[tuple, dict[str, Any]] = {}


def export_csp(tracer: bool) -> str:
    """The response policy of an export, with or without the path tracer."""
    return EXPORT_TRACER_CSP if tracer else EXPORT_CSP


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


def _pack(data: bytes) -> str:
    """gzip, then base64: text with no markup characters, for a ``text/plain`` block."""
    return base64.b64encode(gzip.compress(data, compresslevel=9, mtime=0)).decode("ascii")


def pyodide_dir() -> Path:
    """The directory of the vendored Pyodide runtime."""
    configured = os.environ.get(PYODIDE_DIR_ENV, "").strip()
    return Path(configured) if configured else _PYODIDE_DEFAULT_DIR


def pyodide_runtime() -> dict[str, Any] | None:
    """The vendored runtime, packed for the export (``version`` and ``files``
    by name), or ``None`` when it is not there or incomplete. Packed once and
    kept until a file changes."""
    directory = pyodide_dir()
    try:
        version = (directory / "VERSION").read_text(encoding="utf-8").strip()
        stats = tuple((name, (directory / name).stat()) for name in PYODIDE_FILES)
    except OSError:
        return None
    if not version:
        return None
    key = (str(directory.resolve()), version, tuple((name, s.st_size, s.st_mtime_ns) for name, s in stats))
    runtime = _RUNTIME_CACHE.get(key)
    if runtime is None:
        try:
            files = {name: _pack((directory / name).read_bytes()) for name in PYODIDE_FILES}
        except OSError:
            return None
        _RUNTIME_CACHE.clear()
        runtime = _RUNTIME_CACHE[key] = {"version": version, "files": files}
    return runtime


def tracer_payload(inputs_json: str) -> dict[str, Any] | None:
    """What the export carries to trace by itself: the runtime, the engine's
    module sources and ``inputs_json`` (``pathtrace.offline.inputs`` as
    JSON). ``None`` when the runtime is not available."""
    runtime = pyodide_runtime()
    if runtime is None:
        return None
    modules = json.dumps(module_sources(), ensure_ascii=False).encode("utf-8")
    return {
        "version": runtime["version"],
        "files": runtime["files"],
        "modules": _pack(modules),
        "inputs": _pack(inputs_json.encode("utf-8")),
    }


def _tracer_blocks(tracer: dict[str, Any]) -> str:
    meta = {"pyodide": tracer["version"], "files": {name: PYODIDE_FILES[name] for name in tracer["files"]}}
    script = _TRACER_SCRIPT_PATH.read_text(encoding="utf-8").replace("</", "<\\/")
    blocks = [
        f'<script type="application/json" id="tracer-meta">{_embed_json(meta)}</script>',
        f'<script type="text/plain" id="tracer-runtime">{script}</script>',
        f'<script type="text/plain" id="tracer-modules">{tracer["modules"]}</script>',
        f'<script type="text/plain" id="tracer-inputs">{tracer["inputs"]}</script>',
    ]
    for name, packed in tracer["files"].items():
        blocks.append(f'<script type="text/plain" data-tracer-file="{html.escape(name)}">{packed}</script>')
    return "\n".join(blocks)


def render_topology_html(
    snapshot: dict[str, Any], *, path: dict[str, Any] | None = None, tracer: dict[str, Any] | None = None
) -> str:
    """Return the complete standalone HTML document for ``snapshot``.

    ``path`` is the Path Mode state the export carries (picks, traffic and
    the traces of its legs), embedded as ``data.path`` when given. ``tracer``
    is a ``tracer_payload``: the file then traces any two subnets or
    addresses itself."""
    org_name = str((snapshot.get("org") or {}).get("name") or "Meraki")
    title = html.escape(f"{org_name} - Network Topology")
    # Title first: the JSON may itself contain the title placeholder text.
    # The viewer picks path endpoints by subnet from this index.
    data = {**snapshot, "subnets": subnet_index(snapshot)}
    if path:
        data["path"] = path
    return (
        _template()
        .replace(_TITLE_PLACEHOLDER, title, 1)
        .replace(_CSP_PLACEHOLDER, _META_TRACER_CSP if tracer else _META_CSP, 1)
        .replace(_LAYOUT_PLACEHOLDER, _layout_script(), 1)
        .replace(_TRACER_PLACEHOLDER, _tracer_blocks(tracer) if tracer else "", 1)
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
