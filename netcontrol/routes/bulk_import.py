"""bulk_import.py -- HTTP routes of bulk import (``netcontrol.bulk_import``).

Two routers, each registered in ``app.py`` with the access of what it
imports:

- ``router`` (``inventory`` feature, ``inventory.write`` to import): hosts
  and inventory groups, within the caller's object scope.
- ``ipam_router`` (``ipam`` feature; previewing and committing also need
  admin, like every IPAM, VLAN and VRF write): prefixes, IP addresses, VLANs
  and VRFs.

Each object type has three routes: ``GET .../template`` (an empty CSV with
the expected header), ``POST .../preview`` (what an import would do, nothing
written) and ``POST .../commit`` (plan again and write). Preview and commit
take a multipart form: ``file`` (an upload) or ``text`` (pasted), ``format``
(``csv``, ``yaml`` or ``json``), ``mode`` (``create``, ``update`` or
``upsert``), ``match_key`` and, for commit, ``atomic`` (default true: all or
nothing).
"""

from __future__ import annotations

import csv
import io

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import JSONResponse, Response

from netcontrol.bulk_import import (
    INVENTORY_TYPES,
    IPAM_TYPES,
    MAX_IMPORT_BYTES,
    BulkImportError,
    commit_import,
    decode_upload,
    plan_import,
    template_header,
)
from netcontrol.object_scope import request_scope, scope_exempt, scoped
from netcontrol.routes.shared import _audit, _corr_id, _session_user

router = APIRouter()
ipam_router = APIRouter()

_require_admin = None


def init_bulk_import(require_admin) -> None:
    global _require_admin
    _require_admin = require_admin


async def _require_admin_dep(request: Request):
    if _require_admin is None:
        raise HTTPException(status_code=500, detail="Authorization subsystem not initialized")
    return await _require_admin(request)


def _check_type(object_type: str, allowed: tuple[str, ...]) -> None:
    if object_type not in allowed:
        raise HTTPException(status_code=404, detail=f"Import type must be one of: {', '.join(allowed)}")


async def _upload_text(file: UploadFile | None, text: str | None) -> str:
    """The import text: the uploaded file (at most ``MAX_IMPORT_BYTES``) or
    the pasted text."""
    try:
        if file is not None and file.filename:
            return decode_upload(await file.read(MAX_IMPORT_BYTES + 1))
        if text:
            return text
    except BulkImportError as exc:
        raise HTTPException(status_code=413, detail=str(exc)) from exc
    raise HTTPException(status_code=400, detail="Upload a file or paste the rows to import.")


async def _template(object_type: str) -> Response:
    output = io.StringIO()
    csv.writer(output).writerow(await template_header(object_type))
    return Response(
        content=output.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename={object_type}_import_template.csv"},
    )


async def _preview(
    request: Request, object_type: str, file: UploadFile | None, text: str | None, fmt: str, mode: str, match_key: str
) -> dict:
    body = await _upload_text(file, text)
    try:
        report, _adapter, _ctx = await plan_import(
            object_type,
            body,
            fmt,
            mode=mode,
            match_key=match_key,
            scope=await request_scope(request),
            user=_session_user(request),
        )
    except BulkImportError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return report.as_dict()


async def _commit(
    request: Request,
    object_type: str,
    file: UploadFile | None,
    text: str | None,
    fmt: str,
    mode: str,
    match_key: str,
    atomic: bool,
) -> JSONResponse:
    body = await _upload_text(file, text)
    try:
        report = await commit_import(
            object_type,
            body,
            fmt,
            mode=mode,
            match_key=match_key,
            scope=await request_scope(request),
            user=_session_user(request),
            atomic=atomic,
        )
    except BulkImportError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    summary = report.summary()
    await _audit(
        "bulk_import",
        f"{object_type}.import",
        user=_session_user(request),
        detail=(
            f"format={report.format} mode={report.mode} match={report.match_key} atomic={atomic} "
            f"applied={report.applied} create={summary['create']} update={summary['update']} "
            f"skip={summary['skip']} error={summary['error']}"
        ),
        correlation_id=_corr_id(request),
    )
    # Nothing written because rows have errors (or a write failed and was
    # rolled back): 422 with the full report, so a client sees each row.
    status = 200 if report.committed else 422
    return JSONResponse(status_code=status, content=report.as_dict())


# ── Hosts and inventory groups ───────────────────────────────────────────────


@router.get("/api/import/inventory/{object_type}/template")
@scope_exempt("an empty CSV of column headers: no host or inventory group data")
async def inventory_template(object_type: str) -> Response:
    _check_type(object_type, INVENTORY_TYPES)
    return await _template(object_type)


@router.post("/api/import/inventory/{object_type}/preview")
@scoped("import")
async def inventory_preview(
    object_type: str,
    request: Request,
    file: UploadFile | None = File(default=None),
    text: str | None = Form(default=None),
    fmt: str = Form(default="csv", alias="format"),
    mode: str = Form(default="create"),
    match_key: str = Form(default=""),
) -> dict:
    """What importing the rows would do; only hosts and groups the caller may
    read are matched, and only groups they may write are written."""
    _check_type(object_type, INVENTORY_TYPES)
    return await _preview(request, object_type, file, text, fmt, mode, match_key)


@router.post("/api/import/inventory/{object_type}/commit")
@scoped("import")
async def inventory_commit(
    object_type: str,
    request: Request,
    file: UploadFile | None = File(default=None),
    text: str | None = Form(default=None),
    fmt: str = Form(default="csv", alias="format"),
    mode: str = Form(default="create"),
    match_key: str = Form(default=""),
    atomic: bool = Form(default=True),
) -> JSONResponse:
    _check_type(object_type, INVENTORY_TYPES)
    return await _commit(request, object_type, file, text, fmt, mode, match_key, atomic)


# ── Prefixes, IP addresses, VLANs and VRFs ───────────────────────────────────


@ipam_router.get("/api/import/ipam/{object_type}/template")
@scope_exempt("an empty CSV of column headers: no host or inventory group data")
async def ipam_template(object_type: str) -> Response:
    _check_type(object_type, IPAM_TYPES)
    return await _template(object_type)


@ipam_router.post("/api/import/ipam/{object_type}/preview", dependencies=[Depends(_require_admin_dep)])
@scoped("admin")
async def ipam_preview(
    object_type: str,
    request: Request,
    file: UploadFile | None = File(default=None),
    text: str | None = Form(default=None),
    fmt: str = Form(default="csv", alias="format"),
    mode: str = Form(default="create"),
    match_key: str = Form(default=""),
) -> dict:
    _check_type(object_type, IPAM_TYPES)
    return await _preview(request, object_type, file, text, fmt, mode, match_key)


@ipam_router.post("/api/import/ipam/{object_type}/commit", dependencies=[Depends(_require_admin_dep)])
@scoped("admin")
async def ipam_commit(
    object_type: str,
    request: Request,
    file: UploadFile | None = File(default=None),
    text: str | None = Form(default=None),
    fmt: str = Form(default="csv", alias="format"),
    mode: str = Form(default="create"),
    match_key: str = Form(default=""),
    atomic: bool = Form(default=True),
) -> JSONResponse:
    _check_type(object_type, IPAM_TYPES)
    return await _commit(request, object_type, file, text, fmt, mode, match_key, atomic)
