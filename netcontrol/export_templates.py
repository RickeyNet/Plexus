"""Export templates: the object types, the validators and rendering, with
no I/O.

An export template is a Jinja2 template bound to one object type. Rendering
it gives the template ``queryset`` (the objects of that type the caller may
read, as dicts, after the request's filters), ``now`` (the UTC time, to the
second) and ``object_type``, and returns one text file: its media type and
file extension come from the template.

Rendering reuses the intended configuration sandbox
(``netcontrol.intended_config.Renderer``): templates cannot reach Python
internals, the filesystem, the network or a process, and a render that grows
past ``OUTPUT_MAX`` characters or runs too long stops with an error.

Storage lives in ``routes.db.export_templates``; the API, the object
loaders and their access checks in ``netcontrol.routes.export_templates``.
See ``docs/export-templates.md``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, datetime

from netcontrol.custom_fields import CustomFieldError, clean_name, clean_text
from netcontrol.intended_config import (
    TEMPLATE_TEXT_MAX,
    Renderer,
    RenderIssue,
    RenderResult,
    clean_template_text,
)

__all__ = [
    "DESCRIPTION_MAX",
    "EXTENSION_MAX",
    "MIME_MAX",
    "NAME_MAX",
    "OBJECT_TYPES",
    "PREVIEW_DEFAULT",
    "PREVIEW_MAX",
    "TEMPLATE_TEXT_MAX",
    "ObjectType",
    "check_syntax",
    "clean_description",
    "clean_extension",
    "clean_mime_type",
    "clean_name_value",
    "clean_object_type",
    "clean_template_text",
    "render",
]

NAME_MAX = 100
DESCRIPTION_MAX = 500
MIME_MAX = 100
EXTENSION_MAX = 16
# Objects a preview renders by default, and at most.
PREVIEW_DEFAULT = 20
PREVIEW_MAX = 1000
# The name a template renders under (the sandbox reports errors by name).
_TEMPLATE_NAME = "export"


@dataclass(frozen=True)
class ObjectType:
    """An object type export templates can bind to: ``feature`` is the
    feature its objects are read with; ``filters`` the query parameters a
    render accepts (besides ``tag=`` and ``cf.<key>=`` where ``tags`` is
    set); ``fields`` the main keys of each ``queryset`` item, for the
    editor's help."""

    key: str
    label: str
    feature: str
    filters: tuple[str, ...]
    fields: tuple[str, ...]
    tags: bool = True


OBJECT_TYPES: dict[str, ObjectType] = {
    t.key: t
    for t in (
        ObjectType(
            "host",
            "Hosts",
            "inventory",
            (
                "group_id",
                "manufacturer_id",
                "device_type_id",
                "role_id",
                "lifecycle_status_id",
                "site_id",
                "tenant_id",
                "region_id",
            ),
            (
                "id",
                "group_id",
                "hostname",
                "ip_address",
                "model",
                "software_version",
                "platform",
                "status",
                "group",
                "manufacturer",
                "device_type",
                "role",
                "lifecycle_status",
                "site",
                "location_detail",
                "tags",
                "custom_fields",
            ),
        ),
        ObjectType(
            "prefix",
            "IPAM prefixes",
            "ipam",
            ("status", "vrf"),
            (
                "id",
                "subnet",
                "description",
                "status",
                "vrf",
                "tenant",
                "site",
                "vlan",
                "provider",
                "source_name",
                "tags",
                "custom_fields",
            ),
        ),
        ObjectType(
            "ip_address",
            "IPAM IP addresses",
            "ipam",
            ("status", "prefix"),
            (
                "id",
                "address",
                "prefix_subnet",
                "dns_name",
                "status",
                "description",
                "vrf_name",
                "vlan_id",
                "provider",
                "source_name",
            ),
            tags=False,
        ),
        ObjectType(
            "vlan",
            "VLANs",
            "ipam",
            ("site_id", "vid", "vlan_group_id"),
            ("id", "vid", "name", "description", "site_id", "site", "vlan_group", "tenant_id", "tags", "custom_fields"),
        ),
        ObjectType(
            "circuit",
            "Circuits",
            "circuits",
            ("provider_id", "circuit_type_id", "status", "tenant_id", "site_id", "host_id", "q"),
            (
                "id",
                "cid",
                "provider_name",
                "circuit_type_name",
                "status",
                "tenant_id",
                "tenant_name",
                "description",
                "terminations",
                "tags",
                "custom_fields",
            ),
        ),
        ObjectType(
            "site",
            "Sites",
            "organization",
            (),
            (
                "id",
                "name",
                "description",
                "address",
                "region_name",
                "tenant_name",
                "host_count",
                "tags",
                "custom_fields",
            ),
        ),
    )
}

# type/subtype, each an RFC 6838 restricted name; parameters are not stored
# (the response adds ``charset=utf-8``).
_MIME_RE = re.compile(r"^[a-z0-9][a-z0-9!#$&^_.+-]{0,63}/[a-z0-9][a-z0-9!#$&^_.+-]{0,63}$")
_EXTENSION_RE = re.compile(r"^[a-z0-9][a-z0-9_-]*$")


# ── Validators ───────────────────────────────────────────────────────────────


def clean_name_value(raw: object) -> str:
    """A template name trimmed; 1 to ``NAME_MAX`` characters."""
    return clean_name(raw, "Name", NAME_MAX)


def clean_description(raw: object) -> str:
    return clean_text(raw, "Description", DESCRIPTION_MAX)


def clean_object_type(raw: object) -> str:
    if not isinstance(raw, str) or raw not in OBJECT_TYPES:
        raise CustomFieldError(f"Object type must be one of: {', '.join(OBJECT_TYPES)}.")
    return raw


def clean_mime_type(raw: object) -> str:
    """A media type such as ``text/csv``, lower-cased; empty means
    ``text/plain``. Parameters (``; charset=...``) are not accepted."""
    text = clean_text(raw, "MIME type", MIME_MAX).lower()
    if not text:
        return "text/plain"
    if not _MIME_RE.match(text):
        raise CustomFieldError("MIME type must look like type/subtype, for example text/csv.")
    return text


def clean_extension(raw: object) -> str:
    """A file extension without the leading dot, lower-cased (``csv``);
    may be empty (the file then has none)."""
    text = clean_text(raw, "File extension", EXTENSION_MAX + 1).lower().removeprefix(".")
    if len(text) > EXTENSION_MAX:
        raise CustomFieldError(f"File extension must be at most {EXTENSION_MAX} characters.")
    if text and not _EXTENSION_RE.match(text):
        raise CustomFieldError("File extension may hold only letters, digits, '-' and '_'.")
    return text


def check_syntax(text: str) -> RenderIssue | None:
    """The Jinja syntax error of a template text, or ``None``."""
    return Renderer().check(text, _TEMPLATE_NAME)


# ── Rendering ────────────────────────────────────────────────────────────────


def render(text: str, object_type: str, queryset: list[dict], now: datetime | None = None) -> RenderResult:
    """Render ``text`` with ``queryset`` in the sandbox, within its limits.
    Never raises for a template problem: the result carries the error."""
    variables = {
        "queryset": queryset,
        "now": (now or datetime.now(UTC)).replace(microsecond=0),
        "object_type": object_type,
    }
    return Renderer({_TEMPLATE_NAME: text}).render(_TEMPLATE_NAME, variables)
