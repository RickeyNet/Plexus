"""Intended configuration generation: the limits and rules, with no I/O.

Admins write Jinja2 templates (``config_templates``) and config contexts
(``config_contexts``), each scoped to devices by driver, role, site and group
(a context also to one host). For a host, the most specific enabled
``device`` template is rendered with the host's data and the merged context;
the result is that host's intended configuration, compared with its newest
configuration backup by ``compare_configs``.

Rendering is sandboxed and bounded (see ``Renderer``): templates cannot reach
Python internals, the filesystem, the network or a process, and a render
that grows too large or runs too long stops with an error.

Storage lives in ``routes.db.intended_config``, the API and the generation
run in ``netcontrol.routes.intended_config``. See ``docs/intended-config.md``.
"""

from __future__ import annotations

import contextvars
import ipaddress
import json
import re
import string
import time
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass, field
from functools import wraps
from typing import Any

from jinja2 import StrictUndefined, TemplateNotFound, TemplateSyntaxError, nodes
from jinja2.exceptions import TemplateRuntimeError
from jinja2.loaders import BaseLoader
from jinja2.sandbox import ImmutableSandboxedEnvironment
from jinja2.visitor import NodeTransformer

from netcontrol.custom_fields import CustomFieldError, clean_name, clean_text

__all__ = [
    "COMPLIANCE_STATES",
    "CONTEXT_DATA_MAX",
    "DESCRIPTION_MAX",
    "DEVICE_TYPE_MAX",
    "KINDS",
    "NAME_MAX",
    "OUTPUT_MAX",
    "RANGE_MAX",
    "RENDER_IDLE_SECONDS",
    "SCOPE_FIELDS",
    "STATUSES",
    "TEMPLATE_TEXT_MAX",
    "WEIGHT_DEFAULT",
    "WEIGHT_MAX",
    "Comparison",
    "RenderIssue",
    "RenderResult",
    "Renderer",
    "check_syntax",
    "clean_context_data",
    "clean_description",
    "clean_device_type",
    "clean_kind",
    "clean_name_value",
    "clean_template_text",
    "clean_weight",
    "compare_configs",
    "config_lines",
    "merge_contexts",
    "scope_matches",
    "select_template",
    "verdict",
]

NAME_MAX = 100
DESCRIPTION_MAX = 500
DEVICE_TYPE_MAX = 64
TEMPLATE_TEXT_MAX = 262_144
CONTEXT_DATA_MAX = 65_536
WEIGHT_DEFAULT = 1000
WEIGHT_MAX = 100_000
# Rendering limits: items ``range`` may produce, characters of output (and of
# any one value a template builds), and seconds a render may run between two
# chunks of output.
RANGE_MAX = 10_000
OUTPUT_MAX = 1_048_576
RENDER_IDLE_SECONDS = 5.0

KINDS: tuple[str, ...] = ("device", "snippet")
STATUSES: tuple[str, ...] = ("ok", "error")
COMPLIANCE_STATES: tuple[str, ...] = ("compliant", "non_compliant", "unknown")
# Scope id fields of a template; a context also has ``host_id``.
SCOPE_FIELDS: tuple[str, ...] = ("role_id", "site_id", "group_id")
# Specificity of a template's scope: the most specific matching one wins.
_SCORES = {"group_id": 8, "site_id": 4, "role_id": 2, "device_type": 1}


# ── Validators ───────────────────────────────────────────────────────────────


def clean_name_value(raw: object) -> str:
    """A template or context name trimmed; 1 to ``NAME_MAX`` characters."""
    return clean_name(raw, "Name", NAME_MAX)


def clean_description(raw: object) -> str:
    return clean_text(raw, "Description", DESCRIPTION_MAX)


def clean_device_type(raw: object) -> str:
    """A driver key scope trimmed; ``''`` means any driver."""
    return clean_text(raw, "Driver", DEVICE_TYPE_MAX)


def clean_kind(raw: object) -> str:
    if raw not in KINDS:
        raise CustomFieldError(f"Kind must be one of: {', '.join(KINDS)}.")
    return str(raw)


def clean_template_text(raw: object) -> str:
    """Template text as written (not trimmed); at most ``TEMPLATE_TEXT_MAX``."""
    text = raw if isinstance(raw, str) else ""
    if len(text) > TEMPLATE_TEXT_MAX:
        raise CustomFieldError(f"Template text must be at most {TEMPLATE_TEXT_MAX} characters.")
    return text


def clean_weight(raw: object) -> int:
    if isinstance(raw, bool) or not isinstance(raw, int) or not 0 <= raw <= WEIGHT_MAX:
        raise CustomFieldError(f"Weight must be a number from 0 to {WEIGHT_MAX}.")
    return raw


def clean_context_data(raw: object) -> str:
    """Context data, a JSON object, as the compact text that is stored; at
    most ``CONTEXT_DATA_MAX`` characters."""
    if not isinstance(raw, dict):
        raise CustomFieldError("Data must be a JSON object.")
    text = json.dumps(raw, separators=(",", ":"), ensure_ascii=False)
    if len(text) > CONTEXT_DATA_MAX:
        raise CustomFieldError(f"Data must be at most {CONTEXT_DATA_MAX} characters as JSON.")
    return text


# ── Scope, selection, merge ──────────────────────────────────────────────────


def scope_matches(record: dict, host: dict, *, with_host: bool = False) -> bool:
    """Every scope field the record sets equals the host's value.

    ``device_type`` ``''`` and an id of ``None`` match any host. A set id is
    compared with the host's own reference, so an id that names a deleted
    role, site, group or host matches nothing (hosts only point at records
    that exist, and ids are never reused). ``with_host`` also checks
    ``host_id`` (contexts)."""
    driver = str(record.get("device_type") or "")
    if driver and driver != str(host.get("device_type") or ""):
        return False
    fields = (*SCOPE_FIELDS, "host_id") if with_host else SCOPE_FIELDS
    for name in fields:
        wanted = record.get(name)
        if wanted is None:
            continue
        own = host.get("id") if name == "host_id" else host.get(name)
        if own is None or int(own) != int(wanted):
            return False
    return True


def _specificity(template: dict) -> int:
    return sum(score for name, score in _SCORES.items() if template.get(name) not in (None, ""))


def select_template(templates: Iterable[dict], host: dict) -> dict | None:
    """The enabled ``device`` template that matches the host with the highest
    specificity (group 8 + site 4 + role 2 + driver 1); ties go to the name
    first in case-insensitive order. ``None`` when none matches."""
    candidates = [t for t in templates if t.get("kind") == "device" and t.get("enabled") and scope_matches(t, host)]
    if not candidates:
        return None
    return min(candidates, key=lambda t: (-_specificity(t), str(t["name"]).lower(), int(t.get("id") or 0)))


def _deep_merge(base: Any, over: Any) -> Any:
    if isinstance(base, dict) and isinstance(over, dict):
        merged = dict(base)
        for key, value in over.items():
            merged[key] = _deep_merge(merged[key], value) if key in merged else value
        return merged
    return over


def merge_contexts(contexts: Iterable[dict], host: dict) -> tuple[dict, list[dict]]:
    """The merged context of the host and the contexts used, in merge order.

    Enabled contexts that match the host (``host_id`` included), by weight
    then name ignoring case; each ``data`` (a dict) is deep-merged over the
    result so far: objects merge key by key, anything else (lists too)
    replaces."""
    used = sorted(
        (c for c in contexts if c.get("enabled") and scope_matches(c, host, with_host=True)),
        key=lambda c: (int(c.get("weight") or 0), str(c["name"]).lower(), int(c.get("id") or 0)),
    )
    merged: dict = {}
    for context in used:
        data = context.get("data")
        if isinstance(data, dict):
            merged = _deep_merge(merged, data)
    return merged, used


# ── Rendering ────────────────────────────────────────────────────────────────


class RenderLimitError(TemplateRuntimeError):
    """A render went past one of the limits."""


@dataclass(frozen=True)
class RenderIssue:
    """Why a template did not render or parse: the message and, when Jinja
    gives one, the template name and line."""

    message: str
    template: str | None = None
    line: int | None = None

    def as_dict(self) -> dict:
        return {"message": self.message, "template": self.template, "line": self.line}

    def as_text(self) -> str:
        where = []
        if self.template:
            where.append(f"template '{self.template}'")
        if self.line:
            where.append(f"line {self.line}")
        return f"{self.message} ({', '.join(where)})" if where else self.message


@dataclass(frozen=True)
class RenderResult:
    config_text: str
    error: RenderIssue | None = None

    @property
    def ok(self) -> bool:
        return self.error is None


# The time a render must produce its next chunk by (monotonic seconds).
_deadline: contextvars.ContextVar[float | None] = contextvars.ContextVar("intended_config_deadline", default=None)

_GUARD_FILTER = "_plexus_guard"
_CONCAT_FILTER = "_plexus_concat"
_FILENAME_PREFIX = "<intended-config template "


def _tick() -> None:
    deadline = _deadline.get()
    if deadline is not None and time.monotonic() > deadline:
        raise RenderLimitError(f"The template ran for more than {RENDER_IDLE_SECONDS:g} seconds without output.")


def _check_size(value: Any, what: str = "A value") -> Any:
    if isinstance(value, (str, list, tuple, dict, set, frozenset)) and len(value) > OUTPUT_MAX:
        raise RenderLimitError(f"{what} is longer than {OUTPUT_MAX} characters or items.")
    return value


def _check_number(value: Any, what: str) -> None:
    if isinstance(value, int) and not isinstance(value, bool) and abs(value) > OUTPUT_MAX:
        raise RenderLimitError(f"{what}: {value} is larger than {OUTPUT_MAX}.")


def _check_numbers(values: Iterable[Any], what: str) -> None:
    for value in values:
        _check_number(value, what)


_PERCENT_SPEC = re.compile(r"%(?:\([^)]*\))?[#0\- +]*(\*|\d+)?(?:\.(\*|\d+))?")


def _check_percent_format(fmt: str) -> None:
    for match in _PERCENT_SPEC.finditer(fmt):
        for part in match.groups():
            if part and part.isdigit() and int(part) > OUTPUT_MAX:
                raise RenderLimitError(f"A format width of {part} is larger than {OUTPUT_MAX}.")


def _check_brace_format(fmt: str) -> None:
    try:
        parsed = list(string.Formatter().parse(fmt))
    except ValueError:
        return  # the call itself reports the bad format string
    for _literal, _field, spec, _conversion in parsed:
        for digits in re.findall(r"\d+", spec or ""):
            if int(digits) > OUTPUT_MAX:
                raise RenderLimitError(f"A format width of {digits} is larger than {OUTPUT_MAX}.")


def _check_str_call(method: Any, args: tuple, kwargs: dict) -> None:
    """Refuse a ``str`` method call whose result would pass ``OUTPUT_MAX``."""
    target = getattr(method, "__wrapped__", method)
    owner = getattr(target, "__self__", None)
    if not isinstance(owner, str):
        return
    name = getattr(target, "__name__", "")
    if name in ("format", "format_map"):
        _check_brace_format(owner)
    elif name == "replace" and len(args) >= 2 and isinstance(args[0], str) and isinstance(args[1], str):
        count = owner.count(args[0]) if args[0] else len(owner) + 1
        if len(owner) + count * max(0, len(args[1]) - len(args[0])) > OUTPUT_MAX:
            raise RenderLimitError(f"The replaced text would be longer than {OUTPUT_MAX} characters.")
    elif name == "expandtabs":
        size = args[0] if args else kwargs.get("tabsize", 8)
        if isinstance(size, int) and len(owner) + owner.count("\t") * size > OUTPUT_MAX:
            raise RenderLimitError(f"The expanded text would be longer than {OUTPUT_MAX} characters.")


def _range(*args: Any) -> range:
    """``range`` capped at ``RANGE_MAX`` items."""
    items = range(*args)
    if len(items) > RANGE_MAX:
        raise RenderLimitError(f"range() may produce at most {RANGE_MAX} items.")
    return items


def _guard(value: Any) -> Iterator[Any]:
    """Wraps the iterable of every ``for`` loop: checks the time limit on
    each item."""
    for item in value:
        _tick()
        yield item


def _concat(values: list) -> str:
    """The ``~`` operator, with the size limit."""
    _tick()
    return _check_size("".join(str(v) for v in values), "A joined text")


class _Guards(NodeTransformer):
    """Routes every ``for`` loop through ``_guard`` and every ``~`` through
    ``_concat`` so the time and size limits hold where Jinja has no hook."""

    def visit_For(self, node: nodes.For) -> nodes.Node:
        self.generic_visit(node)
        node.iter = nodes.Filter(node.iter, _GUARD_FILTER, [], [], None, None, lineno=node.lineno)
        return node

    def visit_Concat(self, node: nodes.Concat) -> nodes.Node:
        self.generic_visit(node)
        items = nodes.List(list(node.nodes), lineno=node.lineno)
        return nodes.Filter(items, _CONCAT_FILTER, [], [], None, None, lineno=node.lineno)


# ── Address filters ──────────────────────────────────────────────────────────


def _interface(value: Any, name: str) -> ipaddress.IPv4Interface | ipaddress.IPv6Interface:
    try:
        return ipaddress.ip_interface(str(value).strip())
    except ValueError:
        raise TemplateRuntimeError(f"{name}: '{value}' is not an address or network such as 192.0.2.0/24.") from None


def _netmask(value: Any) -> str:
    return str(_interface(value, "netmask").network.netmask)


def _wildcard(value: Any) -> str:
    return str(_interface(value, "wildcard").network.hostmask)


def _network(value: Any) -> str:
    return str(_interface(value, "network").network.network_address)


def _prefixlen(value: Any) -> int:
    return int(_interface(value, "prefixlen").network.prefixlen)


def _ip(value: Any) -> str:
    return str(_interface(value, "ip").ip)


def _nth_host(value: Any, n: Any) -> str:
    network = _interface(value, "nth_host").network
    if isinstance(n, bool) or not isinstance(n, int):
        raise TemplateRuntimeError(f"nth_host: '{n}' is not a whole number.")
    try:
        return str(network[n])
    except IndexError:
        raise TemplateRuntimeError(f"nth_host: {network} has no address number {n}.") from None


_ADDRESS_FILTERS: dict[str, Callable[..., Any]] = {
    "netmask": _netmask,
    "wildcard": _wildcard,
    "network": _network,
    "prefixlen": _prefixlen,
    "nth_host": _nth_host,
    "ip": _ip,
}

# Built-in filters whose numeric arguments can make a value grow: those
# arguments are capped. Every filter's result is size-checked.
_SIZED_FILTERS = ("batch", "center", "format", "indent", "replace", "slice", "truncate", "wordwrap")


def _checked_filter(name: str, func: Callable[..., Any]) -> Callable[..., Any]:
    # A filter marked pass_context / pass_eval_context / pass_environment
    # gets that object first; the value comes next.
    skip = 2 if getattr(func, "jinja_pass_arg", None) is not None else 1
    sized = name in _SIZED_FILTERS

    @wraps(func)
    def checked(*args: Any, **kwargs: Any) -> Any:
        _tick()
        if not sized:
            return _check_size(func(*args, **kwargs))
        rest = args[skip:]
        _check_numbers((*rest, *kwargs.values()), name)
        value = args[skip - 1] if len(args) >= skip else None
        if name == "format" and isinstance(value, str):
            _check_percent_format(value)
        if name == "replace" and isinstance(value, str) and len(rest) >= 2:
            old, new = str(rest[0]), str(rest[1])
            count = value.count(old) if old else len(value) + 1
            if len(value) + count * max(0, len(new) - len(old)) > OUTPUT_MAX:
                raise RenderLimitError(f"The replaced text would be longer than {OUTPUT_MAX} characters.")
        return _check_size(func(*args, **kwargs))

    return checked


class _Environment(ImmutableSandboxedEnvironment):
    """The sandbox with Plexus's limits (see the module docstring)."""

    intercepted_binops = frozenset({"+", "*", "**", "%"})

    def _generate(self, source: nodes.Template, name: str | None, filename: str | None, defer_init: bool = False):
        return super()._generate(_Guards().visit(source), name, filename, defer_init)

    def call(self, context: Any, obj: Any, /, *args: Any, **kwargs: Any) -> Any:
        _tick()
        _check_numbers((*args, *kwargs.values()), getattr(obj, "__name__", "call"))
        _check_str_call(obj, args, kwargs)
        return _check_size(super().call(context, obj, *args, **kwargs))

    def call_binop(self, context: Any, operator: str, left: Any, right: Any) -> Any:
        _tick()
        sequence = (str, list, tuple)
        if operator == "*":
            for seq, times in ((left, right), (right, left)):
                if isinstance(seq, sequence) and isinstance(times, int) and len(seq) * times > OUTPUT_MAX:
                    raise RenderLimitError(f"A repeated value would be longer than {OUTPUT_MAX} characters or items.")
        elif operator == "**":
            if isinstance(left, int) and isinstance(right, int) and right > 0:
                if max(1, abs(left).bit_length()) * right > OUTPUT_MAX:
                    raise RenderLimitError("A power is too large.")
        elif operator == "%" and isinstance(left, str):
            _check_percent_format(left)
            _check_numbers(right if isinstance(right, tuple) else (right,), "%")
        elif operator == "+" and isinstance(left, sequence) and isinstance(right, sequence):
            if len(left) + len(right) > OUTPUT_MAX:
                raise RenderLimitError(f"A joined value would be longer than {OUTPUT_MAX} characters or items.")
        return _check_size(super().call_binop(context, operator, left, right))

    def getattr(self, obj: Any, attribute: str) -> Any:
        _tick()
        return super().getattr(obj, attribute)

    def getitem(self, obj: Any, argument: Any) -> Any:
        _tick()
        return super().getitem(obj, argument)


def _finalize(value: Any) -> Any:
    """Every ``{{ ... }}`` value: at most ``OUTPUT_MAX`` characters."""
    if isinstance(value, str):
        return _check_size(value, "An output value")
    if isinstance(value, (list, tuple, dict, set, frozenset)):
        _check_size(value, "An output value")
        return _check_size(str(value), "An output value")
    return value


class _Loader(BaseLoader):
    """Resolves ``include`` / ``import`` names (ignoring case) to the given
    template texts."""

    def __init__(self, texts: dict[str, str]):
        self.texts = {name.lower(): (name, text) for name, text in texts.items()}

    def get_source(self, environment: Any, template: str) -> tuple[str, str, Callable[[], bool]]:
        found = self.texts.get(str(template).lower())
        if found is None:
            raise TemplateNotFound(template)
        name, text = found
        return text, f"{_FILENAME_PREFIX}{name}>", lambda: True


def _template_of(filename: str | None) -> str | None:
    if filename and filename.startswith(_FILENAME_PREFIX) and filename.endswith(">"):
        return filename[len(_FILENAME_PREFIX) : -1]
    return None


def _issue(exc: BaseException) -> RenderIssue:
    """The message, template and line of a parse or render error."""
    if isinstance(exc, TemplateSyntaxError):
        name = _template_of(exc.filename) or exc.name
        return RenderIssue(str(exc.message or exc), name, exc.lineno)
    template: str | None = None
    line: int | None = None
    tb = exc.__traceback__
    while tb is not None:
        found = _template_of(tb.tb_frame.f_code.co_filename)
        if found is not None:
            template, line = found, tb.tb_lineno
        tb = tb.tb_next
    if isinstance(exc, TemplateNotFound):
        message = f"No template named '{exc.name}' to include."
    elif isinstance(exc, RecursionError):
        message = "The template includes or calls itself too deeply."
    elif isinstance(exc, MemoryError):
        message = "The template used too much memory."
    else:
        message = str(exc) or type(exc).__name__
    return RenderIssue(message, template, line)


def _tidy(text: str) -> str:
    """Trailing whitespace trimmed per line, no trailing blank lines, and one
    final newline (an empty result stays empty)."""
    lines = [line.rstrip() for line in text.replace("\r\n", "\n").replace("\r", "\n").split("\n")]
    while lines and not lines[-1]:
        lines.pop()
    return "\n".join(lines) + "\n" if lines else ""


class Renderer:
    """Renders templates from a fixed set of named texts (every template,
    snippets and device templates alike, enabled or not, so ``include`` and
    ``import`` find them by name).

    One renderer compiles each template once and can render many hosts; it
    is safe to use from several threads."""

    def __init__(self, texts: dict[str, str] | None = None):
        self.env = _Environment(
            loader=_Loader(dict(texts or {})),
            undefined=StrictUndefined,
            trim_blocks=True,
            lstrip_blocks=True,
            autoescape=False,
            finalize=_finalize,
            auto_reload=False,
        )
        self.env.globals["range"] = _range
        self.env.globals.pop("lipsum", None)
        for name, func in list(self.env.filters.items()):
            self.env.filters[name] = _checked_filter(name, func)
        self.env.filters.update(_ADDRESS_FILTERS)
        self.env.filters[_GUARD_FILTER] = _guard
        self.env.filters[_CONCAT_FILTER] = _concat

    def check(self, text: str, name: str = "template") -> RenderIssue | None:
        """``None`` when the text compiles, else the syntax error."""
        try:
            self.env.compile(text, name, f"{_FILENAME_PREFIX}{name}>")
        except TemplateSyntaxError as exc:
            return _issue(exc)
        return None

    def render(self, name: str, variables: dict) -> RenderResult:
        """Render the named template with ``variables``, within the limits."""
        token = _deadline.set(time.monotonic() + RENDER_IDLE_SECONDS)
        try:
            template = self.env.get_template(name)
            parts: list[str] = []
            size = 0
            for chunk in template.generate(variables):
                size += len(chunk)
                if size > OUTPUT_MAX:
                    raise RenderLimitError(f"The output is longer than {OUTPUT_MAX} characters.")
                parts.append(chunk)
                _deadline.set(time.monotonic() + RENDER_IDLE_SECONDS)
            return RenderResult(_tidy("".join(parts)))
        except Exception as exc:  # any template failure is a result, never a crash
            return RenderResult("", _issue(exc))
        finally:
            _deadline.reset(token)


def check_syntax(text: str, name: str = "template") -> RenderIssue | None:
    """The Jinja syntax error of a template text, or ``None``."""
    return Renderer().check(text, name)


# ── Comparison ───────────────────────────────────────────────────────────────


def _ignored(stripped: str) -> bool:
    return not stripped or stripped.startswith("!") or stripped.startswith("#")


def config_lines(text: str) -> list[tuple[str, tuple[str, ...] | None]]:
    """Each line of a configuration (trailing whitespace trimmed) with its
    path: its own text and the texts of its ancestors by indentation, from
    the top. Blank lines and lines starting with ``!`` or ``#`` have no path
    (``None``) and are no one's parent."""
    out: list[tuple[str, tuple[str, ...] | None]] = []
    stack: list[tuple[int, str]] = []
    for raw in str(text or "").replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        line = raw.rstrip()
        stripped = line.strip()
        if _ignored(stripped):
            out.append((line, None))
            continue
        indent = len(line) - len(line.lstrip())
        while stack and stack[-1][0] >= indent:
            stack.pop()
        path = (*(t for _, t in stack), stripped)
        stack.append((indent, stripped))
        out.append((line, path))
    if out and out[-1] == ("", None):
        out.pop()
    return out


@dataclass
class Comparison:
    """An intended configuration against a backup: each intended line with
    whether the backup lacks it, and the backup's extra lines."""

    lines: list[dict] = field(default_factory=list)
    extra: list[dict] = field(default_factory=list)

    @property
    def missing_count(self) -> int:
        return sum(1 for line in self.lines if line["missing"])

    @property
    def extra_count(self) -> int:
        return len(self.extra)


def compare_configs(intended: str, backup: str) -> Comparison:
    """Compare by indentation trees (see ``config_lines``).

    *Missing*: an intended line whose path the backup lacks (so the children
    of a missing parent are missing too). *Extra*: a backup line the
    intended text lacks whose parent is an intended line that has children;
    top-level backup lines are never extra."""
    intended_lines = config_lines(intended)
    backup_lines = config_lines(backup)
    backup_paths = {path for _, path in backup_lines if path is not None}
    intended_paths = {path for _, path in intended_lines if path is not None}
    parents = {path[:-1] for path in intended_paths if len(path) > 1}
    lines = [{"text": text, "missing": path is not None and path not in backup_paths} for text, path in intended_lines]
    extra: list[dict] = []
    seen: set[tuple[str, ...]] = set()
    for _text, path in backup_lines:
        if path is None or len(path) < 2 or path in intended_paths or path in seen:
            continue
        if path[:-1] in parents:
            seen.add(path)
            extra.append({"path": list(path[:-1]), "text": path[-1]})
    return Comparison(lines, extra)


def verdict(status: str, has_backup: bool, comparison: Comparison | None) -> str:
    """``unknown`` without a successful backup or when the render failed,
    else ``compliant`` when nothing is missing, else ``non_compliant``."""
    if status != "ok" or not has_backup or comparison is None:
        return "unknown"
    return "compliant" if comparison.missing_count == 0 else "non_compliant"
