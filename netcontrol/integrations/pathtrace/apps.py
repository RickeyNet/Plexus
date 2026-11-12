"""Applications, categories and domains as the destination of a path trace.

A firewall rule can name what a flow is for instead of (or as well as) where
it goes: an application, an application category, a domain, an FQDN, a URL
category. A trace that knows only addresses cannot decide such a rule. Asked
about an application or a domain (``target``), it can: a rule that names it
matches, one that names something else provably does not, and one that
needs what was not collected (the categories of an application nobody
catalogued, the application a typed domain belongs to) may match, with the
reason why, never a guess.

Rules carry these as criteria (``criterion``), in a rule's ``dst_names``
(alternatives to the destination addresses in its ``dst_cidrs``, as Cato's
Internet firewall destination: an application OR a category OR a domain OR
an address) or ``app_names`` (a further condition the rule narrows by, as
the application field of a Cato WAN firewall rule or of an FMC, Panorama or
Junos rule). Each criterion's ``text`` is the entry the rule's
``unresolved`` list keeps for it, so a trace that asks about no application
words the rule as it always did. ``match`` decides one criterion and
``any_of`` the criteria of one field.

What an application is comes from a catalog (``catalog_of``): the
``applications`` list a snapshot carries (Cato's custom applications, with
their domains and categories, and Cato's application catalog when it was
collected). ``suggest`` lists names to pick from: the catalogs and every
application, category and domain the rules of the snapshots name.

Pure, standard library only: the HTML export runs this module in the
browser (``pathtrace.offline.MODULES``).
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable
from dataclasses import dataclass
from fnmatch import fnmatchcase
from typing import Any

# How much of the flow a criterion covers: ``model.FULL``, ``PART`` and
# ``NONE``. Not imported: ``meraki.forwarding``, which ``model`` reaches
# through the AWS engine, imports this module.
_FULL, _PART, _NONE = 2, 1, 0

# Criterion kinds.
APPLICATION = "application"
CATEGORY = "category"
# A domain and every name under it; an FQDN is one name only; a wildcard is
# a pattern (``*.example.com``).
DOMAIN = "domain"
FQDN = "fqdn"
WILDCARD = "wildcard"
# An account's own application: matched by its name, or by the domains it
# is defined by when those are all it is defined by.
CUSTOM_APPLICATION = "custom_application"
# Addresses inside an application field (a Cato WAN firewall rule's
# application addresses): the tracer covers them with the destination.
ADDRESS = "address"
# Anything else a name criterion can be (a custom category, an FQDN
# container, a URL...): it may match, and Plexus cannot tell.
OTHER = "other"

# What ``suggest`` reports a criterion as.
_SUGGESTED = {
    APPLICATION: "application",
    CUSTOM_APPLICATION: "application",
    CATEGORY: "category",
    DOMAIN: "domain",
    FQDN: "domain",
}
MAX_LENGTH = 128
_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")


def criterion(
    kind: str,
    value: str,
    text: str,
    *,
    domains: list[str] | None = None,
    fqdns: list[str] | None = None,
    cidrs: list[str] | None = None,
    why: str = "",
    scheme: str = "",
    group: str = "",
) -> dict[str, Any]:
    """One name criterion of a rule. ``text`` is the rule's ``unresolved``
    entry it stands for. A custom application carries the ``domains`` and
    ``fqdns`` it is defined by, ``None`` when its definition is not known
    or is not only names; an ``address`` criterion its ``cidrs``; an
    ``other`` one ``why`` it cannot be decided. A category names the
    vendor whose taxonomy it is in (``scheme``): only that vendor's
    categories of an application decide it. ``group``: in a rule's
    ``app_names``, the field the criterion is in, when a rule has several
    (an application field and a URL field, each of which must match)."""
    found: dict[str, Any] = {"kind": kind, "value": str(value or "").strip(), "text": text}
    if scheme:
        found["scheme"] = scheme
    if group:
        found["group"] = group
    if kind == CUSTOM_APPLICATION:
        found["domains"] = None if domains is None else [d.lower() for d in domains]
        found["fqdns"] = None if domains is None else [f.lower() for f in fqdns or []]
    if kind == ADDRESS:
        found["cidrs"] = list(cidrs or [])
    if why:
        found["why"] = why
    return found


def key(name: Any) -> str:
    """An application or category name as it is compared: case, spaces and
    punctuation do not count (``You Tube`` is ``youtube``)."""
    return re.sub(r"[^0-9a-z]+", "", str(name or "").casefold())


def host(text: Any) -> str:
    """The host name ``text`` names (a bare name, or a URL's host), lower
    case, else ``""``: an address, or not a domain name with at least two
    labels."""
    raw = str(text or "").strip().lower()
    if "://" in raw:
        raw = raw.split("://", 1)[1]
    raw = raw.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    raw = raw.rsplit("@", 1)[-1]
    if raw.count(":") == 1:
        raw = raw.split(":", 1)[0]
    raw = raw.rstrip(".")
    try:
        ipaddress.ip_address(raw)
        return ""
    except ValueError:
        pass
    labels = raw.split(".")
    if len(labels) < 2 or not all(_LABEL.match(label) for label in labels) or labels[-1].isdigit():
        return ""
    return raw


def _covers(pattern: str, kind: str, name: str) -> bool:
    """Whether a domain criterion ``pattern`` covers the host ``name``."""
    pattern = pattern.strip().lower().rstrip(".")
    if not pattern:
        return False
    if kind == WILDCARD or "*" in pattern:
        if pattern.startswith("*.") and "*" not in pattern[2:]:
            return name.endswith(pattern[1:])
        return fnmatchcase(name, pattern)
    if kind == FQDN:
        return name == pattern
    return name == pattern or name.endswith("." + pattern)


def _zone_cover(pattern: str, kind: str, zone: str) -> int:
    """How much of ``zone`` and every name under it a domain criterion covers."""
    pattern = pattern.strip().lower().rstrip(".")
    if kind == WILDCARD or "*" in pattern:
        suffix = pattern[2:] if pattern.startswith("*.") and "*" not in pattern[2:] else ""
        if not suffix:
            return _PART if fnmatchcase(zone, pattern) or fnmatchcase("x." + zone, pattern) else _NONE
        if zone.endswith("." + suffix):
            return _FULL
        return _PART if zone == suffix or suffix.endswith("." + zone) else _NONE
    if kind != FQDN and (zone == pattern or zone.endswith("." + pattern)):
        return _FULL
    return _PART if pattern == zone or pattern.endswith("." + zone) else _NONE


@dataclass(frozen=True)
class Target:
    """What a flow asked about by name is: ``name`` as the trace says it;
    ``domain``, the host the flow is traced to (its address is looked up
    from it), ``""`` when none is known; the ``applications`` it is,
    ``hosts`` (exact names) and ``zones`` (domains with every name under
    them) it uses and the ``categories`` it is in, each ``None`` when not
    known, in the taxonomy of ``scheme``; ``source``, where the details
    come from."""

    name: str
    domain: str = ""
    applications: tuple[str, ...] | None = None
    hosts: tuple[str, ...] = ()
    zones: tuple[str, ...] = ()
    categories: tuple[str, ...] | None = None
    source: str = ""
    scheme: str = ""

    @property
    def domains_known(self) -> bool:
        return bool(self.hosts or self.zones)

    def summary(self, address: str | None) -> dict[str, Any]:
        """The trace result's ``destination_app``."""
        return {
            "name": self.name,
            "domain": self.domain or None,
            "address": address or None,
            "categories": list(self.categories or []),
        }


def _domain_match(kind: str, pattern: str, target: Target) -> int:
    """How much of what ``target`` uses a domain criterion covers."""
    found = [_FULL if _covers(pattern, kind, h) else _NONE for h in target.hosts]
    found += [_zone_cover(pattern, kind, z) for z in target.zones]
    if found and all(f == _FULL for f in found):
        return _FULL
    return _PART if any(f != _NONE for f in found) else _NONE


def _application(value: str, text: str, target: Target) -> tuple[int, str]:
    """An application criterion against the applications ``target`` is:
    the same name matches; a name that holds the other (``youtube-base``
    and ``YouTube``, a vendor's part of an application) may; any other does
    not."""
    wanted = key(value)
    known = {key(a) for a in target.applications or ()}
    if wanted in known:
        return _FULL, ""
    if wanted and any(k and (k in wanted or wanted in k) for k in known):
        return _FULL, f"it names {text}, which may be part of {target.name} or hold it"
    return _NONE, ""


def match(item: dict, target: Target) -> tuple[int, str]:
    """Whether one criterion matches ``target``: ``(cover, reason)``. The
    cover is ``FULL``, ``PART`` or ``NONE`` (``model``); a ``reason``
    says it may match and why that cannot be decided (the cover is then 2,
    what it may be)."""
    kind = str(item.get("kind") or "")
    value = str(item.get("value") or "")
    text = str(item.get("text") or value)
    name = target.name
    if kind == APPLICATION:
        if target.applications is None:
            return _FULL, f"it names {text}, and which application {name} is is not known"
        return _application(value, text, target)
    if kind == CATEGORY:
        scheme = str(item.get("scheme") or "")
        if target.categories is None or scheme != target.scheme:
            whose = f"the {scheme} categories" if scheme and target.categories is not None else "the categories"
            return _FULL, f"it names {text}, and {whose} of {name} are not collected"
        return (_FULL if key(value) in {key(c) for c in target.categories} else _NONE), ""
    if kind in (DOMAIN, FQDN, WILDCARD):
        if not target.domains_known:
            return _FULL, f"it names {text}, and the domains {name} uses are not known"
        return _domain_match(kind, value, target), ""
    if kind == CUSTOM_APPLICATION:
        # An account's own application is the target only by its own name.
        if target.applications is not None and key(value) in {key(a) for a in target.applications}:
            return _FULL, ""
        domains, fqdns = item.get("domains"), item.get("fqdns")
        if domains is None or fqdns is None or not (domains or fqdns):
            return _FULL, f"it names {text}, whose definition is not collected or is not only domains"
        if not target.domains_known:
            return _FULL, f"it names {text}, and the domains {name} uses are not known"
        return max(
            [_domain_match(DOMAIN, d, target) for d in domains] + [_domain_match(FQDN, f, target) for f in fqdns]
        ), ""
    why = str(item.get("why") or "which Plexus cannot evaluate")
    return _FULL, f"it names {text}, {why}"


def all_groups(results: Iterable[tuple[str, int, str, str]]) -> tuple[int, list[str], list[str]]:
    """The criteria of several fields, each of which must match, as
    ``(cover, reasons, matched)`` from each one's ``(group, cover, reason,
    text)``: ``any_of`` within a field, the least of the fields."""
    groups: dict[str, list[tuple[int, str, str]]] = {}
    for group, cover, reason, text in results:
        groups.setdefault(group, []).append((cover, reason, text))
    best = _FULL
    reasons: list[str] = []
    matched: list[str] = []
    for found in groups.values():
        cover, why, hit = any_of(found)
        best = min(best, cover)
        reasons += why
        matched += hit
    return best, (reasons if best != _NONE else []), (matched if best != _NONE else [])


def any_of(results: Iterable[tuple[int, str, str]]) -> tuple[int, list[str], list[str]]:
    """The criteria of one field, any of which matches the flow, as
    ``(cover, reasons, matched)`` from each one's ``(cover, reason, text)``:
    one that matches all of it decides; else one that may match makes the
    field one that may (``reasons``); else the most any covers."""
    best = _NONE
    reasons: list[str] = []
    for cover, reason, text in results:
        if cover == _FULL and not reason:
            return _FULL, [], [text] if text else []
        if reason:
            reasons.append(reason)
        else:
            best = max(best, cover)
    if reasons:
        return _FULL, reasons, []
    return best, [], []


# ── The catalog ─────────────────────────────────────────────────────────────


def catalog_entry(
    name: str,
    *,
    categories: list[str] | None = None,
    domains: list[str] | None = None,
    fqdns: list[str] | None = None,
    website: str = "",
    source: str = "",
    scheme: str = "",
) -> dict[str, Any]:
    """One application of a snapshot's ``applications`` list. ``categories``
    is ``None`` when not known, else in the taxonomy of the vendor
    ``scheme``; ``domains`` and ``fqdns`` are what the application is
    defined by (an account's own application); ``website`` the host its
    catalog names."""
    found: dict[str, Any] = {"name": name, "categories": None if categories is None else list(categories)}
    if scheme:
        found["scheme"] = scheme
    if domains:
        found["domains"] = [d.lower() for d in domains]
    if fqdns:
        found["fqdns"] = [f.lower() for f in fqdns]
    if host(website):
        found["website"] = host(website)
    if source:
        found["source"] = source
    return found


def catalog_of(snapshots: Iterable[dict]) -> list[dict]:
    """Every application the snapshots' catalogs list (``applications``),
    an account's own ones first."""
    found: list[dict] = []
    for snapshot in snapshots:
        entries = snapshot.get("applications") if isinstance(snapshot, dict) else None
        found.extend(e for e in entries or [] if isinstance(e, dict) and str(e.get("name") or "").strip())
    return sorted(found, key=lambda e: 0 if e.get("domains") or e.get("fqdns") else 1)


def target(text: Any, catalog: list[dict] | None = None) -> Target:
    """What the application or domain typed as a destination is.

    A domain (``youtube.com``, or a URL) is the host the flow goes to: an
    account's own application defined by it is that application; else
    which application it is is not known. A name (``YouTube``) is that
    application; the catalog entry of that name gives its categories and
    the domains it uses (an account's own application's definition, else
    the website the catalog names). Raises ``ValueError`` for an empty or
    too long text."""
    raw = str(text or "").strip()
    if not raw or len(raw) > MAX_LENGTH:
        raise ValueError(f"destination_app must be 1 to {MAX_LENGTH} characters")
    entries = list(catalog or [])
    typed = host(raw)
    if typed:
        owners = [
            e
            for e in entries
            if any(_covers(d, DOMAIN, typed) for d in e.get("domains") or [])
            or any(_covers(f, FQDN, typed) for f in e.get("fqdns") or [])
        ]
        names = {key(e["name"]) for e in owners}
        if len(names) == 1:
            owner = owners[0]
            return Target(
                name=typed,
                domain=typed,
                applications=(str(owner["name"]),),
                hosts=(typed,),
                categories=_categories(owner),
                source=str(owner.get("source") or ""),
                scheme=str(owner.get("scheme") or ""),
            )
        return Target(name=typed, domain=typed, hosts=(typed,))
    wanted = key(raw)
    entry = next((e for e in entries if key(e["name"]) == wanted), None) if wanted else None
    if entry is None:
        return Target(name=raw, applications=(raw,))
    fqdns = tuple(str(f) for f in entry.get("fqdns") or [])
    zones = tuple(str(d) for d in entry.get("domains") or [])
    website = str(entry.get("website") or "")
    hosts = fqdns if fqdns or zones else ((website,) if website else ())
    return Target(
        name=str(entry["name"]),
        domain=(hosts or zones or ("",))[0],
        applications=(str(entry["name"]),),
        hosts=hosts,
        zones=zones,
        categories=_categories(entry),
        source=str(entry.get("source") or ""),
        scheme=str(entry.get("scheme") or ""),
    )


def _categories(entry: dict) -> tuple[str, ...] | None:
    found = entry.get("categories")
    return tuple(str(c) for c in found) if isinstance(found, list) else None


# ── Suggestions ─────────────────────────────────────────────────────────────


def _rule_criteria(snapshot: dict) -> Iterable[tuple[dict, str]]:
    """``(criterion, rule set name)`` of every name criterion the rules of a
    snapshot carry, network rules (``egress_policy``) included."""
    for node in snapshot.get("nodes") or []:
        block = node.get("forwarding") if isinstance(node, dict) else None
        if not isinstance(block, dict):
            continue
        for policy in block.get("policies") or []:
            if not isinstance(policy, dict):
                continue
            where = str(policy.get("name") or "Rule set")
            for rule in policy.get("rules") or []:
                if isinstance(rule, dict):
                    for field in ("dst_names", "app_names"):
                        for item in rule.get(field) or []:
                            if isinstance(item, dict):
                                yield item, where
        egress = block.get("egress_policy")
        if isinstance(egress, dict):
            where = str(egress.get("name") or "Egress policy")
            for rule in egress.get("rules") or []:
                for item in (rule or {}).get("app") or [] if isinstance(rule, dict) else []:
                    if isinstance(item, dict) and isinstance(item.get("match"), dict):
                        yield item["match"], where


def names(snapshots: Iterable[dict]) -> list[dict[str, str]]:
    """``[{"name", "kind", "source"}]``: every application, category and
    domain the snapshots' catalogs list or their rules name, once each."""
    found: dict[tuple[str, str], dict[str, str]] = {}

    def add(name: str, kind: str, source: str) -> None:
        name = name.strip()
        if name and (key(name), kind) not in found:
            found[(key(name), kind)] = {"name": name, "kind": kind, "source": source}

    snapshots = list(snapshots)
    for entry in catalog_of(snapshots):
        source = str(entry.get("source") or "Application catalog")
        add(str(entry["name"]), "application", source)
        for category in entry.get("categories") or []:
            add(str(category), "category", source)
    for snapshot in snapshots:
        if not isinstance(snapshot, dict):
            continue
        for item, where in _rule_criteria(snapshot):
            kind = _SUGGESTED.get(str(item.get("kind") or ""))
            if kind:
                add(str(item.get("value") or ""), kind, f"Named by {where}")
    return list(found.values())


def suggest(entries: list[dict[str, str]], text: Any, limit: int = 20) -> list[dict[str, str]]:
    """The ``entries`` whose name holds ``text`` (case does not count), those
    it starts with first, then by name; all of them by name for no text."""
    wanted = str(text or "").strip().casefold()
    ranked = []
    for entry in entries:
        name = entry["name"].casefold()
        if wanted and wanted not in name:
            continue
        ranked.append((0 if name.startswith(wanted) else 1, name, entry["kind"], entry))
    ranked.sort(key=lambda r: r[:3])
    return [r[3] for r in ranked[: max(0, limit)]]


__all__ = [
    "ADDRESS",
    "APPLICATION",
    "CATEGORY",
    "CUSTOM_APPLICATION",
    "DOMAIN",
    "FQDN",
    "MAX_LENGTH",
    "OTHER",
    "WILDCARD",
    "Target",
    "all_groups",
    "any_of",
    "catalog_entry",
    "catalog_of",
    "criterion",
    "host",
    "key",
    "match",
    "names",
    "suggest",
    "target",
]
