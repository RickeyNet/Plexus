"""Cato egress vs cloud allow-lists: does the traffic a cloud filter rule
expects from Cato actually leave Cato from the addresses that rule allows?

A security group (AWS), network security group (Azure) or VPC firewall rule
(GCP) whose source names one of a Cato account's allocated IPs says that
Cato users are meant to reach the resource behind it from those reserved
addresses. Cato sends a flow out of an allocated IP only when the first
INTERNET network rule that matches it NATs there (``network_rules``); a rule
that matches by name (a domain, an application, a custom category) does not
match a connection made to the bare IP, which then falls to a later rule and
leaves from a PoP's shared address the cloud rule does not list.

``check`` walks every instance with a public address in each collected cloud
account (``address_owners`` of the reachability engines, read with
``pathtrace.cloud.public_addresses``), the inbound rules of its filters that
name an allocated IP (``inbound_rules``), and evaluates a flow from every
Cato source (each site range and connected remote user the Cato Cloud
routes) to the public address on the rule's ports with
``network_rules.evaluate``. Whether an allocated IP gets in is decided by
the engine's own filters (``inbound_filters``: network ACLs, security
groups, network security groups, VPC firewall rules). Finding kinds:

  - ``hostname_only`` (warning): the bare-IP flow falls to a rule that does
    not NAT to the allowed IPs while a rule ahead of it does, but matches
    only by name
  - ``allocated_ip_mismatch`` (warning): the rule that matches NATs to
    allocated IPs the filters do not let in
  - ``no_nat_rule`` (warning): no rule that applies NATs to the allowed IPs
  - ``undetermined`` (info): a rule that may apply cannot be resolved, or a
    NAT rule's address could not be read
  - account notes (info): network rules or allocated IPs not collected, no
    Cato sources, no cloud account collected

A source whose flow leaves from an allowed IP raises nothing; one finding is
kept per (Cato account, resource, public address, ports, cloud rule) with
the worst kind over the sources and the sources of each kind listed.

Pure: no I/O. Rules whose source is broader than ``BROAD_PREFIX`` (or
every address) say nothing about Cato and are left out.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from typing import Any

from netcontrol.integrations.cato import network_rules
from netcontrol.integrations.pathtrace.cloud import public_addresses
from netcontrol.integrations.pathtrace.model import OK, Network, contains, net, show, worst

# A source range shorter than this names far more than a Cato account's
# allocated IPs: it says nothing about Cato.
BROAD_PREFIX = {4: 16, 6: 48}

WARNING, INFO = "warning", "info"
HOSTNAME_ONLY = "hostname_only"
IP_MISMATCH = "allocated_ip_mismatch"
NO_NAT_RULE = "no_nat_rule"
UNDETERMINED = "undetermined"
FINE = "ok"
# Account notes.
RULES_NOT_COLLECTED = "network_rules_not_collected"
RULES_UNAVAILABLE = "network_rules_unavailable"
ALLOCATED_NOT_COLLECTED = "allocated_ips_not_collected"
NO_ALLOCATED_IPS = "no_allocated_ips"
NO_SOURCES = "no_cato_sources"
NO_CLOUD = "no_cloud_accounts"

KIND_LABELS = {
    HOSTNAME_ONLY: "Reachable only by hostname",
    IP_MISMATCH: "Allocated IP mismatch",
    NO_NAT_RULE: "No Cato rule egresses via the allowed IPs",
    UNDETERMINED: "Undetermined",
    RULES_NOT_COLLECTED: "Network rules not collected",
    RULES_UNAVAILABLE: "Network rules not evaluable",
    ALLOCATED_NOT_COLLECTED: "Allocated IPs not collected",
    NO_ALLOCATED_IPS: "No allocated IPs",
    NO_SOURCES: "No Cato sources",
    NO_CLOUD: "No cloud account collected",
}
_RANK = {FINE: 0, UNDETERMINED: 1, NO_NAT_RULE: 3, IP_MISMATCH: 4, HOSTNAME_ONLY: 5}
_WARNINGS = (HOSTNAME_ONLY, IP_MISMATCH, NO_NAT_RULE)
_ALL_PROTOCOLS = ("", "all", "any", "*", "-1")
# How many sources a message names before "and N more".
_SHOWN = 3


def severity_of(kind: str) -> str:
    return WARNING if kind in _WARNINGS else INFO


# ── Cato side ───────────────────────────────────────────────────────────────


def cato_account(snapshot: dict) -> dict[str, Any]:
    """What a Cato snapshot holds for the check: the compiled network rules
    (``policy``, ``None`` when the snapshot predates their collection), the
    allocated IPs (``allocated``: ``[{"ip", "pop"}]``, ``None`` when not
    collected) and the ``sources``, ``[(label, network)]``: each range and
    remote user the Cato Cloud routes."""
    found: dict[str, Any] = {"policy": None, "allocated": None, "sources": []}
    for node in snapshot.get("nodes") or []:
        forwarding = node.get("forwarding") if isinstance(node, dict) else None
        if not isinstance(forwarding, dict):
            continue
        policy = forwarding.get("egress_policy")
        if not isinstance(policy, dict) or policy.get("kind") != network_rules.KIND:
            continue
        found["policy"] = policy
        found["allocated"] = policy.get("allocated")
        sources: list[tuple[str, Network]] = []
        for route in forwarding.get("routes") or []:
            prefix = net(route.get("prefix")) if isinstance(route, dict) else None
            if prefix is None or prefix.prefixlen == 0 or route.get("kind") == "default":
                continue
            label = str(route.get("source") or "").strip() or "Cato range"
            sources.append((f"{label} ({show(prefix)})", prefix))
        found["sources"] = sources
        break
    return found


def _nat_ips(rule: dict | None) -> list[str]:
    egress = (rule or {}).get("egress") or {}
    if str(egress.get("route") or "").upper() != "NAT":
        return []
    return [str(a.get("ip")) for a in egress.get("addresses") or [] if a.get("ip")]


def _account_ips(account: dict) -> list[str]:
    """The allocated IPs to look for: the collected list, else the
    addresses the NAT rules name."""
    if account["allocated"] is not None:
        return [a["ip"] for a in account["allocated"]]
    seen: list[str] = []
    for rule in (account["policy"] or {}).get("rules") or []:
        seen.extend(ip for ip in _nat_ips(rule) if ip not in seen)
    return seen


# ── Cloud side ──────────────────────────────────────────────────────────────


def _broad(network: Network) -> bool:
    return network.prefixlen < BROAD_PREFIX[network.version]


def _covered(sources: Iterable[str], ips: list[str]) -> list[str]:
    """The ``ips`` the rule source items name (a CIDR no broader than
    ``BROAD_PREFIX``); tags, groups and every-address items name none."""
    found: list[str] = []
    for item in sources:
        rule_net = net(item)
        if rule_net is None or _broad(rule_net):
            continue
        for ip in ips:
            address = net(ip)
            if address is not None and contains(rule_net, address) and ip not in found:
                found.append(ip)
    return found


def _traffic(protocol: str, low: int | None, high: int | None) -> tuple[str, tuple[int, int] | None, str]:
    """A rule's traffic as ``(protocol, ports, text)`` for ``evaluate``."""
    name = str(protocol or "").strip().lower()
    if name in _ALL_PROTOCOLS:
        return "", None, "all traffic"
    if low is None or name.startswith("icmp"):
        return name, None, f"{name} all ports" if not name.startswith("icmp") else name
    high = low if high is None else high
    return name, (low, high), f"{name} {low}" if low == high else f"{name} {low}-{high}"


def cloud_targets(provider: str, engine: Any, ips: list[str]) -> list[dict[str, Any]]:
    """Every (instance public address, inbound allow rule naming one of
    ``ips``, traffic) of one cloud's reachability engine."""
    targets: list[dict[str, Any]] = []
    owners = engine.address_owners() if callable(getattr(engine, "address_owners", None)) else {}
    for public, (private, network, owner) in sorted(public_addresses(owners).items()):
        try:
            place = engine.locate(private, network)
        except ValueError:
            continue
        if place.get("subnet") is None:
            continue
        for rule in engine.inbound_rules(place):
            if str(rule.get("action") or "allow").lower() != "allow":
                continue
            allowed = _covered(rule.get("sources") or [], ips)
            if not allowed:
                continue
            for protocol, low, high in rule.get("traffic") or [("all", None, None)]:
                name, ports, text = _traffic(protocol, low, high)
                targets.append(
                    {
                        "provider": provider,
                        "engine": engine,
                        "place": place,
                        "resource_id": str(owner.get("rid") or ""),
                        "resource_name": str(owner.get("name") or owner.get("rid") or ""),
                        "public_ip": public,
                        "private_ip": private,
                        "protocol": name,
                        "ports": ports,
                        "traffic": text,
                        "filter": str(rule.get("filter") or ""),
                        "rule": str(rule.get("rule") or ""),
                        "rule_id": str(rule.get("rule_id") or rule.get("rule") or ""),
                        "allowed": allowed,
                    }
                )
    return targets


def _admits(target: dict, cache: dict[str, str]) -> Callable[[str], str]:
    """Whether the filters at the target let ``ip`` in: the worst status of
    the engine's inbound filter steps (``ok`` only if every one passes)."""

    def admits(ip: str) -> str:
        if ip not in cache:
            engine = target["engine"]
            peer = engine.locate(ip)
            steps = engine.inbound_filters(target["place"], peer, target["protocol"], target["ports"])
            cache[ip] = worst([str(s.get("status")) for s in steps]) if steps else "unknown"
        return cache[ip]

    return admits


# ── The verdict for one source ──────────────────────────────────────────────


def verdict(
    policy: dict, src: Network, target: dict, admits: Callable[[str], str], allowed: list[str]
) -> dict[str, Any]:
    """How a flow from ``src`` to the target's public address leaves Cato,
    against the allocated IPs the cloud rule allows: ``{"kind", "rule",
    "name_rules", "doubtful", "ips", "refused"}``."""
    dst = net(target["public_ip"])
    assert dst is not None
    found = network_rules.evaluate(policy, src, dst, target["protocol"], target["ports"])
    rule = found["rule"]
    result: dict[str, Any] = {"kind": FINE, "rule": rule, "name_rules": [], "doubtful": [], "ips": [], "refused": []}
    ips = _nat_ips(rule)
    if rule is not None and str(rule["egress"].get("route") or "").upper() == "NAT":
        if not ips:
            return {**result, "kind": UNDETERMINED}
        refused = [ip for ip in ips if admits(ip) != OK]
        return {**result, "kind": IP_MISMATCH if refused else FINE, "ips": ips, "refused": refused}

    def nats_to_allowed(candidate: dict) -> bool:
        return bool(set(_nat_ips(candidate["rule"])) & set(allowed))

    by_name = [c for c in found["candidates"] if c["why"] == "name" and nats_to_allowed(c)]
    if by_name:
        return {**result, "kind": HOSTNAME_ONLY, "name_rules": by_name}
    doubtful = [c for c in found["candidates"] if c["why"] != "name" and nats_to_allowed(c)]
    if doubtful:
        return {**result, "kind": UNDETERMINED, "doubtful": doubtful}
    return {**result, "kind": NO_NAT_RULE}


# ── Wording ─────────────────────────────────────────────────────────────────


def _listed(labels: list[str]) -> str:
    shown = ", ".join(labels[:_SHOWN])
    return f"{shown} and {len(labels) - _SHOWN} more" if len(labels) > _SHOWN else shown


def _fallen_text(rule: dict | None) -> str:
    if rule is None:
        return "matches no network rule and leaves from the PoP it is connected to, behind its shared Cato address"
    what, _why = network_rules.route_text(rule["egress"])
    return f"falls to {network_rules.rule_label(rule)} ({what})"


def _message(target: dict, kind: str, sample: dict, sources: list[str]) -> str:
    where = (
        f"{target['resource_name']} ({target['public_ip']}) {target['traffic']}: {target['filter']}, "
        f"{target['rule']}, allows the Cato allocated IP{'s' if len(target['allowed']) > 1 else ''} "
        f"{', '.join(target['allowed'])}"
    )
    who = _listed(sources)
    if kind == HOSTNAME_ONLY:
        names = "; ".join(
            f"{network_rules.rule_label(c['rule'])} NATs to {', '.join(_nat_ips(c['rule']))} only when Cato identifies "
            f"the traffic by name ({', '.join(c['detail'])})"
            for c in sample["name_rules"]
        )
        return (
            f"Reachable only by hostname. {where}, but a connection to the bare IP from {who} "
            f"{_fallen_text(sample['rule'])}. {names}."
        )
    if kind == IP_MISMATCH:
        return (
            f"Allocated IP mismatch. {where}, but traffic from {who} matches {network_rules.rule_label(sample['rule'])}, "
            f"which NATs to {', '.join(sample['ips'])}; the cloud filters do not let "
            f"{', '.join(sample['refused'])} in."
        )
    if kind == NO_NAT_RULE:
        return f"No Cato rule egresses via the allowed IPs. {where}, but traffic from {who} {_fallen_text(sample['rule'])}."
    if sample["doubtful"]:
        maybe = "; ".join(
            f"{network_rules.rule_label(c['rule'])} ({', '.join(c['detail'])})" for c in sample["doubtful"]
        )
        return f"Undetermined. {where}; for traffic from {who} a rule that NATs to them may apply: {maybe}."
    return (
        f"Undetermined. {where}; traffic from {who} matches {network_rules.rule_label(sample['rule'])}, "
        "which NATs to an allocated IP whose address could not be read."
    )


# ── The check ───────────────────────────────────────────────────────────────


def _note(org_ref: int, org_name: str, kind: str, message: str) -> dict[str, Any]:
    return {
        "key": f"{org_ref}:account:{kind}",
        "cato_org_ref": org_ref,
        "cato_org_name": org_name,
        "provider": "",
        "resource_id": "",
        "resource_name": "",
        "public_ip": "",
        "private_ip": "",
        "protocol": "",
        "ports": "",
        "filter": "",
        "rule": "",
        "rule_id": "",
        "kind": kind,
        "severity": INFO,
        "message": message,
        "detail": {},
    }


def _check_account(org_ref: int, snapshot: dict, clouds: list[tuple[str, Any]]) -> list[dict[str, Any]]:
    org_name = str((snapshot.get("org") or {}).get("name") or f"Cato account {org_ref}")
    account = cato_account(snapshot)
    policy = account["policy"]
    if policy is None or not policy.get("collected"):
        return [
            _note(
                org_ref,
                org_name,
                RULES_NOT_COLLECTED,
                f"{org_name}: the network rules are not in the latest collection (collect the account again; they "
                "are read with the other policies), so which rule routes Cato traffic to the cloud allow-lists is "
                "not known.",
            )
        ]
    if policy.get("reduced") or policy.get("enabled", True) is False:
        why = (
            "were read with the reduced query, without the fields a rule matches on"
            if policy.get("reduced")
            else "are turned off, and how Cato then routes a flow is not reported"
        )
        return [_note(org_ref, org_name, RULES_UNAVAILABLE, f"{org_name}: the network rules {why}.")]
    notes: list[dict[str, Any]] = []
    ips = _account_ips(account)
    if account["allocated"] is None:
        notes.append(
            _note(
                org_ref,
                org_name,
                ALLOCATED_NOT_COLLECTED,
                f"{org_name}: the allocated IP list is not collected; the cloud rules are matched against the "
                f"addresses the NAT rules name ({', '.join(ips) or 'none'}).",
            )
        )
    if not ips:
        notes.append(
            _note(org_ref, org_name, NO_ALLOCATED_IPS, f"{org_name}: the account has no allocated IP to look for.")
        )
        return notes
    if not clouds:
        notes.append(
            _note(org_ref, org_name, NO_CLOUD, f"{org_name}: no AWS, Azure or GCP account is collected to check.")
        )
        return notes
    sources = account["sources"]
    if not sources:
        notes.append(
            _note(
                org_ref,
                org_name,
                NO_SOURCES,
                f"{org_name}: the Cato Cloud routes no site range or connected remote user to evaluate.",
            )
        )
        return notes

    findings = list(notes)
    for provider, engine in clouds:
        for target in cloud_targets(provider, engine, ips):
            cache: dict[str, str] = {}
            admits = _admits(target, cache)
            by_kind: dict[str, list[tuple[str, dict]]] = {}
            for label, src in sources:
                found = verdict(policy, src, target, admits, target["allowed"])
                by_kind.setdefault(found["kind"], []).append((label, found))
            kind = max(by_kind, key=lambda k: _RANK[k])
            if kind == FINE:
                continue
            labels = [label for label, _found in by_kind[kind]]
            sample = by_kind[kind][0][1]
            ports = "all" if target["ports"] is None else show_ports(target["ports"])
            findings.append(
                {
                    "key": ":".join(
                        str(p)
                        for p in (
                            org_ref,
                            provider,
                            target["resource_id"],
                            target["public_ip"],
                            target["protocol"] or "all",
                            ports,
                            target["rule_id"],
                        )
                    ),
                    "cato_org_ref": org_ref,
                    "cato_org_name": org_name,
                    "provider": provider,
                    "resource_id": target["resource_id"],
                    "resource_name": target["resource_name"],
                    "public_ip": target["public_ip"],
                    "private_ip": target["private_ip"],
                    "protocol": target["protocol"] or "all",
                    "ports": ports,
                    "filter": target["filter"],
                    "rule": target["rule"],
                    "rule_id": target["rule_id"],
                    "kind": kind,
                    "severity": severity_of(kind),
                    "message": _message(target, kind, sample, labels),
                    "detail": {
                        "allowed_ips": target["allowed"],
                        "sources": {k: [label for label, _f in v] for k, v in by_kind.items()},
                        "cato_rule": network_rules.rule_label(sample["rule"]) if sample["rule"] else "",
                        "name_rules": [network_rules.rule_label(c["rule"]) for c in sample["name_rules"]],
                        "nat_ips": sample["ips"],
                        "refused_ips": sample["refused"],
                    },
                }
            )
    return findings


def show_ports(ports: tuple[int, int]) -> str:
    low, high = ports
    return str(low) if low == high else f"{low}-{high}"


def check(cato: list[tuple[int, dict]], clouds: list[tuple[str, Any]]) -> list[dict[str, Any]]:
    """The findings of every Cato account snapshot (``(org_ref, snapshot)``)
    against every cloud reachability engine (``(provider, engine)``)."""
    findings: list[dict[str, Any]] = []
    for org_ref, snapshot in cato:
        findings.extend(_check_account(org_ref, snapshot, clouds))
    return findings


__all__ = [
    "KIND_LABELS",
    "cato_account",
    "check",
    "cloud_targets",
    "severity_of",
    "verdict",
]
