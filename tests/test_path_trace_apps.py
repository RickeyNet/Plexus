"""Applications, categories and domains as a path trace destination
(``netcontrol.integrations.pathtrace.apps``), and how the rules of each
vendor carry them: Cato's firewalls and network rules, FMC, Panorama, Junos
and Meraki."""

from __future__ import annotations

from netcontrol.integrations.cato import network_rules
from netcontrol.integrations.cato.normalize import build_snapshot, network_rule_policy
from netcontrol.integrations.cato.sample import _endpoint, _fw_rule, _ref, build_sample_raw, network_rule
from netcontrol.integrations.meraki.forwarding import meraki_rules
from netcontrol.integrations.pathtrace import apps
from netcontrol.integrations.pathtrace.model import FULL, NONE, PART, dst_cover, net

_CATALOG = [
    apps.catalog_entry(
        "Payroll portal", categories=["Business"], fqdns=["payroll.example.com"], source="custom", scheme="Cato"
    ),
    apps.catalog_entry("Docs suite", categories=["Productivity"], domains=["docs.example.com"], scheme="Cato"),
    apps.catalog_entry("YouTube", categories=["Video Streaming"], website="https://video.example.com", scheme="Cato"),
    apps.catalog_entry("Zoom", categories=["Video Conferencing"], scheme="Cato"),
]


def _match(kind: str, value: str, target: apps.Target, **fields) -> tuple[int, str]:
    return apps.match(apps.criterion(kind, value, f"{kind} {value}", **fields), target)


# ── apps ────────────────────────────────────────────────────────────────────


def test_cover_values_are_the_models():
    assert (apps._FULL, apps._PART, apps._NONE) == (FULL, PART, NONE)


def test_host_reads_a_domain_or_a_url_and_nothing_else():
    assert apps.host("Video.Example.com.") == "video.example.com"
    assert apps.host("https://user@docs.example.com:8443/path?q=1") == "docs.example.com"
    assert apps.host("YouTube") == apps.host("192.0.2.1") == apps.host("bad_name.example.com") == ""


def test_application_names_ignore_case_and_punctuation_and_a_near_name_may_match():
    target = apps.target("you tube", _CATALOG)
    assert target.applications == ("YouTube",)
    assert _match(apps.APPLICATION, "YOUTUBE", target) == (FULL, "")
    assert _match(apps.APPLICATION, "Netflix", target) == (NONE, "")
    # A vendor's part of the application (PAN-OS youtube-base): never a guess either way.
    found, why = _match(apps.APPLICATION, "youtube-base", target)
    assert found == FULL and "may be part of YouTube" in why


def test_a_typed_domain_is_an_application_only_when_a_definition_links_them():
    linked = apps.target("payroll.example.com", _CATALOG)
    assert (linked.applications, linked.categories, linked.domain) == (
        ("Payroll portal",),
        ("Business",),
        "payroll.example.com",
    )
    # Under a custom application's domain: that application.
    assert apps.target("eu.docs.example.com", _CATALOG).applications == ("Docs suite",)
    alone = apps.target("shop.example.com", _CATALOG)
    assert alone.applications is None and alone.categories is None and alone.hosts == ("shop.example.com",)
    found, why = _match(apps.APPLICATION, "YouTube", alone)
    assert (
        found == FULL and why == "it names application YouTube, and which application shop.example.com is is not known"
    )


def test_categories_are_decided_only_in_the_taxonomy_they_were_collected_in():
    target = apps.target("YouTube", _CATALOG)
    assert _match(apps.CATEGORY, "video streaming", target, scheme="Cato") == (FULL, "")
    assert _match(apps.CATEGORY, "Malware", target, scheme="Cato") == (NONE, "")
    found, why = _match(apps.CATEGORY, "Streaming Media", target, scheme="FMC")
    assert found == FULL and why.endswith("the FMC categories of YouTube are not collected")
    unknown = apps.target("Unlisted app", _CATALOG)
    assert _match(apps.CATEGORY, "Malware", unknown, scheme="Cato")[1].endswith(
        "the categories of Unlisted app are not collected"
    )


def test_domains_match_on_a_label_boundary_fqdns_exactly_and_wildcards_as_patterns():
    target = apps.target("www.shop.example.com")
    assert _match(apps.DOMAIN, "example.com", target) == (FULL, "")
    assert _match(apps.DOMAIN, "op.example.com", target) == (NONE, "")
    assert _match(apps.FQDN, "shop.example.com", target) == (NONE, "")
    assert _match(apps.FQDN, "www.shop.example.com", target) == (FULL, "")
    assert _match(apps.WILDCARD, "*.shop.example.com", target) == (FULL, "")
    assert _match(apps.WILDCARD, "*.example.org", target) == (NONE, "")
    # An application known by a domain and every name under it: an FQDN under it is part of it.
    docs = apps.target("Docs suite", _CATALOG)
    assert _match(apps.DOMAIN, "example.com", docs) == (FULL, "")
    assert _match(apps.FQDN, "eu.docs.example.com", docs) == (PART, "")
    # An application whose domains are not known.
    found, why = _match(apps.DOMAIN, "example.com", apps.target("Zoom", _CATALOG))
    assert found == FULL and why.endswith("the domains Zoom uses are not known")


def test_custom_applications_match_by_name_or_by_the_domains_they_are_defined_by():
    target = apps.target("payroll.example.com", _CATALOG)
    assert _match(apps.CUSTOM_APPLICATION, "Payroll Portal", target, domains=[], fqdns=["x.example.org"]) == (FULL, "")
    other = apps.target("shop.example.com")
    assert _match(apps.CUSTOM_APPLICATION, "Shop", other, domains=["example.com"], fqdns=[]) == (FULL, "")
    assert _match(apps.CUSTOM_APPLICATION, "Shop", other, domains=[], fqdns=["a.example.com"]) == (NONE, "")
    found, why = _match(apps.CUSTOM_APPLICATION, "Shop", other)
    assert found == FULL and "whose definition is not collected" in why


def test_any_of_and_all_groups_combine_criteria():
    assert apps.any_of([(NONE, "", "a"), (FULL, "", "b")]) == (FULL, [], ["b"])
    assert apps.any_of([(PART, "", "a"), (FULL, "why", "b")]) == (FULL, ["why"], [])
    assert apps.any_of([(NONE, "", "a"), (PART, "", "b")]) == (PART, [], [])
    # Each group must match: one that does not decides.
    assert apps.all_groups([("app", FULL, "", "a"), ("url", NONE, "", "b")]) == (NONE, [], [])
    assert apps.all_groups([("app", FULL, "", "a"), ("url", FULL, "why", "b")]) == (FULL, ["why"], ["a"])


def test_target_refuses_an_empty_or_too_long_text():
    for bad in ("", "  ", "x" * 129):
        try:
            apps.target(bad)
        except ValueError as exc:
            assert "1 to 128" in str(exc)
        else:
            raise AssertionError(bad)


def test_suggestions_come_from_catalogs_and_rules_prefix_first():
    snapshot = build_snapshot(_raw_with_rules())
    names = apps.names([snapshot])
    found = apps.suggest(names, "vid")
    assert [(e["name"], e["kind"]) for e in found] == [
        ("Video Conferencing", "category"),
        ("Video Streaming", "category"),
        ("video.example.com", "domain"),
    ]
    by_name = {e["name"]: e for e in names}
    assert by_name["YouTube"]["source"] == "Cato application catalog"
    assert by_name["Payroll portal"]["source"] == "Cato custom application"
    assert by_name["Social"]["source"] == "Named by Internet firewall rules"
    assert by_name["sql.example.com"] == {
        "name": "sql.example.com",
        "kind": "domain",
        "source": "Named by Network rules",
    }
    assert len(apps.suggest(names, "", limit=2)) == 2
    assert [e["name"] for e in apps.suggest(names, "tube")] == ["YouTube"]


def test_an_unknown_destination_is_covered_in_part_by_internet_addresses_only():
    anywhere = net("0.0.0.0/0")
    assert anywhere is not None
    assert dst_cover(["any"], anywhere, True) == FULL
    assert dst_cover(["203.0.113.0/24"], anywhere, True) == PART
    assert dst_cover(["10.0.0.0/8", "192.168.1.0/24"], anywhere, True) == NONE
    assert dst_cover(["2001:db8::/32"], anywhere, True) == NONE


# ── Cato firewall rules ─────────────────────────────────────────────────────


def _raw_with_rules() -> dict:
    """The sample account with Internet firewall rules on a category, an
    application, a domain and a category beside addresses, and a WAN
    firewall rule narrowed by application."""
    raw = build_sample_raw()
    raw["internet_firewall"]["rules"] = [
        _fw_rule(1, "Block social", "BLOCK", destination=_endpoint(appCategory=[_ref("social", "Social")])),
        _fw_rule(
            2,
            "Block streaming or the bad range",
            "BLOCK",
            destination=_endpoint(appCategory=[_ref("video_streaming", "Video Streaming")], ip=["203.0.113.50"]),
        ),
        _fw_rule(3, "Allow the video domain", "ALLOW", destination={**_endpoint(), "domain": ["video.example.com"]}),
        _fw_rule(4, "Allow all", "ALLOW"),
    ]
    raw["wan_firewall"]["rules"].insert(
        0,
        _fw_rule(
            1,
            "Payroll only to HQ",
            "ALLOW",
            direction="TO",
            destination=_endpoint(site=[_ref("1001", "HQ-DataCenter")]),
            application={"customApp": [_ref("ca-1", "Payroll portal")], "appCategory": [], "application": []},
        ),
    )
    return raw


def _internet_rules(snapshot: dict) -> list[dict]:
    pop = next(n for n in snapshot["nodes"] if n["id"].startswith("pop:"))
    return next(p for p in pop["forwarding"]["policies"] if p["name"] == "Internet firewall rules")["rules"]


def test_cato_internet_firewall_destinations_keep_their_names_and_the_addresses_beside_them():
    rules = {r["index"]: r for r in _internet_rules(build_snapshot(_raw_with_rules()))}
    # As for a trace asked about no application: any address, the names unresolved.
    assert rules[2]["dst"] == ["any"]
    assert rules[2]["unresolved"] == ["app category Video Streaming"]
    assert rules[2]["dst_cidrs"] == ["203.0.113.50/32"]
    assert [(c["kind"], c["value"], c["text"], c.get("scheme")) for c in rules[2]["dst_names"]] == [
        ("category", "Video Streaming", "app category Video Streaming", "Cato")
    ]
    assert [(c["kind"], c["value"]) for c in rules[3]["dst_names"]] == [("domain", "video.example.com")]
    # A rule that names no application carries no criteria at all.
    assert "dst_names" not in rules[4] and "app_names" not in rules[4]


def test_cato_wan_firewall_application_field_narrows_the_rule():
    snapshot = build_snapshot(_raw_with_rules())
    pop = next(n for n in snapshot["nodes"] if n["id"].startswith("pop:"))
    wan = next(p for p in pop["forwarding"]["policies"] if p["name"] == "WAN firewall rules")["rules"]
    [narrowed] = [r for r in wan if r["name"] == "Payroll only to HQ"]
    assert narrowed["unresolved"] == ["custom application Payroll portal"]
    [criterion] = narrowed["app_names"]
    assert (criterion["kind"], criterion["value"], criterion["fqdns"]) == (
        "custom_application",
        "Payroll portal",
        ["payroll.example.com"],
    )


def test_the_snapshot_lists_the_custom_applications_and_the_catalog():
    found = build_snapshot(build_sample_raw())["applications"]
    assert found[0] == {
        "name": "Payroll portal",
        "categories": ["Business"],
        "fqdns": ["payroll.example.com"],
        "source": "Cato custom application",
        "scheme": "Cato",
    }
    assert {"name": "YouTube", "categories": ["Video Streaming"], "website": "video.example.com"}.items() <= found[
        1
    ].items()
    raw = build_sample_raw()
    raw["app_catalog"] = None
    assert [a["name"] for a in build_snapshot(raw)["applications"]] == ["Payroll portal"]


# ── Cato network rules ──────────────────────────────────────────────────────


def _egress(raw: dict, app: str | None, dst: str = "0.0.0.0/0", unknown: bool = True) -> dict:
    target = apps.target(app, build_snapshot(raw)["applications"]) if app else None
    return network_rules.evaluate(
        network_rule_policy(raw),
        net("10.88.0.11"),  # type: ignore[arg-type]
        net(dst),  # type: ignore[arg-type]
        "tcp",
        (443, 443),
        app=target,
        dst_unknown=unknown,
    )


def test_network_rules_decide_name_criteria_against_the_application():
    raw = build_sample_raw()
    # Rule 2 names the custom application by its FQDN: a flow to it is NATed.
    payroll = _egress(raw, "payroll.example.com")
    assert payroll["state"] == "matched" and payroll["rule"]["index"] == 2 and payroll["candidates"] == []
    # A domain rule 2 names.
    assert _egress(raw, "sql.example.com")["rule"]["index"] == 2
    # Rule 2's custom category cannot be decided for any other application.
    other = _egress(raw, "YouTube")
    assert other["rule"]["index"] == 4
    [candidate] = other["candidates"]
    assert candidate["why"] == "unknown"
    assert candidate["detail"] == ["it names custom category Geoblocked Apps, whose contents are not collected"]


def test_network_rules_without_a_custom_category_route_an_application_that_matches_no_name_by_default():
    raw = build_sample_raw()
    raw["wan_network"]["rules"][1] = network_rule(
        2, "Streaming egress", "NAT", application=[_ref("youtube", "YouTube")], appCategory=[]
    )
    assert _egress(raw, "YouTube")["rule"]["index"] == 2
    zoom = _egress(raw, "Zoom")
    assert zoom["rule"]["index"] == 4 and zoom["candidates"] == []
    # An address rule ahead names an internet address: an unknown address may be in it.
    raw["wan_network"]["rules"].insert(
        1, network_rule(1, "To the partner", "NAT", destination=_endpoint(ip=["203.0.113.70"]))
    )
    partly = _egress(raw, "Zoom")
    assert [(c["rule"]["index"], c["why"]) for c in partly["candidates"]] == [(1, "part")]


def test_network_rules_trace_items_word_the_application_reasons():
    found = network_rules.trace_egress(
        network_rule_policy(build_sample_raw()),
        net("10.88.0.11"),  # type: ignore[arg-type]
        net("0.0.0.0/0"),  # type: ignore[arg-type]
        "tcp",
        (443, 443),
        app=apps.target("YouTube", build_snapshot(build_sample_raw())["applications"]),
        dst_unknown=True,
    )
    texts = [text for _stage, _status, _where, text, _index in found["items"]]
    assert texts[0].startswith(
        "Rule 2 Geoblocked apps egress may apply: it names custom category Geoblocked Apps, whose contents are "
        "not collected. Its route would be: NAT"
    )


# ── Other vendors ───────────────────────────────────────────────────────────


def test_meraki_fqdn_destinations_are_alternatives_to_the_addresses_beside_them():
    [found] = meraki_rules(
        [{"policy": "deny", "protocol": "tcp", "srcCidr": "Any", "destCidr": "*.example.com,192.0.2.0/24"}], {}
    )
    assert found["dst"] == ["any"] and found["unresolved"] == ["*.example.com"]
    assert found["dst_cidrs"] == ["192.0.2.0/24"]
    assert [(c["kind"], c["value"]) for c in found["dst_names"]] == [("wildcard", "*.example.com")]
    [plain] = meraki_rules([{"policy": "deny", "protocol": "any", "srcCidr": "Any", "destCidr": "192.0.2.0/24"}], {})
    assert "dst_names" not in plain


def test_fmc_application_and_url_conditions_are_groups_that_must_each_match():
    from netcontrol.integrations.fmc.forwarding import _app_names, _extras

    item = {
        "applications": {"applications": [{"name": "YouTube"}], "applicationFilters": [{"name": "High risk"}]},
        "urls": {"urlCategoriesWithReputation": [{"category": {"name": "Streaming Media"}}]},
    }
    found = _app_names(item)
    assert [(c["kind"], c["value"], c["group"], c.get("scheme")) for c in found] == [
        ("application", "YouTube", "application", None),
        ("other", "High risk", "application", None),
        ("category", "Streaming Media", "url", "FMC"),
    ]
    # Worded as they always were for a trace asked about no application.
    assert _extras(item) == ["application YouTube", "application High risk", "URL category Streaming Media"]
    target = apps.target("YouTube", _CATALOG)
    results = [(c["group"], *apps.match(c, target), c["text"]) for c in found]
    cover, reasons, _matched = apps.all_groups(results)
    # The application matches; the FMC category of YouTube is not collected.
    assert cover == FULL and reasons == [
        "it names URL category Streaming Media, and the FMC categories of YouTube are not collected"
    ]
    # Another application may be in the application filter.
    other = apps.target("Zoom", _CATALOG)
    cover, reasons, _matched = apps.all_groups([(c["group"], *apps.match(c, other), c["text"]) for c in found])
    assert (
        cover == FULL
        and reasons[0] == "it names application High risk, an application filter, whose members are not collected"
    )
    # Without the filter, the application condition does not match, so the rule does not.
    named = [c for c in found if c["kind"] != "other"]
    assert apps.all_groups([(c["group"], *apps.match(c, other), c["text"]) for c in named])[0] == NONE


def test_panorama_applications_url_categories_and_fqdn_objects_are_name_criteria():
    from netcontrol.integrations.panorama.forwarding import _FirewallForwarding

    item = {"application": {"member": ["youtube-base", "any"]}, "category": {"member": ["streaming-media"]}}
    found = _FirewallForwarding._app_names(item)
    assert [(c["kind"], c["value"], c["group"]) for c in found] == [
        ("application", "youtube-base", "application"),
        ("category", "streaming-media", "url"),
    ]


def test_panorama_fqdn_address_objects_become_fqdn_criteria():
    from netcontrol.integrations.panorama.normalize import Objects

    objects = Objects({}, {})
    entries = {
        ("address", "shop"): {"fqdn": "shop.example.com"},
        ("address", "partner"): {"ip-netmask": "203.0.113.0/24"},
        ("address-group", "mixed"): {"static": {"member": ["shop", "partner", "nowhere"]}},
    }
    objects.find = lambda kind, name, _group: (entries.get((kind, name)), "")  # type: ignore[method-assign]
    criteria: list[dict] = []
    cidrs, unresolved = objects.addresses("mixed", "dg", criteria=criteria)
    assert cidrs == ["203.0.113.0/24"]
    assert unresolved == ["FQDN shop (shop.example.com)", "nowhere"]
    assert [(c["kind"], c["value"], c["text"]) for c in criteria] == [
        ("fqdn", "shop.example.com", "FQDN shop (shop.example.com)"),
        ("other", "nowhere", "nowhere"),
    ]


def test_junos_dynamic_applications_and_url_categories_are_name_criteria():
    from netcontrol.integrations.pathtrace.junos_config import parse_config

    config = parse_config(
        "\n".join(
            [
                "set security zones security-zone trust interfaces ge-0/0/1.0",
                "set security zones security-zone untrust interfaces ge-0/0/0.0",
                "set security policies from-zone trust to-zone untrust policy video match source-address any",
                "set security policies from-zone trust to-zone untrust policy video match destination-address any",
                "set security policies from-zone trust to-zone untrust policy video match application any",
                "set security policies from-zone trust to-zone untrust policy video match dynamic-application "
                "[ junos:YOUTUBE junos:NETFLIX ]",
                "set security policies from-zone trust to-zone untrust policy video match url-category "
                "Enhanced_Streaming_Media",
                "set security policies from-zone trust to-zone untrust policy video then deny",
            ]
        )
    )
    [entry] = config.policies[0].entries
    assert entry.unresolved == [
        "dynamic-application junos:YOUTUBE junos:NETFLIX",
        "url-category Enhanced_Streaming_Media",
    ]
    assert [(c["kind"], c["value"], c["group"], c["text"]) for c in entry.app_names] == [
        ("application", "YOUTUBE", "dynamic-application", "dynamic-application junos:YOUTUBE junos:NETFLIX"),
        ("application", "NETFLIX", "dynamic-application", "dynamic-application junos:YOUTUBE junos:NETFLIX"),
        ("category", "Enhanced_Streaming_Media", "url-category", "url-category Enhanced_Streaming_Media"),
    ]
