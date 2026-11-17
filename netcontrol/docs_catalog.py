"""The documentation catalog: which repository documents are user guides.

One list serves both places the guides are read: ``tools/build_wiki.py``
publishes them as the GitHub wiki, and ``netcontrol.routes.help_docs``
shows them inside Plexus under Help. Both rewrite the links between
documents with ``rewrite_links``; only the form of a page link differs.

Standard library only: the wiki job runs the tool without installing the
application's dependencies.
"""

from __future__ import annotations

import posixpath
import re
from collections.abc import Callable
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
REPO_URL = "https://github.com/RickeyNet/Plexus"
DEFAULT_BRANCH = "main"

# Hand-written pages (the wiki's Home and footer) live here.
WIKI_SOURCE_DIR = "wiki"

# (section, [(page name, source document), ...]) in display order. A page
# name is the wiki file name without ".md" and the in-app page address;
# both show the hyphens as spaces.
PAGES: list[tuple[str, list[tuple[str, str]]]] = [
    (
        "Install and operate",
        [
            ("Deployment-Guide", "deploy/DEPLOYMENT.md"),
            ("Firewall-Rules", "deploy/FIREWALL.md"),
            ("Air-Gapped-Deployment", "deploy/airgap/README.md"),
            ("Air-Gapped-VM-Setup", "deploy/airgap/VM_SETUP.md"),
            ("Database-Backends", "docs/database-backends.md"),
            ("Data-Retention", "DATA_RETENTION.md"),
            ("Administration", "docs/administration.md"),
            ("Federation", "docs/federation.md"),
        ],
    ),
    (
        "Sign-in and access",
        [
            ("Single-Sign-On-OIDC", "docs/sso-oidc.md"),
            ("RADIUS-Login", "RADIUS_CONFIGURATION_GUIDE.md"),
            ("TACACS-Login", "TACACS_CONFIGURATION_GUIDE.md"),
            ("Object-Permissions", "docs/object-permissions.md"),
            ("Secrets-Providers", "docs/secrets-providers.md"),
            ("Authorization-Matrix", "AUTHORIZATION_MATRIX.md"),
            ("Audit-Log", "docs/audit-log.md"),
            ("Change-Log", "docs/change-log.md"),
        ],
    ),
    (
        "Inventory and addressing",
        [
            ("Core-Concepts", "docs/core-concepts.md"),
            ("Discovery", "docs/discovery.md"),
            ("Device-Model", "docs/device-model.md"),
            ("Locations-and-Tenancy", "docs/locations-and-tenancy.md"),
            ("HPE-Aruba-and-HP-Switches", "docs/aruba-switches.md"),
            ("Netgear-Switches-and-Access-Points", "docs/netgear.md"),
            ("Custom-Fields-and-Tags", "docs/custom-fields-and-tags.md"),
            ("Dynamic-Groups", "docs/dynamic-groups.md"),
            ("Data-Validation-Rules", "docs/validation-rules.md"),
            ("VRFs-and-VLANs", "docs/vrfs-and-vlans.md"),
            ("Routing-and-BGP-Intent", "docs/routing.md"),
            ("Circuits", "docs/circuits.md"),
            ("DCIM-Racks-Cables-and-Power", "docs/dcim.md"),
            ("Sync-NetBox-Nautobot-ServiceNow", "docs/sync-framework.md"),
            ("Virtualization", "docs/virtualization.md"),
            ("Bulk-Import", "docs/bulk-import.md"),
            ("IPAM", "docs/ipam.md"),
            ("Floor-Plan", "docs/floor-plan.md"),
            ("Network-Tools", "docs/network-tools.md"),
        ],
    ),
    (
        "Configuration and change",
        [
            ("Running-Jobs", "docs/jobs.md"),
            ("Writing-Playbooks", "docs/writing-playbooks.md"),
            ("Config-Backups-and-Drift", "docs/config-backups-and-drift.md"),
            ("Intended-Configuration", "docs/intended-config.md"),
            ("Git-Data-Sources", "docs/git-data-sources.md"),
            ("Compliance", "docs/compliance.md"),
            ("Change-Management", "docs/change-management.md"),
            ("Risk-Analysis", "docs/risk-analysis.md"),
            ("Deployments", "docs/deployments.md"),
            ("Maintenance-Windows", "docs/maintenance-windows.md"),
            ("Lab-Mode", "docs/lab-mode.md"),
            ("IOS-XE-Upgrade-Tool", "docs/upgrade-tool-guide.md"),
        ],
    ),
    (
        "Topology",
        [
            ("Path-Trace", "docs/path-trace.md"),
            ("AWS-Topology", "docs/aws-topology.md"),
            ("Azure-Topology", "docs/azure-topology.md"),
            ("GCP-Topology", "docs/gcp-topology.md"),
            ("Meraki-Topology", "docs/meraki-topology.md"),
            ("Cato-Topology", "docs/cato-topology.md"),
            ("Cisco-FMC-Topology", "docs/fmc-topology.md"),
            ("Panorama-Topology", "docs/panorama-topology.md"),
            ("Appgate-SDP-Topology", "docs/appgate-topology.md"),
            ("OPNsense-Topology", "docs/opnsense-topology.md"),
            ("Cloud-Visibility", "docs/cloud-visibility.md"),
        ],
    ),
    (
        "Monitoring and reports",
        [
            ("Dashboard", "docs/dashboard.md"),
            ("Monitoring", "docs/monitoring.md"),
            ("Graph-Templates", "docs/graph-templates.md"),
            ("SLA-Monitoring", "docs/sla-monitoring.md"),
            ("Software-Versions-and-Vulnerabilities", "docs/software-versions.md"),
            ("Hardware-Lifecycle", "docs/hardware-lifecycle.md"),
            ("Alert-Notification-Channels", "docs/alert-notification-channels.md"),
            ("Meraki-Alerts", "docs/meraki-alerts.md"),
            ("Meraki-Compliance", "docs/meraki-compliance.md"),
            ("Flow-Collector", "docs/flow-collector.md"),
            ("Vendor-Monitoring-Coverage", "docs/vendor-monitoring-coverage.md"),
            ("Reports", "docs/reports.md"),
            ("Network-Documentation-Reports", "docs/network-documentation-usage.md"),
        ],
    ),
    (
        "API and AI access",
        [
            ("API-Reference", "docs/api-reference.md"),
            ("GraphQL-API", "docs/graphql-api.md"),
            ("WebSocket-Usage", "docs/websocket-usage.md"),
            ("Event-Webhooks", "docs/webhooks.md"),
            ("AI-Access-MCP", "docs/ai-access.md"),
            ("ChatOps", "docs/chatops.md"),
        ],
    ),
    (
        "Developers",
        [
            ("Developer-Setup", "DEVSETUP.md"),
            ("Architecture-and-Conventions", "AGENTS.md"),
            ("Frontend-Style-Guide", "FRONTEND_STYLE.md"),
            ("Plugin-Development", "docs/plugin-development.md"),
            ("Versioning-and-Release", "docs/versioning-and-release.md"),
            ("Changelog", "CHANGELOG.md"),
        ],
    ),
]

# Documents under docs/ that are deliberately not pages. Every other file in
# docs/ must be in PAGES, so a new document cannot be forgotten.
NOT_PUBLISHED = {
    "docs/FRONTEND_MIGRATION.md",  # archived migration plan
}

# Inline markdown link or image: "](target)" or "](target "title")".
LINK = re.compile(r"\]\(\s*<?([^)\s>]+)>?(\s+\"[^\"]*\")?\s*\)")
FENCE = re.compile(r"^\s*(```|~~~)")
EXTERNAL = re.compile(r"^(?:[a-zA-Z][a-zA-Z0-9+.-]*:|//)")


def page_index() -> dict[str, str]:
    """Map each source document to its page name."""
    return {source: name for _, pages in PAGES for name, source in pages}


def page_title(name: str) -> str:
    """A page name as it is shown: hyphens as spaces."""
    return name.replace("-", " ")


def _resolve(target: str, source: str) -> str:
    """Repo-relative path a link in ``source`` points at ("" if outside)."""
    if target.startswith("/"):
        path = posixpath.normpath(target.lstrip("/"))
    else:
        path = posixpath.normpath(posixpath.join(posixpath.dirname(source), target))
    return "" if path.startswith("..") else path


def map_links(text: str, swap: Callable[[re.Match[str]], str]) -> tuple[str, bool]:
    """Replace every inline link outside code fences with ``swap(match)``.

    Returns the new text and whether a code fence was left open.
    """
    out: list[str] = []
    in_fence = False
    for line in text.splitlines(keepends=True):
        if FENCE.match(line):
            in_fence = not in_fence
        out.append(line if in_fence else LINK.sub(swap, line))
    return "".join(out), in_fence


def rewrite_links(
    text: str,
    source: str,
    pages: dict[str, str],
    root: Path,
    errors: list[str],
    page_link: Callable[[str], str] = lambda name: name,
    strict: bool = True,
) -> str:
    """Rewrite the relative links of one repository document.

    Links to another published document become ``page_link(page name)``,
    links to any other repository file become GitHub links, and links that
    were already absolute or in-page are kept. Code fences are left alone.

    ``strict`` reports a link to a file missing under ``root``. Not strict
    (an installed copy, which ships the guides but not every file they
    link to), such a link goes to the file on GitHub, as a file.
    """

    def swap(match: re.Match[str]) -> str:
        target, title = match.group(1), match.group(2) or ""
        if EXTERNAL.match(target) or target.startswith("#"):
            return match.group(0)
        path_part, _, anchor = target.partition("#")
        path = _resolve(path_part, source)
        suffix = f"#{anchor}" if anchor else ""
        if path in pages:
            return f"]({page_link(pages[path])}{suffix}{title})"
        on_disk = root / path if path else None
        if on_disk is not None and not strict and not on_disk.exists():
            return f"]({REPO_URL}/blob/{DEFAULT_BRANCH}/{path}{suffix}{title})"
        if on_disk is None or not on_disk.exists():
            errors.append(f"{source}: link to missing file {target!r}")
            return match.group(0)
        kind = "tree" if on_disk.is_dir() else "blob"
        return f"]({REPO_URL}/{kind}/{DEFAULT_BRANCH}/{path}{suffix}{title})"

    out, fence_open = map_links(text, swap)
    if fence_open:
        errors.append(f"{source}: a code fence is opened and never closed")
    return out
