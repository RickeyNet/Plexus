"""
opnsense_backup.py -- An OPNsense firewall's config.xml as a configuration backup.

An OPNsense firewall has no SSH driver: its configuration is its
``config.xml``, downloaded over the API key of the OPNsense topology source
whose firewall it is (``collector.download_config``, privilege
``Diagnostics: Configuration History``). It is read on two occasions, and
both store it here:

  - the collection of its source, with the source's **Config backup**
    option on (``opnsense_collection.store_config_backup``, capture method
    ``opnsense-api``), so the rule views, drift, rule change alerts and the
    names in IPAM stay current between policy runs;
  - a run of the config backup policy of the host's inventory group
    (``config_backups.backup_host``: scheduled, Run Now, a configuration
    change message), whatever the source's **Config backup** option says,
    with the run's capture method and policy. A policy needs no credential
    for it.

``store_firewall_backup`` stores the text through the store path every
capture uses (``device_config.store_device_config``: an unchanged
configuration writes no new row, it re-checks the newest one), holding the
host's capture lock so a collection and a policy run never race; a new
backup is compared with the one before it for rules that became any-to-any
or shadowed (``opnsense_rule_alerts``).

``backup_firewall`` is the policy's way: the host's source
(``opnsense_health.source_of_host``), its key, the download, the store. A
failure raises ``FirewallBackupError`` with a message fit for the backup's
error row: no API key or secret in it.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import routes.database as db

from netcontrol.integrations.opnsense.client import OpnsenseApiError
from netcontrol.integrations.opnsense.collector import (
    CONFIG_PRIVILEGE,
    NOT_CONFIG_XML_MESSAGE,
    download_config,
    sanitize_options,
)
from netcontrol.routes.device_config import DeviceConfig, host_lock, store_device_config
from netcontrol.telemetry import configure_logging, redact_value

LOGGER = configure_logging("plexus.opnsense")

NO_SOURCE_MESSAGE = (
    "This host is not the firewall of any OPNsense source: collect its OPNsense source "
    "(Map sources) and import the firewall into the inventory first, then run the policy again"
)


class FirewallBackupError(RuntimeError):
    """A policy backup of an OPNsense firewall failed; the message says why
    and holds no secret."""


@dataclass(frozen=True)
class FirewallBackup:
    """What storing a firewall's config.xml did."""

    stored: DeviceConfig
    # The rule change check of a new backup (``opnsense_rule_alerts``);
    # ``None`` when nothing was compared.
    rule_changes: dict[str, Any] | None
    # False when the check failed (logged).
    rules_checked: bool


async def store_firewall_backup(
    host: dict,
    config_xml: str,
    *,
    capture_method: str,
    policy_id: int | None = None,
    org_ref: int | None = None,
) -> FirewallBackup:
    """Store ``config_xml`` as a config backup of inventory host ``host``
    and check a new backup for rule changes to alert on (``org_ref``: the
    OPNsense source, whose firewall mute covers them). Raises what the
    store raises; a failed rule check is logged only."""
    async with host_lock(int(host["id"])):
        stored = await store_device_config(
            int(host["id"]),
            config_xml,
            "",
            capture_method=capture_method,
            policy_id=policy_id,
            device_type=str(host.get("device_type") or ""),
        )
    rule_changes = None
    rules_checked = True
    if stored.created:
        try:
            # Imported here: the alert module imports the monitoring routes.
            from netcontrol.routes.opnsense_rule_alerts import alert_rule_changes

            rule_changes = await alert_rule_changes(host, stored.backup_id, config_xml, org_ref=org_ref)
        except Exception as exc:  # noqa: BLE001 - the backup is stored anyway
            LOGGER.warning("opnsense: rule changes of host %s not checked: %s", host.get("id"), type(exc).__name__)
            rules_checked = False
    return FirewallBackup(stored=stored, rule_changes=rule_changes, rules_checked=rules_checked)


def _api_error_message(exc: OpnsenseApiError, source: str) -> str:
    # Imported here: meraki_topology imports the routes of every source.
    from netcontrol.routes.meraki_topology import _opnsense_error_message

    message = _opnsense_error_message(exc)
    if exc.status_code == 403:
        message += f"; the API user of OPNsense source '{source}' needs the privilege {CONFIG_PRIVILEGE}"
    return f"config.xml download failed: {message}"


async def backup_firewall(host: dict, *, policy_id: int | None, capture_method: str) -> DeviceConfig:
    """Back up OPNsense firewall ``host`` for a backup policy: download its
    config.xml over the API key of its OPNsense source and store it
    (``store_firewall_backup``) with ``policy_id`` and ``capture_method``.
    Raises ``FirewallBackupError`` when it cannot."""
    # Imported here: opnsense_health imports the collection helpers, which import this module.
    from netcontrol.routes.meraki_topology import _opnsense_client
    from netcontrol.routes.opnsense_health import source_of_host

    org = await source_of_host(int(host["id"]))
    if org is None:
        raise FirewallBackupError(NO_SOURCE_MESSAGE)
    name = str(org.get("name") or org.get("id"))
    secret = await db.get_meraki_org_api_key(int(org["id"]))
    if not secret:
        raise FirewallBackupError(
            f"OPNsense source '{name}' has no API key: enter its key:secret under Map sources and run the policy again"
        )
    try:
        async with _opnsense_client(org, secret, sanitize_options(org.get("options")), max_retries=1) as client:
            config_xml = await download_config(client)
    except OpnsenseApiError as exc:
        raise FirewallBackupError(redact_value(_api_error_message(exc, name))) from None
    except ValueError as exc:  # the stored address or key:secret is not valid
        raise FirewallBackupError(redact_value(f"OPNsense source '{name}': {exc}")) from None
    if config_xml is None:
        raise FirewallBackupError(f"{NOT_CONFIG_XML_MESSAGE} (OPNsense source '{name}')")
    backup = await store_firewall_backup(
        host, config_xml, capture_method=capture_method, policy_id=policy_id, org_ref=int(org["id"])
    )
    return backup.stored
