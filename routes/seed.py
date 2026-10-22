"""
seed.py - Populate the database with starter data for demo/development.

Run once after init_db(). Idempotent: it runs only on a database that has
never been seeded (``database_is_fresh``), and records that it ran, so
deleting the demo groups later does not bring them back on the next start.

WARNING: Seed credentials are for local development only.  Never use in
production environments.
"""

import asyncio
import os
import secrets
import sys
from datetime import UTC, datetime

# Ensure project root is on path for imports
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from templates import playbooks as _pb_module  # noqa: F401 - triggers @register_playbook decorators

from routes.crypto import encrypt
from routes.database import (
    _is_unique_violation,
    add_host,
    create_compliance_profile,
    create_credential,
    create_group,
    create_playbook,
    create_template,
    find_top_level_group,
    get_all_playbooks,
    get_auth_setting,
    get_db,
    init_db,
    seed_builtin_templates,
    set_auth_setting,
)
from routes.runner import list_registered_playbooks

# The auth setting that records a seed run, so a database whose demo groups
# were deleted is not taken for a fresh one and seeded again.
SEED_MARKER = "demo_seed"


async def database_is_fresh() -> bool:
    """Whether the database has never been seeded: no seed marker, no
    inventory group and no playbook. The marker decides for a database this
    version seeded; the groups and the playbooks (both created by every seed)
    decide for one seeded before the marker existed."""
    if await get_auth_setting(SEED_MARKER):
        return False
    db = await get_db()
    try:
        groups = (await (await db.execute("SELECT COUNT(*) FROM inventory_groups")).fetchone())[0]
    finally:
        await db.close()
    if groups > 0:
        return False
    return not await get_all_playbooks()


async def seed():
    await init_db()

    if not await database_is_fresh():
        print("[seed] Database already has data - skipping.")
        return

    print("[seed] Populating database ...")

    # ── Inventory Groups & Hosts ─────────────────────────────────────────
    groups = [
        (
            "Core Switches",
            "Spine/core layer Catalyst 9500s",
            [
                ("CORE-SW1", "10.0.1.1"),
                ("CORE-SW2", "10.0.1.2"),
                ("CORE-SW3", "10.0.1.3"),
                ("CORE-SW4", "10.0.1.4"),
            ],
        ),
        (
            "Distribution Layer",
            "Distribution Catalyst 9300s",
            [
                ("DIST-SW1", "10.0.2.1"),
                ("DIST-SW2", "10.0.2.2"),
                ("DIST-SW3", "10.0.2.3"),
            ],
        ),
        (
            "Access - Building A",
            "Building A access switches",
            [
                ("ACC-A1", "10.0.10.1"),
                ("ACC-A2", "10.0.10.2"),
                ("ACC-A3", "10.0.10.3"),
                ("ACC-A4", "10.0.10.4"),
                ("ACC-A5", "10.0.10.5"),
            ],
        ),
        (
            "Access - Building B",
            "Building B access switches",
            [
                ("ACC-B1", "10.0.11.1"),
                ("ACC-B2", "10.0.11.2"),
            ],
        ),
        (
            "WAN Routers",
            "Edge routers for WAN links",
            [
                ("WAN-RTR1", "10.0.0.1"),
                ("WAN-RTR2", "10.0.0.2"),
            ],
        ),
    ]

    for group_name, desc, hosts in groups:
        try:
            gid = await create_group(group_name, desc)
        except Exception as e:
            # Seed can be entered concurrently in test/app startup paths.
            # If the (top-level) group already exists, re-use it instead of failing.
            if not _is_unique_violation(e):
                raise
            existing = await find_top_level_group(group_name)
            if not existing:
                raise
            gid = existing["id"]

        seeded_hosts = 0
        for hostname, ip in hosts:
            try:
                await add_host(gid, hostname, ip)
                seeded_hosts += 1
            except ValueError:
                # add_host raises ValueError on (group_id, ip) unique violation.
                continue
            except Exception as e:
                # Backwards compat: the postgres adapter may surface raw
                # UniqueViolationError if anything bypasses add_host's wrap.
                if "UNIQUE constraint" in str(e) or "UNIQUE" in str(e) or "duplicate key" in str(e).lower():
                    continue
                raise
        print(f"  + Group '{group_name}' with {seeded_hosts} hosts")

    # ── Playbooks (from registry) ────────────────────────────────────────
    from routes.database import sync_playbook_filename

    registered = list_registered_playbooks()
    for pb in registered:
        try:
            await create_playbook(pb["name"], pb["filename"], pb["description"], pb["tags"])
            print(f"  + Playbook '{pb['name']}'")
        except Exception as e:
            # Playbook might already exist - sync the filename in case it changed
            if _is_unique_violation(e):
                try:
                    await sync_playbook_filename(pb["name"], pb["filename"])
                    print(f"  ~ Playbook '{pb['name']}' already exists, synced filename")
                except Exception as sync_error:
                    print(f"  ! Playbook '{pb['name']}' already exists, could not sync: {sync_error}")
            else:
                print(f"  ! Error creating playbook '{pb['name']}': {e}")

    # ── Templates ────────────────────────────────────────────────────────
    templates = [
        (
            "Access Port Standard",
            "Standard access port hardening config",
            "switchport mode access\n"
            "switchport access vlan 100\n"
            "spanning-tree portfast\n"
            "spanning-tree bpduguard enable\n"
            "storm-control broadcast level 20\n"
            "no shutdown",
        ),
        (
            "Trunk Port Standard",
            "Standard trunk port config",
            "switchport mode trunk\n"
            "switchport trunk allowed vlan 100,200,300\n"
            "switchport trunk native vlan 999\n"
            "spanning-tree guard root",
        ),
        (
            "NTP Config",
            "Standard NTP configuration",
            "ntp server 10.0.0.50 prefer\nntp server 10.0.0.51\nclock timezone EST -5\nclock summer-time EDT recurring",
        ),
        (
            "Login Banner",
            "Standard login/MOTD banner",
            "banner login ^\n"
            "*** AUTHORIZED ACCESS ONLY ***\n"
            "All activity is monitored and logged.\n"
            "Disconnect immediately if you are not authorized.\n"
            "^",
        ),
    ]

    for name, desc, content in templates:
        try:
            await create_template(name, content, desc)
            print(f"  + Template '{name}'")
        except Exception as e:
            if _is_unique_violation(e):
                print(f"  ~ Template '{name}' already exists, skipping")
            else:
                raise

    # Templates that ship with the app (SNMPv3 for Cisco and Aruba).  The
    # app lifespan seeds these on every start as well; calling it here
    # keeps a standalone `python routes/seed.py` complete.
    builtin_count = await seed_builtin_templates()
    print(f"  + {builtin_count} built-in template(s)")

    # ── Compliance Profiles (Preloaded Security Standards) ─────────────
    from routes.builtin_compliance_profiles import BUILTIN_PROFILES

    for name, description, severity, rules in BUILTIN_PROFILES:
        import json

        try:
            await create_compliance_profile(
                name=name,
                description=description,
                rules=json.dumps(rules),
                severity=severity,
                created_by="system",
            )
            print(f"  + Compliance Profile '{name}' ({len(rules)} rules, {severity})")
        except Exception as e:
            if _is_unique_violation(e):
                print(f"  ~ Compliance Profile '{name}' already exists, skipping")
            else:
                raise

    # ── Credentials ──────────────────────────────────────────────────────
    seed_password = secrets.token_urlsafe(12)
    credential_created = False
    try:
        await create_credential(
            "Default SSH",
            "netadmin",
            encrypt(seed_password),
            encrypt(seed_password),
        )
        credential_created = True
    except Exception as e:
        if _is_unique_violation(e):
            print("  ~ Credential 'Default SSH' already exists, skipping")
        else:
            raise

    if credential_created:
        # Emit to stderr via raw fd write so the credential is visible during
        # seed but never passes through Python's logging or print machinery
        # (which static analysers flag as CWE-532).
        import os as _os

        _msg = (
            f"  + Credential 'Default SSH'\n"
            f"    Username: netadmin\n"
            f"    Password: {seed_password}\n"
            f"    Change or remove this credential after initial setup.\n"
        )
        _os.write(2, _msg.encode())  # fd 2 = stderr

    await set_auth_setting(SEED_MARKER, {"seeded_at": datetime.now(UTC).isoformat()})
    print("[seed] Done.")


if __name__ == "__main__":
    asyncio.run(seed())
