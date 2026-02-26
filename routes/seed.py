"""
seed.py — Populate the database with starter data for demo/development.

Run once after init_db(). Idempotent — skips if data already exists.
"""

import asyncio
import sys
import os

# Ensure project root is on path for imports
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from routes.database import (
    get_db, init_db,
    create_group, add_host,
    create_playbook, create_template, create_credential,
)
from routes.crypto import encrypt
from templates import playbooks as _pb_module  # noqa: F401 — triggers @register_playbook decorators
from routes.runner import list_registered_playbooks


async def seed():
    await init_db()

    db = await get_db()
    try:
        count = (await (await db.execute("SELECT COUNT(*) FROM inventory_groups")).fetchone())[0]
        if count > 0:
            print("[seed] Database already has data — skipping.")
            return
    finally:
        await db.close()

    print("[seed] Populating database ...")

    # ── Inventory Groups & Hosts ─────────────────────────────────────────
    groups = [
        ("Core Switches", "Spine/core layer Catalyst 9500s", [
            ("CORE-SW1", "10.0.1.1"), ("CORE-SW2", "10.0.1.2"),
            ("CORE-SW3", "10.0.1.3"), ("CORE-SW4", "10.0.1.4"),
        ]),
        ("Distribution Layer", "Distribution Catalyst 9300s", [
            ("DIST-SW1", "10.0.2.1"), ("DIST-SW2", "10.0.2.2"),
            ("DIST-SW3", "10.0.2.3"),
        ]),
        ("Access - Building A", "Building A access switches", [
            ("ACC-A1", "10.0.10.1"), ("ACC-A2", "10.0.10.2"),
            ("ACC-A3", "10.0.10.3"), ("ACC-A4", "10.0.10.4"),
            ("ACC-A5", "10.0.10.5"),
        ]),
        ("Access - Building B", "Building B access switches", [
            ("ACC-B1", "10.0.11.1"), ("ACC-B2", "10.0.11.2"),
        ]),
        ("WAN Routers", "Edge routers for WAN links", [
            ("WAN-RTR1", "10.0.0.1"), ("WAN-RTR2", "10.0.0.2"),
        ]),
    ]

    for group_name, desc, hosts in groups:
        gid = await create_group(group_name, desc)
        for hostname, ip in hosts:
            await add_host(gid, hostname, ip)
        print(f"  + Group '{group_name}' with {len(hosts)} hosts")

    # ── Playbooks (from registry) ────────────────────────────────────────
    from routes.database import sync_playbook_filename
    registered = list_registered_playbooks()
    for pb in registered:
        try:
            await create_playbook(pb["name"], pb["filename"], pb["description"], pb["tags"])
            print(f"  + Playbook '{pb['name']}'")
        except Exception as e:
            # Playbook might already exist - sync the filename in case it changed
            if "UNIQUE constraint" in str(e) or "UNIQUE" in str(e):
                try:
                    await sync_playbook_filename(pb["name"], pb["filename"])
                    print(f"  ~ Playbook '{pb['name']}' already exists, synced filename")
                except Exception as sync_error:
                    print(f"  ! Playbook '{pb['name']}' already exists, could not sync: {sync_error}")
            else:
                print(f"  ! Error creating playbook '{pb['name']}': {e}")

    # ── Templates ────────────────────────────────────────────────────────
    templates = [
        ("Access Port Standard",
         "Standard access port hardening config",
         "switchport mode access\n"
         "switchport access vlan 100\n"
         "spanning-tree portfast\n"
         "spanning-tree bpduguard enable\n"
         "storm-control broadcast level 20\n"
         "no shutdown"),
        ("Trunk Port Standard",
         "Standard trunk port config",
         "switchport mode trunk\n"
         "switchport trunk allowed vlan 100,200,300\n"
         "switchport trunk native vlan 999\n"
         "spanning-tree guard root"),
        ("NTP Config",
         "Standard NTP configuration",
         "ntp server 10.0.0.50 prefer\n"
         "ntp server 10.0.0.51\n"
         "clock timezone EST -5\n"
         "clock summer-time EDT recurring"),
        ("Login Banner",
         "Standard login/MOTD banner",
         "banner login ^\n"
         "*** AUTHORIZED ACCESS ONLY ***\n"
         "All activity is monitored and logged.\n"
         "Disconnect immediately if you are not authorized.\n"
         "^"),
    ]

    for name, desc, content in templates:
        await create_template(name, content, desc)
        print(f"  + Template '{name}'")

    # ── Credentials ──────────────────────────────────────────────────────
    await create_credential(
        "Default SSH",
        "netadmin",
        encrypt("cisco123"),
        encrypt("cisco123"),
    )
    print("  + Credential 'Default SSH'")

    print("[seed] Done.")


if __name__ == "__main__":
    asyncio.run(seed())
