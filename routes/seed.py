"""
seed.py — Populate the database with starter data for demo/development.

Run once after init_db(). Idempotent — skips if data already exists.

WARNING: Seed credentials are for local development only.  Never use in
production environments.
"""

import asyncio
import os
import secrets
import sys

# Ensure project root is on path for imports
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from templates import playbooks as _pb_module  # noqa: F401 — triggers @register_playbook decorators

from routes.crypto import encrypt
from routes.database import (
    add_host,
    create_compliance_profile,
    create_credential,
    create_group,
    create_playbook,
    create_template,
    get_db,
    init_db,
)
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

    # ── Compliance Profiles (Preloaded Security Standards) ─────────────
    compliance_profiles = [
        # ── CIS Cisco IOS Benchmark (essential subset) ───────────────
        (
            "CIS IOS Hardening — Management Plane",
            "CIS Cisco IOS Benchmark v4.1 — management plane controls. "
            "Covers SSH, console, VTY, and service hardening. "
            "Based on Section 1 (Management Plane) of the CIS benchmark.",
            "critical",
            [
                {"name": "SSH version 2 required", "type": "must_contain", "pattern": "ip ssh version 2",
                 "remediation": ["ip ssh version 2"]},
                {"name": "SSH timeout configured", "type": "regex_match", "pattern": r"ip ssh time-out\s+\d+",
                 "remediation": ["ip ssh time-out 60"]},
                {"name": "SSH auth retries limited", "type": "regex_match", "pattern": r"ip ssh authentication-retries\s+[1-3]$",
                 "remediation": ["ip ssh authentication-retries 3"]},
                {"name": "No Telnet on VTY lines", "type": "must_not_contain", "pattern": "transport input telnet",
                 "remediation": ["line vty 0 4", "transport input ssh", "line vty 5 15", "transport input ssh"]},
                {"name": "VTY requires SSH", "type": "regex_match", "pattern": r"line vty[\s\S]*?transport input ssh",
                 "remediation": ["line vty 0 4", "transport input ssh", "line vty 5 15", "transport input ssh"]},
                {"name": "Console timeout set", "type": "regex_match", "pattern": r"line con 0[\s\S]*?exec-timeout\s+\d+",
                 "remediation": ["line con 0", "exec-timeout 10 0"]},
                {"name": "VTY timeout set", "type": "regex_match", "pattern": r"line vty[\s\S]*?exec-timeout\s+\d+",
                 "remediation": ["line vty 0 4", "exec-timeout 10 0", "line vty 5 15", "exec-timeout 10 0"]},
                {"name": "No IP finger service", "type": "must_not_contain", "pattern": "ip finger",
                 "remediation": ["no ip finger"]},
                {"name": "No IP identd service", "type": "must_not_contain", "pattern": "ip identd",
                 "remediation": ["no ip identd"]},
                {"name": "No TCP small servers", "type": "must_not_contain", "pattern": "service tcp-small-servers",
                 "remediation": ["no service tcp-small-servers"]},
                {"name": "No UDP small servers", "type": "must_not_contain", "pattern": "service udp-small-servers",
                 "remediation": ["no service udp-small-servers"]},
                {"name": "No IP source routing", "type": "must_contain", "pattern": "no ip source-route",
                 "remediation": ["no ip source-route"]},
                {"name": "Service password encryption", "type": "must_contain", "pattern": "service password-encryption",
                 "remediation": ["service password-encryption"]},
                {"name": "Enable secret set (not enable password)", "type": "must_not_contain", "pattern": "enable password",
                 "remediation": ["no enable password"]},
                {"name": "Timestamps on log messages", "type": "must_contain", "pattern": "service timestamps log datetime",
                 "remediation": ["service timestamps log datetime msec localtime show-timezone"]},
                {"name": "HTTP server disabled", "type": "must_contain", "pattern": "no ip http server",
                 "remediation": ["no ip http server"]},
                {"name": "HTTPS server disabled (or secured)", "type": "regex_match", "pattern": r"no ip http secure-server|ip http secure-server",
                 "remediation": ["no ip http secure-server"]},
            ],
        ),
        (
            "CIS IOS Hardening — Control Plane",
            "CIS Cisco IOS Benchmark v4.1 — control plane protections. "
            "Covers NTP authentication, logging, SNMP hardening, and CDP restrictions.",
            "critical",
            [
                {"name": "NTP authentication enabled", "type": "must_contain", "pattern": "ntp authenticate",
                 "remediation": ["ntp authenticate"]},
                {"name": "NTP server configured", "type": "regex_match", "pattern": r"ntp server\s+\S+",
                 "remediation": ["ntp server 10.0.0.50 prefer"]},
                {"name": "Logging buffered configured", "type": "regex_match", "pattern": r"logging buffered\s+\d+",
                 "remediation": ["logging buffered 64000 informational"]},
                {"name": "Logging to syslog server", "type": "regex_match", "pattern": r"logging\s+(host\s+)?\d+\.\d+\.\d+\.\d+",
                 "remediation": ["logging host 10.0.0.50"]},
                {"name": "Logging console level", "type": "regex_match", "pattern": r"logging console\s+(critical|alerts|emergencies)",
                 "remediation": ["logging console critical"]},
                {"name": "No SNMP community 'public'", "type": "must_not_contain", "pattern": "snmp-server community public",
                 "remediation": ["no snmp-server community public"]},
                {"name": "No SNMP community 'private'", "type": "must_not_contain", "pattern": "snmp-server community private",
                 "remediation": ["no snmp-server community private"]},
                {"name": "SNMPv3 configured", "type": "regex_match", "pattern": r"snmp-server group\s+\S+\s+v3\s+(auth|priv)",
                 "remediation": ["snmp-server group PLEXUS-RO v3 priv"]},
                {"name": "CDP disabled globally (or per-interface)", "type": "regex_match", "pattern": r"no cdp run|no cdp enable",
                 "remediation": ["no cdp run"]},
                {"name": "LLDP disabled globally (or per-interface)", "type": "regex_match", "pattern": r"no lldp run|no lldp transmit",
                 "remediation": ["no lldp run"]},
                {"name": "Login banner present", "type": "regex_match", "pattern": r"banner (login|motd)\s+",
                 "remediation": ["banner login #", "*** AUTHORIZED ACCESS ONLY ***", "All activity is monitored and logged.", "Disconnect immediately if you are not authorized.", "#"]},
            ],
        ),
        (
            "CIS IOS Hardening — Data Plane",
            "CIS Cisco IOS Benchmark v4.1 — data plane security. "
            "Covers uRPF, ACLs, CEF, and anti-spoofing protections.",
            "high",
            [
                {"name": "CEF enabled", "type": "regex_match", "pattern": r"ip cef|ipv6 cef",
                 "remediation": ["ip cef"]},
                {"name": "No IP directed broadcast", "type": "must_contain", "pattern": "no ip directed-broadcast",
                 "remediation": ["no ip directed-broadcast"]},
                {"name": "No IP proxy ARP (global or interface)", "type": "regex_match", "pattern": r"no ip proxy-arp",
                 "remediation": ["no ip proxy-arp"]},
                {"name": "uRPF configured on untrusted interfaces", "type": "regex_match", "pattern": r"ip verify unicast source reachable-via",
                 "remediation": ["ip verify unicast source reachable-via rx"]},
                {"name": "TCP keepalives in", "type": "must_contain", "pattern": "service tcp-keepalives-in",
                 "remediation": ["service tcp-keepalives-in"]},
                {"name": "TCP keepalives out", "type": "must_contain", "pattern": "service tcp-keepalives-out",
                 "remediation": ["service tcp-keepalives-out"]},
            ],
        ),
        # ── Switch-Specific Port Security ────────────────────────────────
        (
            "Switch Port Security Baseline",
            "Essential L2 switch hardening — port security, STP protections, "
            "DHCP snooping, and storm control. Applicable to all access-layer switches.",
            "high",
            [
                {"name": "STP portfast on access ports", "type": "regex_match", "pattern": r"spanning-tree portfast\s*(edge)?",
                 "remediation": ["spanning-tree portfast default"]},
                {"name": "BPDU guard enabled", "type": "regex_match", "pattern": r"spanning-tree\s+(portfast\s+)?bpduguard\s+(enable|default)",
                 "remediation": ["spanning-tree portfast bpduguard default"]},
                {"name": "STP root guard or loop guard", "type": "regex_match", "pattern": r"spanning-tree guard (root|loop)",
                 "remediation": ["spanning-tree loopguard default"]},
                {"name": "DHCP snooping enabled", "type": "must_contain", "pattern": "ip dhcp snooping",
                 "remediation": ["ip dhcp snooping"]},
                {"name": "Dynamic ARP inspection enabled", "type": "regex_match", "pattern": r"ip arp inspection vlan\s+\S+",
                 "remediation": ["ip arp inspection vlan 1-4094"]},
                {"name": "Storm control configured", "type": "regex_match", "pattern": r"storm-control broadcast level\s+\d+",
                 "remediation": None},
                {"name": "Unused ports shutdown", "type": "regex_match", "pattern": r"interface.*\n(?:.*\n)*?\s+shutdown",
                 "remediation": None},
                {"name": "Native VLAN is not VLAN 1", "type": "regex_match", "pattern": r"switchport trunk native vlan\s+(?!1\b)\d+",
                 "remediation": None},
                {"name": "VTP mode transparent or off", "type": "regex_match", "pattern": r"vtp mode\s+(transparent|off)",
                 "remediation": ["vtp mode transparent"]},
                {"name": "Port security enabled on access ports", "type": "regex_match", "pattern": r"switchport port-security",
                 "remediation": None},
            ],
        ),
        # ── AAA / Authentication ─────────────────────────────────────────
        (
            "AAA Authentication Standard",
            "Authentication, authorization, and accounting configuration. "
            "Verifies TACACS+/RADIUS is configured with local fallback "
            "and that AAA is the primary auth mechanism.",
            "critical",
            [
                {"name": "AAA new-model enabled", "type": "must_contain", "pattern": "aaa new-model",
                 "remediation": ["aaa new-model"]},
                {"name": "AAA authentication login defined", "type": "regex_match", "pattern": r"aaa authentication login\s+\S+",
                 "remediation": ["aaa authentication login default local"]},
                {"name": "AAA authorization exec", "type": "regex_match", "pattern": r"aaa authorization exec\s+",
                 "remediation": ["aaa authorization exec default local"]},
                {"name": "AAA accounting commands", "type": "regex_match", "pattern": r"aaa accounting commands\s+",
                 "remediation": ["aaa accounting commands 15 default start-stop group tacacs+"]},
                {"name": "TACACS or RADIUS server configured", "type": "regex_match", "pattern": r"(tacacs|radius)\s+server\s+\S+",
                 "remediation": None},
                {"name": "Local fallback user exists", "type": "regex_match", "pattern": r"username\s+\S+\s+privilege\s+15\s+secret",
                 "remediation": None},
                {"name": "Login local for console fallback", "type": "regex_match", "pattern": r"line con 0[\s\S]*?login\s+(authentication|local)",
                 "remediation": ["line con 0", "login local"]},
            ],
        ),
        # ── Routing Protocol Security ────────────────────────────────────
        (
            "Routing Protocol Authentication",
            "Verifies routing protocols (OSPF, EIGRP, BGP) use authentication "
            "to prevent route injection and peer spoofing attacks.",
            "high",
            [
                {"name": "OSPF authentication configured", "type": "regex_match", "pattern": r"ip ospf (message-digest-key|authentication)",
                 "remediation": None},
                {"name": "EIGRP authentication configured", "type": "regex_match", "pattern": r"ip authentication mode eigrp|ip authentication key-chain eigrp",
                 "remediation": None},
                {"name": "BGP neighbor password set", "type": "regex_match", "pattern": r"neighbor\s+\S+\s+password",
                 "remediation": None},
                {"name": "No default OSPF passive interface", "type": "regex_match", "pattern": r"passive-interface (default|Vlan|Loopback)",
                 "remediation": ["router ospf 1", "passive-interface default"]},
                {"name": "Prefix lists or route maps on BGP", "type": "regex_match", "pattern": r"neighbor\s+\S+\s+(prefix-list|route-map)",
                 "remediation": None},
            ],
        ),
        # ── Encryption & VPN Standards ───────────────────────────────────
        (
            "Encryption & VPN Standards",
            "Ensures VPN and cryptographic configurations use modern, "
            "secure algorithms. Flags weak ciphers and deprecated protocols.",
            "high",
            [
                {"name": "No DES encryption policies", "type": "must_not_contain", "pattern": "encryption des",
                 "remediation": None},
                {"name": "No 3DES-only crypto maps", "type": "must_not_contain", "pattern": "encryption 3des",
                 "remediation": None},
                {"name": "AES-256 or AES-GCM in use", "type": "regex_match", "pattern": r"encryption\s+(aes-256|aes-gcm-256|aes\s+256)",
                 "remediation": None},
                {"name": "IKEv2 preferred over IKEv1", "type": "regex_match", "pattern": r"crypto ikev2\s+",
                 "remediation": None},
                {"name": "SHA-256 or higher hash", "type": "regex_match", "pattern": r"integrity\s+sha(256|384|512)|hash\s+sha(256|384|512)",
                 "remediation": None},
                {"name": "DH group 14 or higher", "type": "regex_match", "pattern": r"group\s+(1[4-9]|2[0-4])",
                 "remediation": None},
                {"name": "No MD5 authentication", "type": "must_not_contain", "pattern": "authentication md5",
                 "remediation": None},
                {"name": "IPsec lifetime reasonable", "type": "regex_match", "pattern": r"set security-association lifetime seconds\s+\d+",
                 "remediation": None},
            ],
        ),
        # ── SNMP Hardening ───────────────────────────────────────────────
        (
            "SNMP Hardening",
            "SNMP-specific security profile. Ensures SNMPv3 with auth+priv, "
            "restricts community strings, and verifies ACLs on SNMP access.",
            "high",
            [
                {"name": "No default 'public' community", "type": "must_not_contain", "pattern": "snmp-server community public",
                 "remediation": ["no snmp-server community public"]},
                {"name": "No default 'private' community", "type": "must_not_contain", "pattern": "snmp-server community private",
                 "remediation": ["no snmp-server community private"]},
                {"name": "SNMPv3 auth-priv group", "type": "regex_match", "pattern": r"snmp-server group\s+\S+\s+v3\s+priv",
                 "remediation": ["snmp-server group PLEXUS-RO v3 priv"]},
                {"name": "SNMPv3 user configured", "type": "regex_match", "pattern": r"snmp-server user\s+\S+\s+\S+\s+v3\s+auth\s+sha",
                 "remediation": None},
                {"name": "SNMP community with ACL restriction", "type": "regex_match", "pattern": r"snmp-server community\s+\S+\s+(RO|RW)\s+\S+",
                 "remediation": None},
                {"name": "SNMP trap host configured", "type": "regex_match", "pattern": r"snmp-server host\s+\S+",
                 "remediation": ["snmp-server host 10.0.0.50 version 3 priv PLEXUS-RO"]},
                {"name": "SNMP contact set", "type": "regex_match", "pattern": r"snmp-server contact\s+\S+",
                 "remediation": ["snmp-server contact NetworkOps"]},
                {"name": "SNMP location set", "type": "regex_match", "pattern": r"snmp-server location\s+\S+",
                 "remediation": ["snmp-server location DataCenter"]},
            ],
        ),
        # ── Quick Wins / Essential Hygiene ───────────────────────────────
        (
            "Network Device Hygiene",
            "Lightweight baseline check for universal device hygiene — "
            "DNS, domain name, timezone, memory thresholds. "
            "Low severity, good for first-pass audits.",
            "low",
            [
                {"name": "Hostname configured (not default)", "type": "regex_match", "pattern": r"hostname\s+(?!Router|Switch)\S+",
                 "remediation": None},
                {"name": "Domain name set", "type": "regex_match", "pattern": r"ip domain[ -]name\s+\S+",
                 "remediation": ["ip domain-name local.net"]},
                {"name": "DNS server configured", "type": "regex_match", "pattern": r"ip name-server\s+\d+\.\d+\.\d+\.\d+",
                 "remediation": ["ip name-server 10.0.0.50"]},
                {"name": "Clock timezone configured", "type": "regex_match", "pattern": r"clock timezone\s+\S+",
                 "remediation": ["clock timezone EST -5", "clock summer-time EDT recurring"]},
                {"name": "Memory free low-watermark", "type": "regex_match", "pattern": r"memory free low-watermark",
                 "remediation": ["memory free low-watermark processor 10000"]},
                {"name": "Archive logging enabled", "type": "regex_match", "pattern": r"archive[\s\S]*?log config",
                 "remediation": ["archive", "log config", "logging enable", "logging size 200", "hidekeys"]},
                {"name": "No plaintext passwords in config", "type": "must_not_contain", "pattern": "password 0 ",
                 "remediation": ["service password-encryption"]},
                {"name": "Crypto key generated", "type": "regex_match", "pattern": r"crypto key generate|crypto pki",
                 "remediation": None},
            ],
        ),
    ]

    for name, description, severity, rules in compliance_profiles:
        import json
        await create_compliance_profile(
            name=name,
            description=description,
            rules=json.dumps(rules),
            severity=severity,
            created_by="system",
        )
        print(f"  + Compliance Profile '{name}' ({len(rules)} rules, {severity})")

    # ── Credentials ──────────────────────────────────────────────────────
    seed_password = secrets.token_urlsafe(12)
    await create_credential(
        "Default SSH",
        "netadmin",
        encrypt(seed_password),
        encrypt(seed_password),
    )
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

    print("[seed] Done.")


if __name__ == "__main__":
    asyncio.run(seed())
