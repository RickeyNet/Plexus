"""
builtin_templates.py - Config templates (Delegator > Instructions) that ship
with Plexus.

These are starting points, not fixed content: ``seed_builtin_templates``
(routes/db/playbooks.py) inserts each one into the ``templates`` table
the first time the app starts and records that it did so, after which
the rows are ordinary user-owned templates.  Editing, renaming or
deleting one is respected across restarts; only built-ins that were
never seeded on this install (for example ones added in a later
release) are inserted.

Each entry is one ``(name, device_type)`` variant.  Variants of the same
name form one logical template: a job that selects any of them sends
each host the body matching its ``device_type`` (see
``resolve_template_for_device_type``).  There is deliberately no
generic ('' device_type) body, so a vendor without a variant never
receives another vendor's syntax.

Secrets are never written into templates.  The SNMPv3 auth and
privacy keys are ``{{secret.NAME}}`` references resolved at run time
from Delegator > Credentials > Secret Variables; the pre-launch check
reports any that are missing.  The ``device_type`` values are Netmiko
platform names (``aruba_aoscx`` is AOS-CX; ``aruba_osswitch`` is
ArubaOS-Switch, the former HP ProCurve line).
"""

from __future__ import annotations

# Secret variable names the shipped bodies reference.  Listed here so the
# descriptions, the tests and the docs stay in step.
SECRET_SNMPV3_AUTH_KEY = "snmp_v3_auth_key"
SECRET_SNMPV3_PRIV_KEY = "snmp_v3_priv_key"

SNMPV3_TEMPLATE_NAME = "SNMPv3 Monitoring (Read-Only)"

_SECRETS_HINT = "Set secret variables {secrets} under Delegator > Credentials > Secret Variables before running."

# IOS and IOS-XE share the classic snmp-server syntax, so one body serves
# both device types.  The user line is not echoed in the running config;
# verify with "show snmp user".
_CISCO_IOS_SNMPV3 = (
    "ip access-list standard SNMP-MGMT\n"
    " permit 10.0.0.0 0.255.255.255\n"
    "snmp-server view PLEXUS-VIEW iso included\n"
    "snmp-server group PLEXUS-RO v3 priv read PLEXUS-VIEW access SNMP-MGMT\n"
    f"snmp-server user plexus PLEXUS-RO v3 auth sha {{{{secret.{SECRET_SNMPV3_AUTH_KEY}}}}} "
    f"priv aes 128 {{{{secret.{SECRET_SNMPV3_PRIV_KEY}}}}}\n"
    "snmp-server location HQ\n"
    "snmp-server contact netops@example.com"
)

_CISCO_NXOS_SNMPV3 = (
    "ip access-list SNMP-MGMT\n"
    "  10 permit ip 10.0.0.0/8 any\n"
    f"snmp-server user plexus network-operator auth sha {{{{secret.{SECRET_SNMPV3_AUTH_KEY}}}}} "
    f"priv aes-128 {{{{secret.{SECRET_SNMPV3_PRIV_KEY}}}}}\n"
    "snmp-server user plexus use-ipv4acl SNMP-MGMT\n"
    "snmp-server location HQ\n"
    "snmp-server contact netops@example.com"
)

_ARUBA_AOSCX_SNMPV3 = (
    "snmp-server vrf default\n"
    f"snmpv3 user plexus auth sha auth-pass plaintext {{{{secret.{SECRET_SNMPV3_AUTH_KEY}}}}} "
    f"priv aes priv-pass plaintext {{{{secret.{SECRET_SNMPV3_PRIV_KEY}}}}}\n"
    "snmp-server system-location HQ\n"
    "snmp-server system-contact netops@example.com"
)

# ArubaOS-Switch turns SNMPv3 on with "snmpv3 enable", which is an
# interactive dialogue the push cannot answer, so that step is a
# prerequisite done once on the console.  The group "operatorauth" is
# read-only with authentication; "managerpriv" would grant write access.
_ARUBA_OSSWITCH_SNMPV3 = (
    f"snmpv3 user plexus auth sha {{{{secret.{SECRET_SNMPV3_AUTH_KEY}}}}} priv aes {{{{secret.{SECRET_SNMPV3_PRIV_KEY}}}}}\n"
    "snmpv3 group operatorauth user plexus sec-model ver3\n"
    'snmp-server location "HQ"\n'
    'snmp-server contact "netops@example.com"'
)

def _v3_description(platform: str, detail: str) -> str:
    return (
        f"{platform}: read-only SNMPv3 user 'plexus' with SHA authentication and AES privacy. {detail} "
        + _SECRETS_HINT.format(secrets=f"{SECRET_SNMPV3_AUTH_KEY} and {SECRET_SNMPV3_PRIV_KEY}")
        + " Edit the management range, location and contact to match your network."
    )


# One dict per (name, device_type) variant.  Keep (name, device_type)
# unique: the templates table enforces it.
BUILTIN_TEMPLATES: list[dict[str, str]] = [
    {
        "name": SNMPV3_TEMPLATE_NAME,
        "device_type": "cisco_ios",
        "description": _v3_description(
            "Cisco IOS",
            "Group PLEXUS-RO reads view PLEXUS-VIEW and is limited to the SNMP-MGMT standard ACL. "
            "The user line is not shown in the running config; verify with 'show snmp user'.",
        ),
        "content": _CISCO_IOS_SNMPV3,
    },
    {
        "name": SNMPV3_TEMPLATE_NAME,
        "device_type": "cisco_xe",
        "description": _v3_description(
            "Cisco IOS-XE",
            "Group PLEXUS-RO reads view PLEXUS-VIEW and is limited to the SNMP-MGMT standard ACL. "
            "The user line is not shown in the running config; verify with 'show snmp user'.",
        ),
        "content": _CISCO_IOS_SNMPV3,
    },
    {
        "name": SNMPV3_TEMPLATE_NAME,
        "device_type": "cisco_nxos",
        "description": _v3_description(
            "Cisco NX-OS",
            "The user joins the built-in network-operator role and is limited to the SNMP-MGMT IPv4 ACL.",
        ),
        "content": _CISCO_NXOS_SNMPV3,
    },
    {
        "name": SNMPV3_TEMPLATE_NAME,
        "device_type": "aruba_aoscx",
        "description": _v3_description(
            "Aruba AOS-CX",
            "Enables the SNMP agent on the default VRF (change to 'mgmt' for the out-of-band port).",
        ),
        "content": _ARUBA_AOSCX_SNMPV3,
    },
    {
        "name": SNMPV3_TEMPLATE_NAME,
        "device_type": "aruba_osswitch",
        "description": _v3_description(
            "Aruba AOS-Switch / HP ProCurve",
            "Requires 'snmpv3 enable' to have been run once on the console (it is interactive). "
            "Group operatorauth is read-only.",
        ),
        "content": _ARUBA_OSSWITCH_SNMPV3,
    },
]


def builtin_template_key(name: str, device_type: str) -> str:
    """Stable identity of a built-in across releases: its (name, device_type)."""
    return f"{name}|{device_type}"
