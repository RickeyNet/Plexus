"""Demo OPNsense firewall for previewing the map without credentials.

``sample_api_answers`` is what an OPNsense firewall answers on each API
path the collector reads, shaped like the answers of the OPNsense core
controllers (``opnsense/core``, 25.7); the two IPsec child SA searches,
which answer per connection, map the connection (the phase 1 name for
``search_phase2``, its UUID for ``search_child``) to the answer.
``build_sample_raw`` is the collector's output for it. Every name and address is invented: the
addresses are documentation ranges (192.0.2.0/24, 198.51.100.0/24,
203.0.113.0/24, 2001:db8::/32) and the names are under example.com.
Nothing here is ever sent anywhere.
"""

from __future__ import annotations

import copy
from typing import Any

SAMPLE_HOSTNAME = "fw-edge-1.example.com"
SAMPLE_VERSION = "25.7.6"
SAMPLE_LATEST = "25.7.7"
# The address the demo entry is registered with: never contacted.
SAMPLE_URL = "https://192.0.2.1"
# IPsec connections (phase 1 UUIDs of the Connections model).
IPSEC_BRANCH_1 = "a1b2c3d4-0000-4000-8000-000000000001"
IPSEC_PARTNER = "a1b2c3d4-0000-4000-8000-000000000002"
IPSEC_BRANCH_4 = "a1b2c3d4-0000-4000-8000-000000000003"

SAMPLE_CONFIG_XML = """<?xml version="1.0"?>
<opnsense>
  <version>25.7</version>
  <system>
    <hostname>fw-edge-1</hostname>
    <domain>example.com</domain>
    <user>
      <name>root</name>
      <password>$2y$11$sample.hash.not.a.real.one.sample.hash.value000000</password>
    </user>
  </system>
  <interfaces>
    <wan><if>igb0</if><ipaddr>203.0.113.10</ipaddr><subnet>28</subnet></wan>
    <lan><if>igb1</if><ipaddr>192.0.2.1</ipaddr><subnet>25</subnet></lan>
  </interfaces>
  <revision><time>1760000000</time><description>sample</description></revision>
</opnsense>
"""

AUDIT_LOG = """***GOT REQUEST TO AUDIT SECURITY***
Currently running OPNsense 25.7.6 (amd64) at Sat Nov 14 09:00:00 UTC 2026
Fetching vuln.xml.xz: .......... done
openssl-3.0.17 is vulnerable:
  OpenSSL -- Sample out-of-bounds read
  CVE: CVE-2026-0001
  CVE: CVE-2026-0002
  WWW: https://vuxml.FreeBSD.org/freebsd/00000000-0000-4000-8000-000000000001.html

curl-8.15.0 is vulnerable:
  cURL -- Sample cookie handling issue
  CVE: CVE-2026-0003
  WWW: https://vuxml.FreeBSD.org/freebsd/00000000-0000-4000-8000-000000000002.html

2 problem(s) in 2 installed package(s) found.
***DONE***
"""

# A config.xml whose rules name aliases only the firewall's pf tables
# resolve (GeoIP, URL tables, a host alias with a host name), and the
# answers of ``firewall/alias_util`` for them (``alias_table_answers``).
# ``UnreadFeed`` has no pf table; ``BigFeed``'s table is larger than what
# one read returns. Every address is a documentation range.
SAMPLE_ALIAS_CONFIG_XML = """<?xml version="1.0"?>
<opnsense>
  <version>25.7</version>
  <system><hostname>fw-alias-1</hostname><domain>example.com</domain></system>
  <interfaces>
    <wan><if>igb0</if><ipaddr>203.0.113.2</ipaddr><subnet>29</subnet><gateway>WAN_GW</gateway></wan>
    <lan><if>igb1</if><ipaddr>192.0.2.1</ipaddr><subnet>25</subnet></lan>
  </interfaces>
  <gateways>
    <gateway_item>
      <name>WAN_GW</name><interface>wan</interface><gateway>203.0.113.1</gateway>
      <ipprotocol>inet</ipprotocol><defaultgw>1</defaultgw>
    </gateway_item>
  </gateways>
  <OPNsense>
    <Firewall>
      <Alias>
        <aliases>
          <alias uuid="e0000000-0000-4000-8000-000000000001">
            <enabled>1</enabled><name>BlockedCountries</name><type>geoip</type>
            <content>AQ</content><description>Sample GeoIP alias</description>
          </alias>
          <alias uuid="e0000000-0000-4000-8000-000000000002">
            <enabled>1</enabled><name>PartnerFeed</name><type>urltable</type>
            <content>https://lists.example.com/partners.txt</content><description>Sample URL table</description>
          </alias>
          <alias uuid="e0000000-0000-4000-8000-000000000003">
            <enabled>1</enabled><name>UpdateHosts</name><type>host</type>
            <content>192.0.2.10
updates.example.com</content><description>Literal address and host name</description>
          </alias>
          <alias uuid="e0000000-0000-4000-8000-000000000004">
            <enabled>1</enabled><name>WebServers</name><type>host</type>
            <content>192.0.2.20
192.0.2.21</content><description>Resolved from the configuration</description>
          </alias>
          <alias uuid="e0000000-0000-4000-8000-000000000005">
            <enabled>1</enabled><name>Trusted</name><type>networkgroup</type>
            <content>PartnerFeed
WebServers</content><description>Nested aliases</description>
          </alias>
          <alias uuid="e0000000-0000-4000-8000-000000000006">
            <enabled>1</enabled><name>BigFeed</name><type>urltable</type>
            <content>https://lists.example.com/big.txt</content><description>Larger than one read</description>
          </alias>
          <alias uuid="e0000000-0000-4000-8000-000000000007">
            <enabled>1</enabled><name>UnreadFeed</name><type>urltable</type>
            <content>https://lists.example.com/unread.txt</content><description>No pf table</description>
          </alias>
        </aliases>
      </Alias>
    </Firewall>
  </OPNsense>
  <filter>
    <rule uuid="f0000000-0000-4000-8000-000000000001">
      <type>block</type><interface>wan</interface><ipprotocol>inet</ipprotocol>
      <source><address>BlockedCountries</address></source><destination><any/></destination>
      <descr>Block countries</descr>
    </rule>
    <rule uuid="f0000000-0000-4000-8000-000000000002">
      <type>pass</type><interface>wan</interface><ipprotocol>inet</ipprotocol><protocol>tcp</protocol>
      <source><address>PartnerFeed</address></source>
      <destination><address>WebServers</address><port>443</port></destination>
      <descr>Partners to web</descr>
    </rule>
    <rule uuid="f0000000-0000-4000-8000-000000000003">
      <type>pass</type><interface>lan</interface><ipprotocol>inet</ipprotocol><protocol>tcp</protocol>
      <source><network>lan</network></source>
      <destination><address>UpdateHosts</address><port>443</port></destination>
      <descr>Updates</descr>
    </rule>
    <rule uuid="f0000000-0000-4000-8000-000000000004">
      <type>pass</type><interface>wan</interface><ipprotocol>inet</ipprotocol><protocol>tcp</protocol>
      <source><address>BigFeed</address></source>
      <destination><address>192.0.2.30</address><port>22</port></destination>
      <descr>Big feed to bastion</descr>
    </rule>
    <rule uuid="f0000000-0000-4000-8000-000000000005">
      <type>pass</type><interface>wan</interface><ipprotocol>inet</ipprotocol><protocol>tcp</protocol>
      <source><address>UnreadFeed</address></source>
      <destination><address>192.0.2.31</address><port>22</port></destination>
      <descr>Unread feed</descr>
    </rule>
    <rule uuid="f0000000-0000-4000-8000-000000000006">
      <type>pass</type><interface>wan</interface><ipprotocol>inet</ipprotocol><protocol>tcp</protocol>
      <source><address>Trusted</address><not>1</not></source>
      <destination><address>192.0.2.32</address><port>80</port></destination>
      <descr>Everyone but trusted</descr>
    </rule>
    <rule uuid="f0000000-0000-4000-8000-000000000007">
      <type>pass</type><interface>wan</interface><ipprotocol>inet</ipprotocol><protocol>tcp</protocol>
      <source><address>Trusted</address></source>
      <destination><address>192.0.2.33</address><port>8443</port></destination>
      <descr>Trusted to admin</descr>
    </rule>
  </filter>
</opnsense>
"""

# How many entries the sample ``BigFeed`` table holds (more than one read returns).
SAMPLE_BIG_FEED_TOTAL = 50000


def _table_rows(entries: list[str], total: int | None = None) -> dict[str, Any]:
    """A ``firewall/alias_util/list/{alias}`` answer (``searchRecordsetBase``
    over ``list_table.py``'s items: ``{"ip": ...}``, with packet counters
    only for entries that matched)."""
    rows: list[dict[str, Any]] = [{"ip": entry} for entry in entries]
    if rows:
        rows[0].update({"in_pass_p": 12, "in_pass_b": 7340})
    return {"total": total if total is not None else len(rows), "rowCount": len(rows), "current": 1, "rows": rows}


def alias_table_answers() -> dict[str, Any]:
    """What ``firewall/alias_util`` answers for ``SAMPLE_ALIAS_CONFIG_XML``:
    the loaded tables (``aliases``, ``pfctl -sT``: no ``UnreadFeed``) and the
    entries of each (``list/{alias}``)."""
    big = [f"198.51.100.{n}" for n in range(128, 160)]
    return {
        "firewall/alias_util/aliases": [
            "BigFeed",
            "BlockedCountries",
            "PartnerFeed",
            "Trusted",
            "UpdateHosts",
            "WebServers",
            "bogons",
            "bogonsv6",
            "sshlockout",
            "virusprot",
        ],
        "firewall/alias_util/list/BlockedCountries": _table_rows(["198.51.100.64/26", "2001:db8:aa::/48"]),
        # A negated entry is carved out of the network that holds it.
        "firewall/alias_util/list/PartnerFeed": _table_rows(["198.51.100.0/26", "!198.51.100.7"]),
        # pf resolved the host name: the table holds both addresses.
        "firewall/alias_util/list/UpdateHosts": _table_rows(["192.0.2.10", "198.51.100.200"]),
        "firewall/alias_util/list/Trusted": _table_rows(
            ["198.51.100.0/26", "!198.51.100.7", "192.0.2.20", "192.0.2.21"]
        ),
        "firewall/alias_util/list/BigFeed": _table_rows(big, SAMPLE_BIG_FEED_TOTAL),
    }


def _interface(
    identifier: str,
    device: str,
    description: str,
    ipv4: list[str],
    *,
    ipv6: list[str] | None = None,
    status: str = "up",
    enabled: bool = True,
    vlan: int | None = None,
    link_type: str = "static",
    mac: str = "",
    gateways: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "device": device,
        "identifier": identifier,
        "description": description,
        "status": status,
        "enabled": enabled,
        "link_type": link_type,
        "link_typev6": "static" if ipv6 else "none",
        "addr4": ipv4[0] if ipv4 else "",
        "addr6": (ipv6 or [""])[0],
        "ipv4": [{"ipaddr": a} for a in ipv4],
        "ipv6": [{"ipaddr": a} for a in ipv6 or []],
        "vlan_tag": vlan,
        "macaddr": mac,
        "flags": ["up", "broadcast", "running", "simplex", "multicast"] if status == "up" else ["broadcast"],
        "is_physical": vlan is None,
        "gateways": gateways or [],
        "routes": [],
        # OPNsense attaches the interface's section of config.xml.
        "config": {
            "if": device,
            "descr": description,
            "enable": "1" if enabled else "",
            "ipaddr": ipv4[0].split("/")[0] if ipv4 else "dhcp",
            "subnet": ipv4[0].split("/")[1] if ipv4 else "",
            "identifier": identifier,
            # A PPPoE or wireless setting would sit here; never kept.
            "password": "not-a-real-secret",
        },
    }


def _phase1(uuid: str, description: str, remote: str, remote_id: str, *, connected: bool) -> dict[str, Any]:
    return {
        "name": uuid,
        "ikeid": uuid,
        "phase1desc": description,
        "version": "IKEv2",
        "local-addrs": "203.0.113.10",
        "remote-addrs": remote,
        "local-id": "203.0.113.10",
        "remote-id": remote_id,
        "local-class": "pre-shared key",
        "remote-class": "pre-shared key",
        "routed": True,
        "connected": connected,
        "install-time": 3600 if connected else None,
        "bytes-in": 104857600 if connected else 0,
        "bytes-out": 52428800 if connected else 0,
        "packets-in": 81000 if connected else 0,
        "packets-out": 64000 if connected else 0,
    }


def _child_sa(ikeid: str, name: str, description: str, local: str, remote: str, remote_host: str) -> dict[str, Any]:
    """A row of ``ipsec/sessions/search_phase2``: a strongSwan child SA
    (``list-sas``) with the phase 2 description OPNsense adds."""
    return {
        "name": name,
        "uniqueid": "5",
        "reqid": "1",
        "state": "INSTALLED",
        "mode": "TUNNEL",
        "protocol": "ESP",
        "encap": "no",
        "encr-alg": "AES_GCM_16",
        "encr-keysize": "256",
        "dh-group": "ECP_256",
        "bytes-in": "104857600",
        "bytes-out": "52428800",
        "packets-in": "81000",
        "packets-out": "64000",
        "rekey-time": "3000",
        "life-time": "3420",
        "install-time": "180",
        "local-ts": local,
        "remote-ts": remote,
        "remote-host": remote_host,
        "ikeid": ikeid,
        "phase2desc": description,
    }


def _search(rows: list[dict]) -> dict[str, Any]:
    return {"total": len(rows), "rowCount": len(rows), "current": 1, "rows": rows}


def _child_config(uuid: str, description: str, local: str, remote: str, enabled: str = "1") -> dict[str, Any]:
    """A row of ``ipsec/connections/search_child``: one configured child SA."""
    return {"uuid": uuid, "enabled": enabled, "description": description, "local_ts": local, "remote_ts": remote}


def _route(destination: str, gateway: str, flags: str, netif: str, description: str, proto: str = "ipv4") -> dict:
    return {
        "proto": proto,
        "destination": destination,
        "gateway": gateway,
        "flags": flags,
        "use": "0",
        "mtu": "1500",
        "netif": netif,
        "expire": "",
        "intf_description": description,
    }


def _neighbour(ip: str, mac: str, intf: str, description: str, hostname: str = "", **extra: Any) -> dict[str, Any]:
    """A row of ``diagnostics/interface/search_arp`` / ``search_ndp``."""
    return {
        "mac": mac,
        "ip": ip,
        "intf": intf,
        "intf_description": description,
        "manufacturer": "",
        "hostname": hostname,
        **extra,
    }


def _client_answers() -> dict[str, Any]:
    """The ARP / NDP tables and the DHCP leases: ISC DHCPv4 on LAN, Kea
    DHCPv4 on the DMZ, Kea DHCPv6 on LAN and Dnsmasq on Guest. ISC DHCPv6
    is not there (404). One ARP entry is incomplete (no MAC)."""
    arp = [
        _neighbour("192.0.2.10", "02:00:5e:00:53:10", "igb1", "LAN", "nas.example.com", expired=False, expires=1180),
        _neighbour("192.0.2.11", "02:00:5e:00:53:11", "igb1", "LAN", "printer.example.com", expires=900),
        _neighbour("192.0.2.140", "02:00:5e:00:53:20", "vlan0.20", "DMZ", "web1.example.com", expires=1100),
        _neighbour("192.0.2.2", "02:00:5e:00:53:02", "igb1", "LAN", "core.example.com", permanent=True),
        _neighbour("192.0.2.12", "(incomplete)", "igb1", "LAN", expired=True),
        _neighbour("203.0.113.1", "02:00:5e:00:53:01", "igb0", "WAN", expires=1200),
    ]
    ndp = [
        {**_neighbour("2001:db8:10::10", "02:00:5e:00:53:10", "igb1", "LAN"), "type": "dynamic"},
        {**_neighbour("fe80::ff:fe00:5310%igb1", "02:00:5e:00:53:10", "igb1", "LAN"), "type": "dynamic"},
    ]
    isc4 = [
        {
            "address": "192.0.2.10",
            "starts": "2026/11/14 07:00:00",
            "ends": "2026/11/14 09:00:00",
            "binding": "active",
            "uid": "01:02:00:5e:00:53:10",
            "client-hostname": "nas",
            "type": "dynamic",
            "status": "online",
            "descr": "",
            "mac": "02:00:5e:00:53:10",
            "hostname": "nas",
            "if": "lan",
            "if_descr": "LAN",
            "man": "",
        },
        {
            "address": "192.0.2.11",
            "starts": "",
            "ends": "",
            "binding": "",
            "type": "static",
            "status": "offline",
            "descr": "Printer reservation",
            "mac": "02-00-5E-00-53-11",
            "hostname": "printer",
            "if": "lan",
            "if_descr": "LAN",
        },
    ]
    kea4 = [
        {
            "address": "192.0.2.140",
            "hwaddr": "02:00:5e:00:53:20",
            "client_id": "",
            "valid_lifetime": "3600",
            "expire": "1794646800",
            "subnet_id": "2",
            "hostname": "web1.example.com.",
            "state": "0",
            "if": "opt1",
            "if_descr": "DMZ",
            "is_reserved": "",
        },
        # Also an ISC lease: the ISC one is kept.
        {"address": "192.0.2.10", "hwaddr": "02:00:5e:00:53:99", "expire": "1794646800", "state": "0"},
        {"address": "192.0.2.141", "hwaddr": "02:00:5e:00:53:21", "expire": "1794636000", "state": "2"},
    ]
    kea6 = [
        {
            "address": "2001:db8:10::100",
            "duid": "00:01:00:01:00:00:00:01:02:00:5e:00:53:10",
            "iaid": "1",
            "hwaddr": "02:00:5e:00:53:10",
            "hostname": "nas.example.com",
            "expire": "1794646800",
            "valid_lifetime": "7200",
            "state": "0",
            "type": "IA_NA",
            "if": "lan",
            "if_descr": "LAN",
        },
        # A delegated prefix is no address.
        {"address": "2001:db8:ff00::/56", "type": "IA_PD", "state": "0"},
    ]
    dnsmasq = [
        {
            "expire": "1794646000",
            "hwaddr": "02:00:5e:00:53:30",
            "address": "192.0.2.200",
            "hostname": "guest-phone",
            "client_id": "01:02:00:5e:00:53:30",
            "if": "opt2",
            "if_descr": "Guest",
            "is_reserved": "0",
        }
    ]
    return {
        "diagnostics/interface/search_arp": _search(arp),
        "diagnostics/interface/search_ndp": _search(ndp),
        "dhcpv4/leases/search_lease": {**_search(isc4), "interfaces": {"lan": "LAN"}},
        "kea/leases4/search": _search(kea4),
        "kea/leases6/search": _search(kea6),
        "dnsmasq/leases/search": _search(dnsmasq),
    }


def _health_answers() -> dict[str, Any]:
    """The health calls: the dashboard widgets' answers, ``top``'s header
    lines (its process list is dropped by the collector) and the services
    the configuration enables, all running."""
    service_rows = [
        ("configd", "configd", "System Configuration Daemon", 1),
        ("dhcpd", "dhcpd", "DHCPv4 Server", 0),
        ("dpinger", "dpinger", "Gateway Monitoring Daemon", 0),
        ("kea-dhcp/v6", "kea-dhcp", "KEA DHCPv6 server", 0),
        ("ntpd", "ntpd", "Network Time Daemon", 0),
        ("openvpn/1", "openvpn", "OpenVPN server Road warrior", 0),
        ("suricata", "suricata", "Intrusion Detection", 0),
        ("unbound", "unbound", "Unbound", 0),
    ]
    return {
        "diagnostics/system/system_resources": {
            "memory": {
                "total": "4294967296",
                "total_frmt": "4096",
                "used": 1932735283,
                "used_frmt": "1843",
                "arc": "536870912",
                "arc_frmt": "512",
                "arc_txt": "ARC size 512 MB",
            }
        },
        "diagnostics/system/system_disk": {
            "devices": [
                {
                    "device": "zroot/ROOT/default",
                    "type": "zfs",
                    "blocks": "18.5G",
                    "total": "18.5G",
                    "total_bytes": 19864223744,
                    "used": "4.20G",
                    "used_bytes": 4509715660,
                    "available": "14.3G",
                    "available_bytes": 15354508084,
                    "used_pct": 23,
                    "mountpoint": "/",
                },
                {
                    "device": "zroot/var/log",
                    "type": "zfs",
                    "blocks": "24.3G",
                    "total": "24.3G",
                    "total_bytes": 26091302912,
                    "used": "10.0G",
                    "used_bytes": 10737418240,
                    "available": "14.3G",
                    "available_bytes": 15354508084,
                    "used_pct": 41,
                    "mountpoint": "/var/log",
                },
                {
                    "device": "/dev/gpt/efiboot0",
                    "type": "msdosfs",
                    "blocks": "260M",
                    "total": "260M",
                    "total_bytes": 272629760,
                    "used": "1.3M",
                    "used_bytes": 1363148,
                    "available": "259M",
                    "available_bytes": 271266612,
                    "used_pct": 1,
                    "mountpoint": "/boot/efi",
                },
            ]
        },
        "diagnostics/system/system_temperature": [
            {
                "device": "dev.cpu.0.temperature",
                "device_seq": 0,
                "temperature": "47.0",
                "type_translated": "CPU",
                "type": "cpu",
            },
            {
                "device": "dev.cpu.1.temperature",
                "device_seq": 1,
                "temperature": "49.0",
                "type_translated": "CPU",
                "type": "cpu",
            },
            {
                "device": "hw.acpi.thermal.tz0.temperature",
                "device_seq": 0,
                "temperature": "27.9",
                "type_translated": "Zone",
                "type": "zone",
            },
        ],
        "diagnostics/system/system_time": {
            "uptime": "12 days, 03:04:05",
            "datetime": "Sat Nov 14 9:00:00 UTC 2026",
            "boottime": "Mon Nov 2 5:55:55 UTC 2026",
            "config": "Fri Nov 13 16:20:00 UTC 2026",
            "loadavg": "0.31, 0.24, 0.20",
        },
        "diagnostics/activity/get_activity": {
            "headers": [
                "last pid: 81234;  load averages:  0.31,  0.24,  0.20  up 12+03:04:05    09:00:00",
                "213 threads:   3 running, 191 sleeping, 19 waiting",
                "CPU:  4.1% user,  0.0% nice,  2.3% system,  0.6% interrupt, 93.0% idle",
                "Mem: 160M Active, 1250M Inact, 1100M Wired, 1980M Free",
                "ARC: 512M Total, 120M MFU, 330M MRU, 1236K Anon, 6200K Header, 54M Other",
                "Swap: 8192M Total, 8192M Free",
            ],
            "details": [
                {
                    "PID": "5555",
                    "USERNAME": "root",
                    "PRI": "20",
                    "NICE": "0",
                    "SIZE": "40M",
                    "RES": "28M",
                    "STATE": "select",
                    "C": "1",
                    "TIME": "2:10",
                    "WCPU": "0.10%",
                    "COMMAND": "/usr/local/bin/example-daemon --token=not-a-real-secret",
                }
            ],
        },
        "diagnostics/firewall/pf_states": {"current": "1830", "limit": "404000"},
        "core/service/search": {
            "total": len(service_rows),
            "rowCount": len(service_rows),
            "current": 1,
            "rows": [
                {"id": ident, "locked": locked, "running": 1, "description": description, "name": name}
                for ident, name, description, locked in service_rows
            ],
        },
    }


def sample_api_answers() -> dict[str, Any]:
    """API path (as the collector names it, newest form) -> the answer."""
    interfaces = [
        _interface(
            "wan",
            "igb0",
            "WAN",
            ["203.0.113.10/28"],
            mac="00:00:5e:00:53:01",
            gateways=["203.0.113.1"],
        ),
        _interface(
            "lan",
            "igb1",
            "LAN",
            ["192.0.2.1/25"],
            ipv6=["2001:db8:10::1/64"],
            mac="00:00:5e:00:53:02",
        ),
        _interface("opt1", "vlan0.20", "DMZ", ["192.0.2.129/26"], vlan=20, mac="00:00:5e:00:53:02"),
        _interface(
            "opt2",
            "vlan0.30",
            "Guest",
            ["192.0.2.193/27"],
            vlan=30,
            status="down",
            enabled=False,
            mac="00:00:5e:00:53:02",
        ),
        _interface(
            "opt3",
            "igb2",
            "WAN2",
            ["198.51.100.10/28"],
            status="no carrier",
            mac="00:00:5e:00:53:03",
            gateways=["198.51.100.1"],
        ),
        _interface("opt4", "wg0", "WireGuard", ["198.51.100.129/28"], link_type="none"),
    ]
    return {
        "diagnostics/system/system_information": {
            "name": SAMPLE_HOSTNAME,
            "versions": [
                f"OPNsense {SAMPLE_VERSION}-amd64",
                "FreeBSD 14.3-RELEASE-p4",
                "OpenSSL 3.0.17 1 Jul 2025",
            ],
            "updates": "Click to view pending updates.",
        },
        "core/firmware/status": {
            "status": "update",
            "status_msg": "There are 2 updates available, total download size is 31.4 MiB.",
            "status_reboot": "0",
            "needs_reboot": "0",
            "upgrade_needs_reboot": "0",
            "last_check": "Sat Nov 14 08:00:00 UTC 2026",
            "connection": "ok",
            "repository": "ok",
            "all_packages": {
                "opnsense": {
                    "name": "opnsense",
                    "old": SAMPLE_VERSION,
                    "new": SAMPLE_LATEST,
                    "reason": "upgrade",
                    "repository": "OPNsense",
                },
                "openssl": {
                    "name": "openssl",
                    "old": "3.0.17",
                    "new": "3.0.18",
                    "reason": "upgrade",
                    "repository": "OPNsense",
                },
            },
            "product": {
                "product_name": "OPNsense",
                "product_version": SAMPLE_VERSION,
                "product_latest": SAMPLE_LATEST,
                "product_arch": "amd64",
                "product_series": "25.7",
                "product_nickname": "Sample Series",
                "product_id": "opnsense",
                "product_abi": "25.7",
                "product_mirror": "https://mirror.example.com/${SUBSCRIPTION}/FreeBSD:14:amd64/25.7",
                "product_license": {"valid_to": "", "serial": "not-a-real-licence"},
            },
        },
        "interfaces/overview/interfaces_info": {
            "total": len(interfaces),
            "rowCount": len(interfaces),
            "current": 1,
            "rows": interfaces,
        },
        "routes/gateway/status": {
            "items": [
                {
                    "name": "WAN_GW",
                    "address": "203.0.113.1",
                    "status": "none",
                    "loss": "0.0 %",
                    "delay": "4.2 ms",
                    "stddev": "0.3 ms",
                    "monitor": "203.0.113.1",
                    "status_translated": "Online",
                },
                {
                    "name": "WAN2_GW",
                    "address": "198.51.100.1",
                    "status": "down",
                    "loss": "100.0 %",
                    "delay": "0.0 ms",
                    "stddev": "0.0 ms",
                    "monitor": "198.51.100.1",
                    "status_translated": "Offline",
                },
                {
                    "name": "WAN_GW6",
                    "address": "2001:db8:ffff::1",
                    "status": "delay",
                    "loss": "0.0 %",
                    "delay": "182.5 ms",
                    "stddev": "40.1 ms",
                    "monitor": "2001:db8:ffff::1",
                    "status_translated": "Latency",
                },
                {
                    "name": "CORE_GW",
                    "address": "192.0.2.2",
                    "status": "none",
                    "loss": "~",
                    "delay": "~",
                    "stddev": "~",
                    "monitor": "~",
                    "status_translated": "Online",
                },
            ],
            "status": "ok",
        },
        "diagnostics/interface/get_routes": [
            _route("default", "203.0.113.1", "UGS", "igb0", "WAN"),
            _route("192.0.2.0/25", "link#2", "U", "igb1", "LAN"),
            _route("192.0.2.1", "link#2", "UHS", "lo0", "Loopback"),
            _route("192.0.2.128/26", "link#5", "U", "vlan0.20", "DMZ"),
            _route("198.51.100.192/27", "192.0.2.2", "UGS", "igb1", "LAN"),
            _route("203.0.113.0/28", "link#1", "U", "igb0", "WAN"),
            _route("2001:db8:10::/64", "link#2", "U", "igb1", "LAN", proto="ipv6"),
        ],
        "ipsec/sessions/search_phase1": _search(
            [
                _phase1(IPSEC_BRANCH_1, "Branch office 1", "198.51.100.20", "198.51.100.20", connected=True),
                _phase1(IPSEC_PARTNER, "Partner VPN", "203.0.113.200", "partner.example.com", connected=False),
                # Phase 1 up, its one child SA not installed: degraded.
                # No child SA: the phase 1 byte totals (sums over its child SAs) are 0.
                {
                    **_phase1(IPSEC_BRANCH_4, "Branch office 4", "198.51.100.30", "198.51.100.30", connected=True),
                    **dict.fromkeys(("bytes-in", "bytes-out", "packets-in", "packets-out"), 0),
                },
            ]
        ),
        # Per connection (POST {"id": <phase 1 name>}): the installed child SAs.
        "ipsec/sessions/search_phase2": {
            IPSEC_BRANCH_1: _search(
                [
                    _child_sa(
                        IPSEC_BRANCH_1,
                        "child-lan",
                        "LAN to branch 1",
                        "192.0.2.0/25",
                        "198.51.100.0/27",
                        "198.51.100.20",
                    )
                ]
            ),
            IPSEC_BRANCH_4: _search([]),
        },
        # Per connection (?connection=<uuid>): the configured child SAs.
        "ipsec/connections/search_child": {
            IPSEC_BRANCH_1: _search(
                [
                    _child_config(
                        "c0000000-0000-4000-8000-000000000011", "LAN to branch 1", "192.0.2.0/25", "198.51.100.0/27"
                    ),
                    _child_config(
                        "c0000000-0000-4000-8000-000000000012", "DMZ to branch 1", "192.0.2.128/26", "198.51.100.32/27"
                    ),
                ]
            ),
            IPSEC_PARTNER: _search(
                [
                    _child_config(
                        "c0000000-0000-4000-8000-000000000021", "Partner exchange", "192.0.2.0/25", "203.0.113.208/28"
                    )
                ]
            ),
            IPSEC_BRANCH_4: _search(
                [
                    _child_config(
                        "c0000000-0000-4000-8000-000000000031", "LAN to branch 4", "192.0.2.0/25", "198.51.100.64/27"
                    )
                ]
            ),
        },
        "wireguard/service/show": {
            "total": 3,
            "rowCount": 3,
            "current": 1,
            "rows": [
                {
                    "if": "wg0",
                    "type": "interface",
                    "public-key": "c2FtcGxlLWludGVyZmFjZS1wdWJsaWMta2V5LTAwMDA=",
                    "listen-port": "51820",
                    "fwmark": "off",
                    "endpoint": "51820",
                    "status": "up",
                    "name": "wg-site",
                    "ifname": "wg-site",
                    "peer-status": "offline",
                    "latest-handshake-age": None,
                },
                {
                    "if": "wg0",
                    "type": "peer",
                    "public-key": "c2FtcGxlLXBlZXItYnJhbmNoLTItcHVibGljLWtleTA=",
                    "endpoint": "198.51.100.40:51820",
                    "allowed-ips": "198.51.100.144/28",
                    "latest-handshake": 1763110000,
                    "latest-handshake-age": 45,
                    "transfer-rx": 2048000,
                    "transfer-tx": 1024000,
                    "persistent-keepalive": "25",
                    "name": "branch-2",
                    "ifname": "wg-site",
                    "peer-status": "online",
                },
                {
                    "if": "wg0",
                    "type": "peer",
                    "public-key": "c2FtcGxlLXBlZXItYnJhbmNoLTMtcHVibGljLWtleTA=",
                    "endpoint": "203.0.113.77:51820",
                    "allowed-ips": "198.51.100.160/28",
                    "latest-handshake": 1763100000,
                    "latest-handshake-age": 900,
                    "transfer-rx": 4096,
                    "transfer-tx": 4096,
                    "persistent-keepalive": "25",
                    "name": "branch-3",
                    "ifname": "wg-site",
                    "peer-status": "stale",
                },
            ],
        },
        "openvpn/service/search_sessions": {
            "total": 4,
            "rowCount": 4,
            "current": 1,
            "rows": [
                {
                    "id": "1_198.51.100.50:51234",
                    "service_id": "openvpn/1",
                    "type": "server",
                    "description": "Road warrior",
                    "status": "ok",
                    "is_client": True,
                    "common_name": "ana.example",
                    "username": "ana",
                    "real_address": "198.51.100.50:51234",
                    "virtual_address": "192.0.2.226",
                    "connected_since": "2026-11-14 07:30:00",
                    "bytes_received": 102400,
                    "bytes_sent": 204800,
                },
                {
                    "id": "2",
                    "service_id": "openvpn/2",
                    "type": "client",
                    "description": "Datacenter link",
                    "status": "connected",
                    "real_address": "203.0.113.150",
                    "virtual_address": "192.0.2.250",
                    "connected_since": "2026-11-13 22:10:00",
                    # ``status 3`` of a client instance: TCP/UDP read / write bytes.
                    "bytes_received": "73400320",
                    "bytes_sent": "36700160",
                    "is_client": None,
                },
                {
                    "id": "3",
                    "service_id": "openvpn/3",
                    "type": "server",
                    "description": "Legacy server",
                    "status": None,
                    "is_client": None,
                },
                {
                    "id": "4",
                    "service_id": "openvpn/4",
                    "type": "client",
                    "description": "Backup datacenter",
                    "status": "reconnecting",
                    "real_address": "198.51.100.180",
                    "virtual_address": "",
                    "is_client": None,
                },
            ],
        },
        "diagnostics/interface/get_vip_status": {
            **_search(
                [
                    {
                        "interface": "lan",
                        "vhid": "1",
                        "advbase": "1",
                        "advskew": "0",
                        "subnet": "192.0.2.3",
                        "status": "MASTER",
                        "mode": "carp",
                        "status_txt": "MASTER",
                        "vhid_txt": "1 (freq. 1/0)",
                    },
                    {
                        "interface": "wan",
                        "vhid": "2",
                        "advbase": "1",
                        "advskew": "0",
                        "subnet": "203.0.113.11",
                        "status": "MASTER",
                        "mode": "carp",
                        "status_txt": "MASTER",
                        "vhid_txt": "2 (freq. 1/0)",
                    },
                ]
            ),
            "carp": {"demotion": "0", "allow": "1", "maintenancemode": False, "status_msg": ""},
        },
        **_client_answers(),
        **_health_answers(),
        # The filter rule counters by rule uuid (``filter rule stats``).
        "firewall/filter_util/rule_stats": {
            "status": "ok",
            "stats": {
                "d0000000-0000-4000-8000-000000000001": {
                    "pf_rules": 1,
                    "evaluations": 18230,
                    "packets": 9120,
                    "bytes": 7340032,
                    "states": 14,
                },
                "d0000000-0000-4000-8000-000000000002": {
                    "pf_rules": 1,
                    "evaluations": 18230,
                    "packets": 0,
                    "bytes": 0,
                    "states": 0,
                },
            },
        },
        "core/firmware/running": {"status": "ready"},
        "core/firmware/audit": {"status": "ok", "msg_uuid": "00000000-0000-4000-8000-0000000000aa"},
        "core/firmware/upgradestatus": {"status": "done", "log": AUDIT_LOG},
        "core/backup/download/this": SAMPLE_CONFIG_XML,
    }


def build_sample_raw() -> dict[str, Any]:
    """The collector's output for the demo firewall (no config.xml: the
    demo entry is no inventory host)."""
    # Imported here: the collector's scrubbers shape the sample like a collection.
    from netcontrol.integrations.meraki.collector import scrub_secrets
    from netcontrol.integrations.opnsense.collector import (
        _UUID,
        DEFAULT_OPTIONS,
        HEALTH_PARTS,
        LEASE_BACKENDS,
        _health_part,
        _rows,
        parse_audit_log,
        scrub_firmware,
        scrub_interface,
    )

    answers = copy.deepcopy(sample_api_answers())
    ipsec = _rows(answers["ipsec/sessions/search_phase1"])
    phase2 = answers["ipsec/sessions/search_phase2"]
    children = answers["ipsec/connections/search_child"]
    vips = answers["diagnostics/interface/get_vip_status"]
    return {
        "firewall": {"name": "", "base_url": SAMPLE_URL, "address": SAMPLE_URL.removeprefix("https://")},
        "timestamp": "2026-11-14T09:00:00+00:00",
        "system": answers["diagnostics/system/system_information"],
        "firmware": scrub_firmware(answers["core/firmware/status"]),
        "interfaces": [scrub_interface(r) for r in _rows(answers["interfaces/overview/interfaces_info"])],
        "gateways": scrub_secrets(_rows(answers["routes/gateway/status"], "items")),
        "routes": _rows(answers["diagnostics/interface/get_routes"]),
        "ipsec": ipsec,
        "ipsec_phase2": {r["name"]: _rows(phase2[r["name"]]) for r in ipsec if r.get("connected")},
        "ipsec_child_config": {r["ikeid"]: _rows(children[r["ikeid"]]) for r in ipsec if _UUID.match(r["ikeid"])},
        "wireguard": _rows(answers["wireguard/service/show"]),
        "openvpn": _rows(answers["openvpn/service/search_sessions"]),
        "carp": {"rows": _rows(vips), "carp": vips["carp"]},
        "clients": {
            "arp": _rows(answers["diagnostics/interface/search_arp"]),
            "ndp": _rows(answers["diagnostics/interface/search_ndp"]),
            "leases": {
                key: _rows(answers[paths[0]]) for key, _name, paths, _privilege in LEASE_BACKENDS if paths[0] in answers
            },
        },
        "rule_stats": answers["firewall/filter_util/rule_stats"],
        "health": {key: _health_part(key, answers[paths[0]]) for key, paths, _privilege in HEALTH_PARTS},
        "audit": {"ran_at": "2026-11-14T09:00:05+00:00", **parse_audit_log(AUDIT_LOG)},
        "config_xml": None,
        "alias_tables": None,
        "errors": [],
        "stats": {"requests": 12, "retries": 0, "rate_limited": 0},
        "options": dict(DEFAULT_OPTIONS),
    }
