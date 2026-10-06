# Meraki Security Compliance - Usage Guide

The Compliance page (**Security → Compliance**) audits IOS devices by matching
text patterns against the running configuration. A Meraki organization has
no running config: its configuration is a set of Dashboard API objects. The
**Meraki** tab brings the same controls to Meraki by evaluating *checks*
against those objects - the Meraki equivalents of DHCP snooping, port
security, BPDU guard, storm control and the rest - per organization, per
network, per switch and per SSID.

- Permission: the `compliance` feature (same as host compliance)
- API: `/api/compliance/meraki/*`
- Read-only: Plexus only issues `GET` requests to the Dashboard API. There is
  no remediation for Meraki findings; each failed check says what to change
  in the Meraki Dashboard.

## Quick start

1. Register the organization on the Topology page (**Network → Topology →
   Sources → Add Source → Meraki Organization**; a read-only API key is
   enough). **Load Sample → Meraki** adds a demo organization that can be
   scanned without a key.
2. On the Compliance page click **Load Built-in**. Four Meraki baselines are
   added: **Meraki Switch Security Baseline**, **Meraki Security Appliance
   Baseline**, **Meraki Wireless Security Baseline** and **Meraki Dashboard
   Access Hardening**.
3. Open the **Meraki** tab and click **Assign to Organization**: pick a
   profile, tick the organizations, set the interval. Or click **Run Scan**
   in the page header, choose **Meraki Organization**, and scan once.
4. Click **Scan Now** on the assignment. The scan runs in the background
   (collection progress is shown) and the **Target Status** and **Scan
   Results** views fill in. **View findings** on a target lists every check
   with the offending ports, SSIDs, rules or administrators.

Scheduled scans run from the same compliance scheduler as host scans
(**Admin → Compliance**), each assignment at its own interval.

## How a scan works

A profile may mix two kinds of rules. Config rules (`must_contain`,
`must_not_contain`, `regex_match`) are evaluated by host scans over SSH and
skipped by Meraki scans; Meraki rules are evaluated by Meraki scans and
skipped by host scans. A Meraki rule names a check and, optionally, its
parameters:

```json
{"name": "Access ports use an access policy", "type": "meraki",
 "check": "switch_port_access_policy",
 "params": {"allowed_types": ["Sticky MAC allow list", "MAC allow list", "Custom access policy"],
            "exempt_tags": ["uplink"], "exempt_name_pattern": "^Printer"}}
```

The profile editor has an **Add a Meraki check** picker that inserts the
rule JSON with its default parameters; `GET /api/compliance/meraki/checks`
returns the same catalog.

A scan reads only what the profile's checks need (one call per endpoint per
network, one organization-wide call for all switch ports, one call per
enabled SSID for the SSID firewall, plus one call per switch only for the
live port-status check), honouring the Dashboard API rate
limit like a topology collection, and limited to the same networks (the
organization's network tag / name filter). It then produces one result per
**target**:

| Target | Checks evaluated | Example |
|---|---|---|
| Organization | dashboard administrators, login security, organization SNMP | 1 administrator without two-factor authentication |
| Network | DHCP server policy, STP, storm control, MX security, SSIDs, syslog, SNMP, alerts (only the checks whose product the network has) | Branch-Boston: DHCP server policy is *allow* |
| Switch | every per-port check | Branch-Boston-SW1: 3 of 21 access ports without an access policy (port 5, 6, 7) |
| SSID | every wireless check that concerns the SSID (guest vs corporate, open vs secured) | Guest in Branch-Boston: SSID firewall allows the LAN |

A target is **compliant**, **non-compliant** (at least one check failed) or
**error** (a payload could not be read - typically an API key without access
to that endpoint - and nothing failed). An unreadable payload is never
reported as compliant or as a violation. An endpoint Meraki answers with 400
or 404 means the feature is not applicable to that network, and the check is
left out of the target.

## The checks

### Switching (per network)

| Check | Meraki object | IOS equivalent |
|---|---|---|
| `switch_dhcp_server_policy` | DHCP server policy `defaultPolicy: block` | `ip dhcp snooping` |
| `switch_dhcp_rogue_alert` | DHCP policy email alert or the *Rogue DHCP server* network alert | DHCP snooping violation logging |
| `switch_arp_inspection` | DHCP server policy `arpInspection.enabled` | `ip arp inspection vlan` |
| `switch_rstp_enabled` | STP `rstpEnabled` | `spanning-tree mode rapid-pvst` |
| `switch_stp_root_pinned` | an STP bridge priority at or below `max_priority` (32767) | `spanning-tree vlan priority` |
| `switch_storm_control` | broadcast threshold below 100% (`max_broadcast_percent`; `require_multicast`, `require_unknown_unicast`) | `storm-control broadcast level` |

### Switching (per switch, from the port configuration)

Every per-port check takes `exempt_tags` (port tags to skip) and
`exempt_name_pattern` (a regular expression on the port name); disabled ports
are never counted.

| Check | Condition on enabled ports | IOS equivalent |
|---|---|---|
| `switch_port_access_policy` | access ports have an `accessPolicyType` in `allowed_types` (sticky MAC allow list, MAC allow list, custom 802.1X/MAB access policy) | `switchport port-security` / `authentication port-control auto` |
| `switch_port_mac_limit` | sticky MAC ports learn at most `max_addresses` (5) | `switchport port-security maximum` |
| `switch_port_bpdu_guard` | access ports have STP guard in `accepted` (BPDU guard) | `spanning-tree bpduguard enable` |
| `switch_port_uplink_guard` | trunk ports have STP guard in `accepted` (root guard or loop guard) | `spanning-tree guard root` / `loop` |
| `switch_port_native_vlan` | trunk native VLAN not in `forbidden_vlans` (1) | `switchport trunk native vlan` |
| `switch_port_trunk_pruned` | trunk ports do not allow *all* VLANs | `switchport trunk allowed vlan` |
| `switch_port_dai_trusted` | access ports are not ARP-inspection trusted | `ip arp inspection trust` on uplinks only |
| `switch_port_storm_control` | access ports have per-port storm control | per-interface `storm-control` |
| `switch_port_unused_disabled` | ports with nothing connected (live status, one call per switch) are disabled | `shutdown` |

### Security appliance (per network)

| Check | Meraki object | IOS equivalent |
|---|---|---|
| `mx_ip_source_guard` | firewall settings, IP source guard `block` | uRPF (`ip verify unicast source`) |
| `mx_ids_prevention` | intrusion `mode: prevention`, ruleset at least `min_ruleset` (balanced) | IPS |
| `mx_amp_enabled` | malware protection enabled | - |
| `mx_firewalled_services` | the `services` (web, SNMP) blocked or restricted from the WAN | `no ip http server`, SNMP ACL |
| `mx_port_forwarding_restricted` | no rule allows any source (except public ports in `allow_any_for_ports`) | static NAT with inbound ACL |
| `mx_one_to_one_nat_restricted` | inbound allowances from any only on `allow_any_for_ports` (80, 443) | static NAT with inbound ACL |
| `mx_l3_firewall_logging` | the default outbound rule (or `every_rule`) logs to syslog | `access-list ... log` |
| `mx_content_filtering` | at least `min_categories` URL categories blocked | - |

### Wireless (per SSID)

Every enabled SSID of a wireless network is its own target ("Guest in
Branch-Boston"). A check that does not concern the SSID - a guest check on
a corporate SSID, a WPA check on an open SSID - leaves no finding. Guest
SSIDs are those whose name matches `guest_name_pattern`
(`guest|visitor|public`). The SSID's own L3 firewall is read per SSID, only
for enabled SSIDs and only when a check needs it.

| Check | Condition | IOS equivalent |
|---|---|---|
| `ssid_requires_auth` | not open (`exempt_name_pattern` skips SSIDs) | no open WLAN |
| `ssid_wpa2_or_better` | secured SSIDs: no WEP, WPA mode at least `minimum` (*WPA2 only*; WPA3 modes count as stronger) | `security wpa wpa2` / `wpa3` |
| `ssid_enterprise_auth` | non-guest SSIDs use 802.1X | `dot1x` on the WLAN |
| `ssid_radius_redundancy` | RADIUS SSIDs list at least `min_servers` (2); `require_accounting` | redundant RADIUS group, `aaa accounting` |
| `ssid_pmf_enabled` | secured SSIDs enable 802.11w (`require_mandatory`) | `security pmf` |
| `ssid_splash_on_open` | open SSIDs present a splash page | web authentication |
| `ssid_guest_isolated` | guest SSIDs use NAT mode, LAN isolation, or an SSID firewall rule denying *Local LAN* | guest ACL |
| `ssid_guest_lan_firewall` | guest SSID firewall sets *Wireless clients accessing LAN* to deny (per-SSID endpoint) | `ip access-group` on the WLAN |
| `ssid_mandatory_dhcp` | mandatory DHCP on guest SSIDs (`guest_only: false` for all) | IP source guard on the WLAN |
| `ssid_guest_bandwidth_limit` | guest SSIDs cap per-client download (`require_upload_limit`) | QoS policing |

### Network services (per network, any product)

`net_syslog_configured` (`min_servers`), `net_snmp_no_v2c` (device SNMP
access `none` or `users`, never a community string) and
`net_alerts_destination` (a default alert destination exists).

### Dashboard and organization (per organization)

`org_admins_2fa` and `org_admins_active` (`max_inactive_days`, both with
`exempt_emails`), `org_login_2fa_enforced`, `org_login_strong_passwords`,
`org_login_idle_timeout` (`max_minutes`), `org_login_lockout`
(`max_attempts`), `org_login_password_expiration` (`max_days`),
`org_login_password_reuse`, `org_api_key_ip_restriction` and
`org_snmp_v3_only`.

## API

| Method and path | Purpose |
|---|---|
| `GET /api/compliance/meraki/checks` | the check catalog with the rule JSON for each check |
| `GET /api/compliance/meraki/orgs` | Meraki organizations a profile can be scanned against |
| `GET/POST /api/compliance/meraki/assignments`, `PUT/DELETE .../{id}` | assignments (`profile_id`, `org_ref`, `interval_seconds`, `enabled`) |
| `POST /api/compliance/meraki/assignments/{id}/scan-now` | start a scan of the assignment (`202`, `job_id`) |
| `POST /api/compliance/meraki/scan` | start a one-off scan (`profile_id`, `org_ref`; `202`, `job_id`) |
| `GET /api/compliance/meraki/scans/{job_id}` | scan progress and result |
| `GET /api/compliance/meraki/results`, `GET/DELETE .../{id}` | stored results (filters `org_ref`, `profile_id`, `scan_id`, `status`, `target_kind`); the detail carries the findings |
| `GET /api/compliance/meraki/status` | the latest result per target and profile |
| `GET /api/compliance/meraki/summary` | counts for the summary strip |

One scan runs per organization at a time (`409` otherwise). Results are
kept for the compliance retention period (**Admin → Compliance**). Tables:
`meraki_compliance_assignments`, `meraki_compliance_results` (migration
0068).
