# AI Access (MCP)

Plexus can let an AI client read the network data it has collected, so the AI
can help diagnose a problem ("why can't this host reach that server", "what
changed before the outage") or produce a report ("which devices have SNMPv2
configured", "which devices run a version with open CVEs").

## What it is

Plexus serves a [Model Context Protocol](https://modelcontextprotocol.io)
(MCP) endpoint at `/mcp`. An MCP-capable AI client, such as Claude Code or
Claude Desktop, connects to it with a token an administrator created and gets
a set of read-only tools. The AI calls those tools to answer your questions.

- Plexus does not contain a chat window and does not store any AI provider
  key. You use the AI client you already have.
- The endpoint is off until an administrator turns it on.
- Every tool reads data Plexus already holds. No tool changes anything, and no
  tool connects to a device or to a vendor API.

## What the AI can and cannot see

A token is limited twice:

1. **By category.** The administrator ticks the data categories the token may
   read: `inventory`, `configs`, `compliance`, `monitoring`, `topology`,
   `software`, `traffic`, `audit`.
2. **By its owner.** Each token acts as one Plexus user. It can use a
   category only if that user has the matching feature. Removing a feature
   from the user narrows the token on the next request.

| Category | Owner needs |
|---|---|
| inventory | `inventory` |
| configs | `config-backups` (`list_config_drift` also needs `config-drift`) |
| compliance | `compliance` |
| monitoring | `monitoring` |
| topology | `topology` |
| software | `software` |
| traffic | `mac-tracking` for `search_mac_or_ip`, `traffic-analysis` for `get_top_talkers` |
| audit | The owner must be an admin |

An admin owner passes every feature check.

Never available through any tool: stored credentials, secret variables,
integration API keys, user accounts and password hashes, sessions, and the
sign-in provider configuration.

A tool the token may not use is not listed, and calling it by name gives the
same answer as a tool that does not exist.

## Enabling the endpoint

1. Sign in as an administrator and open **Settings > AI Access**.
2. Tick **Enable the MCP endpoint** and select **Save AI Access Settings**.

While the endpoint is off it answers `404` and no token works.

## Creating and revoking tokens

1. In **Settings > AI Access**, select **Create token**.
2. Enter a name (the client or person that will use it), choose the owner,
   tick the data categories, and optionally set an expiry date. A token works
   through the end of its expiry day (UTC).
3. Select **Create token**. The token is shown **once**. Copy it, and the
   connection settings under it, before closing the dialog. Plexus stores only
   a hash, so a lost token cannot be shown again: revoke it and create another.

To revoke a token, select **Revoke token** on its row and confirm. Clients
using it stop working at once. A revoked token stays in the list so the audit
log still shows its name.

A token also stops working when it expires, or when its owner is deleted.

Create one token per client. The token name appears on every audit entry, so
separate tokens tell you which client asked for what.

## Connecting a client

The endpoint URL is your Plexus address followed by `/mcp`, for example
`https://plexus.example.com/mcp`. A trailing slash is also accepted. The client
must send the token in an `Authorization: Bearer` header.

**Claude Code** (run in a terminal):

```
claude mcp add --transport http plexus https://plexus.example.com/mcp --header "Authorization: Bearer plx_mcp_..."
```

**Claude Desktop** (add to `claude_desktop_config.json`, then restart Claude
Desktop). This uses the `mcp-remote` bridge, which needs Node.js:

```json
{
  "mcpServers": {
    "plexus": {
      "command": "npx",
      "args": ["-y", "mcp-remote", "https://plexus.example.com/mcp", "--header", "Authorization: Bearer plx_mcp_..."]
    }
  }
}
```

**Other MCP clients:** transport *Streamable HTTP*, URL
`https://plexus.example.com/mcp`, header `Authorization: Bearer plx_mcp_...`.

The client must be able to reach Plexus over the network and must trust its
TLS certificate. Once connected, ask the AI to call `plexus_overview` first:
it reports which categories the token can use and how recent each data source
is.

## Tool reference

Lists are paged: pass `limit`, and pass the `next_cursor` of one page as
`cursor` to get the next. A `host` argument accepts a host name, an IP address
or the numeric id from an earlier result; if it matches several devices the
tool lists them and asks for one. Time arguments (`since`, `until`) are
ISO 8601, for example `2026-01-31T14:00:00Z`.

**Always available**

| Tool | Arguments | Answers |
|---|---|---|
| `plexus_overview` | none | Which categories this token can use; with `inventory`, device counts by device type; with `inventory`, `monitoring` or `topology`, every data source with its status and last collection time |

**inventory**

| Tool | Arguments | Answers |
|---|---|---|
| `list_groups` | `limit`, `cursor` | Inventory groups with parent and device count |
| `search_hosts` | `query`, `vendor`, `group`, `limit`, `cursor` | Devices by name, address, model, serial, version or device type |
| `get_host` | `host` | One device: identity, platform, version, status, group, secondary addresses |

**configs**

| Tool | Arguments | Answers |
|---|---|---|
| `search_configs` | `pattern`, `mode` (`text` or `regex`), `not_matching`, `vendor`, `group`, `context_lines`, `limit`, `cursor` | Which devices have (or, with `not_matching`, lack) a line in their latest stored configuration, with the matching lines |
| `get_device_config` | `host`, `backup_id`, `section` | A stored configuration, or only the sections whose first line starts with `section` |
| `diff_device_configs` | `host`, `from_backup_id`, `to_backup_id` | What changed between two backups (by default the last two) |
| `list_config_drift` | `host`, `status`, `since`, `until`, `limit`, `cursor` | Times a device differed from its baseline, with the diff |

Regex patterns use RE2 syntax, at most 200 characters, tested line by line.

**compliance**

| Tool | Arguments | Answers |
|---|---|---|
| `list_compliance_results` | `profile`, `host`, `status` (`pass` or `fail`), `limit`, `cursor` | Latest result per device or Meraki network and profile, with failed rules |
| `get_compliance_summary` | `profile` | Compliant and non-compliant counts per profile and source |

**monitoring**

| Tool | Arguments | Answers |
|---|---|---|
| `list_alerts` | `host`, `severity`, `state` (`active` or `all`), `since`, `until`, `limit`, `cursor` | Monitoring alerts and Meraki alerts |
| `get_device_health` | `host`, `hours` | Latest poll, minimum / average / maximum per metric over the window, failed polls, interface error counters |
| `get_sla_status` | `target` | SLA targets, devices not meeting them, 30-day summary |
| `list_outages` | `since`, `until`, `entity`, `limit`, `cursor` | Outages and up/down transitions across every tracked vendor |

**topology**

| Tool | Arguments | Answers |
|---|---|---|
| `get_neighbors` | `host` | CDP / LLDP links of a device |
| `get_interfaces` | `host`, `name` | Interfaces, VLANs and spanning-tree port states |
| `list_topology_changes` | `since`, `until`, `limit`, `cursor` | Links that appeared or disappeared, spanning-tree events |
| `trace_path` | `source`, `destination`, `protocol`, `port` | How traffic would be forwarded hop by hop, and the device and rule that blocks it |

`trace_path` uses the same engine as Path Mode on the Topology page
([path-trace.md](path-trace.md)) against stored data. It sends nothing on the
network, so its answer is as current as the last collection.

**software**

| Tool | Arguments | Answers |
|---|---|---|
| `list_software_versions` | `vendor`, `version`, `host`, `changed_since`, `limit`, `cursor` | Version per tracked device from every source, version changes, open advisory count |
| `list_advisories` | `severity`, `cve`, `host`, `limit`, `cursor` | Advisories and CVEs with affected devices and fixed versions; `platforms_without_advisories` names platforms that have devices but nothing to check them against |

**traffic**

| Tool | Arguments | Answers |
|---|---|---|
| `search_mac_or_ip` | `query`, `history` | Where a MAC or IP address was seen: switch and port, or Meraki device, network and SSID |
| `get_top_talkers` | `kind` (`talkers`, `applications`, `conversations`), `exporter`, `direction`, `hours`, `limit` | Traffic ranked by bytes from stored flow records |

**audit** (admin owner only)

| Tool | Arguments | Answers |
|---|---|---|
| `search_audit_log` | `category`, `user`, `since`, `until`, `limit`, `cursor` | Who did what and when, including AI tool calls (category `mcp`) |

When a data source has never been collected, a tool says so
(`"no_data": true` with a message) instead of returning an empty list.

## Secret masking

Masking is always on. There is no setting, argument or token option that
turns it off, and if masking fails the result is withheld.

In configuration text (including search matches, diffs and error messages)
Plexus masks the secret and keeps the rest of the line, so the AI can still
see that a feature is configured:

```
snmp-server community ******** RO
enable secret 9 ********
```

Covered forms include: enable and user passwords and hashes; SNMP communities
and SNMPv3 keys; TACACS+ and RADIUS keys; OSPF, IS-IS, BGP, MSDP, NHRP, NTP,
HSRP, VRRP and key-chain authentication; IKE and IPsec pre-shared keys;
MACsec and failover keys; wireless pre-shared keys and passphrases; private
key and certificate blocks; Junos `$9$` and hashed values; PAN-OS `<phash>`,
`<key>`, `<password>`, `<secret>`, `<authpwd>` and `<privpwd>` values;
Fortinet `ENC` values, `set password` / `set psksecret` lines and SNMP
community names; Aruba AOS-CX `ciphertext` / `plaintext` values; HP Comware
and ProCurve `cipher` values and `snmp-agent community`.

`search_configs` tests your pattern against the masked text, so a search
cannot be used to guess a secret one character at a time: search for the
command (`snmp-server community`), not for a value.

In structured results, any value under a key whose name contains `password`,
`secret`, `token`, `api_key`, `community`, `psk`, `private_key` or
`passphrase` is replaced.

**Limit you should know about.** Masking is done by pattern. It cannot
guarantee that it catches every secret in every vendor's syntax. Known gaps:
a secret written in free text is not recognised (a `description` or `remark`
command is left exactly as written, and a banner is masked only where its
text happens to look like a command); an all-numeric key on a bare indented
`key <number>` line is treated as a key-chain id; and a secret made of
several words is masked only up to the first space. The reverse also
happens: an ordinary word that follows `password`, `secret` or `key` in a
banner or a message is masked. If any
unmasked secret reaching an AI provider is unacceptable for your
organization, leave the `configs` category off the token.

## Data sent to the AI provider

Data returned by these tools is sent to the AI provider your client uses.
Secrets in device configurations are masked. Configurations, IP addresses and
hostnames are not.

Plexus does not anonymise addresses or names. Decide which categories a token
gets with that in mind, and check your AI provider's data handling terms.

## Limits

Set in **Settings > AI Access**.

| Limit | Default | Range | When reached |
|---|---|---|---|
| Result size | 100,000 bytes | 10,000 to 1,000,000 | The result is cut short and carries `"truncated": true` with a hint; paged lists keep a working `next_cursor`. A single row larger than the limit is skipped (`"skipped_oversized_row": true`) |
| Rows per page | 200 | 10 to 1,000 | The list continues with `next_cursor` |
| Calls per token per minute | 120 | 1 to 600 | The call is refused with "Rate limit reached" until the minute passes |

A tool call that runs longer than 30 seconds is stopped with a message asking
for a narrower query.

## Audit trail

Every tool call writes an audit event in category `mcp` (action `tool_call`):
the token name, its owner, the tool, the arguments, the number of rows and
bytes returned, the duration and the outcome. The returned data is not
logged. Creating or revoking a token, changing the settings, and failed
sign-in attempts (`auth_failed`, at most one entry per address per minute)
are logged too. See them on the audit page, or ask the AI with
`search_audit_log` using an admin-owned token that has the `audit` category.

## Not supported

- **Cloud-hosted connectors** (for example connectors added on a provider's
  website). They need Plexus reachable from the internet and sign in with
  OAuth, which Plexus does not offer. Use a client that runs on your own
  machine and can reach Plexus directly.
- **OAuth sign-in.** Tokens only.
- **Write actions.** No tool changes configuration, inventory or settings.
- **Live checks.** No ping, SNMP poll, show command or re-collection. Answers
  come from stored data.

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `404` from `/mcp` | The endpoint is off. Turn it on in **Settings > AI Access**. |
| `401 {"error": "unauthorized"}` | The token is missing, mistyped, revoked or expired, or its owner was deleted. Check the `Authorization: Bearer` header; create a new token if needed. A session cookie or the server's `APP_API_TOKEN` does not work here. |
| `429` | More than 20 failed sign-in attempts from one address in a minute. Fix the token and wait a minute. |
| `405` | The endpoint accepts `POST` only. Use the Streamable HTTP transport. |
| Only `plexus_overview` is listed | The token's owner lacks the features for its categories. Give the owner the features (Settings > Access Groups) or choose another owner. |
| A tool is missing | Its category is not on the token, or the owner lacks the feature in the table above. |
| "No data collected for ..." | Plexus has not collected that data yet. Run or schedule the collection (backups, monitoring, discovery, a source) and ask again. |
| "Rate limit reached" | The token passed its calls-per-minute limit. Wait, or raise the limit. |
| `"truncated": true` | The result passed the size limit. Ask for a section, a filter or a smaller `limit`. |
| The client cannot connect at all | Check that the client's machine can reach Plexus and trusts its certificate. |
