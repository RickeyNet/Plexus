# ChatOps (Slack, Webex and Microsoft Teams)

Run Plexus commands from a chat: look up a device, its interfaces and its
health, list and acknowledge alerts, look up an address or prefix in IPAM,
trace the path between two addresses, check jobs, and launch a job an admin
approved for chat. Alerts can also be posted to Slack or Webex with an
**Acknowledge** button.

```
/plexus device edge-rtr-01
/plexus alerts critical
/plexus ack 42
/plexus ip 198.51.100.0/24
/plexus trace 192.0.2.10 198.51.100.20 tcp 443
/plexus run nightly backup
```

Every command runs as a Plexus user: an admin maps each chat user to a
Plexus account, and the command gets exactly that account's permissions. A
chat user with no mapping gets the help text (which shows them the id to
give an admin) and nothing else. Every command is written to the command
log and the audit log.

## Contents

- [Commands](#commands)
- [Permissions](#permissions)
- [Set up Slack](#set-up-slack)
- [Set up Webex](#set-up-webex)
- [Set up Microsoft Teams](#set-up-microsoft-teams)
- [Map chat users](#map-chat-users)
- [Job presets](#job-presets)
- [Alert notifications with an Acknowledge button](#alert-notifications-with-an-acknowledge-button)
- [Command log and audit](#command-log-and-audit)
- [Security](#security)
- [Troubleshooting](#troubleshooting)

## Commands

Type `/plexus` (Slack), mention the bot (Webex group spaces), message it
directly (Webex), or mention the outgoing webhook (Teams), then the command.
`/plexus help` lists the commands available to you on that bot.

| Command | What it answers | Feature needed |
|---|---|---|
| `help [command]` | The commands you can use, or one command's usage | none |
| `device <name, address or id>` | Platform, model, software, serial, status, group, secondary addresses | `inventory` |
| `interfaces <device> [name filter]` | Each interface with admin / operational state, speed and description | `topology` |
| `status <device>` | The latest poll: status, CPU, memory, response time, packet loss, failed polls in 24 h | `monitoring` |
| `alerts [device] [critical\|warning\|info]` | The newest active alerts (inventory and Meraki), with Acknowledge buttons when you may acknowledge | `monitoring` |
| `ack <alert id>` | Acknowledges a monitoring alert as you | `monitoring` and `monitoring.write` |
| `ip <address or prefix>` | IPAM: the subnet an address is in (utilisation, conflicts, interfaces carrying it), or a prefix's usage, records and next free addresses | `ipam` |
| `trace <source> <destination> [tcp\|udp\|icmp] [port]` | The path trace from stored routes, NAT and firewall rules: verdict, hops, return path. Nothing is sent on the network | `topology` |
| `jobs [count]` | The most recent jobs (up to 25) | `jobs` |
| `job <id>` | One job's status, mode, host counts and last log lines; only jobs you launched unless you are an admin | `jobs` |
| `run [preset] [confirm]` | Launches an approved [job preset](#job-presets); without a name, lists them | `jobs` and `jobs.write` |

A device can be named by host name (or part of it), primary or secondary
address, or the numeric id a previous answer showed; when several match,
the answer lists them with their ids. The query commands are the same
queries the read-only [AI access](ai-access.md) tools use, including their
secret masking.

Slack answers within its three-second limit; a slower command (a large
trace) answers "Working on it..." and posts the result a moment later.
Teams outgoing webhooks wait at most five seconds and cannot be answered
later, so a slower command says so. Answers to a slash command are visible
only to you; acknowledgements and job launches are posted to the channel.

## Permissions

A command runs only when all of these hold:

1. The command is ticked under **Allowed commands** for that platform's bot.
   New bots allow every read command; `ack` and `run` (the two that change
   anything) are off until an admin ticks them.
2. The chat user is mapped to a Plexus user that still exists.
3. That user holds the `chatops` feature (admins hold every feature), and the
   features the command needs (table above). Grant them in **Settings >
   Access Groups**.
4. That user is not limited to selected inventory groups: such accounts are
   refused, as they are for AI access, because the query commands do not
   apply object scope.
5. For `run`: the playbook's own run (and, for a commit preset, commit)
   rule allows the user, an Ansible playbook needs an admin, and the
   preset's credential must be one the user may use (see
   [jobs.md](jobs.md)). `job <id>` shows other people's jobs only to admins.

Each chat user may send 30 commands a minute; more are refused until the
minute passes.

## Set up Slack

1. At <https://api.slack.com/apps> create an app **From scratch** in your
   workspace.
2. **Slash Commands** > **Create New Command**: command `/plexus`, request
   URL `https://plexus.example.com/api/chatops/slack/commands` (Settings >
   ChatOps shows the exact address with a copy button), a short description,
   usage hint `help`.
3. **Interactivity & Shortcuts**: turn it on and set the request URL to
   `https://plexus.example.com/api/chatops/slack/interactivity`. The
   Acknowledge and Run buttons need it.
4. **OAuth & Permissions**: add the bot scopes `commands` and `chat:write`,
   then **Install to Workspace** and copy the **Bot User OAuth Token**
   (`xoxb-...`).
5. **Basic Information** > **App Credentials**: copy the **Signing Secret**.
6. In Plexus, **Settings > ChatOps > Slack**: paste the signing secret and
   the bot token, tick the commands to allow, and **Set Up Slack Bot**.
7. Invite the app to channels where alerts are posted (`/invite @Plexus`).

Plexus must be reachable from Slack over HTTPS at those addresses. The bot
token is needed only for alert notifications; slash commands and buttons
answer through the URL Slack sends with each request.

## Set up Webex

1. At <https://developer.webex.com/my-apps> create a **Bot** and copy its
   access token.
2. Choose a webhook secret (8 to 512 characters, for example the output of
   `openssl rand -hex 24`).
3. In Plexus, **Settings > ChatOps > Webex**: paste the webhook secret and
   the bot access token, tick the commands, and **Set Up Webex Bot**.
4. Create two webhooks for the bot with the Webex API (with the bot's token),
   both with `targetUrl` `https://plexus.example.com/api/chatops/webex` and
   the same `secret`:

   ```
   curl -X POST https://webexapis.com/v1/webhooks \
     -H "Authorization: Bearer <bot access token>" -H "Content-Type: application/json" \
     -d '{"name":"plexus messages","targetUrl":"https://plexus.example.com/api/chatops/webex",
          "resource":"messages","event":"created","secret":"<webhook secret>"}'
   ```

   and the same with `"resource":"attachmentActions"` (card buttons).
5. Add the bot to a space, or message it directly. In a group space mention
   it first: `@Plexus alerts`.

Plexus fetches each message and card action by id with the bot token (the
webhook carries only ids) and answers in the same space.

## Set up Microsoft Teams

Plexus uses a Teams **outgoing webhook**: no Azure bot registration and no
app package, and every request is signed with a shared HMAC key. It was
chosen over a Bot Framework bot (which needs an Entra app registration and
JWT validation against Microsoft's signing keys) as the simpler option that
is still verified on every request. Its limits: it works in channels of one
team (not in personal chats), answers only the person who mentioned it,
must answer within five seconds, and cannot post alerts or receive button
presses, so the Teams card shows the command to type instead of a button.

1. In Teams, open the team > **Manage team** > **Apps** > **Create an
   outgoing webhook**.
2. Name it `Plexus` and set the callback URL to
   `https://plexus.example.com/api/chatops/teams`.
3. Copy the **security token** Teams shows (it is shown once).
4. In Plexus, **Settings > ChatOps > Microsoft Teams**: paste the token, tick
   the commands and **Set Up Microsoft Teams Bot**.
5. In a channel of that team: `@Plexus device edge-rtr-01`.

For alerts in Teams keep using the **Microsoft Teams** notification channel
type (incoming webhook) in [alert-notification-channels.md](alert-notification-channels.md).

## Map chat users

**Settings > ChatOps > User mappings**: choose the platform, enter the chat
user's id and pick the Plexus user. The id is:

| Platform | Id to enter |
|---|---|
| Slack | The member ID: the person's profile, **⋮** > **Copy member ID** (for example `U0123ABCD`) |
| Webex | The person's e-mail address (or their person ID) |
| Teams | The user's Microsoft Entra object ID, or their Teams user id |

Ids are compared ignoring case. One chat identity maps to one Plexus user;
several chat identities may map to the same user. An unmapped person who
types `/plexus` is shown their id, so they can send it to an admin.
Deleting a Plexus user deletes its mappings.

## Job presets

A preset is the allowlist entry for `/plexus run`. **Settings > ChatOps > Job
presets**: give it a name and the number of a job to copy (from the Jobs
page). Plexus copies that job's playbook, targets (hosts, inventory group,
dynamic group or addresses), credential, template, priority and inputs, so
later changes to the job history do not change the preset. Each preset runs
as a **dry run** unless **Run with commit** is set; a commit preset asks for
confirmation in chat (a **Run with commit** button, or
`/plexus run <name> confirm`). A preset can be disabled without deleting it.

The job is queued as the chat user (`launched_by`), so the usual job checks
apply: the playbook's run and commit rules, admin only for Ansible, and the
credential must be one that user may use. Launches are audited as
`jobs` / `job.launch` with `via=chatops:<platform>`.

## Alert notifications with an Acknowledge button

Alerts can be posted by the Slack or Webex bot through the normal
[notification channels](alert-notification-channels.md): **Settings >
Notifications > Add Channel**, type **Slack (ChatOps bot)** with the channel
ID, or **Webex (ChatOps bot)** with the room ID. The channel uses the same
queue, retries, severity floor and rule assignment as every other channel.
The bot needs its token stored.

When `ack` is an allowed command of the bot, the message has an
**Acknowledge** button. Pressing it runs `ack <id>` as the person who
pressed it, so they must be mapped to a Plexus user with `monitoring.write`.
The result is posted to the channel.

## Command log and audit

**Settings > ChatOps > Command log** shows the newest 200 commands with the
platform, chat user, Plexus user, command, outcome and duration, filterable
by platform and outcome. Outcomes: `ok`, `denied` (not allowed, with the
reason), `unmapped`, `error`, `unknown` (no such command) and
`rate_limited`. Rows older than 90 days are deleted. The same command is
written to the audit log as category `chatops`, action `command`;
configuration changes are `chatops` / `bot.update`, `bot.delete`,
`mapping.create`, `mapping.delete`, `preset.create`, `preset.update` and
`preset.delete`. An acknowledgement is also audited as `monitoring` /
`alert.acknowledged`, as from the web page.

## Security

- **Signatures.** Each platform's request is checked before its body is
  used: Slack's `X-Slack-Signature` (HMAC-SHA256 of `v0:<timestamp>:<body>`,
  refused when the timestamp is more than five minutes from now, and a
  signature seen before is refused); Webex's `X-Spark-Signature`
  (HMAC-SHA1 of the body); the Teams `Authorization: HMAC` header
  (HMAC-SHA256 with the base64 security token). Webex and Teams deliveries
  are also de-duplicated by message id for ten minutes. A failed check
  answers `401`; a platform with no enabled bot answers `404`.
- **No session.** The four inbound paths take no cookie and no CSRF token;
  they are rate limited per source IP on the webhook budget and read at most
  64 KiB of body.
- **Secrets.** The signing secrets and bot tokens are encrypted at rest
  (`routes/crypto.py`) and never returned by the API; Settings shows only
  whether each is set.
- **Outbound.** Replies and alerts go only to `slack.com` (a Slack
  `response_url` that is not an https `slack.com` address is refused) and
  `webexapis.com`, through the same SSRF guard as webhooks, with no
  redirects.
- **What reaches the chat.** Answers are what the mapped user could see in
  Plexus. Secrets in configurations are masked; host names, addresses and
  alert text are not. Mentions and links in names are escaped.

## Troubleshooting

| Symptom | Cause |
|---|---|
| Slack says `dispatch_failed` or the platform shows `404` | No enabled bot for that platform, or it has no signing secret |
| `401` in the platform's delivery log | The signing secret or security token in Plexus is not the one the platform uses, the server clock is more than five minutes off (Slack), or a request was replayed |
| "Your chat account is not linked" | No mapping for the id shown; add it under User mappings |
| "not enabled on this bot" | Tick the command under Allowed commands |
| "needs the ... feature" | Grant the feature to the user's access group |
| Webex never answers | No bot access token stored, or no `messages` webhook; in a group space the bot must be mentioned |
| No Acknowledge button on an alert | `ack` is not allowed on the bot |
| "The preset's credential is not one your Plexus account may use" | The copied job used a credential the chat user does not own; copy a job that uses theirs or a credential they own |
