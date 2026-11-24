# Federation

Federation connects this Plexus instance to other Plexus instances, called
peers. This instance reads summary numbers from each peer (device counts,
alert counts, compliance profile counts and the peer's version) and shows
them, with totals, on one page. Use it when you run several Plexus
instances, for example one per region or per customer, and want one place
to see their state.

Each peer stays independent. Federation only reads from peers. It never
changes anything on a peer, and a peer does not receive any data from this
instance.

The feature is marked experimental: the page shows the banner
"Federation has not been tested yet." Check the numbers against the peer
itself before you rely on them (see [Known gaps](#known-gaps)).

## Before you start

- **Admin role.** Every federation action needs an admin. See
  [Who can do what](#who-can-do-what).
- **Show the page.** Federation is hidden from the navigation on a fresh
  install. An admin turns it on under **Settings > Features** by ticking
  **Federation** and choosing **Save Visibility**. Hiding a feature only
  removes it from the menu; see [administration.md](administration.md#features).
- **The peer's API token.** Plexus signs in to a peer with the peer's
  server API token (`APP_API_TOKEN` in the peer's environment). This token
  is admin-equivalent on the peer. A new install leaves it empty (off), so
  enable it on the peer first ([deploy/DEPLOYMENT.md](../deploy/DEPLOYMENT.md#server-api-token)).
  See [Trust and credentials](#trust-and-credentials).
- **An HTTPS URL** that this instance can reach.

## Adding a peer

1. Open **Federation** in the navigation. The page title is
   **Federation Overview**.
2. Choose **Add Peer**.
3. Fill in the **Add Federation Peer** dialog:

| Field | What to enter |
|---|---|
| **Name** (required) | A name for the peer, 1 to 200 characters. |
| **URL** (required) | The peer's base URL, for example `https://plexus-eu.example.com`. A trailing `/` is removed. |
| **API Token** | The peer's `APP_API_TOKEN`. You can leave it empty, but then the peer refuses the requests. |
| **Description** | Free text. |
| **Enabled** | On by default. Only enabled peers are synced and counted. |
| **Verify TLS certificate** | On by default. Turn it off only for a self-signed certificate on a trusted network; the dialog warns that an on-path attacker could then read the token. |

4. Choose **Add Peer**. Plexus checks the URL before it saves the peer.
5. In the peer row, choose **Test**. A good result says
   "Connection OK - remote version: ...".
6. Choose **Sync** to read the peer's numbers now. Without this, the first
   automatic sync runs within five minutes.

To change a peer, choose **Edit**. The **API Token** field is always empty
when the dialog opens; leave it empty to keep the saved token, or type a new
one to replace it. A change to where the token goes (the URL's scheme, host
or port, or **Verify TLS certificate** turned off) needs the token typed
again: the save is refused with "url changed, so the stored API token cannot
be reused: enter API token again". Without this rule an admin could point a
peer at a server of their own and receive the other instance's token. To delete a peer, choose **Delete** and confirm. This
removes the peer and all numbers cached from it.

## Reading the page

The cards at the top add up the cached numbers of all enabled peers:

| Card | Meaning |
|---|---|
| **Total Peers** | Enabled peers. |
| **Healthy Peers** | Enabled peers whose last sync status is `ok` (shown as "Synced"). |
| **Total Devices**, **Devices Up**, **Devices Down** | Sum of the peers' host counts. |
| **Active Alerts**, **Critical Alerts** | Sum of the peers' active alerts, and of those with severity `critical`. |

The **Registered Peers** table lists every peer, enabled or not:

| Column | Meaning |
|---|---|
| **Status** | **Enabled** or **Disabled**. |
| **Sync** | Result of the last sync: **Synced** (every request worked), **Partial** (at least one request failed), **Error** (the sync failed as a whole) or **Never**. |
| **Last Synced** | Time of the last sync attempt. |
| **Token** | **Yes** when a token is saved. The token itself is never shown. |

Below the table, one card per enabled peer shows its URL, version, devices
(total, up, down), active alerts and number of compliance profiles, with the
sync status.

A peer that cannot be reached usually shows **Partial**, not **Error**,
because each request fails on its own. The reason for a partial or failed
sync is stored in `last_sync_message`; the page does not show it, but
`GET /api/federation/peers` returns it.

## What is shared, and in which direction

Data flows one way: from the peer to this instance. On every sync this
instance sends these `GET` requests to the peer, with the token in the
`X-API-Token` header:

| Request to the peer | Used for |
|---|---|
| `/api/inventory/groups` | Number of inventory groups. |
| `/api/inventory/hosts` | Device total and the number of hosts with status `up` and `down`. |
| `/api/monitoring/alerts` | Active alerts, and how many are `critical` or `warning`. |
| `/api/compliance/profiles` | Number of compliance profiles. |
| `/api/admin/capabilities` | The peer's version. **Test** calls only this one. |

Only the counts are stored here, as one snapshot per peer and category
(`devices`, `alerts`, `compliance`, `metadata`). Each sync replaces the
previous snapshot, so there is no history. Host names, addresses and alert
texts are not stored.

## Trust and credentials

- The token you enter is the **peer's** server API token. On the peer it
  passes every admin and feature check. Anyone who holds it has full API
  access to that peer. Treat it like a root password.
- The token is stored encrypted in this instance's database and is never
  returned by the API.
- The peer does not need to know this instance. There is no handshake and
  no token in the other direction.
- **HTTPS is required.** An `http://` URL is refused unless the server sets
  `PLEXUS_FEDERATION_ALLOW_HTTP=true`, meant for isolated labs only.
- **Address check.** The URL passes the outbound address check when it is
  saved and again before every request (Test, Sync and the background
  sync), and the request connects to the address the check approved, so a
  name that later resolves elsewhere cannot redirect the token. Cloud
  metadata addresses are always refused, a name that does not resolve is
  refused unless it is listed in `APP_SSRF_ALLOW`, and link-local,
  multicast, reserved and unspecified addresses are refused. Private and
  loopback addresses are allowed unless the server sets
  `APP_SSRF_BLOCK_PRIVATE=true`. See
  [webhooks.md](webhooks.md#outbound-address-check). A sync whose URL is
  refused records the status `error`; **Test** shows "Peer URL rejected".

## Rules worth knowing

- **Automatic sync** runs every 5 minutes for every enabled peer. Peers
  are contacted in parallel. **Sync** runs one peer at once.
- **Timeout:** 30 seconds per connect, read or write, and 120 seconds for
  a whole request, so a peer that answers a few bytes at a time is cut off
  too.
- **Response size:** at most 10 MiB per request, counted after
  decompression. A larger answer is dropped and that part of the sync
  fails (**Partial**). The version a peer reports is kept to 64
  characters.
- **Disabled peers** are not synced and are left out of the cards and
  totals. Their last snapshot is kept until the peer is deleted.
- **Deleting a peer** also deletes its cached snapshots. Nothing changes on
  the peer.
- **Audit:** adding, editing, deleting and manual sync are written to the
  audit log under category `federation` (`peer_created`, `peer_updated`,
  `peer_deleted`, `peer_synced`). Automatic syncs are not audited. See
  [audit-log.md](audit-log.md).

## Known gaps

The paths this version asks a peer for do not all exist on a Plexus peer of
the same version:

- A Plexus instance serves no `GET /api/inventory/groups` or
  `GET /api/inventory/hosts` list. Against such a peer these two requests
  fail, the device numbers stay at 0 and the sync shows **Partial**.
- Alerts from `/api/monitoring/alerts` carry no `state` field, so the
  active and critical alert counts stay at 0.
- `/api/admin/capabilities` returns no version, so **Test** reports
  "remote version: unknown" and the version is empty.
- The compliance snapshot has a `compliant_pct` field that is never filled.

## Who can do what

| Action | Needs |
|---|---|
| See **Federation** in the navigation | The feature is visible (Settings > Features) and the user has the `federation` feature |
| List peers, view the overview, add, edit, delete, test, sync | Admin (every federation endpoint checks for an admin) |

## API

All endpoints need an admin session (with CSRF token on writes) or the
server API token. See [api-reference.md](api-reference.md) for the
general rules.

```
GET    /api/federation/peers
POST   /api/federation/peers
GET    /api/federation/peers/{id}
PUT    /api/federation/peers/{id}
DELETE /api/federation/peers/{id}
POST   /api/federation/peers/{id}/test
POST   /api/federation/peers/{id}/sync
GET    /api/federation/overview
```

```json
POST /api/federation/peers
{
  "name": "plexus-eu",
  "url": "https://plexus-eu.example.com",
  "api_token": "<peer APP_API_TOKEN>",
  "description": "EU region",
  "enabled": true,
  "tls_verify": true
}
```

The answer is the stored peer without the token, with `has_token: true`.
A URL that is not `https` (or `http` with the override), has no host name
or fails the address check gives `422`.

On `PUT`, a field left out is not changed. `"api_token": ""` removes the
saved token; leaving `api_token` out keeps it.

`POST /api/federation/peers/{id}/test` answers
`{"status": "ok", "remote_version": "...", "response_code": 200}` or
`{"status": "error", "message": "Remote returned HTTP 401", "response_code": 401}`.
`POST /api/federation/peers/{id}/sync` answers
`{"status": "ok", "peer_id": 3, "data": {...}}`, where `data.errors` lists
each request that failed; it gives `502` when the sync fails as a whole.
