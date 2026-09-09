# How to Upgrade Switches with the Plexus Upgrade Tool

This guide covers upgrading Cisco IOS-XE switches (Catalyst 9200/9300/9400/9600, including dual-supervisor chassis and StackWise Virtual pairs) using the staged upgrade tool built into Plexus.

The tool runs upgrades as **campaigns**: you pick a set of devices, map each hardware model to a software image, and then run four phases in order — **Prestage → Transfer → Activate → Verify**. Only the Activate phase reboots devices; everything before it is safe to run during business hours.

---

## Prerequisites

- A Plexus account with access to the **Delegator → Upgrades** page (the `upgrades` feature).
- A device credential with privileged EXEC access to the target switches, either:
  - a credential you own (selectable per campaign), or
  - the site-wide **service credential** configured in Settings (used automatically when the campaign has no credential set — required for scheduled/unattended reloads).
- SSH (port 22) and SCP enabled on the target switches. Devices must be running in **install mode** (the standard mode on modern IOS-XE); the tool refuses to activate on bundle-mode devices.
- The target `.bin` image file downloaded from Cisco (typically 400–900 MB; uploads are capped at 2 GB by default).
- Enough free space on `flash:` for the image plus its unpacked packages.

---

## Step 1 — Upload the software image

1. Go to **Delegator → Upgrades → Images**.
2. Upload the IOS-XE `.bin` file. Keep Cisco's original filename (letters, numbers, dot, hyphen, underscore only) — the version number is auto-detected from it.
3. After upload, check the row in the Images table:
   - **Version** — auto-detected from the filename (e.g. `17.15.3`). Verify it.
   - **Model Pattern** — the substring used to match device models (e.g. `9200`, `9300`). Auto-detected for common images; edit it if it's blank or wrong.
   - **MD5** — computed on upload and later used to verify the copy on each switch. Compare it against the checksum published on Cisco's download page before proceeding.

Duplicate filenames are rejected — delete the old image first if you're re-uploading.

## Step 2 — Create a campaign

1. Go to **Delegator → Upgrades → Campaigns** and create a new campaign.
2. Fill in:
   - **Campaign Name / Description** — e.g. `Q2 2026 IOS-XE 17.15 Upgrade`.
   - **Image map** — one row per hardware family: a model pattern (e.g. `9200`) and the image to install on devices matching it. Longer/more specific patterns win when several match. A device whose model matches no pattern is skipped with a warning.
   - **Credential** — pick your credential, or leave "Use default service credential".
   - **Devices** — tick inventory groups/hosts, and/or paste ad-hoc IPs (one per line).
3. Options (defaults are sensible; change only with a reason):

   | Option | Default | Meaning |
   |---|---|---|
   | Skip config backup | off | Skips saving `show running-config` during Prestage |
   | Skip MD5 verification | off | Skips checksum verification after the image copy |
   | Skip health check | off | Skips the pre-flight health check (also downgrades the dual-sup standby gate to a warning) |
   | Verify upgrade after reboot | **on** | After Activate, wait for the switch to return, confirm the version, and run `install commit`. Turning this off leaves the install uncommitted — the switch rolls back on its own timer unless you commit manually |
   | ISSU | off | In-service upgrade for dual-sup / StackWise Virtual only. Requires SSO with the standby in STANDBY HOT. Refused on unsupported platforms |
   | Parallel Workers | 4 (max 8) | Devices upgraded concurrently |
   | SSH Retries | 2 | Connection retry attempts per device |

A campaign can be edited later (devices, images, options) as long as no phase is currently running.

## Step 3 — Run the phases

Open the campaign to see the **Upgrade steps** panel and the device table. Each step runs against **all campaign devices**, or only the devices you select in the table ("Steps apply to" shows the current target). Progress streams live into the per-device logs; click a device to see its full log.

### Phase 1 — Prestage (safe, no reboot)

Click **Run prestage**. On each device the tool:

1. Connects and detects the model and running version, then resolves the target image from the image map.
2. Runs a pre-flight health check (skippable). A failed check fails the device and stops it there.
3. Backs up `show running-config` (downloadable later from the **Backups** tab).
4. Saves the config (`write memory`).
5. Frees flash space with `install remove inactive`.

### Phase 2 — Transfer (safe, no reboot, slow)

Click **Run transfer**. On each device the tool:

1. Checks free space on `flash:`.
2. Copies the image via SCP (30–60 minutes per device is normal).
3. Verifies the on-device MD5 against the uploaded image (skippable).
4. Runs `install add` to unpack the image, and verifies the unpacked packages.

**Dual-sup / StackWise Virtual:** before `install add`, the standby supervisor must be **STANDBY HOT**. If it isn't, the transfer is refused (with "Skip health check" enabled it's only a warning) — because `install add` silently skips syncing packages to a cold/absent standby and the problem would otherwise only surface at Activate time. Timeouts are automatically widened for redundant chassis.

Use **Retry failed (N)** to re-run only the devices that failed, and **Re-verify** (on the Prestage step) to re-check the unpacked artifacts on flash — useful if time has passed between Transfer and the reload window.

### Phase 3 — Activate (**causes downtime**)

Run this in a maintenance window. Two ways to start it:

- **Activate now (reload)** — starts immediately after confirmation.
- **Schedule…** — pick a future date/time (shown in your local timezone). The reload then runs unattended at that time. Scheduled reloads survive a Plexus server restart; if the server was down when the window arrived, the campaign is marked **"Reload missed — reschedule"** and nothing reloads out-of-window.

On each device the tool:

1. Re-verifies the image on flash, then checks the boot-mode and (on redundant chassis) redundancy gates — a non-HOT standby blocks activation.
2. Runs `install activate` (with the ISSU verb when the ISSU option is set) and the switch reloads:
   - Normal reload: ~5–15 minutes (up to ~20 for a fully-populated dual-sup chassis).
   - ISSU: standby reloads first, switchover, then the old active reloads — 20–45 minutes, but the chassis keeps forwarding.
3. Waits for the switch to go down and come back, then verifies the running version.
4. Runs `install commit` to make the new version permanent. For ISSU it first waits for the former active to return as STANDBY HOT (committing earlier would abort the ISSU). After commit it re-reads the version to confirm nothing rolled back.

If the commit fails or the post-commit version is wrong, the device is marked **failed** and the log will say whether the switch is going to roll back — act on that before the auto-rollback timer expires.

### Phase 4 — Verify

Click **Verify upgrade** any time after the reload: the tool reconnects to each device and confirms the running version matches the target image. Use it as the final sign-off, or to re-check devices later.

## Monitoring, cancelling, retrying

- **Live logs** — the campaign view streams per-device output in real time; the **Operation history** table records every phase run with counts, timestamps, and who requested it.
- **Cancel running step** — stops the current phase. Devices already finished stay finished.
- **Cancel scheduled reload** — cancels a pending scheduled Activate before it fires.
- **Cancel selected activate** — during a running/scheduled Activate, cancels only the selected devices; the rest continue.
- **Retry** — re-running a phase with failed/cancelled devices selected clears their state and runs them again.
- Campaign details, logs, and backups are visible only to the campaign's creator and admins.

## Backups

The **Backups** tab lists every running-config capture taken during Prestage (`backup_<hostname>_<timestamp>.txt`). Download one to diff or restore a config after an upgrade; delete old ones as needed.

## Troubleshooting

| Symptom | Likely cause / fix |
|---|---|
| Device shows "No image map match for model" | Add or fix the model pattern on the image (Images tab) or in the campaign's image map |
| Transfer refused: standby not STANDBY HOT | Fix the standby sup (reseat/boot/sync) before transferring; don't bypass unless you accept an unsynced standby |
| Health check FAILED | Open the device log for the specific warnings; fix and re-run Prestage |
| Activate refused: bundle mode / boot-mode gate | Convert the switch to install mode first |
| "ISSU not supported on this platform" | Untick the ISSU option — the device will do a normal reload |
| "Reload missed — reschedule" | The Plexus server was down over the scheduled window; schedule a new time |
| Commit failed / switch will roll back | Connect to the switch and investigate immediately; run `install commit` manually if the state is good, before the rollback timer expires |
| Image upload fails with a storage error | On Docker deployments: `sudo chown -R 1000:1000 ./software_images`, then restart the container |
