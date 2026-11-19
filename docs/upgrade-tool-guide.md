# Method of Procedure: Cisco Catalyst IOS-XE Software Upgrade (Plexus Upgrade Tool)

## Table of Contents

- [General Guidelines](#general-guidelines)
- [Introduction](#introduction)
- [Schedule & Key Resources](#schedule--key-resources)
- [Expected Time to Complete](#expected-time-to-complete)
- [Expected Impact](#expected-impact)
- [Self-Assessed Risk Level](#self-assessed-risk-level)
- [Glossary](#glossary)
- [Completed Pre-Work](#completed-pre-work)
  - [Document and Save Configurations - Before Change](#document-and-save-configurations---before-change)
- [Lab, Testing, Proof of Concept](#lab-testing-proof-of-concept)
- [Work](#work)
- [Roll Back / Backout](#roll-back--backout)
- [Diagrams](#diagrams)
  - [Logical Drawings](#logical-drawings)
  - [Physical System Drawings](#physical-system-drawings)
  - [Detailed Technical Drawings](#detailed-technical-drawings)
- [Appendices](#appendices)
- [APC Smart-UPS (Network Management Card)](#apc-smart-ups-network-management-card)
- [External Documentation](#external-documentation)

---

## General Guidelines

--- Do not remove or update this section. ---

This document is intended to explain complicated, technical changes that need to be made to the network environment. It is intended to share with non-technical users, or other personnel who need to be informed, but may not have a technical Networking skillset. Furthermore, this document is intended to be used by you during the change, in the middle of the night, when you're tired and not necessarily at the top of your game - so that you do not have to think too hard about what you're doing, how you're doing it, or what to do when it doesn't work.

Additionally - this document should be written in such a way, that anyone - from outside the team - could pick it up, grasp a general understanding of what we are doing, why we are doing it, and how to do it themselves.

Sections and instructions and examples on how to complete follow.

---

## Introduction

Cisco Catalyst switches run an operating system called IOS-XE. Like any software, it must be kept current to receive security fixes, bug fixes, and new features. Running outdated switch software exposes the business to known vulnerabilities and unsupported configurations.

This procedure upgrades the IOS-XE software on one or more Cisco Catalyst switches (9200, 9300, 9400, and 9600 series, including dual-supervisor chassis and StackWise Virtual pairs) using the staged upgrade tool built into Plexus. The tool uses Cisco's recommended install mode upgrade method and performs the same steps an engineer would do by hand, but consistently and with built-in safety checks.

The tool runs upgrades as **campaigns**: you pick a set of devices, map each hardware model to a software image, and then run four phases in order. The disruptive part is kept as small and as late as possible:

| Phase | What it does | Causes an outage? |
|---|---|---|
| Prestage | Backs up the config, saves it, and frees up flash storage | No |
| Transfer | Copies the new software image to the switch and unpacks it | No |
| Activate | Installs the new software and reboots the switch | Yes (switch reload) |
| Verify | Reconnects and confirms the new version is running | No |

Phases 1 and 2 can be run during business hours with no impact. Only Phase 3 needs a maintenance window. After Phase 3, the tool waits for the switch to come back, confirms the new version is running, and commits the install so it becomes permanent.

### Participants

| Name | Phone | Role | Note |
|---|---|---|---|
| | | Network Engineer | |
| | | | |

### Escalations

| Name | Phone | Role | Note |
|---|---|---|---|
| | | Manager, IT Networking | |
| | | | |
| Cisco TAC | 1-800-553-2447 | Vendor Support | Have the switch serial number and Smart Account ready |

---

## Schedule & Key Resources

| Resource | Location / Value |
|---|---|
| Upgrade tool | Plexus web UI: **Network → Software → Upgrades** |
| Software images | **Network → Software → Upgrades → Images** tab |
| Campaigns | **Network → Software → Upgrades → Campaigns** tab |
| Config backups | **Backups** tab inside the campaign (`backup_<hostname>_<timestamp>.txt`) |
| Per-device logs | Click a device in the campaign's device table |
| Operation history | **Operation history** table inside the campaign |
| Device credential | A credential you own, or the site-wide service credential in Settings |
| Jump host / workstation | |
| Console / OOB access | |
| Cisco Software Download | https://software.cisco.com/download/home |
| Maintenance window | |

---

## Expected Time to Complete

Times are per switch. Prestage and Transfer run against several devices at once (the **Parallel Workers** option, default 4, maximum 8). Activate also honours the worker count, so set it to 1 if only one device should be rebooting at any moment.

| Phase | Typical Duration | Notes |
|---|---|---|
| Pre-flight health check | Under a few minutes | Automatic during Prestage |
| Prestage | Varies | `install remove inactive` can be slow on switches with many old packages |
| Transfer (SCP) | 30 - 60 minutes | Depends on link speed and image size (roughly 400 - 900 MB) |
| MD5 verification and `install add` | Several minutes | Automatic after transfer |
| Activate (normal reload) | 5 - 15 minutes | Up to about 20 minutes for a fully populated dual-supervisor chassis. Switch is down for this period |
| Activate (ISSU) | 20 - 45 minutes | Dual-sup / StackWise Virtual only. The chassis keeps forwarding |
| Post-upgrade verification and commit | Several minutes | Automatic when "Verify upgrade after reboot" is on |
| Total per switch (all phases) | Roughly 1 - 2 hours | Mostly transfer time |
| Total for this change | | Fill in based on switch count and strategy |

Recommended strategy: Run Prestage and Transfer during business hours the day before. Run Activate only during the maintenance window. This reduces the maintenance-window time to roughly 10 - 25 minutes per switch for a normal reload.

---

## Expected Impact

**Phases 1, 2, and 4 (Prestage, Transfer, Verify):** No user impact. The switch keeps running its current software. Network traffic is unaffected. The only observable effect is slightly higher CPU on the switch during the file copy, MD5 check, and package unpack.

**Phase 3 (Activate):** Full outage for every device connected to that switch while it reloads, typically 5 - 15 minutes. This includes:

- All wired users, printers, phones, and cameras on that switch
- Wireless access points powered by or uplinked through that switch (and therefore the Wi-Fi they provide)
- Any downstream switches uplinked through it

For a switch stack, the entire stack reloads together. All members go down at once.

For a dual-supervisor chassis or StackWise Virtual pair with the **ISSU** option enabled, the standby reloads first, a switchover occurs, then the old active reloads. The chassis keeps forwarding throughout, but expect a brief interruption at switchover.

Sites / users affected by this change:

| Switch | Location | Users / Services Affected |
|---|---|---|
| | | |
| | | |
| | | |

After the reload, the switch returns with its exact prior configuration. No manual reconfiguration is expected.

---

## Self-Assessed Risk Level

**Risk Level:** ☐ Low ☐ Medium ☐ High (select one; default is Medium)

The procedure is well understood and Cisco's install-mode upgrade is the vendor-recommended method. The risk is rated Medium rather than Low because Phase 3 requires a reboot, which is inherently disruptive, and because a switch that fails to boot cannot be recovered remotely without console access.

Risk mitigations built into this procedure:

- Pre-flight health check fails the device and stops it there on any switch that is not healthy enough to upgrade.
- Running configuration is backed up before any change is made and is downloadable from the Backups tab.
- The software image is MD5-verified after transfer, so a corrupt image is never installed.
- The unpacked packages are verified on flash after `install add`, and can be re-verified any time before the reload window.
- On redundant chassis, the standby supervisor must be STANDBY HOT before both Transfer and Activate. A cold or absent standby blocks the operation.
- Each switch's boot mode (INSTALL or BUNDLE) is read from `show version` in Prestage, before the Transfer copy, in Check status and in Activate, and shown in the campaign's **Mode** column. Stackable switches report it in the `show version` Mode table; a modular chassis (9400, 9600) has no such table, so the mode is taken from the `System image file` line (`packages.conf` is INSTALL, a `.bin` file is BUNDLE). A bundle-mode switch is stopped before any image is copied. Install mode is required for every upgrade the tool runs, ISSU included.
- The switch is not rebooted until the image is re-verified on flash and the boot-mode, redundancy and install-state gates pass. The install-state gate (IOS-XE) refuses to activate while an earlier install is left uncommitted, and when the target was never added. See Appendix F.
- Post-upgrade verification confirms the running version, then runs `install commit`, then re-reads the version to confirm nothing rolled back.
- Interactive confirmation is required before an immediate Activate.
- The previous software version remains on the switch and can be restored with a single command.

Residual risks (not mitigated by the tool):

- A switch that does not return after reload requires console or on-site access.
- Hardware faults exposed by a reboot (failed power supply, bad flash) are outside the tool's control.
- If "Verify upgrade after reboot" is turned off, the install is left uncommitted and the switch rolls back on its own timer unless someone commits manually.
- If the Plexus server is down when a scheduled reload window arrives, the reload does not run. The campaign is marked "Reload missed - reschedule" and nothing reloads out-of-window.

---

## Glossary

Try not to be too technical. However, as this is a technical MOP, sometimes acronyms are just too handy vs. typing out the words all the time, repetitively. If you use an acronym that anyone outside your team might not understand, include it below (in alphabetical order).

| Term | Meaning |
|---|---|
| Activate | The upgrade phase that installs the new software and reboots the switch. |
| Bundle Mode | The older IOS-XE upgrade method that boots from a single large file. The tool refuses to activate on devices in this mode. |
| Campaign | A named set of devices, an image map, a credential, and options that the tool upgrades together. |
| Commit | Making the newly installed software permanent. Until commit, the switch will roll back on its own timer. |
| Dual-sup | A chassis switch with two supervisor modules, one active and one standby. |
| Flash | The switch's internal storage where software images are kept. |
| Image Map | One row per hardware family: a model pattern and the image to install on devices matching it. |
| Install Mode | Cisco's recommended IOS-XE upgrade method. Software is unpacked into individual packages on flash. Supports rollback. |
| IOS-XE | The operating system that runs on Cisco Catalyst switches. |
| ISSU | In-Service Software Upgrade. Upgrades a dual-sup or StackWise Virtual pair one supervisor at a time so the chassis keeps forwarding. |
| MD5 | A checksum used to confirm a file was not corrupted during copy. |
| MOP | Method of Procedure. This document. |
| Prestage | The upgrade phase that backs up and saves the config and frees up flash space. No outage. |
| RFC | Request for Change. The formal change-control ticket. |
| SCP | Secure Copy Protocol. Used to copy the software image to the switch over SSH. |
| Service Credential | The site-wide device credential configured in Settings, used automatically when a campaign has no credential set. Required for scheduled, unattended reloads. |
| SSH | Secure Shell. Encrypted remote command-line access to the switch. |
| SSO | Stateful Switchover. The redundancy mode that lets the standby supervisor take over without dropping traffic. |
| Stack | Two or more physical switches joined to act as one logical switch. They upgrade and reboot together. |
| StackWise Virtual | Two chassis switches joined to act as one logical switch, similar to a stack but for larger platforms. |
| STANDBY HOT | The state a standby supervisor must be in for it to take over. The tool requires this before Transfer and Activate on redundant chassis. |
| TAC | Cisco Technical Assistance Center. Cisco's support organization. |
| Transfer | The upgrade phase that copies the new image to the switch and unpacks it. No outage. |
| Verify | The upgrade phase that reconnects to each device and confirms the running version matches the target. |

---

## Completed Pre-Work

Check each item off as it is completed. All items must be done before the maintenance window.

- ☐ Completed and submitted RFC for change in the change-control system: ______________________________
- ☐ Communicated upcoming upgrade and expected interruption to the appropriate team chat channels and site contacts.
- ☐ Confirmed you have a Plexus account with access to the **Network → Software → Upgrades** page (the `upgrades` feature).
- ☐ Confirmed a device credential with privileged EXEC access to every target switch, either one you own or the site-wide service credential in Settings.
- ☐ Downloaded the target IOS-XE image(s) from https://software.cisco.com/download/home (typically 400 - 900 MB; uploads are capped at 2 GB by default).
- ☐ Uploaded each image on the **Images** tab, keeping Cisco's original filename (see Appendix A).
- ☐ Recorded the Cisco-published MD5 for each image and confirmed it matches the MD5 shown in the Images table.
- ☐ Confirmed the auto-detected **Version** and **Model Pattern** on each image row are correct (9200 images match `9200`, 9300 and above match `9300`, and so on).
- ☐ Confirmed the target version is compatible with all hardware in scope (Cisco release notes).
- ☐ Confirmed every switch in scope is running in install mode. **Check status** (or Prestage) fills the campaign's **Mode** column; any switch showing BUNDLE must be converted before it can be upgraded.
- ☐ Confirmed SSH (port 22) and SCP are enabled on every switch (see Appendix B).
- ☐ Confirmed there is enough free space on `flash:` for the image plus its unpacked packages.
- ☐ Created the campaign with only the in-scope devices, the correct image map, and reviewed options (see Appendix C).
- ☐ For dual-sup / StackWise Virtual: confirmed the standby is STANDBY HOT with `show redundancy`.
- ☐ Ran the Prestage phase during business hours and confirmed every device shows success.
- ☐ Ran the Transfer phase during business hours and reviewed each device log for MD5 verified and packages verified.
- ☐ Confirmed console or out-of-band access is available for every switch in scope, or that an on-site contact is available.
- ☐ Confirmed nobody else has a change scheduled on the same switches or sites during the window.
- ☐ If scheduling the reload: confirmed the campaign uses the service credential, or a credential that does not require an interactive session.

### Document and Save Configurations - Before Change

The Prestage phase does this automatically. For each switch it:

1. Retrieves the full `show running-config` and saves it under the campaign's **Backups** tab as `backup_<hostname>_<timestamp>.txt`. For a switch that is in the inventory, the same capture (with `show running-config all`) is also stored in **Config Backups**, where backup search finds it
2. Runs `write memory` so the startup-config on the switch matches the running-config

Confirm a backup file exists for every switch before proceeding by opening the **Backups** tab in the campaign.

If Prestage was skipped, or you want a manual copy, run the following on each switch and save the output:

```
show running-config
show version
show install summary
show switch          ! stacks only
show redundancy      ! dual-sup / StackWise Virtual only
show inventory
```

Record the current version for each switch so you know what "rolled back" looks like:

| Switch | Current Version (before) | Target Version (after) |
|---|---|---|
| | | |
| | | |
| | | |

---

## Lab, Testing, Proof of Concept

The tool supports the following platforms:

- Cisco Catalyst 9200 / 9200L
- Cisco Catalyst 9300 / 9300L
- Cisco Catalyst 9400 (including dual-supervisor chassis)
- Cisco Catalyst 9600 (including dual-supervisor chassis and StackWise Virtual pairs)

Before using a new target version or a new switch model in production, upgrade one lab or non-critical switch first. Create a separate campaign containing only that device and run all four phases. Confirm the lab switch returns on the expected version, that its configuration is intact, and that attached devices work normally. Record the result:

| Lab Switch | Model | From Version | To Version | Result | Date | Tested By |
|---|---|---|---|---|---|---|
| | | | | ☐ Pass ☐ Fail | | |

Cisco also publishes release notes and known-caveat lists for every IOS-XE release. Review them for the target version before the change.

---

## Work

All steps below are performed in the Plexus web UI under **Network → Software → Upgrades**. Open the campaign to see the **Upgrade steps** panel and the device table. Each step runs against **all campaign devices**, or only the devices you select in the table ("Steps apply to" shows the current target). Progress streams live into the per-device logs; click a device to see its full log.

### Step 0. Open the session and confirm the plan

1. Log in to Plexus and open **Network → Software → Upgrades → Campaigns**.
2. Open the campaign for this RFC and confirm the device list contains only the switches in this change.
3. Confirm the image map points at the image(s) named in the RFC and that each has the expected version and MD5.
4. Confirm the options are as intended. **Verify upgrade after reboot** should be on unless there is a specific reason otherwise.
5. Announce the start of the change in the team chat channel.

### Step 1. Prestage (no outage) - skip if already done in Pre-Work

Click **Run prestage**. On each device the tool:

1. Connects and detects the model and running version, then resolves the target image from the image map.
2. Reads the boot mode and shows it in the **Mode** column. A BUNDLE-mode switch fails Prestage here, because install-mode upgrades and ISSU cannot run on it.
3. Runs a pre-flight health check (skippable). A failed check fails the device and stops it there.
4. Backs up `show running-config` (downloadable later from the **Backups** tab, and stored in **Config Backups** for an inventory switch).
5. Saves the config (`write memory`).
6. Frees flash space with `install remove inactive`.

**What you will see, per device:** model and version detected, image resolved, health check result, backup saved, config saved, inactive packages removed.

**If it fails:** The most common cause is a health-check failure or "No image map match for model". Open the device log for the specific warnings. Do not upgrade an unhealthy switch. Fix the cause and use **Retry failed (N)** to re-run only the devices that failed.

### Step 2. Transfer (no outage, slow) - skip if already done in Pre-Work

Click **Run transfer**. On each device the tool:

1. Checks free space on `flash:`.
2. Reads the switch's TCP and SSH receive windows and logs a warning when they will slow the copy (see Appendix B). The transfer continues either way and no configuration is changed.
3. Copies the image via SCP (30 - 60 minutes per device is normal).
4. Verifies the on-device MD5 against the uploaded image (skippable).
5. Runs `install add` to unpack the image, and verifies the unpacked packages. Before `install add` it reads `show install summary` (IOS-XE). If an earlier install is still uncommitted it logs a warning, because Activate will be refused until that install is closed. The transfer itself goes on.

**Dual-sup / StackWise Virtual:** before `install add`, the standby supervisor must be **STANDBY HOT**. If it isn't, the transfer is refused (with "Skip health check" enabled it is only a warning). This is because `install add` silently skips syncing packages to a cold or absent standby and the problem would otherwise only surface at Activate time. Timeouts are automatically widened for redundant chassis.

**What you will see, per device:** flash free space, a live progress bar in the device's Status cell (percent, MB sent, rate, ETA), MD5 verified, `install add` output, packages verified.

**If it fails:** See Appendix E. Use **Retry failed (N)** to re-run only the devices that failed.

**Check status (read-only):** the **Check status** button next to "Upgrade steps" reconnects to each selected device and resets its checkmarks from what is actually on the switch. Nothing is copied, installed or reloaded. Use it when time has passed between Transfer and the reload window, or when checkmarks look wrong.

| What the switch shows | Result |
|---|---|
| Already running the target version | Every step is marked done |
| Running the target version, but it was never committed | Transfer is marked failed with "not committed". Run **Activate** to commit it (no reload), or run `install commit` on the switch |
| An earlier install is still uncommitted (another version in state U, or a package in state D) | Transfer is marked failed with the same message Activate gives (see Appendix E). With **Commit a pending install before activating** on, when the uncommitted version is the running one, it is only a warning |
| Image on flash, MD5 matches the server copy, `install add` artifacts present | Transfer is marked done, ready to activate |
| Image on flash and complete, but not expanded | Transfer is marked failed. **Retry failed** finishes `install add` without re-copying the image |
| Image on flash but MD5 mismatch (partial/corrupt copy) | Transfer is marked failed. **Retry failed** re-copies it |
| Image not on flash | Transfer is left pending |
| Switch unreachable, or the check errors | The previous checkmark is kept and the error is shown |

### Step 3. Activate (OUTAGE - maintenance window only)

Confirm you are inside the approved window before running this step.

Two ways to start it:

- **Activate now (reload)** - starts immediately after confirmation.
- **Schedule…** - pick a future date/time (shown in your local timezone). The reload then runs unattended at that time. Scheduled reloads survive a Plexus server restart. If the server was down when the window arrived, the campaign is marked **"Reload missed - reschedule"** and nothing reloads out-of-window.

On each device the tool will:

1. Re-verify the image on flash, then check the boot-mode gate and (on redundant chassis) the redundancy gate. A non-HOT standby blocks activation.
2. Read `show install summary` (IOS-XE install mode). Activate is refused, before any command is sent, when:
   - an earlier install is still open: a version is "Activated & Uncommitted" (U) or a package is "Deactivated & Uncommitted" (D). The message names the version, the auto-abort timer state and, when the timer runs, the time before rollback. With the **Commit a pending install before activating** option on, and when the uncommitted version is the one the switch is running, the tool runs `install commit` first (no reload), re-reads the state and goes on only when nothing is left uncommitted.
   - the target version is not listed at all, so `install add` never ran for it. Run Transfer again.
   If the reply cannot be read or is not recognised, the tool logs a warning and goes on as before.
3. Run `install activate` (with the ISSU verb when the ISSU option is set) and the switch reloads:
   - Normal reload: about 5 - 15 minutes (up to about 20 for a fully populated dual-sup chassis).
   - ISSU: standby reloads first, switchover, then the old active reloads. 20 - 45 minutes, but the chassis keeps forwarding.
4. Wait for the switch to go down and come back, then verify the running version.
5. Run `install commit` to make the new version permanent. For ISSU it first waits for the former active to return as STANDBY HOT, because committing earlier would abort the ISSU. After commit it re-reads the version to confirm nothing rolled back. Then it reads `show install summary` once more: the target must be committed (C) and nothing may be left uncommitted.

If the switch already runs the target version, Activate does not reload it. When that version was never committed, the tool runs `install commit` first and marks the device done only when the commit succeeds.

**How the activate reply is read.** The tool keeps the switch's reply to `install activate`:

- If the reply says the activate failed (a `FAILED` line, a `% ` error line, "not allowed", "no inactive package"), the device fails at once with the switch's own text. The tool does not wait for a reload that will not come.
- If the SSH session closes, the reload has started. The log says "SSH session closed (expected during reload)".
- If the prompt does not come back within 2 minutes but the session is still open, the log says the switch has not finished the activate yet. The tool keeps reading the switch's output until a failure line appears (the device fails with that text), the session closes (the reload started) or the prompt returns. This reading time comes out of the budget for the switch to go offline, so the overall wait does not grow.

**When the switch did not reload or came back on the wrong version**, the tool reconnects, reads `show install summary` and `show install log`, and adds a short diagnosis to the error. For example: "Version mismatch: 17.x. Switch did not reload. Install state: 17.x (running) activated but not committed, auto-abort timer inactive. Last install operation: install_activate FAILED: ...". Platforms without these commands keep the plain "Version mismatch" message.

Expect no response from the switch for 5 - 15 minutes during step 4. This is normal. Do not cancel the step while a device is mid-reload.

If the commit fails or the post-commit version is wrong, the device is marked **failed** and the log will say whether the switch is going to roll back. Act on that before the auto-rollback timer expires (see Roll Back / Backout, Scenario 2).

### Step 4. Verify each switch

Click **Verify upgrade** any time after the reload. The tool reconnects to each device and confirms the running version matches the target image. Use it as the final sign-off, or to re-check devices later.

Then log in to each switch and confirm by hand:

```
show version                 ! Version line shows the target version
show install summary         ! Target packages show state "C" (Activated & Committed)
show switch                  ! Stacks only: all members "Ready"
show redundancy              ! Dual-sup / SVL only: standby is STANDBY HOT
show interfaces status       ! Expected ports up
show ip interface brief      ! Uplinks and SVIs up
show log | include -3-|-2-|-1-    ! No new critical errors
```

Ask the site contact or Verifier to confirm users, phones, and Wi-Fi are working.

### Step 5. Review the summary and record results

The **Operation history** table inside the campaign records every phase run with success and failure counts, timestamps, and who requested it. Use it and the per-device logs to fill in the table below and attach the relevant details to the RFC.

| Switch | Result | Version After | Verified By | Time Completed |
|---|---|---|---|---|
| | ☐ Success ☐ Failed | | | |
| | ☐ Success ☐ Failed | | | |
| | ☐ Success ☐ Failed | | | |

### Step 6. Close out

1. Post completion (or partial completion with details) to the team chat channel.
2. Update the RFC with results and the campaign's operation history.
3. If any switch failed, open the Roll Back / Backout section and follow it before closing the window.

### Monitoring, cancelling, retrying

- **Live logs** - the campaign view streams per-device output in real time.
- **Cancel running step** - stops the current phase. Devices already finished stay finished.
- **Cancel scheduled reload** - cancels a pending scheduled Activate before it fires.
- **Cancel selected activate** - during a running or scheduled Activate, cancels only the selected devices. The rest continue.
- **Retry** - re-running a phase with failed or cancelled devices selected clears their state and runs them again.
- Campaign details, logs, and backups are visible only to the campaign's creator and admins.

---

## Roll Back / Backout

Because install mode keeps the previous software on flash, rollback is a single command and one additional reload. Three scenarios, in order of likelihood:

### Scenario 1. The install was never committed and the switch rolled back on its own

If the tool could not commit (for example the switch came back on the wrong version, or "Verify upgrade after reboot" was off), the switch reloads a second time onto the previous version when its auto-rollback timer expires. The device log will say so. Verify with `show version`, then leave the switch on the old version and investigate after the window.

### Scenario 2. The switch came back on the wrong version, or is misbehaving on the new version

Log in and act before the auto-rollback timer expires. If the state is good and you want to keep the new version:

```
show install summary                 ! Note which packages are "C" (committed) vs "U" (uncommitted)
install commit                       ! Makes the new version permanent
```

If you want to go back, the switch will reload again (another 5 - 15 minute outage):

```
install rollback to committed        ! Reverts to the last committed version and reloads
```

If the new version was already committed (state "C") and you need to go back further:

```
show install rollback                ! Lists rollback points
install rollback to id <n>           ! Roll back to a specific point
```

After it reloads, confirm with `show version` that it is on the original version recorded in the Pre-Work table.

### Scenario 3. The switch did not come back online

The tool cannot recover a switch that does not respond to SSH. This requires console access.

1. Wait the full reload window. Large stacks and dual-sup chassis can take longer than expected.
2. Connect to the console (on-site or out-of-band).
3. If the switch is at the `switch:` ROMMON prompt, it failed to boot the new image. Boot the old one:

   ```
   switch: dir flash:
   switch: boot flash:packages.conf          ! or the previous .bin / .conf
   ```

4. If the switch is booting but hanging, power-cycle it once.
5. If it still fails, escalate per the Escalations table and open a Cisco TAC case. Have the serial number (`show inventory` from the pre-change backup) ready.

### Restoring configuration

The reload does not change configuration. If configuration is ever lost, the pre-change backup is on the campaign's **Backups** tab as `backup_<hostname>_<timestamp>.txt`. Download it and paste it into config mode, or copy it to the switch with SCP and run `configure replace`.

### Backout decision point

If more than ______ switches fail, or the window has less than ______ minutes remaining, stop activating additional switches. Use **Cancel selected activate** or **Cancel scheduled reload** as appropriate. Roll back the failed ones, leave the rest on the current version (their images are staged and can be activated in a future window), and record the decision in the RFC.

---

## Diagrams

None

### Logical Drawings

None

### Physical System Drawings

None

### Detailed Technical Drawings

None

---

## Appendices

### Appendix A. Uploading and verifying the software image

1. Go to **Network → Software → Upgrades → Images**.
2. Upload the IOS-XE `.bin` file. Keep Cisco's original filename (letters, numbers, dot, hyphen, underscore only). The version number is auto-detected from it.
3. After upload, check the row in the Images table:
   - **Version** - auto-detected from the filename (for example `17.15.3`). Verify it.
   - **Model Pattern** - the substring used to match device models (for example `9200`, `9300`). Auto-detected for common images. Edit it if it is blank or wrong.
   - **MD5** - computed on upload and later used to verify the copy on each switch. Compare it against the checksum published on Cisco's download page before proceeding.

Duplicate filenames are rejected. Delete the old image first if you are re-uploading.

### Appendix B. Switch prerequisites

Each switch must have SSH version 2 and the SCP server enabled, and the account used must land at privilege 15. Devices must be running in install mode.

```
ip ssh version 2
ip scp server enable
aaa authorization exec default local
```

Confirm install mode with `show version` (look for "Installation mode is INSTALL").

**Optional, for faster transfers.** An SCP copy can go no faster than the switch's receive window divided by the round-trip time to it. On the default 4128-byte TCP window a switch 50 ms away accepts about 80 KB/s, whatever the link speed. Raising the windows removes that cap:

```
ip tcp window-size 65536
ip ssh bulk-mode
```

The SSH command depends on the release:

- From IOS XE 17.10, SSH bulk mode is on by default and only the TCP window needs raising.
- Some releases accept `ip ssh bulk-mode` only without a size. Use `ip ssh bulk-mode ?` to see what the switch takes.
- Where bulk mode is not available, use `ip ssh window-size 65536` with the TCP window set to the same value.

The switch warns that a larger SSH window can raise CPU load and should be used only for SCP. Try the settings on one switch before rolling them out, and remove them after the upgrade if CPU is a concern. They apply to SSH sessions opened after the change, so set them before starting Transfer. The Transfer phase reports the current values in each device log and warns when either window is small.

### Appendix C. Creating a campaign

1. Go to **Network → Software → Upgrades → Campaigns** and create a new campaign.
2. Fill in:
   - **Campaign Name / Description** - for example `Q2 2026 IOS-XE 17.15 Upgrade`.
   - **Image map** - one row per hardware family: a model pattern (for example `9200`) and the image to install on devices matching it. Longer or more specific patterns win when several match. A device whose model matches no pattern is skipped with a warning.
   - **Credential** - pick your credential, or leave "Use default service credential".
   - **Devices** - tick inventory groups and hosts, and/or paste ad-hoc IPs (one per line).
3. Options (defaults are sensible; change only with a reason):

| Option | Default | Meaning |
|---|---|---|
| Skip config backup | off | Skips saving `show running-config` during Prestage |
| Skip MD5 verification | off | Skips checksum verification after the image copy |
| Skip health check | off | Skips the pre-flight health check (also downgrades the dual-sup standby gate to a warning) |
| Verify upgrade after reboot | **on** | After Activate, wait for the switch to return, confirm the version, and run `install commit`. Turning this off leaves the install uncommitted. The switch rolls back on its own timer unless you commit manually |
| ISSU | off | In-service upgrade for dual-sup / StackWise Virtual only. Requires SSO with the standby in STANDBY HOT. Refused on unsupported platforms |
| Commit a pending install before activating | off | IOS-XE install mode. If the switch runs a version that was activated but never committed, run `install commit` before the activate (no reload). Only the running version is committed. Without this option the activate is refused and you close the install by hand |
| Parallel Workers | 4 (max 8) | Devices upgraded concurrently |
| SSH Retries | 2 | Connection retry attempts per device |

A campaign can be edited later (devices, images, options) as long as no phase is currently running.

### Appendix D. Backups

The **Backups** tab lists every running-config capture taken during Prestage (`backup_<hostname>_<timestamp>.txt`). Download one to diff or restore a config after an upgrade. Delete old ones as needed.

### Appendix E. Troubleshooting

| Symptom | Likely cause | Action |
|---|---|---|
| Device shows "No image map match for model" | The model pattern on the image or in the campaign's image map does not match this device | Add or fix the model pattern on the image (Images tab) or in the campaign's image map |
| Transfer refused: standby not STANDBY HOT | The standby supervisor is cold, absent, or not synced | Fix the standby sup (reseat, boot, sync) before transferring. Do not bypass unless you accept an unsynced standby |
| "Small receive window on the switch" warning; transfer runs at tens of KB/s | The switch's TCP or SSH receive window is at its default, which caps SCP speed on a high-latency path | Apply the window settings in Appendix B, then cancel and re-run Transfer. The running copy keeps its old window |
| Health check FAILED | Switch is not healthy enough to upgrade safely | Open the device log for the specific warnings. Fix and re-run Prestage |
| "Device is booted in BUNDLE mode" (Prestage, Transfer, Check status or Activate); **Mode** shows BUNDLE | The switch boots the `.bin` directly, not `packages.conf` | Convert the switch to install mode first, then re-run the step. No image is copied while it is in bundle mode |
| "ISSU not supported on this platform" | The device does not support in-service upgrade | Untick the ISSU option. The device will do a normal reload |
| "Reload missed - reschedule" | The Plexus server was down over the scheduled window | Schedule a new time |
| "An earlier install is still open on the switch: ... is activated but not committed" (Activate, Check status, warning in Transfer) | An earlier upgrade activated a version and never committed it. The install is still open, so the switch refuses a new activate. With the auto-abort timer inactive it stays that way | On the switch run `show install summary`. Then run `install commit` to keep the running version (no reload), or `install abort` to roll back to the last committed version (reloads). Or turn on **Commit a pending install before activating** in the campaign and run Activate again |
| "Target ... is not added on the switch" | `show install summary` does not list the target version, so `install add` did not run or the package was removed | Run Transfer again. It re-runs `install add` without re-copying a good image |
| "Activate failed on the switch: ..." | The switch answered `install activate` with an error. It did not reload | Read the switch's text in the error. Check `show install summary` and `show install log`, fix the cause, then run Activate again |
| "Version mismatch: ... Switch did not reload. Install state: ..." | The activate did not take effect, or the switch rolled back | The diagnosis names the install state and the last install operation. Act on it as above |
| "install commit ran but the switch still lists an open install" | `install commit` did not close the install | Check `show install summary` and `show install log` on the switch |
| Commit failed / switch will roll back | The post-reload version check or `install commit` did not succeed | Connect to the switch and investigate immediately. Run `install commit` manually if the state is good, before the rollback timer expires |
| Image upload fails with a storage error | The image directory is not writable by the application | On Docker deployments: `sudo chown -R 1000:1000 ./software_images`, then restart the container |

Manual recovery commands on the switch:

```
show install summary            ! Current package states
show install log                ! What the install process did
install commit                  ! If packages are in "U" (uncommitted) state
install rollback to committed   ! Revert to last committed version (reloads)
install remove file flash:<filename>
```

### Appendix F. How install mode works

The tool runs the install in separate steps so the reboot can be scheduled apart from the copy:

```
install add file flash:<image>.bin      ! Transfer phase: unpacks packages onto flash, no reload
install activate                        ! Activate phase: switches to the new packages and reloads
install commit                          ! Verify: makes the new packages permanent
```

Until `install commit` runs, the switch keeps a rollback timer and will revert to the previously committed packages on its own if the timer expires. The tool commits automatically after it confirms the running version.

The timer can also be inactive. Then an uncommitted version stays uncommitted and the install stays open. IOS-XE refuses the next `install activate` until it is closed with `install commit` or `install abort`. This is why the tool reads `show install summary` before Activate, in Check status and in Transfer, and refuses to activate while an install is open. `show install summary` marks each package I (Inactive), U (Activated & Uncommitted), C (Activated & Committed) or D (Deactivated & Uncommitted), and shows the auto-abort timer.

These install-state checks cover Cisco IOS-XE in install mode only. IOS-XR has a similar add, activate and commit model, but the tool does not read its install state yet. That is a known gap. Other platforms have no such check and behave as before.

### Appendix G. Scheduling unattended reloads

Use **Schedule…** on the Activate step and pick a future date and time. The reload runs unattended at that time. For this to work:

- The campaign must use the site-wide **service credential**, or a credential that is available without an interactive session.
- **Verify upgrade after reboot** should be on so the install is committed automatically.
- The Plexus server must be running when the window arrives. Scheduled reloads survive a server restart, but if the server is down over the window the campaign is marked "Reload missed - reschedule" and nothing reloads.

Use **Cancel scheduled reload** to cancel a pending schedule before it fires.

---

## APC Smart-UPS (Network Management Card)

The same campaigns update APC Smart-UPS firmware through the UPS's Network Management Card (NMC2 or NMC3), following Schneider Electric FAQ000242942 / FA170679. A UPS is an inventory host with device type `apc_ups` (see [APC Smart-UPS](apc-ups.md) for adding it and for monitoring). Scheduling, batches (selected devices), approval, cancel and the live log work as they do for switches.

### Prerequisites

- SSH and SCP enabled on the NMC (Configuration > Network > Console > Access). Plexus logs in to the NMC command line (`apc>` prompt) over SSH and copies the file with SCP, using the legacy SCP protocol (the equivalent of `scp -O`).
- A credential that logs in to the NMC as an administrator: the campaign's credential, or the service credential when the campaign has none.
- NMC application firmware: NMC2 `sumx` v6.4.0 or later, NMC3 `su` v1.0 or later. A Smart-UPS Ultra (UPS ID 1226 or 1227) needs NMC firmware 2.5.4.4 or later.
- The firmware file for the UPS in the image library (**Upgrades > Images > Upload**). Upload the vendor `.enc` file with its original name, `<prefix><UPS ID>UPS_<major>-<minor>.enc` (for example `SRT1025UPS_15-0.enc`), or the vendor `.zip` that holds it; Plexus unpacks the one `.enc` (a zip with several `.enc` files, unsafe paths or an oversize file is refused). The library shows the UPS ID as the model pattern and the version (`15.0`). Plexus never downloads firmware from the vendor.

### Campaigns

A campaign holds either UPS devices or other devices, not both (create and edit refuse a mix, and ad-hoc addresses count as switches). Add the UPS firmware files to the image map; by convention the pattern is the UPS ID. Each UPS takes the mapped file whose UPS ID matches the ID the NMC reports, the newest one when there are several.

| Step | What it does on a UPS |
|---|---|
| Prestage | Pre-checks only: reads `upsabout` (UPS ID, firmware), `about` (NMC generation and application firmware) and `alarmcount`. Nothing changes on the UPS. |
| Transfer | Repeats the pre-checks, copies the file to `/tmp/<file>` on the NMC with SCP and confirms it with `cd /tmp` and `dir`. |
| Activate (**Install now** or scheduled) | Repeats the pre-checks, runs `upsfwupdate -install -file "/tmp/<file>"` (copying the file first if it is no longer in `/tmp`), polls `upsfwupdate -status` every 20 seconds until it reports `No firmware update in progress` (or `... is in progress`, depending on the card firmware), then reads `upsabout` again and requires the new version. The UPS output stays on. |
| Verify | Reads `upsabout` and compares it with the target. |
| Check status | Read only: already on the target (every step done), an update in progress, or whether the file is in `/tmp`. |

There is no commit step for a UPS.

### Pre-checks

A device is stopped with the reason shown in its status when:

- the UPS or NMC has active alarms (`alarmcount` is not 0, or cannot be read);
- the NMC firmware is below the minimum, or the NMC cannot be identified from `about`;
- no image in the campaign is for the UPS's ID (the NMC would refuse it);
- the image is older than the running firmware (Plexus never downgrades). An image at the running version means the UPS is already up to date: every step is marked done and nothing is installed.

### Special UPS IDs

- **1001** updates twice: `SRT1001UPS_02-9.enc` (which changes the UPS ID to 1013), then the newest UPS ID 1013 file (for example `SRT1013UPS_15-0.enc`). Activate runs both back to back when both are in the image library; otherwise the device is stopped naming the missing file.
- **1226 / 1227** (Smart-UPS Ultra, SRTL) need a manual Logic Reset ("brain dead" reset) before the update. Prestage passes them to **Waiting for Logic Reset**; Transfer and Activate wait too. Do the reset, then press **Confirm Logic Reset** on the device in the campaign. The confirmation is recorded with your name in the campaign log and the audit log (`logic_reset_confirm`). Do the reset before Transfer: it can restart the NMC, which empties `/tmp` (Activate copies the file again if it is gone).
- **1225** (Smart-UPS Modular Ultra) needs the extra steps in Schneider FAQ000261838 and is marked **Manual**.

### Manual updates

Plexus never turns the UPS output off. When a model needs its output off for the update (the NMC refuses the install with a message about the output being off, or the UPS ID is listed in `OUTPUT_OFF_REQUIRED_IDS` in `netcontrol/integrations/apc/firmware.py`, which is filled in from Schneider's model table) the device is marked **Manual** with the reason, and a person updates it.

### Timeouts and cancel

An install may take several minutes. Plexus waits up to 30 minutes per UPS, 45 minutes for a Smart-UPS Modular Ultra (SRYL), then fails the device. Cancelling the campaign or the device stops Plexus from watching between two status polls, but an install already started on the UPS cannot be aborted: it continues on its own, and the log says so. Use **Check status** later to see the result.

### Verification

After the install Plexus reads `upsabout` again. When the firmware is unchanged the device fails with "Firmware file was transferred but not installed" (Schneider FAQ000258690); check the NMC event log and that the file was for this UPS ID.

### Gaps

- FTP transfer is not supported: it is cleartext and needs enabling plus an NMC reboot. Use SCP.
- No automated UPS output control (see Manual updates).
- The `OUTPUT_OFF_REQUIRED_IDS` table starts empty; until it is filled, such a model is caught by the NMC's refusal.
- The layout of `upsabout`, `about`, `alarmcount` and `upsfwupdate -status` output has been checked on an embedded NMC3 (application `su` v2.0) in a Smart-UPS SRT, not on every NMC firmware; `upsfwupdate -install` output and an NMC2 have not been seen yet. Plexus reads `Key: value` lines without regard to case and ignores lines it does not know; when a value cannot be read the device is stopped with a reason (for example "Could not read the UPS ID") rather than guessed. If that happens, send a sample of the command output (with serial numbers and addresses removed) so the parser can be extended.

---

## External Documentation
- Plexus Application Code base - https://github.com/RickeyNet/Plexus 
- Cisco Catalyst 9000 Series Software Installation and Upgrade (install mode):
- Cisco Software Download Center: https://software.cisco.com/download/home
- Cisco IOS-XE Release Notes (select the target release for your platform):
- Cisco In-Service Software Upgrade (ISSU) for Catalyst 9400 / 9600:
- Cisco TAC Support:
- Change Control / RFC system: ______________________________
