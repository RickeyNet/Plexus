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
| Upgrade tool | Plexus web UI: **Delegator → Upgrades** |
| Software images | **Delegator → Upgrades → Images** tab |
| Campaigns | **Delegator → Upgrades → Campaigns** tab |
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
- The tool refuses to activate on bundle-mode devices.
- The switch is not rebooted until the image is re-verified on flash and the boot-mode and redundancy gates pass.
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
- ☐ Confirmed you have a Plexus account with access to the **Delegator → Upgrades** page (the `upgrades` feature).
- ☐ Confirmed a device credential with privileged EXEC access to every target switch, either one you own or the site-wide service credential in Settings.
- ☐ Downloaded the target IOS-XE image(s) from https://software.cisco.com/download/home (typically 400 - 900 MB; uploads are capped at 2 GB by default).
- ☐ Uploaded each image on the **Images** tab, keeping Cisco's original filename (see Appendix A).
- ☐ Recorded the Cisco-published MD5 for each image and confirmed it matches the MD5 shown in the Images table.
- ☐ Confirmed the auto-detected **Version** and **Model Pattern** on each image row are correct (9200 images match `9200`, 9300 and above match `9300`, and so on).
- ☐ Confirmed the target version is compatible with all hardware in scope (Cisco release notes).
- ☐ Confirmed every switch in scope is running in install mode. The tool refuses to activate on bundle-mode devices.
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

1. Retrieves the full `show running-config` and saves it under the campaign's **Backups** tab as `backup_<hostname>_<timestamp>.txt`
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

All steps below are performed in the Plexus web UI under **Delegator → Upgrades**. Open the campaign to see the **Upgrade steps** panel and the device table. Each step runs against **all campaign devices**, or only the devices you select in the table ("Steps apply to" shows the current target). Progress streams live into the per-device logs; click a device to see its full log.

### Step 0. Open the session and confirm the plan

1. Log in to Plexus and open **Delegator → Upgrades → Campaigns**.
2. Open the campaign for this RFC and confirm the device list contains only the switches in this change.
3. Confirm the image map points at the image(s) named in the RFC and that each has the expected version and MD5.
4. Confirm the options are as intended. **Verify upgrade after reboot** should be on unless there is a specific reason otherwise.
5. Announce the start of the change in the team chat channel.

### Step 1. Prestage (no outage) - skip if already done in Pre-Work

Click **Run prestage**. On each device the tool:

1. Connects and detects the model and running version, then resolves the target image from the image map.
2. Runs a pre-flight health check (skippable). A failed check fails the device and stops it there.
3. Backs up `show running-config` (downloadable later from the **Backups** tab).
4. Saves the config (`write memory`).
5. Frees flash space with `install remove inactive`.

**What you will see, per device:** model and version detected, image resolved, health check result, backup saved, config saved, inactive packages removed.

**If it fails:** The most common cause is a health-check failure or "No image map match for model". Open the device log for the specific warnings. Do not upgrade an unhealthy switch. Fix the cause and use **Retry failed (N)** to re-run only the devices that failed.

### Step 2. Transfer (no outage, slow) - skip if already done in Pre-Work

Click **Run transfer**. On each device the tool:

1. Checks free space on `flash:`.
2. Copies the image via SCP (30 - 60 minutes per device is normal).
3. Verifies the on-device MD5 against the uploaded image (skippable).
4. Runs `install add` to unpack the image, and verifies the unpacked packages.

**Dual-sup / StackWise Virtual:** before `install add`, the standby supervisor must be **STANDBY HOT**. If it isn't, the transfer is refused (with "Skip health check" enabled it is only a warning). This is because `install add` silently skips syncing packages to a cold or absent standby and the problem would otherwise only surface at Activate time. Timeouts are automatically widened for redundant chassis.

**What you will see, per device:** flash free space, transfer progress, MD5 verified, `install add` output, packages verified.

**If it fails:** See Appendix E. Use **Retry failed (N)** to re-run only the devices that failed. If time has passed between Transfer and the reload window, click **Re-verify** (on the Prestage step) to re-check the unpacked artifacts on flash.

### Step 3. Activate (OUTAGE - maintenance window only)

Confirm you are inside the approved window before running this step.

Two ways to start it:

- **Activate now (reload)** - starts immediately after confirmation.
- **Schedule…** - pick a future date/time (shown in your local timezone). The reload then runs unattended at that time. Scheduled reloads survive a Plexus server restart. If the server was down when the window arrived, the campaign is marked **"Reload missed - reschedule"** and nothing reloads out-of-window.

On each device the tool will:

1. Re-verify the image on flash, then check the boot-mode gate and (on redundant chassis) the redundancy gate. A non-HOT standby blocks activation.
2. Run `install activate` (with the ISSU verb when the ISSU option is set) and the switch reloads:
   - Normal reload: about 5 - 15 minutes (up to about 20 for a fully populated dual-sup chassis).
   - ISSU: standby reloads first, switchover, then the old active reloads. 20 - 45 minutes, but the chassis keeps forwarding.
3. Wait for the switch to go down and come back, then verify the running version.
4. Run `install commit` to make the new version permanent. For ISSU it first waits for the former active to return as STANDBY HOT, because committing earlier would abort the ISSU. After commit it re-reads the version to confirm nothing rolled back.

Expect no response from the switch for 5 - 15 minutes during step 3. This is normal. Do not cancel the step while a device is mid-reload.

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

1. Go to **Delegator → Upgrades → Images**.
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

### Appendix C. Creating a campaign

1. Go to **Delegator → Upgrades → Campaigns** and create a new campaign.
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
| Health check FAILED | Switch is not healthy enough to upgrade safely | Open the device log for the specific warnings. Fix and re-run Prestage |
| Activate refused: bundle mode / boot-mode gate | The switch is not in install mode | Convert the switch to install mode first |
| "ISSU not supported on this platform" | The device does not support in-service upgrade | Untick the ISSU option. The device will do a normal reload |
| "Reload missed - reschedule" | The Plexus server was down over the scheduled window | Schedule a new time |
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

### Appendix G. Scheduling unattended reloads

Use **Schedule…** on the Activate step and pick a future date and time. The reload runs unattended at that time. For this to work:

- The campaign must use the site-wide **service credential**, or a credential that is available without an interactive session.
- **Verify upgrade after reboot** should be on so the install is committed automatically.
- The Plexus server must be running when the window arrives. Scheduled reloads survive a server restart, but if the server is down over the window the campaign is marked "Reload missed - reschedule" and nothing reloads.

Use **Cancel scheduled reload** to cancel a pending schedule before it fires.

---

## External Documentation
- Plexus Application Code base - https://github.com/RickeyNet/Plexus 
- Cisco Catalyst 9000 Series Software Installation and Upgrade (install mode):
- Cisco Software Download Center: https://software.cisco.com/download/home
- Cisco IOS-XE Release Notes (select the target release for your platform):
- Cisco In-Service Software Upgrade (ISSU) for Catalyst 9400 / 9600:
- Cisco TAC Support:
- Change Control / RFC system: ______________________________
