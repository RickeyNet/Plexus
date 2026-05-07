# Ubuntu 26.04 VM Setup for Plexus (Air-Gapped)

Step-by-step prep for a fresh Ubuntu Server 26.04 VM **before** running the
Plexus air-gap installer. Covers networking, hostname, SSH, time sync, RDP
desktop access, Active Directory join, and firewall.

This doc assumes you already extracted `plexus-airgap.tar.gz` somewhere on
the VM (the `desktop-debs/` directory it contains is what every `dpkg`
command below installs from).

> **Anything in `<angle brackets>` is a placeholder you replace with values
> from your network team.**

---

## 0. Console access first

Until networking and SSH are working, you'll do this from the VM's console
(VMware/Hyper-V/Proxmox console window, or physical KVM). Get a working
shell as a sudo-capable local user before continuing.

---

## 1. Hostname

Pick a hostname that matches what users will type into RDP / browsers (e.g.
`plexus`, `plexus.corp.local`). The self-signed TLS cert generated later
uses this hostname's FQDN as the cert SAN, so set it before running the
Plexus installer.

```bash
sudo hostnamectl set-hostname <HOSTNAME>
```

If your network has DNS, also make sure forward + reverse records exist for
`<HOSTNAME>` pointing at the static IP you'll set in step 2. Without DNS,
users will browse to `https://<IP>` and accept the cert warning per-IP.

---

## 2. Static IP (netplan)

Ubuntu Server uses netplan. The default file is usually
`/etc/netplan/00-installer-config.yaml` or `/etc/netplan/50-cloud-init.yaml`.
Find it:

```bash
ls /etc/netplan/
```

Replace its contents with a static config (substitute your interface name —
find it with `ip -br link`, typically `ens18`, `eth0`, or `enp0s3`):

```yaml
network:
  version: 2
  renderer: networkd
  ethernets:
    <INTERFACE>:
      dhcp4: false
      addresses:
        - <IP>/<CIDR>          # e.g. 10.0.0.50/24
      routes:
        - to: default
          via: <GATEWAY>       # e.g. 10.0.0.1
      nameservers:
        addresses:
          - <DNS1>             # e.g. your AD domain controller
          - <DNS2>
        search:
          - <DOMAIN>           # e.g. corp.local
```

Apply:

```bash
sudo chmod 600 /etc/netplan/*.yaml      # netplan warns if world-readable
sudo netplan apply
ip addr show <INTERFACE>                # confirm the IP is set
ping -c 2 <GATEWAY>                     # confirm L3 reachability
```

If you typo the file, `sudo netplan try` will roll back automatically after
120 s if you don't confirm — safer than `apply` for remote edits.

---

## 3. Time sync (NTP)

Plexus needs accurate time for TLS, Kerberos (AD), and audit logs. Ubuntu's
default `systemd-timesyncd` works but `chrony` is more flexible for
internal NTP. The bundle ships `chrony` as a `.deb`.

Install from the local debs:

```bash
cd ~/plexus-airgap-bundle/desktop-debs
sudo dpkg -i chrony*.deb libnss3*.deb libtomcrypt1*.deb 2>/dev/null || true
sudo apt-get install -f --no-download   # resolve any local-only deps
```

> If `apt-get install -f` complains it can't reach the internet, that's
> fine — the air-gap apt sources are already gone after step 5. Use
> `sudo dpkg -i *.deb` and let dpkg sort dependencies among the bundled
> files. The bundle is built with `apt-get install --download-only` which
> resolves the full dependency closure, so everything chrony needs is
> already in the directory.

Edit `/etc/chrony/chrony.conf`. Comment out the `pool ...debian.pool.ntp.org`
lines and add your time source(s):

```conf
# Internal NTP server (preferred for air-gapped networks)
server <INTERNAL_NTP> iburst

# Or, if the VM can reach an external NTP server:
# server <EXTERNAL_NTP> iburst    # e.g. time.nist.gov

# Allow time to step (large jump) on the first three updates only.
makestep 1.0 3
```

Restart and verify:

```bash
sudo systemctl enable --now chrony
chronyc sources -v
chronyc tracking
```

`chronyc tracking` should show "Leap status : Normal" within ~30 s.

---

## 4. SSH access

OpenSSH server is in the bundle. Install:

```bash
cd ~/plexus-airgap-bundle/desktop-debs
sudo dpkg -i openssh-server*.deb openssh-sftp-server*.deb openssh-client*.deb 2>/dev/null || true
sudo systemctl enable --now ssh
```

Add your public key (paste it into the file — `nano` is on a base server
install; otherwise `cat >> ~/.ssh/authorized_keys` and Ctrl-D):

```bash
mkdir -p ~/.ssh && chmod 700 ~/.ssh
nano ~/.ssh/authorized_keys      # paste your id_ed25519.pub or id_rsa.pub
chmod 600 ~/.ssh/authorized_keys
```

Lock down `/etc/ssh/sshd_config` (recommended):

```conf
PasswordAuthentication no
PermitRootLogin no
```

```bash
sudo systemctl restart ssh
```

Test from your workstation **before** disabling password auth on a remote
session — keep one console session open as a fallback.

---

## 5. RDP desktop (XFCE + xrdp)

Install XFCE and xrdp from the bundled `.deb`s. There are a lot of files;
let `dpkg` consume the whole directory at once.

```bash
cd ~/plexus-airgap-bundle/desktop-debs
sudo dpkg -i *.deb
# If dpkg reports unmet deps, run again — dpkg processes packages in the
# order it reads them, and a second pass usually resolves what was deferred.
sudo dpkg -i *.deb
```

Configure xrdp to launch XFCE on login:

```bash
echo "xfce4-session" | sudo tee /etc/skel/.xsession
# Existing users: copy to their home dir too
echo "xfce4-session" > ~/.xsession
chmod +x ~/.xsession
```

Enable + start:

```bash
sudo systemctl enable --now xrdp
sudo adduser xrdp ssl-cert        # lets xrdp read the TLS cert it generates
sudo systemctl restart xrdp
```

Test from a Windows machine: `mstsc` → connect to `<IP>` → log in with the
local user account you use for SSH. You should land in an XFCE desktop.

> If you see a black screen after login, the most common cause is `~/.xsession`
> missing or not executable. Re-check `ls -l ~/.xsession`.

---

## 6. Active Directory integration (Linux host login)

This joins the VM to your AD domain so users can SSH/RDP in with their AD
credentials and `sudo` based on AD group membership. Plexus-app-level AD
auth is configured separately in the web UI (see "Plexus → AD" below).

### Prerequisites
- DC reachable from the VM on TCP/UDP 88 (Kerberos), 389/636 (LDAP/LDAPS),
  53 (DNS), 464 (kpasswd).
- Time sync against the domain (step 3) — Kerberos rejects skew > 5 min.
- An AD account with permission to join machines to the domain (or a
  pre-created computer object).

### Install AD-join packages
Already covered by the `dpkg -i *.deb` in step 5 (the bundle includes
`realmd`, `sssd`, `sssd-tools`, `adcli`, `oddjob`, `oddjob-mkhomedir`,
`packagekit`, `samba-common-bin`, `krb5-user`).

### Discover and join
Replace `<DOMAIN>` with your AD domain (e.g. `corp.local`) and `<JOIN_USER>`
with an account allowed to join machines:

```bash
sudo realm discover <DOMAIN>
sudo realm join -U <JOIN_USER> <DOMAIN>
```

`realm` writes a basic `sssd.conf` on success. Verify the VM is joined:

```bash
realm list
id <DOMAIN_USER>@<DOMAIN>     # should print uid/gid + group list
```

### Allow logins by AD users
By default, after `realm join`, all valid AD users in the domain can log in.
Lock it down to a specific group:

```bash
sudo realm permit -g 'Network Admins'@<DOMAIN>
```

Or restrict to specific users:

```bash
sudo realm permit jdoe@<DOMAIN> jsmith@<DOMAIN>
```

### Auto-create home directories on first login
Already enabled by `oddjob-mkhomedir`. Confirm:

```bash
grep -i mkhomedir /etc/pam.d/common-session
# expect: session optional pam_mkhomedir.so umask=0077 ...
```

If missing, run `sudo pam-auth-update --enable mkhomedir`.

### Sudo via AD group
Drop a sudoers file that grants `sudo` to an AD group:

```bash
sudo bash -c 'cat > /etc/sudoers.d/ad-admins <<EOF
%network\ admins@<DOMAIN> ALL=(ALL) ALL
EOF'
sudo chmod 0440 /etc/sudoers.d/ad-admins
sudo visudo -cf /etc/sudoers.d/ad-admins  # syntax check
```

> Group names with spaces need the backslash escape, and AD makes
> everything lowercase by default in `id` output. Match what `id`
> shows, not what AD displays.

### Test
- SSH in as `jdoe@<DOMAIN>` — should work and create `/home/jdoe@<DOMAIN>/`.
- RDP in as `jdoe@<DOMAIN>` (or just `jdoe` if `default_domain_suffix` is
  set in `/etc/sssd/sssd.conf`) — should land in XFCE.
- Run `sudo whoami` as a member of your admin group — should print `root`.

---

## 7. Firewall (ufw)

Open only what you need. Adjust based on which collectors you'll use.

```bash
sudo ufw default deny incoming
sudo ufw default allow outgoing

# Management
sudo ufw allow 22/tcp           # SSH
sudo ufw allow 3389/tcp         # RDP

# Plexus web UI (handled by nginx)
sudo ufw allow 80/tcp           # HTTP → HTTPS redirect
sudo ufw allow 443/tcp          # HTTPS

# Plexus collectors (only open the ones you'll actually receive on)
sudo ufw allow 2055/udp         # NetFlow
sudo ufw allow 6343/udp         # sFlow
sudo ufw allow 162/udp          # SNMP traps
sudo ufw allow 1514/udp         # Syslog

sudo ufw enable
sudo ufw status verbose
```

> Restrict by source if you can — `sudo ufw allow from <CIDR> to any port 22`
> is safer than the open `allow 22/tcp` on a sensitive network.

---

## 8. Plexus → Active Directory (web UI)

This is **separate** from the host AD join in step 6 — this controls who
can log into Plexus's web UI.

After the Plexus stack is running (per the main README):

1. Browse to `https://<HOSTNAME>` and log in as `admin` / `netcontrol`.
2. Force-change the admin password.
3. Settings → Authentication Provider → **LDAP / Active Directory**.
4. Fill in:

| Field                    | Example                                                 |
|--------------------------|---------------------------------------------------------|
| LDAP Server              | `dc01.<DOMAIN>`                                         |
| Port                     | `389` (LDAP) or `636` (LDAPS — check "Use SSL")         |
| Service Account DN       | `CN=svc_plexus,OU=Service Accounts,DC=corp,DC=local`    |
| Service Account Password | *(read-only AD service account)*                        |
| Base DN                  | `DC=corp,DC=local`                                      |
| User Search Filter       | `(sAMAccountName={username})`                           |
| Admin Group DN           | `CN=Network Admins,OU=Groups,DC=corp,DC=local`          |

5. Check "Enable LDAP / Active Directory authentication" → Save.
6. Log out, log back in with your AD credentials.

For a deeper walkthrough including troubleshooting, see
[deploy/DEPLOYMENT.md](../DEPLOYMENT.md).

---

## 9. Now run the Plexus installer

You're ready for the main air-gap install. From the bundle root:

```bash
cd ~/plexus-airgap-bundle
sudo bash install.sh
```

Then jump back to [README.md](README.md) for first-login steps.

---

## Troubleshooting

### `dpkg -i *.deb` keeps failing on missing dependencies
Something Plexus's `bundle.sh` didn't anticipate. Either (a) re-run
`bundle.sh` on the online machine with the missing package added to the
`apt-get install --download-only` list in the desktop-debs stage, or
(b) sneakernet the missing single `.deb` over and drop it next to the
others.

### `realm join` fails with "Couldn't authenticate"
Time skew or DNS. Run `chronyc tracking` (must be Normal) and
`nslookup <DOMAIN>` (must resolve to a DC). Both must work before Kerberos
will hand out tickets.

### RDP connects but immediately disconnects
Usually `~/.xsession` is missing/empty/not-executable, or the user's home
dir doesn't exist (AD users on first login — run `getent passwd <user>`,
then trigger a console login first to create the home dir). Check
`/var/log/xrdp.log` and `/var/log/xrdp-sesman.log`.

### SSH locks me out after disabling password auth
You missed adding your key, or `~/.ssh/authorized_keys` permissions are
wrong. Use the console to check `chmod 600 ~/.ssh/authorized_keys` and
`chmod 700 ~/.ssh`. SELinux contexts are not relevant on Ubuntu.
