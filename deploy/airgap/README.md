# Plexus Air-Gapped Deployment

End-to-end recipe for deploying Plexus on an offline Ubuntu 26.04 amd64 VM.
You build a self-contained bundle on a machine **with** internet access, copy
it to the VM, and run one installer script.

## Prerequisites

**On the online machine** (Linux/macOS/WSL2 with Docker Desktop or Engine):
- Docker 24+ with `buildx` enabled (default on modern Docker)
- ~3 GB free disk for the bundle
- Network access to Docker Hub and `download.docker.com`

**On the offline VM:**
- Ubuntu 26.04 amd64
- 2 vCPU / 4 GB RAM / 40 GB disk minimum
- `sudo` access
- A way to receive ~1 GB of files (USB, SCP from a jump host, hypervisor shared folder, etc.)

> **First time installing on a fresh VM?** Do the network/RDP/AD prep in
> [VM_SETUP.md](VM_SETUP.md) first — static IP, hostname, SSH, time sync,
> XFCE+xrdp for RDP, and AD domain join. The `desktop-debs/` directory in
> this bundle has all the `.deb`s those steps need.

## Step 1 — Build the bundle (online machine)

From the repo root:

```bash
bash deploy/airgap/bundle.sh
```

This produces `plexus-airgap.tar.gz` (~800 MB – 1.2 GB) in the repo root. It
contains:

```
plexus-airgap-bundle/
├── images/
│   ├── plexus.tar          # Plexus app image (built from this repo)
│   ├── postgres.tar        # postgres:16-alpine
│   └── nginx.tar           # nginx:alpine
├── debs/
│   └── docker-*.deb        # Docker Engine + compose plugin (resolute/amd64)
├── desktop-debs/
│   └── *.deb               # XFCE + xrdp + AD-join (realmd/sssd/adcli) +
│                           # chrony + openssh-server + ufw + firefox.
│                           # Used by VM_SETUP.md, NOT installed automatically.
├── repo/
│   ├── docker-compose.yml
│   ├── .env.example
│   └── deploy/             # nginx.conf, setup.sh, backup.sh, plexus.cron
├── install.sh              # one-shot Plexus installer (Docker + compose stack)
├── VM_SETUP.md             # network, RDP, AD-join walkthrough — do this first
└── README.md               # this file (Plexus install)
```

### Overrides

You can override any of these via env vars before running `bundle.sh`:

| Variable             | Default              | Notes                                              |
|----------------------|----------------------|----------------------------------------------------|
| `OUT_DIR`            | `./plexus-airgap-bundle` | Where to assemble the bundle              |
| `PLATFORM`           | `linux/amd64`        | Target platform for built/pulled images            |
| `UBUNTU_CODENAME`    | `resolute`           | Apt suite for Docker repo. Set to `noble` for 24.04, `jammy` for 22.04, `questing` for 25.10. |
| `APT_BASE_IMAGE`     | `ubuntu:$UBUNTU_CODENAME` | Base image used to download `.deb`s. Override only if `ubuntu:resolute` isn't on Docker Hub yet — fall back to `ubuntu:noble` and accept the libc-version mismatch risk. |
| `PLEXUS_IMAGE_TAG`   | `plexus:airgap`      | Image tag for the built app                        |

## Step 2 — Transfer to the VM

Copy `plexus-airgap.tar.gz` to the VM by whatever offline channel you have
(USB stick, SCP from a jump host, VMware/Hyper-V shared folder, etc.). Drop it
in the user's home directory or `/tmp`.

## Step 3 — Install on the VM

```bash
tar -xzf plexus-airgap.tar.gz
cd plexus-airgap-bundle
sudo bash install.sh
```

The installer:

1. Installs Docker Engine + compose plugin from the bundled `.deb`s (skips if
   Docker is already present).
2. Loads `plexus`, `postgres:16-alpine`, and `nginx:alpine` images via
   `docker load`.
3. Stages the compose project into `/opt/plexus` and rewrites
   `build: .` → `image: plexus:airgap` so compose uses the loaded image
   instead of trying to build (no internet, can't reach Docker Hub).
4. Runs `deploy/setup.sh` to generate `.env` (random DB password + API token)
   and a self-signed TLS cert from the VM's hostname.
5. `docker compose up -d` to start `plexus`, `postgres`, and `nginx`.
6. Opens firewall ports if `ufw` is active.

## Step 4 — First login

Browse to `https://<vm-ip-or-hostname>`. Click through the self-signed
certificate warning. Default login: `admin` / `netcontrol` (forced password
change on first login).

## Common follow-ups

### Use your own TLS cert
The self-signed cert lives at `/opt/plexus/certs/{cert,key}.pem` (bind-mounted
into the nginx container). To swap in a CA-signed cert, see the "Using Your
Own TLS Certificate" section in `deploy/DEPLOYMENT.md`.

### Edit configuration
```bash
sudo nano /opt/plexus/.env
sudo docker compose -f /opt/plexus/docker-compose.yml restart
```

The most common edit: set `APP_CORS_ORIGINS=https://your.vm.hostname` so
browser requests with credentials work correctly.

### Updates
You're offline, so updates mean: rebuild the bundle on the online machine,
transfer the new `plexus-airgap.tar.gz`, extract, and re-run
`sudo bash install.sh`. The installer is idempotent — it will re-load the
images and `docker compose up -d` (compose recreates containers whose image
changed and leaves state volumes intact).

### Backups
`/opt/plexus/deploy/backup.sh` dumps Postgres and tars the state volume
(which holds `netcontrol.key` — losing it permanently breaks decryption of
stored device credentials). Schedule it via the included
`/opt/plexus/deploy/plexus.cron`.

## Troubleshooting

### `dpkg` complains about missing dependencies
The bundle was built against a base image whose package set didn't fully
match your VM. Re-run `bundle.sh` with `UBUNTU_CODENAME` set to a closer
match, or stage the missing `.deb`s manually under `debs/` before re-running
`install.sh`.

### `docker compose up -d` tries to pull images
That means the compose file still says `build: .` — the rewrite step in
`install.sh` didn't fire. Manually edit `/opt/plexus/docker-compose.yml`
and replace `build: .` with `image: plexus:airgap`, then re-run
`docker compose up -d`.

### Bundle build fails on `buildx --load`
Older Docker installs don't have buildx by default. Either upgrade Docker on
the online machine, or replace the `docker buildx build` line in `bundle.sh`
with `docker build`.
