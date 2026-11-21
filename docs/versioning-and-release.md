# Versioning and Release

- Plexus follows Semantic Versioning (`MAJOR.MINOR.PATCH`).
- The declared release version is `_FALLBACK_VERSION` in `netcontrol/version.py`; it must match the latest numbered entry in `CHANGELOG.md`.
- Check runtime version with:
```bash
python templates/run.py --version
```
- See release notes in `CHANGELOG.md`.

## Published images

| Tag | Built by | When | Platforms |
|---|---|---|---|
| `ghcr.io/rickeynet/plexus:<vX.Y.Z>`, `:latest` | `.github/workflows/release.yml` | a `v*.*.*` tag is pushed | amd64, arm64 (trivy-gated) |
| `ghcr.io/rickeynet/plexus:edge`, `:sha-<12-char sha>` | `publish-edge` job in `.github/workflows/ci.yml` | every push to `main` after secret scan, backend and frontend jobs pass | amd64 |

A manual run of the release workflow (**Run workflow**, with a release tag)
publishes only when that tag exists and names the commit the run builds:
start the run from the tag, not from a branch. A run started anywhere else
fails before anything is built.

Edge images report `PLEXUS_VERSION=<base>+edge.<sha>` and the full commit
SHA, so **Settings → System** on the `edge` channel compares the head of
`main` with the running build's SHA. Version comparison drops the `+...`
suffix, so a release check still sees the base version.

The in-app **Install** button maps channels to images: `release` →
`<image repo>:<tag>`, `edge` → `<image repo>:edge`, `git` → a local build
of the tracked branch. See `deploy/DEPLOYMENT.md`, *Update from the web UI*.

Interactive API docs: `http://localhost:8080/docs`
