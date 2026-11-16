# Git data sources

A Git data source is a Git repository Plexus clones and imports from, so
templates, Ansible playbooks and config contexts can live in version control
and be reviewed there instead of being typed into Plexus. Each sync fetches
the head of one branch, records its commit and imports the files by folder.

It is on **Settings > Git Sources** (`/settings/git-sources`), for
administrators.

| Folder in the repository | Imported as | Shown on |
|---|---|---|
| `templates/` | Instruction set templates (the `templates` store jobs use) | Jobs > Instructions |
| `playbooks/` | Ansible playbooks | Jobs > Tasks |
| `config_contexts/` | Config contexts of [intended configuration](intended-config.md) | Configuration > Intended > Contexts |

Other files and folders (a `README.md`, CI files) are ignored.

## A source

| Field | Rules |
|---|---|
| Name | 1 to 100 characters, unique ignoring case |
| Repository URL | `https://host/path`, `ssh://[user@]host[:port]/path` or `user@host:path`. Any other transport (`file://`, `ext::`, `git://`, `http://`, a local path) is refused, and so is a URL with a password (or, for https, a user name) in it |
| Branch | Default `main`. Letters, digits, `. _ / -`; not starting with `-` or `.`, no `..` |
| Credential | Optional: a service credential (Settings > Authentication). For https its user name and password (an access token on most Git hosts); for ssh its password field holds the private key |
| Provides | One or more of templates, playbooks, config contexts |
| Sync every | `0` (only Sync now) or 5 to 10080 minutes |
| Enabled | A disabled source keeps its records but is not synced on a schedule |

Saving a source does not sync it. **Sync now** syncs at once and shows what
changed; the table shows each source's status, last commit, last successful
sync and the files that were skipped.

## What a sync does

1. The remote host is checked by the same outbound-address guard the other
   integrations use (link-local and metadata addresses are refused; see
   `APP_SSRF_BLOCK_PRIVATE` and `APP_SSRF_ALLOW`).
2. The branch head is fetched (shallow, no tags, no submodules) into the
   source's working copy, `<state dir>/git_sources/<id>`: `PLEXUS_STATE_DIR`,
   else the folder of `APP_SESSION_KEY_FILE` (`/app/state` in the
   container), else `state/` in the checkout. `PLEXUS_GIT_SOURCES_DIR`
   overrides the folder. The commit SHA is recorded.
3. Each provided folder is read and its records are created or updated,
   owned by the source. A record the source owned whose file is gone (or
   whose type the source no longer provides) is removed.

A failed fetch (a wrong URL, branch or credential, a timeout) sets the
status to *Sync failed* with git's message and changes no record. A file
that cannot be imported is skipped and listed with the reason; the rest of
the sync goes on and the status is *Synced with warnings*.

A record written in Plexus is never overwritten: a file whose name is
already taken by one (or by a record of another source) is skipped with a
warning. A removed record that job history still references cannot be
deleted; it is detached instead and stays as an ordinary record.

## Files

**Templates.** `templates/<name>.<ext>` is the generic body of the template
`<name>`; `templates/<driver>/<name>.<ext>` is its variant for one driver
(`cisco_ios`, `paloalto_panos`: lower-case letters, digits and `_`).
Extensions: `.j2`, `.jinja`, `.jinja2`, `.txt`, `.cfg`, `.conf`, `.tmpl`.
Deeper folders are skipped.

**Playbooks.** `playbooks/<name>.yml` or `.yaml`, a YAML list of plays,
imported as an Ansible playbook named `<name>` (letters, digits, `_` and
`-`). The first play's `name` becomes the description. Python playbooks
(`.py`) are not imported: they would run as code inside the Plexus server,
so they stay a separate, deliberate step (see
[writing-playbooks.md](writing-playbooks.md)).

**Config contexts.** `config_contexts/<name>.json`, `.yml` or `.yaml`, an
object. An optional `_metadata` key sets how the context is stored; every
other key is the context data:

```yaml
_metadata:
  name: branch-ntp          # default: the file name without extension
  weight: 50                # default 1000; lower merges first
  description: NTP for branch routers
  enabled: true
  device_type: cisco_ios    # scope, as on a context written in Plexus
  group: branch-sites       # an inventory group by name (or group_id)
  host: edge-r1             # one host by hostname (or host_id)
  role_id: 3
  site_id: 2
ntp:
  - 192.0.2.1
  - 198.51.100.1
```

A group or host name must match exactly one record. Unknown `_metadata`
keys, unknown ids and data larger than 65536 characters are skipped with a
warning. The merged context of a host is
`GET /api/intended-config/hosts/{host_id}/variables`, as for contexts
written in Plexus.

Limits for every type: files of at most 262144 bytes, UTF-8 text, at most
2000 files per folder. Hidden files are ignored and symbolic links are
skipped (the checkout writes them as plain files).

## Records a source owns

A synced template, playbook or context carries `git_source_id`,
`git_source_name`, `git_path` and `git_commit`, and shows a *Git: source @
commit* badge. Editing or deleting it answers `409` (*managed by the Git
source ...; change it in the repository and sync*); the Edit and Delete
buttons are hidden. A playbook's input form and run permissions stay
editable in Plexus. Deleting the source removes its records.

## Security

- `git` runs from an argument list (never a shell) with a 120-second
  timeout per command, no terminal prompt, no system or global git config and no
  credential helper, and only the `https` and `ssh` protocols allowed
  (`GIT_ALLOW_PROTOCOL`).
- An https credential is passed as an `Authorization` header through
  `GIT_CONFIG_*` environment variables, never on the command line or in the
  stored URL. An ssh key is written to a private temporary file for the
  command and removed after it; host keys are accepted on first use and
  pinned in `<git sources folder>/known_hosts`.
- Errors shown and logged have the credential masked.
- The container image installs `git` and `openssh-client`; outside it, `git`
  must be on the `PATH` of the Plexus service.

## Permissions and audit

Every route is admin only. Creating, changing, deleting and syncing a
source are audited (category `config`, actions `git_source_create`,
`git_source_update`, `git_source_delete`, `git_source_sync`); a scheduled
sync is recorded with the user `system`.

| Method | Path | |
|---|---|---|
| GET | `/api/git-sources` | `{sources, content_types}` |
| POST | `/api/git-sources` | Create; `201` with the source |
| GET | `/api/git-sources/{id}` | One source |
| PUT | `/api/git-sources/{id}` | Full replace |
| DELETE | `/api/git-sources/{id}` | Delete with its records |
| GET | `/api/git-sources/{id}/objects` | The records it owns, by type |
| POST | `/api/git-sources/{id}/sync` | Sync now; `{ok, source, result}` |

See [api-reference.md](api-reference.md#git-data-sources) for the bodies.

## What it does not do

- Write back to the repository: Plexus only reads.
- Import intended configuration (Jinja2) templates, graph templates or
  Python playbooks.
- Follow submodules or Git LFS files.
