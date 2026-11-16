import type { GitContentType, GitSource, GitSourceInput, GitSyncSummary } from '@/api/gitSources';
import type { Tone } from '@/lib/severity';

// Pure helpers of the Git sources tab. The server checks every rule again;
// these only catch mistakes before the request.

export const GIT_SOURCE_NAME_MAX = 100;
export const GIT_INTERVAL_MIN = 5;
export const GIT_INTERVAL_MAX = 7 * 24 * 60;

export const CONTENT_TYPE_LABEL: Record<GitContentType, string> = {
  templates: 'Templates',
  playbooks: 'Playbooks',
  config_contexts: 'Config contexts',
};

export const CONTENT_TYPE_HELP: Record<GitContentType, string> = {
  templates: 'templates/<name>.j2, or templates/<driver>/<name>.j2 for one driver. Shown under Jobs > Instructions.',
  playbooks: 'playbooks/<name>.yml Ansible playbooks. Python playbooks are not imported.',
  config_contexts:
    'config_contexts/<name>.json or .yml objects; an optional _metadata key sets name, weight, scope and description.',
};

const STATUS: Record<string, { tone: Tone; label: string }> = {
  never: { tone: 'neutral', label: 'Not synced' },
  syncing: { tone: 'info', label: 'Syncing' },
  ok: { tone: 'success', label: 'Synced' },
  warning: { tone: 'warning', label: 'Synced with warnings' },
  error: { tone: 'danger', label: 'Sync failed' },
};

export function statusBadge(status: string): { tone: Tone; label: string } {
  return STATUS[status] ?? { tone: 'neutral', label: status };
}

/** The first 10 characters of a commit SHA, or '' for none. */
export function shortSha(sha: string | null | undefined): string {
  return (sha ?? '').slice(0, 10);
}

export type GitSourceErrors = Partial<Record<'name' | 'remote_url' | 'branch' | 'provides' | 'interval', string>>;

const SCP_RE = /^[A-Za-z0-9._-]+@[A-Za-z0-9.-]+:[^/-]/;

/** Why the remote URL would be refused, or undefined when it looks right. */
export function remoteUrlError(raw: string): string | undefined {
  const url = raw.trim();
  if (!url) return 'Enter the repository URL.';
  if (/\s/.test(url)) return 'The URL must not contain spaces.';
  const scheme = /^([A-Za-z][A-Za-z0-9+.-]*):\/\//.exec(url)?.[1]?.toLowerCase();
  if (!scheme) {
    if (url.includes('::')) return 'Remote helper transports (such as ext::) are not allowed.';
    return SCP_RE.test(url) ? undefined : 'Use https://…, ssh://… or user@host:path.';
  }
  if (scheme !== 'https' && scheme !== 'ssh') return `${scheme}:// is not allowed; use https or ssh.`;
  const rest = url.slice(scheme.length + 3);
  const authority = rest.split('/', 1)[0];
  if (authority.includes('@') && (scheme === 'https' || authority.split('@')[0].includes(':'))) {
    return 'Do not put credentials in the URL; choose a credential instead.';
  }
  const path = rest.slice(authority.length);
  if (!path || path === '/') return 'The URL must name a repository path.';
  return undefined;
}

export function validateGitSource(input: GitSourceInput): GitSourceErrors {
  const errors: GitSourceErrors = {};
  const name = input.name.trim();
  if (!name) errors.name = 'Enter a name.';
  else if (name.length > GIT_SOURCE_NAME_MAX) errors.name = `At most ${GIT_SOURCE_NAME_MAX} characters.`;
  const url = remoteUrlError(input.remote_url);
  if (url) errors.remote_url = url;
  const branch = input.branch.trim();
  if (!branch) errors.branch = 'Enter a branch.';
  else if (!/^[A-Za-z0-9][A-Za-z0-9._/-]*$/.test(branch) || branch.includes('..') || branch.endsWith('/')) {
    errors.branch = 'Not a valid branch name.';
  }
  if (input.provides.length === 0) errors.provides = 'Choose at least one content type.';
  const n = input.sync_interval_minutes;
  if (!Number.isInteger(n) || (n !== 0 && (n < GIT_INTERVAL_MIN || n > GIT_INTERVAL_MAX))) {
    errors.interval = `0 (on demand only) or ${GIT_INTERVAL_MIN} to ${GIT_INTERVAL_MAX.toLocaleString()} minutes.`;
  }
  return errors;
}

export function emptyGitSource(contentTypes: GitContentType[]): GitSourceInput {
  return {
    name: '',
    remote_url: '',
    branch: 'main',
    credential_id: null,
    provides: [...contentTypes],
    sync_interval_minutes: 0,
    enabled: true,
  };
}

export function toGitSourceInput(source: GitSource): GitSourceInput {
  return {
    name: source.name,
    remote_url: source.remote_url,
    branch: source.branch,
    credential_id: source.credential_id,
    provides: [...source.provides],
    sync_interval_minutes: source.sync_interval_minutes,
    enabled: source.enabled,
  };
}

/** "2 templates, 1 playbook" from a source's record counts; '' when none. */
export function objectCountText(counts: Partial<Record<GitContentType, number>>): string {
  const words: Record<GitContentType, [string, string]> = {
    templates: ['template', 'templates'],
    playbooks: ['playbook', 'playbooks'],
    config_contexts: ['context', 'contexts'],
  };
  return (Object.keys(words) as GitContentType[])
    .filter((t) => (counts[t] ?? 0) > 0)
    .map((t) => `${counts[t]} ${words[t][counts[t] === 1 ? 0 : 1]}`)
    .join(', ');
}

/** One line describing what a sync changed: "3 created, 1 updated, 2 removed". */
export function syncResultText(summary: GitSyncSummary): string {
  const total = { created: 0, updated: 0, removed: 0, detached: 0 };
  for (const counts of Object.values(summary.counts)) {
    total.created += counts.created;
    total.updated += counts.updated;
    total.removed += counts.removed;
    total.detached += counts.detached;
  }
  const parts = (Object.keys(total) as (keyof typeof total)[])
    .filter((k) => total[k] > 0)
    .map((k) => `${total[k]} ${k}`);
  const changes = parts.length ? parts.join(', ') : 'no changes';
  const warnings = summary.warnings.length;
  return `Commit ${shortSha(summary.commit)}: ${changes}${warnings ? `, ${warnings} file${warnings === 1 ? '' : 's'} skipped` : ''}.`;
}
