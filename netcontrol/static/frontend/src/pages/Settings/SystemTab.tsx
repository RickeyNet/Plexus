import { useEffect, useState } from 'react';

import {
  type UpdateChannel,
  type UpdatesConfig,
  useCheckForUpdates,
  useSaveUpdatesConfig,
  useUpdatesConfig,
  useUpdatesStatus,
} from '@/api/adminUpdates';

const CHANNEL_LABELS: Record<UpdateChannel, string> = {
  release: 'GitHub Releases (stable)',
  git: 'Git (track a branch)',
  disabled: 'Disabled (air-gapped)',
};

const CHANNEL_HELP: Record<UpdateChannel, string> = {
  release:
    'Polls api.github.com for the latest tagged release on the configured repo. Requires outbound HTTPS to github.com.',
  git:
    'Runs `git fetch` on the configured remote/branch and reports how many commits ahead it is of HEAD. Useful for edge deploys following main.',
  disabled:
    'No upstream checks. Use this for air-gapped installs; upgrade via `bash deploy/upgrade.sh --image …` on the host.',
};

export function SystemTab() {
  const status = useUpdatesStatus();
  const configQ = useUpdatesConfig();
  const save = useSaveUpdatesConfig();
  const check = useCheckForUpdates();

  const [draft, setDraft] = useState<UpdatesConfig | null>(null);
  const [savedMsg, setSavedMsg] = useState<string | null>(null);

  useEffect(() => {
    if (configQ.data) setDraft(configQ.data);
  }, [configQ.data]);

  if (status.isLoading || configQ.isLoading || !draft) {
    return <p className="text-muted">Loading…</p>;
  }
  if (status.isError) {
    return (
      <div className="error">
        Failed to load update status: {(status.error as Error).message}
      </div>
    );
  }
  if (configQ.isError) {
    return (
      <div className="error">
        Failed to load update config: {(configQ.error as Error).message}
      </div>
    );
  }

  const cur = status.data!.current;
  const last = check.data ?? status.data!.last_check ?? null;
  const draftChanged =
    configQ.data != null &&
    (draft.channel !== configQ.data.channel ||
      draft.repo !== configQ.data.repo ||
      draft.git_remote !== configQ.data.git_remote ||
      draft.git_branch !== configQ.data.git_branch);

  const onSave = async () => {
    setSavedMsg(null);
    try {
      await save.mutateAsync(draft);
      setSavedMsg('Saved.');
    } catch (e) {
      setSavedMsg(`Save failed: ${(e as Error).message}`);
    }
  };

  return (
    <div className="card" style={{ padding: '1rem', display: 'grid', gap: '1.25rem' }}>
      <CurrentVersionBox version={cur.version} sha={cur.git_sha} />

      <section>
        <h4 style={{ margin: '0 0 0.5rem 0' }}>Update channel</h4>
        <div className="form-group" style={{ marginBottom: '0.5rem' }}>
          <label className="form-label" htmlFor="update-channel">
            Source
          </label>
          <select
            id="update-channel"
            className="form-select"
            style={{ maxWidth: 360 }}
            value={draft.channel}
            onChange={(e) =>
              setDraft({ ...draft, channel: e.target.value as UpdateChannel })
            }
          >
            {(Object.keys(CHANNEL_LABELS) as UpdateChannel[]).map((c) => (
              <option key={c} value={c}>
                {CHANNEL_LABELS[c]}
              </option>
            ))}
          </select>
          <div className="text-muted" style={{ fontSize: '0.78rem', marginTop: '0.25rem' }}>
            {CHANNEL_HELP[draft.channel]}
          </div>
        </div>

        {draft.channel === 'release' && (
          <div className="form-group">
            <label className="form-label" htmlFor="update-repo">
              Repository (owner/name)
            </label>
            <input
              id="update-repo"
              className="form-input"
              style={{ maxWidth: 360 }}
              value={draft.repo}
              onChange={(e) => setDraft({ ...draft, repo: e.target.value })}
              placeholder="RickeyNet/Plexus"
            />
          </div>
        )}

        {draft.channel === 'git' && (
          <div style={{ display: 'flex', gap: '0.75rem', flexWrap: 'wrap' }}>
            <div className="form-group" style={{ flex: '0 0 200px' }}>
              <label className="form-label" htmlFor="update-remote">
                Remote
              </label>
              <input
                id="update-remote"
                className="form-input"
                value={draft.git_remote}
                onChange={(e) => setDraft({ ...draft, git_remote: e.target.value })}
              />
            </div>
            <div className="form-group" style={{ flex: '0 0 240px' }}>
              <label className="form-label" htmlFor="update-branch">
                Branch
              </label>
              <input
                id="update-branch"
                className="form-input"
                value={draft.git_branch}
                onChange={(e) => setDraft({ ...draft, git_branch: e.target.value })}
              />
            </div>
          </div>
        )}

        <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
          <button
            type="button"
            className="btn btn-primary btn-sm"
            disabled={!draftChanged || save.isPending}
            onClick={onSave}
          >
            {save.isPending ? 'Saving…' : 'Save channel settings'}
          </button>
          {savedMsg && (
            <span
              className={savedMsg.startsWith('Save failed') ? 'error' : 'text-muted'}
              style={{ fontSize: '0.85rem' }}
            >
              {savedMsg}
            </span>
          )}
        </div>
      </section>

      <section>
        <h4 style={{ margin: '0 0 0.5rem 0' }}>Check for updates</h4>
        <p
          className="text-muted"
          style={{ fontSize: '0.85rem', marginTop: 0, marginBottom: '0.5rem' }}
        >
          Read-only check against the configured channel. Applying an update still
          happens via <code>bash deploy/upgrade.sh</code> on the host. The in-app
          apply button lands in a follow-up release.
        </p>
        <button
          type="button"
          className="btn btn-secondary btn-sm"
          disabled={check.isPending || draft.channel === 'disabled'}
          onClick={() => check.mutate()}
        >
          {check.isPending ? 'Checking…' : 'Check now'}
        </button>

        {last && <CheckResultBox last={last} currentVersion={cur.version} />}
      </section>
    </div>
  );
}

function CurrentVersionBox({
  version,
  sha,
}: {
  version: string;
  sha: string | null;
}) {
  return (
    <section>
      <h4 style={{ margin: '0 0 0.5rem 0' }}>Current version</h4>
      <div style={{ display: 'flex', gap: '1.25rem', alignItems: 'baseline' }}>
        <div>
          <div className="text-muted" style={{ fontSize: '0.78rem' }}>
            Version
          </div>
          <div style={{ fontSize: '1.15rem', fontWeight: 600 }}>{version}</div>
        </div>
        {sha && (
          <div>
            <div className="text-muted" style={{ fontSize: '0.78rem' }}>
              Git SHA
            </div>
            <div style={{ fontFamily: 'var(--font-mono, monospace)' }}>{sha}</div>
          </div>
        )}
      </div>
    </section>
  );
}

function CheckResultBox({
  last,
  currentVersion,
}: {
  last: NonNullable<ReturnType<typeof useUpdatesStatus>['data']>['last_check'];
  currentVersion: string;
}) {
  if (!last) return null;
  if (!last.ok) {
    return (
      <div className="error" style={{ marginTop: '0.75rem' }}>
        {last.error ?? 'Check failed.'}
      </div>
    );
  }

  const newer = last.is_newer;
  const tone = newer ? 'var(--accent, #4a9eff)' : 'var(--text-muted)';
  const headline = newer
    ? `Update available: ${last.latest_version}`
    : `Up to date (latest: ${last.latest_version ?? currentVersion})`;

  return (
    <div
      style={{
        marginTop: '0.75rem',
        padding: '0.75rem',
        border: '1px solid var(--border)',
        borderLeft: `3px solid ${tone}`,
        borderRadius: 4,
      }}
    >
      <div style={{ fontWeight: 600, marginBottom: '0.25rem' }}>{headline}</div>
      {last.commits_behind != null && newer && (
        <div className="text-muted" style={{ fontSize: '0.85rem', marginBottom: '0.25rem' }}>
          {last.commits_behind} commit(s) behind upstream.
        </div>
      )}
      {last.published_at && (
        <div className="text-muted" style={{ fontSize: '0.78rem', marginBottom: '0.25rem' }}>
          Published {new Date(last.published_at).toLocaleString()}
        </div>
      )}
      {last.html_url && (
        <div style={{ fontSize: '0.85rem', marginBottom: '0.5rem' }}>
          <a href={last.html_url} target="_blank" rel="noreferrer">
            View release on GitHub →
          </a>
        </div>
      )}
      {last.release_notes && (
        <details>
          <summary style={{ cursor: 'pointer', fontSize: '0.85rem' }}>
            Release notes / changes
          </summary>
          <pre
            style={{
              whiteSpace: 'pre-wrap',
              fontSize: '0.8rem',
              marginTop: '0.5rem',
              maxHeight: 320,
              overflow: 'auto',
            }}
          >
            {last.release_notes}
          </pre>
        </details>
      )}
    </div>
  );
}
