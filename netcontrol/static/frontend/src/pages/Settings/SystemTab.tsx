import { useState } from 'react';

import {
  type CheckResult,
  type CurrentVersion,
  type UpdateChannel,
  type UpdateProgress,
  type UpdatesConfig,
  isUpdateBusy,
  useAppVersion,
  useApplyUpdate,
  useCheckForUpdates,
  useRollbackUpdate,
  useSaveUpdatesConfig,
  useUpdateProgress,
  useUpdatesConfig,
  useUpdatesStatus,
} from '@/api/adminUpdates';
import { useDialogs } from '@/components/DialogProvider-context';

const CHANNEL_LABELS: Record<UpdateChannel, string> = {
  release: 'GitHub Releases (stable)',
  edge: 'Edge (latest build of main)',
  git: 'Git (build a branch on the host)',
  disabled: 'Disabled (air-gapped)',
};

const CHANNEL_HELP: Record<UpdateChannel, string> = {
  release:
    'Polls api.github.com for the latest tagged release. Install pulls the matching image (<image repo>:<tag>). Requires outbound HTTPS to github.com and the registry.',
  edge:
    'Compares the head of the tracked branch on GitHub with this build. Install pulls <image repo>:edge, which CI publishes after every green push to main.',
  git:
    'Runs `git fetch` on the configured remote/branch and reports how many commits HEAD is behind. Install checks out the branch and rebuilds the image on the host (slow on small servers).',
  disabled:
    'No upstream checks and no in-app install. Use this for air-gapped installs; upgrade via `bash deploy/upgrade.sh --image …` on the host.',
};

const AGENT_MISSING =
  'Host updater not installed — run deploy/bootstrap.sh on the server to enable in-app installs.';

const mutedSmall = { fontSize: '0.78rem' } as const;

export function SystemTab() {
  const { confirm } = useDialogs();
  const status = useUpdatesStatus();
  const configQ = useUpdatesConfig();
  const save = useSaveUpdatesConfig();
  const check = useCheckForUpdates();
  const progressQ = useUpdateProgress();
  const apply = useApplyUpdate();
  const rollback = useRollbackUpdate();

  const [draft, setDraft] = useState<UpdatesConfig | null>(null);
  const [savedMsg, setSavedMsg] = useState<string | null>(null);
  const [actionMsg, setActionMsg] = useState<string | null>(null);
  // The queued request plus the version running when it was queued. The
  // restarted container shows up as /api/version moving off that version;
  // the updater's result.json for this request ends the watch either way.
  const [watch, setWatch] = useState<{ id: string; base: CurrentVersion } | null>(null);
  const [prevData, setPrevData] = useState(configQ.data);
  if (configQ.data !== prevData) {
    setPrevData(configQ.data);
    if (configQ.data) setDraft(configQ.data);
  }

  const appVersion = useAppVersion(watch != null);
  const progress = progressQ.data;
  if (watch) {
    const v = appVersion.data;
    const finished =
      progress?.result?.id === watch.id && progress.result.status !== 'running'
        ? progress.result
        : null;
    const moved = v != null && (v.version !== watch.base.version || v.git_sha !== watch.base.git_sha);
    if (finished?.status === 'failed') {
      setWatch(null);
      setActionMsg(`Update failed: ${finished.message}`);
    } else if (moved || finished) {
      const now = moved ? v : (progress?.current ?? v);
      setWatch(null);
      setActionMsg(
        now
          ? `Restarted into v${now.version}${now.git_sha ? ` (${now.git_sha})` : ''}. Reload the page to load the new interface.`
          : 'Update finished.',
      );
    }
  }

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
  const saved = configQ.data!;
  const last = check.data ?? status.data!.last_check ?? null;
  const busy = isUpdateBusy(progress);
  const draftChanged =
    draft.channel !== saved.channel ||
    draft.repo !== saved.repo ||
    draft.git_remote !== saved.git_remote ||
    draft.git_branch !== saved.git_branch ||
    draft.image_repo !== saved.image_repo;

  const onSave = async () => {
    setSavedMsg(null);
    try {
      await save.mutateAsync(draft);
      setSavedMsg('Saved.');
    } catch (e) {
      setSavedMsg(`Save failed: ${(e as Error).message}`);
    }
  };

  const onInstall = async (target: string) => {
    const how =
      saved.channel === 'git'
        ? `check out ${saved.git_remote}/${saved.git_branch} and rebuild the image on the host`
        : `pull ${saved.image_repo}:${saved.channel === 'edge' ? 'edge' : target}`;
    const ok = await confirm({
      title: 'Install update',
      message: `Install ${target}? The host will snapshot the database, ${how}, and restart Plexus. The UI is unavailable for a minute or two while the container restarts.`,
      confirmLabel: `Install ${target}`,
      confirmVariant: 'primary',
    });
    if (!ok) return;
    setActionMsg(null);
    apply.mutate(target, {
      onSuccess: (req) => {
        setWatch({ id: req.id, base: cur });
        setActionMsg(`Install of ${target} queued.`);
      },
      onError: (e) => setActionMsg(`Install failed: ${(e as Error).message}`),
    });
  };

  const onRollback = async () => {
    const target = progress?.rollback?.target ?? 'the previous version';
    const ok = await confirm({
      title: 'Roll back',
      message: `Roll back to ${target}? This restores the previous code/image only. If the newer version already migrated the database, restore its pre-upgrade snapshot first (see deploy/DEPLOYMENT.md).`,
      confirmLabel: 'Roll back',
      confirmVariant: 'danger',
    });
    if (!ok) return;
    setActionMsg(null);
    rollback.mutate(undefined, {
      onSuccess: (req) => {
        setWatch({ id: req.id, base: cur });
        setActionMsg('Rollback queued.');
      },
      onError: (e) => setActionMsg(`Rollback failed: ${(e as Error).message}`),
    });
  };

  const showRepo = draft.channel === 'release' || draft.channel === 'edge';

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
          <div className="text-muted" style={{ ...mutedSmall, marginTop: '0.25rem' }}>
            {CHANNEL_HELP[draft.channel]}
          </div>
        </div>

        {showRepo && (
          <div style={{ display: 'flex', gap: '0.75rem', flexWrap: 'wrap' }}>
            <div className="form-group" style={{ flex: '0 0 280px' }}>
              <label className="form-label" htmlFor="update-repo">
                GitHub repository (owner/name)
              </label>
              <input
                id="update-repo"
                className="form-input"
                value={draft.repo}
                onChange={(e) => setDraft({ ...draft, repo: e.target.value })}
                placeholder="RickeyNet/Plexus"
              />
            </div>
            <div className="form-group" style={{ flex: '0 0 320px' }}>
              <label className="form-label" htmlFor="update-image-repo">
                Image repository
              </label>
              <input
                id="update-image-repo"
                className="form-input"
                value={draft.image_repo}
                onChange={(e) => setDraft({ ...draft, image_repo: e.target.value })}
                placeholder="ghcr.io/rickeynet/plexus"
              />
              <div className="text-muted" style={{ ...mutedSmall, marginTop: '0.25rem' }}>
                Must match PLEXUS_UPDATE_IMAGE_REPO in the server&apos;s .env.
              </div>
            </div>
          </div>
        )}

        {(draft.channel === 'git' || draft.channel === 'edge') && (
          <div style={{ display: 'flex', gap: '0.75rem', flexWrap: 'wrap' }}>
            {draft.channel === 'git' && (
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
            )}
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
          Checks the saved channel. Installing hands the upgrade to the host updater, which
          snapshots the database, runs <code>deploy/upgrade.sh</code>, waits for the health
          check, and keeps a rollback target.
        </p>
        {progress && !progress.agent_installed && (
          <p className="text-muted" style={{ ...mutedSmall, marginTop: 0 }}>
            {AGENT_MISSING}
          </p>
        )}
        <button
          type="button"
          className="btn btn-secondary btn-sm"
          disabled={check.isPending || saved.channel === 'disabled'}
          onClick={() => check.mutate()}
        >
          {check.isPending ? 'Checking…' : 'Check now'}
        </button>

        {last && (
          <CheckResultBox
            last={last}
            currentVersion={cur.version}
            install={
              last.ok && last.is_newer && last.latest_version && last.channel === saved.channel
                ? {
                    target: last.latest_version,
                    disabledReason: !progress
                      ? 'Loading updater status…'
                      : !progress.agent_installed
                        ? AGENT_MISSING
                        : saved.channel === 'disabled'
                          ? 'Updates are disabled for this instance.'
                          : busy
                            ? 'An update is already queued or running.'
                            : null,
                    pending: apply.isPending,
                    onInstall,
                  }
                : null
            }
          />
        )}
      </section>

      <UpdateProgressPanel
        progress={progress}
        busy={busy}
        actionMsg={actionMsg}
        waitingForRestart={watch != null}
        rollbackDisabled={busy || rollback.isPending || saved.channel === 'disabled'}
        onRollback={onRollback}
      />
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
          <div className="text-muted" style={mutedSmall}>
            Version
          </div>
          <div style={{ fontSize: '1.15rem', fontWeight: 600 }}>{version}</div>
        </div>
        {sha && (
          <div>
            <div className="text-muted" style={mutedSmall}>
              Git SHA
            </div>
            <div style={{ fontFamily: 'var(--font-mono, monospace)' }}>{sha}</div>
          </div>
        )}
      </div>
    </section>
  );
}

interface InstallAction {
  target: string;
  disabledReason: string | null;
  pending: boolean;
  onInstall: (target: string) => void;
}

function CheckResultBox({
  last,
  currentVersion,
  install,
}: {
  last: CheckResult;
  currentVersion: string;
  install: InstallAction | null;
}) {
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
        <div className="text-muted" style={{ ...mutedSmall, marginBottom: '0.25rem' }}>
          Published {new Date(last.published_at).toLocaleString()}
        </div>
      )}
      {last.html_url && /^https?:\/\//i.test(last.html_url) && (
        <div style={{ fontSize: '0.85rem', marginBottom: '0.5rem' }}>
          <a href={last.html_url} target="_blank" rel="noreferrer">
            View on GitHub →
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
      {install && (
        <div style={{ marginTop: '0.75rem' }}>
          <button
            type="button"
            className="btn btn-primary btn-sm"
            disabled={install.disabledReason != null || install.pending}
            title={install.disabledReason ?? undefined}
            onClick={() => install.onInstall(install.target)}
          >
            {install.pending ? 'Queueing…' : `Install ${install.target}`}
          </button>
          {install.disabledReason && (
            <div className="text-muted" style={{ ...mutedSmall, marginTop: '0.25rem' }}>
              {install.disabledReason}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function formatTime(iso: string | null | undefined): string | null {
  if (!iso) return null;
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleString();
}

function UpdateProgressPanel({
  progress,
  busy,
  actionMsg,
  waitingForRestart,
  rollbackDisabled,
  onRollback,
}: {
  progress: UpdateProgress | undefined;
  busy: boolean;
  actionMsg: string | null;
  waitingForRestart: boolean;
  rollbackDisabled: boolean;
  onRollback: () => void;
}) {
  if (!progress) return null;
  const { result, pending, in_progress: running } = progress;
  if (!result && !pending && !running && !actionMsg && !progress.rollback_available) {
    return null;
  }

  let statusLine: string;
  if (pending) {
    statusLine = `Queued: ${pending.action} to ${pending.target_version || 'previous version'} — waiting for the host updater.`;
  } else if (running || result?.status === 'running') {
    const req = running ?? result?.request;
    statusLine = `Running: ${req?.action ?? 'update'}${req?.target_version ? ` to ${req.target_version}` : ''}…`;
  } else if (result) {
    statusLine = `Last run ${result.status === 'success' ? 'succeeded' : 'failed'}: ${result.message}`;
  } else {
    statusLine = 'No update has been run from the UI yet.';
  }
  const tone =
    busy ? 'var(--accent, #4a9eff)' : result?.status === 'failed' ? 'var(--danger)' : 'var(--border)';
  const started = formatTime(result?.started_at);
  const finished = formatTime(result?.finished_at);

  return (
    <section>
      <h4 style={{ margin: '0 0 0.5rem 0' }}>Update progress</h4>
      <div
        style={{
          padding: '0.75rem',
          border: '1px solid var(--border)',
          borderLeft: `3px solid ${tone}`,
          borderRadius: 4,
          display: 'grid',
          gap: '0.5rem',
        }}
      >
        <div style={{ fontWeight: 600 }}>{statusLine}</div>
        {(started || finished) && !pending && (
          <div className="text-muted" style={mutedSmall}>
            {started && <>Started {started}</>}
            {started && finished && ' · '}
            {finished && <>Finished {finished}</>}
          </div>
        )}
        {actionMsg && (
          <div
            className={/failed/i.test(actionMsg) ? 'error' : 'text-muted'}
            style={{ fontSize: '0.85rem' }}
          >
            {actionMsg}
          </div>
        )}
        {waitingForRestart && (
          <div className="text-muted" style={mutedSmall}>
            Waiting for Plexus to restart into the new version…
          </div>
        )}
        {progress.log_tail && (
          <pre
            style={{
              fontFamily: 'var(--font-mono, monospace)',
              whiteSpace: 'pre-wrap',
              fontSize: '0.75rem',
              margin: 0,
              maxHeight: 320,
              overflow: 'auto',
              padding: '0.5rem',
              background: 'var(--bg-secondary, rgba(0,0,0,0.2))',
              borderRadius: 4,
            }}
          >
            {progress.log_tail}
          </pre>
        )}
        {progress.rollback_available && (
          <div>
            <button
              type="button"
              className="btn btn-secondary btn-sm"
              disabled={rollbackDisabled || !progress.agent_installed}
              title={!progress.agent_installed ? AGENT_MISSING : undefined}
              onClick={onRollback}
            >
              Roll back to previous
            </button>
            {progress.rollback?.target && (
              <span className="text-muted" style={{ ...mutedSmall, marginLeft: '0.5rem' }}>
                {progress.rollback.target}
              </span>
            )}
          </div>
        )}
      </div>
    </section>
  );
}
