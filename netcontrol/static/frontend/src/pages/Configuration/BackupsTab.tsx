import { useMemo, useState } from 'react';

import { useDialogs } from '@/components/DialogProvider-context';
import {
  type ConfigBackup,
  type ConfigBackupPolicy,
  configBackupBulkDownloadUrl,
  configBackupDownloadUrl,
  useConfigBackupPolicies,
  useConfigBackupSummary,
  useConfigBackups,
  useDeleteBackup,
  useDeleteBackupPolicy,
  useRunBackupPolicy,
} from '@/api/configuration';

import { BackupDetailModal } from './BackupDetailModal';
import { BackupDiffModal } from './BackupDiffModal';
import { BackupPolicyModal } from './BackupPolicyModal';
import { RestoreBackupModal } from './RestoreBackupModal';
import {
  formatInterval,
  formatRelative,
  formatStamp,
} from './helpers';

type SubTab = 'policies' | 'history';

interface Props {
  subTab: SubTab;
  onSubTab: (tab: SubTab) => void;
}

export function BackupsTab({ subTab, onSubTab }: Props) {
  const summary = useConfigBackupSummary();
  const policies = useConfigBackupPolicies();
  const backups = useConfigBackups();
  const [query, setQuery] = useState('');

  const [createPolicy, setCreatePolicy] = useState(false);
  const [editPolicy, setEditPolicy] = useState<ConfigBackupPolicy | null>(null);
  const [detailId, setDetailId] = useState<number | null>(null);
  const [diffId, setDiffId] = useState<number | null>(null);
  const [restoreId, setRestoreId] = useState<number | null>(null);

  return (
    <>
      <BackupSummaryStrip summary={summary.data} />

      <div
        style={{
          display: 'flex',
          gap: '0.5rem',
          alignItems: 'center',
          flexWrap: 'wrap',
          margin: '0.75rem 0',
        }}
      >
        <div style={{ display: 'flex', gap: '0.25rem' }}>
          <button
            type="button"
            className={`btn btn-sm ${subTab === 'policies' ? 'btn-primary' : 'btn-secondary'}`}
            onClick={() => onSubTab('policies')}
          >
            Policies
          </button>
          <button
            type="button"
            className={`btn btn-sm ${subTab === 'history' ? 'btn-primary' : 'btn-secondary'}`}
            onClick={() => onSubTab('history')}
          >
            History
          </button>
        </div>
        <input
          className="form-input"
          placeholder="Search…"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          style={{ maxWidth: 240 }}
        />
        <div style={{ marginLeft: 'auto', display: 'flex', gap: '0.4rem' }}>
          {subTab === 'policies' ? (
            <button
              type="button"
              className="btn btn-sm btn-primary"
              onClick={() => setCreatePolicy(true)}
            >
              New Policy
            </button>
          ) : (
            <a
              className="btn btn-sm btn-secondary"
              href={configBackupBulkDownloadUrl()}
              download
            >
              Download All
            </a>
          )}
        </div>
      </div>

      {subTab === 'policies' ? (
        <PoliciesList
          policies={policies.data || []}
          loading={policies.isPending}
          query={query}
          onEdit={setEditPolicy}
        />
      ) : (
        <HistoryList
          backups={backups.data || []}
          loading={backups.isPending}
          query={query}
          onView={setDetailId}
          onDiff={setDiffId}
          onRestore={setRestoreId}
        />
      )}

      {(createPolicy || editPolicy) && (
        <BackupPolicyModal
          policy={editPolicy}
          onClose={() => {
            setCreatePolicy(false);
            setEditPolicy(null);
          }}
        />
      )}
      <BackupDetailModal
        backupId={detailId}
        onClose={() => setDetailId(null)}
      />
      <BackupDiffModal backupId={diffId} onClose={() => setDiffId(null)} />
      <RestoreBackupModal
        backupId={restoreId}
        onClose={() => setRestoreId(null)}
      />
    </>
  );
}

function BackupSummaryStrip({
  summary,
}: {
  summary?: {
    total_policies?: number;
    total_backups?: number;
    hosts_backed_up?: number;
    last_backup_at?: string | null;
  };
}) {
  const items = [
    { label: 'Policies', value: String(summary?.total_policies ?? '-') },
    { label: 'Backups', value: String(summary?.total_backups ?? '-') },
    { label: 'Hosts', value: String(summary?.hosts_backed_up ?? '-') },
    { label: 'Last backup', value: formatRelative(summary?.last_backup_at) },
  ];
  return (
    <div className="card">
      <div
        className="card-body"
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(140px, 1fr))',
          gap: '0.5rem',
          padding: '0.75rem',
        }}
      >
        {items.map((it) => (
          <div
            key={it.label}
            style={{ display: 'flex', flexDirection: 'column' }}
          >
            <span style={{ color: 'var(--text-muted)', fontSize: '0.75rem' }}>
              {it.label}
            </span>
            <span style={{ fontWeight: 600 }}>{it.value}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

function PoliciesList({
  policies,
  loading,
  query,
  onEdit,
}: {
  policies: ConfigBackupPolicy[];
  loading: boolean;
  query: string;
  onEdit: (p: ConfigBackupPolicy) => void;
}) {
  const { confirm, alert } = useDialogs();
  const run = useRunBackupPolicy();
  const remove = useDeleteBackupPolicy();
  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return policies;
    return policies.filter(
      (p) =>
        p.name.toLowerCase().includes(q) ||
        (p.group_name || '').toLowerCase().includes(q),
    );
  }, [policies, query]);

  if (loading) return <p className="text-muted">Loading policies…</p>;
  if (!filtered.length) {
    return (
      <p className="text-muted">
        No backup policies. Click "New Policy" to create one.
      </p>
    );
  }

  return (
    <>
      {filtered.map((p) => {
        const runningId = run.variables;
        const isRunning = run.isPending && runningId === p.id;
        return (
          <div
            key={p.id}
            className="card"
            style={{ marginBottom: '0.75rem', padding: '1rem' }}
          >
            <div
              style={{
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
                flexWrap: 'wrap',
                gap: '0.5rem',
              }}
            >
              <div>
                <strong>{p.name}</strong>
                <span
                  style={{
                    marginLeft: '0.5rem',
                    fontSize: '0.85em',
                    color: 'var(--text-muted)',
                  }}
                >
                  Group: {p.group_name || '?'} ({p.host_count || 0} hosts)
                </span>
              </div>
              <div
                style={{
                  display: 'flex',
                  gap: '0.5rem',
                  alignItems: 'center',
                }}
              >
                <span
                  style={{
                    color: p.enabled ? 'var(--success)' : 'var(--text-muted)',
                  }}
                >
                  {p.enabled ? 'Enabled' : 'Disabled'}
                </span>
                <button
                  type="button"
                  className="btn btn-sm btn-secondary"
                  disabled={isRunning}
                  onClick={() =>
                    run.mutate(p.id, {
                      onSuccess: (res) => {
                        let msg = `Backup complete: ${res.backed_up} saved, ${res.errors} errors`;
                        if (res.skipped)
                          msg += `, ${res.skipped} unchanged (skipped)`;
                        void alert(msg);
                      },
                      onError: (e) => {
                        void alert({ message: (e as Error).message, variant: 'error' });
                      },
                    })
                  }
                >
                  {isRunning ? 'Running…' : 'Run Now'}
                </button>
                <button
                  type="button"
                  className="btn btn-sm btn-secondary"
                  onClick={() => onEdit(p)}
                >
                  Edit
                </button>
                <button
                  type="button"
                  className="btn btn-sm btn-danger"
                  onClick={async () => {
                    if (
                      !(await confirm(
                        `Delete the backup policy "${p.name}"? This cannot be undone.`,
                      ))
                    )
                      return;
                    remove.mutate(p.id, {
                      onError: (e) => {
                        void alert({ message: (e as Error).message, variant: 'error' });
                      },
                    });
                  }}
                >
                  Delete
                </button>
              </div>
            </div>
            <div
              style={{
                marginTop: '0.5rem',
                fontSize: '0.85em',
                color: 'var(--text-muted)',
              }}
            >
              Interval: {formatInterval(p.interval_seconds)} • Retention:{' '}
              {p.retention_days}d • Last Run: {formatStamp(p.last_run_at) || 'Never'}
            </div>
          </div>
        );
      })}
    </>
  );
}

function HistoryList({
  backups,
  loading,
  query,
  onView,
  onDiff,
  onRestore,
}: {
  backups: ConfigBackup[];
  loading: boolean;
  query: string;
  onView: (id: number) => void;
  onDiff: (id: number) => void;
  onRestore: (id: number) => void;
}) {
  const { confirm, alert } = useDialogs();
  const remove = useDeleteBackup();
  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return backups;
    return backups.filter(
      (b) =>
        (b.hostname || '').toLowerCase().includes(q) ||
        (b.ip_address || '').toLowerCase().includes(q),
    );
  }, [backups, query]);

  if (loading) return <p className="text-muted">Loading backups…</p>;
  if (!filtered.length) {
    return <p className="text-muted">No backups yet.</p>;
  }

  return (
    <>
      {filtered.map((b) => {
        const sizeKb =
          b.config_length != null
            ? `${(b.config_length / 1024).toFixed(1)} KB`
            : '-';
        return (
          <div
            key={b.id}
            className="card"
            style={{ marginBottom: '0.75rem', padding: '1rem' }}
          >
            <div
              style={{
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
                flexWrap: 'wrap',
                gap: '0.5rem',
              }}
            >
              <div>
                <strong>{b.hostname || b.ip_address || '?'}</strong>
                <span
                  style={{
                    marginLeft: '0.5rem',
                    fontSize: '0.85em',
                    color: 'var(--text-muted)',
                  }}
                >
                  {b.ip_address || ''}
                </span>
              </div>
              <div
                style={{
                  display: 'flex',
                  gap: '0.5rem',
                  alignItems: 'center',
                }}
              >
                <span
                  style={{
                    color:
                      b.status === 'success'
                        ? 'var(--success)'
                        : 'var(--danger)',
                    fontSize: '0.85em',
                  }}
                >
                  {b.status}
                </span>
                <button
                  type="button"
                  className="btn btn-sm btn-secondary"
                  onClick={() => onView(b.id)}
                >
                  View
                </button>
                {b.status === 'success' && (
                  <>
                    <button
                      type="button"
                      className="btn btn-sm btn-secondary"
                      onClick={() => onDiff(b.id)}
                    >
                      Diff
                    </button>
                    <a
                      className="btn btn-sm btn-secondary"
                      href={configBackupDownloadUrl(b.id)}
                      download
                      title="Download running-config as .txt"
                    >
                      Download
                    </a>
                  </>
                )}
                <button
                  type="button"
                  className="btn btn-sm btn-secondary"
                  onClick={() => onRestore(b.id)}
                >
                  Restore
                </button>
                <button
                  type="button"
                  className="btn btn-sm btn-danger"
                  onClick={async () => {
                    if (
                      !(await confirm(
                        'Delete this backup? This cannot be undone.',
                      ))
                    )
                      return;
                    remove.mutate(b.id, {
                      onError: (e) => {
                        void alert({ message: (e as Error).message, variant: 'error' });
                      },
                    });
                  }}
                >
                  Delete
                </button>
              </div>
            </div>
            <div
              style={{
                marginTop: '0.5rem',
                fontSize: '0.85em',
                color: 'var(--text-muted)',
              }}
            >
              {formatStamp(b.captured_at)} • {b.capture_method || '-'} • {sizeKb}
              {b.error_message && (
                <span style={{ color: 'var(--danger)' }}>
                  {' '}
                  • {b.error_message}
                </span>
              )}
            </div>
          </div>
        );
      })}
    </>
  );
}
