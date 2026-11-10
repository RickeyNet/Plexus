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
import { EmptyState } from '@/components/EmptyState';
import { LoadingState } from '@/components/LoadingState';
import { KebabMenu, MenuItem, MenuSeparator } from '@/components/Menu';
import { SegmentedControl } from '@/components/SegmentedControl';
import { SummaryStrip } from '@/components/SummaryStrip';
import { formatBackendDateTime, formatRelativeTime } from '@/lib/datetime';

import { BackupModal } from './BackupModal';
import { BackupPolicyModal } from './BackupPolicyModal';
import { RestoreBackupModal } from './RestoreBackupModal';
import {
  type BackupView,
  formatInterval,
} from './helpers';

type SubTab = 'policies' | 'history';

const SUB_TABS: { key: SubTab; label: string }[] = [
  { key: 'policies', label: 'Policies' },
  { key: 'history', label: 'History' },
];

// The Policies / History switch is local to this tab; the page shows a single
// "Backups" tab for both.
export function BackupsTab() {
  const [subTab, setSubTab] = useState<SubTab>('policies');
  const summary = useConfigBackupSummary();
  const policies = useConfigBackupPolicies();
  const backups = useConfigBackups();
  const [query, setQuery] = useState('');

  const [createPolicy, setCreatePolicy] = useState(false);
  const [editPolicy, setEditPolicy] = useState<ConfigBackupPolicy | null>(null);
  const [viewing, setViewing] = useState<{ id: number; view: BackupView } | null>(null);
  const [restoreId, setRestoreId] = useState<number | null>(null);

  return (
    <>
      <BackupSummaryStrip summary={summary.data} />

      <div className="toolbar">
        <SegmentedControl options={SUB_TABS} value={subTab} onChange={setSubTab} aria-label="Backups view" />
        <input
          className="form-input form-input-sm"
          placeholder="Search…"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          style={{ maxWidth: 240 }}
        />
        <div style={{ marginLeft: 'auto', display: 'flex', gap: 'var(--space-2)' }}>
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
          onView={(id) => setViewing({ id, view: 'config' })}
          onDiff={(id) => setViewing({ id, view: 'diff' })}
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
      <BackupModal
        backupId={viewing?.id ?? null}
        view={viewing?.view ?? 'config'}
        onViewChange={(view) => setViewing((v) => (v ? { ...v, view } : v))}
        onClose={() => setViewing(null)}
      />
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
    { label: 'Last backup', value: formatRelativeTime(summary?.last_backup_at, undefined, 'Never') },
  ];
  return <SummaryStrip items={items} />;
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

  if (loading) return <LoadingState text="Loading policies…" />;
  if (!filtered.length) {
    return (
      <p className="text-muted">
        No backup policies. Click "New Policy" to create one.
      </p>
    );
  }

  return (
    <div className="stack stack-sm">
      {filtered.map((p) => {
        const runningId = run.variables;
        const isRunning = run.isPending && runningId === p.id;
        return (
          <div key={p.id} className="card">
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
                <KebabMenu label={`Actions for ${p.name}`}>
                  <MenuItem onSelect={() => onEdit(p)}>Edit</MenuItem>
                  <MenuSeparator />
                  <MenuItem
                    danger
                    onSelect={async () => {
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
                  </MenuItem>
                </KebabMenu>
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
              {p.retention_days}d • Last Run: {formatBackendDateTime(p.last_run_at, '') || 'Never'}
            </div>
          </div>
        );
      })}
    </div>
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

  if (loading) return <LoadingState text="Loading backups…" />;
  if (!filtered.length) {
    return <EmptyState compact message="No backups yet." />;
  }

  return (
    <div className="stack stack-sm">
      {filtered.map((b) => {
        const sizeKb =
          b.config_length != null
            ? `${(b.config_length / 1024).toFixed(1)} KB`
            : '-';
        return (
          <div key={b.id} className="card">
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
                <KebabMenu label={`Actions for ${b.hostname || b.ip_address || 'backup'}`}>
                  {b.status === 'success' && (
                    <>
                      <MenuItem onSelect={() => onDiff(b.id)}>Diff</MenuItem>
                      <MenuItem
                        href={configBackupDownloadUrl(b.id)}
                        download
                        title="Download running-config as .txt"
                      >
                        Download
                      </MenuItem>
                      <MenuSeparator />
                    </>
                  )}
                  <MenuItem danger onSelect={() => onRestore(b.id)}>
                    Restore
                  </MenuItem>
                  <MenuItem
                    danger
                    onSelect={async () => {
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
                  </MenuItem>
                </KebabMenu>
              </div>
            </div>
            <div
              style={{
                marginTop: '0.5rem',
                fontSize: '0.85em',
                color: 'var(--text-muted)',
              }}
            >
              {formatBackendDateTime(b.captured_at, '')} • {b.capture_method || '-'} • {sizeKb}
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
    </div>
  );
}
