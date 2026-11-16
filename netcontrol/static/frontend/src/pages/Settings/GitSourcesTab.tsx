import { useState } from 'react';

import {
  type GitSource,
  useDeleteGitSource,
  useGitSources,
  useSyncGitSource,
} from '@/api/gitSources';
import { Badge } from '@/components/Badge';
import { BusyButton } from '@/components/BusyButton';
import { DataTable } from '@/components/DataTable';
import { DeleteButton } from '@/components/DeleteButton';
import { useDialogs } from '@/components/DialogProvider-context';
import { EmptyState } from '@/components/EmptyState';
import { LoadingState } from '@/components/LoadingState';
import { QueryError } from '@/components/QueryError';
import { formatBackendDateTime } from '@/lib/datetime';
import { usePendingKeys } from '@/lib/usePendingKeys';

import { GitSourceModal } from './GitSourceModal';
import { CONTENT_TYPE_LABEL, objectCountText, shortSha, statusBadge, syncResultText } from './gitSources';

const RIGHT = { textAlign: 'right' } as const;

function SourceStatus({ source }: { source: GitSource }) {
  const badge = statusBadge(source.status);
  const warnings = source.summary.warnings ?? [];
  return (
    <div>
      <Badge tone={badge.tone} size="sm">
        {badge.label}
      </Badge>
      {source.status === 'error' && source.error && (
        <div className="form-help" style={{ margin: 0, overflowWrap: 'anywhere' }}>
          {source.error}
        </div>
      )}
      {source.status === 'warning' && warnings.length > 0 && (
        <details className="form-help" style={{ margin: 0 }}>
          <summary>
            {warnings.length} file{warnings.length === 1 ? '' : 's'} skipped
          </summary>
          <ul style={{ margin: 'var(--space-1) 0 0 0', paddingLeft: 'var(--space-4)' }}>
            {warnings.map((w) => (
              <li key={`${w.path}:${w.message}`} style={{ overflowWrap: 'anywhere' }}>
                <code>{w.path}</code>: {w.message}
              </li>
            ))}
          </ul>
        </details>
      )}
    </div>
  );
}

/** Settings tab: Git repositories templates, playbooks and config contexts sync from. */
export function GitSourcesTab() {
  const query = useGitSources();
  const sync = useSyncGitSource();
  const remove = useDeleteGitSource();
  const syncing = usePendingKeys<number>();
  const deleting = usePendingKeys<number>();
  const { confirm, alert } = useDialogs();
  const [editing, setEditing] = useState<GitSource | 'new' | null>(null);

  const rows = query.data?.sources ?? [];
  const contentTypes = query.data?.content_types ?? [];
  const addButton = (
    <button type="button" className="btn btn-sm btn-primary" onClick={() => setEditing('new')}>
      Add Git source
    </button>
  );

  const handleSync = (source: GitSource) =>
    void syncing.run(source.id, async () => {
      try {
        const out = await sync.mutateAsync(source.id);
        if (!out.ok) {
          await alert({
            title: 'Sync failed',
            message: `${source.name} was not synced: ${out.source.error} Its records are unchanged. Fix the source and sync again.`,
            variant: 'error',
          });
        } else if (out.result) {
          await alert({ title: `Synced ${source.name}`, message: syncResultText(out.result) });
        }
      } catch (err) {
        await alert({
          title: 'Sync failed',
          message: `${source.name} was not synced: ${(err as Error).message} Try again.`,
          variant: 'error',
        });
      }
    });

  const handleDelete = (source: GitSource) =>
    void deleting.run(source.id, async () => {
      const owned = objectCountText(source.object_counts);
      const agreed = await confirm({
        title: 'Delete Git source',
        message: `Delete the Git source "${source.name}"?${owned ? ` Its ${owned} are removed from Plexus too (records still used by job history are kept as ordinary records).` : ''} The repository itself is not changed.`,
        confirmLabel: 'Delete source',
      });
      if (!agreed) return;
      try {
        await remove.mutateAsync(source.id);
      } catch (err) {
        await alert({
          title: 'Source not deleted',
          message: `The Git source "${source.name}" was not deleted: ${(err as Error).message} Try again.`,
          variant: 'error',
        });
      }
    });

  if (query.isError && !query.data) return <QueryError what="Git sources" query={query} />;
  if (query.isPending) return <LoadingState />;

  return (
    <div className="stack stack-sm">
      {rows.length > 0 && <div style={{ display: 'flex', justifyContent: 'flex-end' }}>{addButton}</div>}
      {rows.length === 0 ? (
        <EmptyState
          compact
          message="No Git sources yet."
          description="Add a repository to keep templates, Ansible playbooks and config contexts in Git. Synced records are read-only in Plexus."
          action={addButton}
        />
      ) : (
        <DataTable compact aria-label="Git sources">
          <thead>
            <tr>
              <th>Name</th>
              <th>Provides</th>
              <th>Status</th>
              <th>Last commit</th>
              <th>Schedule</th>
              <th style={RIGHT}>Actions</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((source) => (
              <tr key={source.id}>
                <td>
                  {source.name}
                  {!source.enabled && (
                    <>
                      {' '}
                      <Badge tone="neutral" size="sm">
                        Disabled
                      </Badge>
                    </>
                  )}
                  <div className="form-help" style={{ margin: 0, overflowWrap: 'anywhere' }}>
                    <code>{source.remote_url}</code> @ <code>{source.branch}</code>
                    {source.credential_name ? ` · ${source.credential_name}` : ''}
                  </div>
                </td>
                <td>
                  {source.provides.map((t) => CONTENT_TYPE_LABEL[t] ?? t).join(', ')}
                  <div className="form-help" style={{ margin: 0 }}>
                    {objectCountText(source.object_counts) || 'No records yet'}
                  </div>
                </td>
                <td>
                  <SourceStatus source={source} />
                </td>
                <td>
                  {source.last_commit ? <code title={source.last_commit}>{shortSha(source.last_commit)}</code> : '-'}
                  <div className="form-help" style={{ margin: 0 }}>
                    {source.last_synced_at ? formatBackendDateTime(source.last_synced_at) : 'Never synced'}
                  </div>
                </td>
                <td>
                  {source.sync_interval_minutes > 0
                    ? `Every ${source.sync_interval_minutes.toLocaleString()} min`
                    : 'On demand'}
                </td>
                <td style={RIGHT}>
                  <div style={{ display: 'inline-flex', gap: 'var(--space-1)', flexWrap: 'wrap', justifyContent: 'flex-end' }}>
                    <BusyButton
                      className="btn btn-sm btn-primary"
                      busy={syncing.isPending(source.id)}
                      busyLabel="Syncing…"
                      onClick={() => handleSync(source)}
                    >
                      Sync now
                    </BusyButton>
                    <button type="button" className="btn btn-sm btn-secondary" onClick={() => setEditing(source)}>
                      Edit
                    </button>
                    <DeleteButton
                      busy={deleting.isPending(source.id)}
                      onClick={() => handleDelete(source)}
                      aria-label={`Delete Git source ${source.name}`}
                    />
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </DataTable>
      )}
      {editing && (
        <GitSourceModal
          source={editing === 'new' ? null : editing}
          contentTypes={contentTypes}
          onClose={() => setEditing(null)}
        />
      )}
    </div>
  );
}
