import { useState } from 'react';

import { type SyncJob, useDeleteSyncJob, useRunSyncJob, useSyncConnections, useSyncJobs } from '@/api/sync';
import { StatusBadge } from '@/components/Badge';
import { BusyButton } from '@/components/BusyButton';
import { CardHeader, CatalogueBody, RowActions } from '@/components/CatalogueParts';
import { DataTable } from '@/components/DataTable';
import { useDialogs } from '@/components/DialogProvider-context';
import { EmptyState } from '@/components/EmptyState';
import { formatBackendDateTime } from '@/lib/datetime';
import { DIRECTION_LABEL, KIND_LABEL, OBJECT_TYPE_LABEL, POLICY_LABEL, describeSchedule, writesPlexus } from '@/lib/sync';
import { usePendingKeys } from '@/lib/usePendingKeys';

import { useCanWriteSync, useConfirmDelete } from './hooks';
import { JobModal } from './JobModal';

const RIGHT = { textAlign: 'right' } as const;

interface JobsTabProps {
  onOpenRun: (runId: number) => void;
}

/** Sync jobs with their last run; dry run and run now open the run's diff. */
export function JobsTab({ onOpenRun }: JobsTabProps) {
  const canWrite = useCanWriteSync();
  const q = useSyncJobs();
  const connections = useSyncConnections();
  const remove = useDeleteSyncJob();
  const run = useRunSyncJob();
  const confirmDelete = useConfirmDelete();
  const { confirm, alert } = useDialogs();
  const busy = usePendingKeys<string>();
  const [editing, setEditing] = useState<SyncJob | 'new' | null>(null);
  const rows = q.data ?? [];
  const noConnections = connections.data !== undefined && connections.data.length === 0;

  const start = (job: SyncJob, dryRun: boolean) =>
    void busy.run(`${dryRun ? 'dry' : 'run'}-${job.id}`, async () => {
      if (!dryRun) {
        const target = KIND_LABEL[job.connection_kind] ?? job.connection_name;
        const where =
          job.direction === 'import'
            ? 'Plexus'
            : job.direction === 'export'
              ? `${target} (${job.connection_name})`
              : `Plexus and ${target} (${job.connection_name})`;
        const agreed = await confirm({
          title: 'Run sync job',
          message:
            `Run "${job.name}" now? It writes the planned changes to ${where}` +
            (job.delete_missing ? ', including deletes of records missing on the other side.' : '.') +
            '\nRun a dry run first to see them.',
          confirmLabel: 'Run now',
          confirmVariant: 'primary',
        });
        if (!agreed) return;
      }
      try {
        const started = await run.mutateAsync({ id: job.id, dryRun });
        onOpenRun(started.id);
      } catch (err) {
        await alert({ title: 'Run not started', message: (err as Error).message, variant: 'error' });
      }
    });

  const addButton = canWrite && !noConnections && (
    <button type="button" className="btn btn-sm btn-primary" onClick={() => setEditing('new')}>
      Add job
    </button>
  );

  return (
    <div className="card">
      <CardHeader
        title="Sync jobs"
        sub={q.data && `${rows.length.toLocaleString()} job${rows.length === 1 ? '' : 's'}`}
        actions={rows.length > 0 && addButton}
      />
      <CatalogueBody
        query={q}
        what="sync jobs"
        rows={rows}
        empty={
          <EmptyState
            compact
            message="No sync jobs yet."
            description={
              noConnections
                ? 'Add a connection to NetBox, Nautobot or ServiceNow first (Connections tab, admins).'
                : 'A job syncs chosen object types with one connection: import, export or both ways, by hand or on a schedule.'
            }
            action={addButton || undefined}
          />
        }
      >
        <DataTable compact aria-label="Sync jobs">
          <thead>
            <tr>
              <th>Name</th>
              <th>Connection</th>
              <th>Direction</th>
              <th>Objects</th>
              <th>Schedule</th>
              <th>Last run</th>
              <th style={RIGHT}>Actions</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((job) => (
              <tr key={job.id}>
                <td style={{ fontWeight: 600 }}>
                  {job.name}
                  {job.description && <div className="text-muted">{job.description}</div>}
                </td>
                <td>
                  {job.connection_name}
                  <div className="text-muted">{KIND_LABEL[job.connection_kind] ?? job.connection_kind}</div>
                </td>
                <td>
                  {DIRECTION_LABEL[job.direction]}
                  {job.direction === 'bidirectional' && (
                    <div className="text-muted">{POLICY_LABEL[job.conflict_policy]}</div>
                  )}
                  {job.delete_missing && <div className="text-muted">Deletes missing records</div>}
                </td>
                <td>{job.object_types.map((t) => OBJECT_TYPE_LABEL[t] ?? t).join(', ')}</td>
                <td>
                  {describeSchedule(job.interval_minutes)}
                  {!job.enabled && job.interval_minutes > 0 && <div className="text-muted">Paused</div>}
                </td>
                <td>
                  {job.running ? (
                    <StatusBadge status="running" size="sm" />
                  ) : job.last_run_id ? (
                    <button
                      type="button"
                      className="btn-link"
                      aria-label={`Open the last run of ${job.name}`}
                      onClick={() => onOpenRun(job.last_run_id as number)}
                    >
                      <StatusBadge status={job.last_run_status} size="sm" />{' '}
                      <span className="text-muted">{formatBackendDateTime(job.last_run_at)}</span>
                    </button>
                  ) : (
                    <span className="text-muted">Never</span>
                  )}
                </td>
                <td style={RIGHT}>
                  {canWrite && (
                    <div className="table-actions" style={{ justifyContent: 'flex-end' }}>
                      <BusyButton
                        className="btn btn-sm btn-secondary"
                        busy={busy.isPending(`dry-${job.id}`)}
                        disabled={job.running}
                        aria-label={`Dry run ${job.name}`}
                        onClick={() => start(job, true)}
                      >
                        Dry run
                      </BusyButton>
                      <BusyButton
                        className="btn btn-sm btn-secondary"
                        busy={busy.isPending(`run-${job.id}`)}
                        disabled={job.running}
                        aria-label={`Run ${job.name} now`}
                        title={writesPlexus(job.direction) ? 'Writes into Plexus' : 'Writes to the remote system'}
                        onClick={() => start(job, false)}
                      >
                        Run now
                      </BusyButton>
                      <RowActions
                        label={`sync job ${job.name}`}
                        onEdit={() => setEditing(job)}
                        onDelete={() =>
                          void busy.run(`delete-${job.id}`, () =>
                            confirmDelete('sync job', job.name, () => remove.mutateAsync(job.id), 'Its run history goes with it.'),
                          )
                        }
                        deleting={busy.isPending(`delete-${job.id}`)}
                      />
                    </div>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </DataTable>
      </CatalogueBody>
      {editing && <JobModal job={editing === 'new' ? null : editing} onClose={() => setEditing(null)} />}
    </div>
  );
}
