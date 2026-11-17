import { useId, useState } from 'react';

import { useSyncJobs, useSyncRuns } from '@/api/sync';
import { Badge, StatusBadge } from '@/components/Badge';
import { CardHeader, CatalogueBody } from '@/components/CatalogueParts';
import { DataTable } from '@/components/DataTable';
import { EmptyState } from '@/components/EmptyState';
import { clickableProps } from '@/lib/clickable';
import { formatBackendDateTime } from '@/lib/datetime';
import { describeTotals, runTotals } from '@/lib/sync';

interface RunsTabProps {
  onOpenRun: (runId: number) => void;
}

/** Every job's runs, newest first (the last 50 of each job are kept); a row opens its diff. */
export function RunsTab({ onOpenRun }: RunsTabProps) {
  const id = useId();
  const [jobId, setJobId] = useState<number | null>(null);
  const jobs = useSyncJobs();
  const q = useSyncRuns(jobId);
  const rows = q.data ?? [];

  return (
    <div className="card">
      <CardHeader
        title="Run history"
        sub={q.data && `${rows.length.toLocaleString()} run${rows.length === 1 ? '' : 's'}`}
        actions={
          <>
            <label className="sr-only" htmlFor={`${id}-job`}>
              Job
            </label>
            <select
              id={`${id}-job`}
              className="form-select form-select-sm"
              value={jobId ?? ''}
              onChange={(e) => setJobId(e.target.value ? Number(e.target.value) : null)}
            >
              <option value="">All jobs</option>
              {(jobs.data ?? []).map((j) => (
                <option key={j.id} value={j.id}>
                  {j.name}
                </option>
              ))}
            </select>
          </>
        }
      />
      <CatalogueBody
        query={q}
        what="sync runs"
        rows={rows}
        empty={
          <EmptyState
            compact
            message={jobId === null ? 'No runs yet.' : 'This job has not run yet.'}
            description="Start a dry run from the Jobs tab to see what a sync would change."
          />
        }
      >
        <DataTable compact aria-label="Sync runs">
          <thead>
            <tr>
              <th>Started</th>
              <th>Job</th>
              <th>Kind</th>
              <th>Status</th>
              <th>Changes</th>
              <th>Message</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((run) => {
              const totals = runTotals(run.summary);
              return (
                <tr
                  key={run.id}
                  className="row-clickable"
                  aria-label={`Open run ${run.id} of ${run.job_name}`}
                  {...clickableProps(() => onOpenRun(run.id), { role: null })}
                >
                  <td>
                    {formatBackendDateTime(run.started_at)}
                    <div className="text-muted">
                      {run.trigger === 'schedule' ? 'Scheduled' : run.started_by || 'Manual'}
                    </div>
                  </td>
                  <td>{run.job_name}</td>
                  <td>
                    <Badge size="sm" tone={run.dry_run ? 'neutral' : 'primary'}>
                      {run.dry_run ? 'Dry run' : 'Run'}
                    </Badge>
                  </td>
                  <td>
                    <StatusBadge status={run.status} size="sm" />
                  </td>
                  <td>
                    {describeTotals(totals)}
                    {(totals.failed > 0 || totals.errors > 0) && (
                      <div className="text-muted">
                        {totals.failed > 0 && `${totals.failed} failed`}
                        {totals.failed > 0 && totals.errors > 0 && ' · '}
                        {totals.errors > 0 && `${totals.errors} type${totals.errors === 1 ? '' : 's'} not read`}
                      </div>
                    )}
                  </td>
                  <td className="text-muted">{run.message}</td>
                </tr>
              );
            })}
          </tbody>
        </DataTable>
      </CatalogueBody>
    </div>
  );
}
