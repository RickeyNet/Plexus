import { useState } from 'react';

import { StatusBadge } from '@/components/Badge';
import { useDialogs } from '@/components/DialogProvider-context';
import { useReportRuns, type ReportRun } from '@/api/reports';
import { EmptyState } from '@/components/EmptyState';
import { LoadingState } from '@/components/LoadingState';
import { formatBackendDateTime } from '@/lib/datetime';

import { ArtifactsModal } from './ArtifactsModal';
import { downloadReportExport } from './helpers';

export function HistoryTab() {
  const { alert } = useDialogs();
  const query = useReportRuns();
  const [artifactsRunId, setArtifactsRunId] = useState<number | null>(null);

  if (query.isPending) return <LoadingState />;
  if (query.error) {
    return <div className="card-inset" style={{ color: 'var(--danger)' }}>Error loading reports: {(query.error as Error).message}</div>;
  }

  const data = query.data;
  const runs: ReportRun[] = Array.isArray(data) ? data : data?.runs ?? [];

  if (!runs.length) {
    return (
      <div className="card-inset">
        <EmptyState compact message="No reports generated yet." />
      </div>
    );
  }

  function downloadCsv(runId: number) {
    downloadReportExport(`/api/reports/runs/${runId}/csv`, `report_${runId}.csv`).catch((err) => {
      void alert({ message: (err as Error).message, variant: 'error' });
    });
  }

  return (
    <>
      <table className="data-table">
        <thead>
          <tr>
            <th>ID</th>
            <th>Type</th>
            <th>Status</th>
            <th>Rows</th>
            <th>Started</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>
          {runs.map((r) => (
            <tr key={r.id}>
              <td>#{r.id}</td>
              <td>{r.report_type ?? ''}</td>
              <td><StatusBadge status={r.status} /></td>
              <td>{r.row_count ?? '-'}</td>
              <td>{formatBackendDateTime(r.started_at)}</td>
              <td style={{ display: 'flex', gap: '0.35rem' }}>
                {r.status === 'completed' && (
                  <>
                    <button className="btn btn-sm btn-secondary" onClick={() => downloadCsv(r.id)}>CSV</button>
                    <button className="btn btn-sm btn-secondary" onClick={() => setArtifactsRunId(r.id)}>Artifacts</button>
                  </>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>

      <ArtifactsModal
        runId={artifactsRunId}
        isOpen={artifactsRunId != null}
        onClose={() => setArtifactsRunId(null)}
      />
    </>
  );
}
