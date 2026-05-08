import { useState } from 'react';

import { useReportRuns, type ReportRun } from '@/api/reports';

import { ArtifactsModal } from './ArtifactsModal';
import { downloadReportExport } from './helpers';

export function HistoryTab() {
  const query = useReportRuns();
  const [artifactsRunId, setArtifactsRunId] = useState<number | null>(null);

  if (query.isPending) return <p className="text-muted">Loading…</p>;
  if (query.error) {
    return <div className="card" style={{ color: 'var(--danger)', padding: '1rem' }}>Error loading reports: {(query.error as Error).message}</div>;
  }

  const data = query.data;
  const runs: ReportRun[] = Array.isArray(data) ? data : data?.runs ?? [];

  if (!runs.length) {
    return (
      <div className="card" style={{ padding: '1.5rem' }}>
        <p className="text-muted">No reports generated yet.</p>
      </div>
    );
  }

  function statusBadge(status?: string) {
    if (status === 'completed') return 'badge-success';
    if (status === 'error') return 'badge-danger';
    return 'badge-warning';
  }

  function downloadCsv(runId: number) {
    downloadReportExport(`/api/reports/runs/${runId}/csv`, `report_${runId}.csv`).catch((err) =>
      alert((err as Error).message),
    );
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
              <td><span className={`badge ${statusBadge(r.status)}`}>{r.status ?? ''}</span></td>
              <td>{r.row_count ?? '-'}</td>
              <td>{r.started_at ? new Date(r.started_at).toLocaleString() : '-'}</td>
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
