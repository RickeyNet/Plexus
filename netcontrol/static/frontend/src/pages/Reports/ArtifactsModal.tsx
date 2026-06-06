import { Modal } from '@/components/Modal';
import { useDialogs } from '@/components/DialogProvider-context';
import { reportArtifactUrl, useReportRunArtifacts } from '@/api/reports';

import { downloadReportExport } from './helpers';

interface Props {
  runId: number | null;
  isOpen: boolean;
  onClose: () => void;
}

export function ArtifactsModal({ runId, isOpen, onClose }: Props) {
  const { alert } = useDialogs();
  const query = useReportRunArtifacts(runId);

  function handleDownload(id: number) {
    downloadReportExport(reportArtifactUrl(id), `artifact_${id}`).catch((err) => {
      void alert({ message: (err as Error).message, variant: 'error' });
    });
  }

  return (
    <Modal isOpen={isOpen} onClose={onClose} title={runId != null ? `Run #${runId} Artifacts` : 'Artifacts'}>
      {query.isPending && <p className="text-muted">Loading…</p>}
      {query.error && (
        <p style={{ color: 'var(--danger)' }}>Failed to load artifacts: {(query.error as Error).message}</p>
      )}
      {query.data && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.45rem' }}>
          {(query.data.artifacts ?? []).length === 0 ? (
            <p className="text-muted">No persisted artifacts found for this run.</p>
          ) : (
            (query.data.artifacts ?? []).map((a) => (
              <div
                key={a.id}
                className="card"
                style={{ padding: '0.65rem 0.8rem', display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '0.75rem' }}
              >
                <div>
                  <div style={{ fontWeight: 600 }}>{a.file_name || `artifact_${a.id}`}</div>
                  <div className="text-muted" style={{ fontSize: '0.82rem' }}>
                    {a.artifact_type ?? ''} · {a.media_type ?? ''} · {Number(a.size_bytes ?? 0).toLocaleString()} bytes
                  </div>
                </div>
                <button className="btn btn-sm btn-secondary" onClick={() => handleDownload(a.id)}>Download</button>
              </div>
            ))
          )}
        </div>
      )}
      <div style={{ marginTop: '1rem', display: 'flex', justifyContent: 'flex-end' }}>
        <button className="btn btn-secondary" onClick={onClose}>Close</button>
      </div>
    </Modal>
  );
}
