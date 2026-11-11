import { BusyButton } from '@/components/BusyButton';
import { EmptyState } from '@/components/EmptyState';
import { LoadingState } from '@/components/LoadingState';
import { Modal } from '@/components/Modal';
import { QueryError } from '@/components/QueryError';
import { useDialogs } from '@/components/DialogProvider-context';
import { reportArtifactUrl, useReportRunArtifacts } from '@/api/reports';
import { usePendingKeys } from '@/lib/usePendingKeys';
import { formatBytes } from '@/pages/NetworkTools/formatting';

import { artifactTypeLabel, downloadReportExport } from './helpers';

interface Props {
  runId: number | null;
  isOpen: boolean;
  onClose: () => void;
}

export function ArtifactsModal({ runId, isOpen, onClose }: Props) {
  const { alert } = useDialogs();
  const query = useReportRunArtifacts(runId);
  const downloading = usePendingKeys<number>();

  function handleDownload(id: number) {
    void downloading.run(id, () =>
      downloadReportExport(reportArtifactUrl(id), `artifact_${id}`).catch((err) => {
        void alert({ message: (err as Error).message, variant: 'error' });
      }),
    );
  }

  return (
    <Modal
      isOpen={isOpen}
      onClose={onClose}
      title={runId != null ? `Run #${runId} Artifacts` : 'Artifacts'}
      footer={<button type="button" className="btn btn-secondary" onClick={onClose}>Close</button>}
    >
      {query.isPending && <LoadingState />}
      {query.isError && !query.data && (
        <QueryError what="artifacts" query={query} />
      )}
      {query.data && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.45rem' }}>
          {(query.data.artifacts ?? []).length === 0 ? (
            <EmptyState compact message="No persisted artifacts found for this run." />
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
                    {artifactTypeLabel(a.artifact_type)} · {formatBytes(a.size_bytes)}
                  </div>
                </div>
                <BusyButton
                  className="btn btn-sm btn-secondary"
                  busy={downloading.isPending(a.id)}
                  onClick={() => handleDownload(a.id)}
                >
                  Download
                </BusyButton>
              </div>
            ))
          )}
        </div>
      )}
    </Modal>
  );
}
