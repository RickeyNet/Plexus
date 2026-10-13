import { useQueryClient } from '@tanstack/react-query';

import { JobStreamModal } from '@/components/JobStreamModal';

interface Props {
  isOpen: boolean;
  onClose: () => void;
  jobId: string | null;
  wsPath: 'config-capture' | 'config-revert';
  title: string;
}

const INVALIDATE_ON_COMPLETE = [
  'config-drift-summary',
  'config-drift-events',
  'config-snapshots',
  'config-backups',
  'config-backup-summary',
];

export function ConfigJobStreamModal({ isOpen, onClose, jobId, wsPath, title }: Props) {
  const qc = useQueryClient();
  return (
    <JobStreamModal
      isOpen={isOpen}
      onClose={onClose}
      title={title}
      wsPath={jobId ? `${wsPath}/${jobId}` : null}
      subtitle={`Job: ${jobId || '-'}`}
      onComplete={() => {
        for (const key of INVALIDATE_ON_COMPLETE) qc.invalidateQueries({ queryKey: [key] });
      }}
    />
  );
}
