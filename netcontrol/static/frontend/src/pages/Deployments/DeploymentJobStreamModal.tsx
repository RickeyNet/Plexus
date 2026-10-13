import { useQueryClient } from '@tanstack/react-query';

import { JobStreamModal, type JobStreamMessage } from '@/components/JobStreamModal';

interface Props {
  isOpen: boolean;
  onClose: () => void;
  jobId: string | null;
  deploymentId: number | null;
  title: string;
}

function parseDeploymentLine(msg: JobStreamMessage): string | null {
  return typeof msg.data === 'string' ? msg.data : null;
}

export function DeploymentJobStreamModal({ isOpen, onClose, jobId, deploymentId, title }: Props) {
  const qc = useQueryClient();
  return (
    <JobStreamModal
      isOpen={isOpen}
      onClose={onClose}
      title={title}
      wsPath={jobId ? `deployment/${jobId}` : null}
      subtitle={
        <>
          {deploymentId != null && `Deployment #${deploymentId} · `}
          Job: {jobId || '-'}
        </>
      }
      parseLine={parseDeploymentLine}
      onComplete={() => {
        qc.invalidateQueries({ queryKey: ['deployment-summary'] });
        qc.invalidateQueries({ queryKey: ['deployments'] });
        if (deploymentId != null) qc.invalidateQueries({ queryKey: ['deployment', deploymentId] });
      }}
    />
  );
}
