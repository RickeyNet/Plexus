import { useEffect, useRef, useState } from 'react';
import { useQueryClient } from '@tanstack/react-query';

import { Modal } from '@/components/Modal';

interface Props {
  isOpen: boolean;
  onClose: () => void;
  jobId: string | null;
  deploymentId: number | null;
  title: string;
}

type JobStatus =
  | { kind: 'connecting' }
  | { kind: 'streaming' }
  | { kind: 'complete'; status: string }
  | { kind: 'error' }
  | { kind: 'closed' };

interface WsMessage {
  type?: string;
  data?: string;
  status?: string;
}

export function DeploymentJobStreamModal({
  isOpen,
  onClose,
  jobId,
  deploymentId,
  title,
}: Props) {
  const qc = useQueryClient();
  const [output, setOutput] = useState('');
  const [status, setStatus] = useState<JobStatus>({ kind: 'connecting' });
  const outputRef = useRef<HTMLPreElement | null>(null);
  const wsRef = useRef<WebSocket | null>(null);

  useEffect(() => {
    if (!isOpen || !jobId) return;

    setOutput('');
    setStatus({ kind: 'connecting' });

    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const ws = new WebSocket(`${protocol}//${window.location.host}/ws/deployment/${jobId}`);
    wsRef.current = ws;

    ws.onopen = () => {
      setStatus({ kind: 'streaming' });
    };

    ws.onmessage = (event) => {
      let msg: WsMessage;
      try {
        msg = JSON.parse(event.data);
      } catch {
        return;
      }
      if (msg.type === 'line' && typeof msg.data === 'string') {
        setOutput((prev) => prev + msg.data);
      } else if (msg.type === 'job_complete') {
        setStatus({ kind: 'complete', status: msg.status || 'completed' });
        ws.close();
        qc.invalidateQueries({ queryKey: ['deployment-summary'] });
        qc.invalidateQueries({ queryKey: ['deployments'] });
        if (deploymentId != null) {
          qc.invalidateQueries({ queryKey: ['deployment', deploymentId] });
        }
      }
    };

    ws.onerror = () => {
      setStatus({ kind: 'error' });
    };

    ws.onclose = () => {
      setStatus((prev) => (prev.kind === 'streaming' ? { kind: 'closed' } : prev));
    };

    return () => {
      wsRef.current = null;
      // Detach handlers before close so any in-flight buffered messages or
      // the synthetic onclose don't fire setState on an unmounted/replaced
      // effect run.
      ws.onopen = null;
      ws.onmessage = null;
      ws.onerror = null;
      ws.onclose = null;
      try {
        ws.close();
      } catch {
        /* ignore */
      }
    };
  }, [isOpen, jobId, deploymentId, qc]);

  // Auto-scroll output to bottom on every update
  useEffect(() => {
    const el = outputRef.current;
    if (el) el.scrollTop = el.scrollHeight;
  }, [output]);

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(output);
    } catch {
      /* ignore — clipboard not available */
    }
  };

  return (
    <Modal isOpen={isOpen} onClose={onClose} title={title}>
      <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <span style={{ fontSize: '0.85em', color: 'var(--text-muted)' }}>
            {deploymentId != null && `Deployment #${deploymentId} · `}
            Job: {jobId || '-'}
          </span>
          <button
            type="button"
            className="btn btn-sm btn-secondary"
            onClick={handleCopy}
            disabled={!output}
            title="Copy output to clipboard"
          >
            Copy
          </button>
        </div>
        <pre
          ref={outputRef}
          tabIndex={0}
          style={{
            background: 'var(--bg-secondary)',
            padding: '1rem',
            borderRadius: 8,
            maxHeight: 400,
            overflowY: 'auto',
            fontFamily: 'var(--font-mono)',
            fontSize: '0.82rem',
            whiteSpace: 'pre-wrap',
            lineHeight: 1.5,
            userSelect: 'text',
            cursor: 'text',
            margin: 0,
          }}
        >
          {output}
        </pre>
        <StatusLine status={status} />
        <div style={{ display: 'flex', gap: '0.5rem', justifyContent: 'flex-end' }}>
          <button type="button" className="btn btn-secondary" onClick={onClose}>
            Close
          </button>
        </div>
      </div>
    </Modal>
  );
}

function StatusLine({ status }: { status: JobStatus }) {
  let text: string;
  let color = 'var(--text-muted)';
  let bold = false;
  switch (status.kind) {
    case 'connecting':
      text = 'Connecting…';
      break;
    case 'streaming':
      text = 'Connected — streaming output…';
      break;
    case 'complete':
      text = status.status === 'completed' ? 'Completed' : 'Failed';
      color = status.status === 'completed' ? 'var(--success)' : 'var(--danger)';
      bold = true;
      break;
    case 'error':
      text = 'WebSocket error';
      color = 'var(--danger)';
      break;
    case 'closed':
      text = 'Disconnected';
      break;
  }
  return (
    <div style={{ textAlign: 'center', color, fontWeight: bold ? 600 : 400 }}>{text}</div>
  );
}
