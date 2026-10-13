import { useEffect, useRef, useState, type ReactNode } from 'react';

import { Modal } from '@/components/Modal';

export interface JobStreamMessage {
  type?: string;
  text?: string;
  data?: string;
  status?: string;
}

export interface JobStreamModalProps {
  isOpen: boolean;
  onClose: () => void;
  title: string;
  /** Path under `/ws/`, e.g. `deployment/<jobId>`. No socket is opened while null. */
  wsPath: string | null;
  /** Context line above the output, e.g. "Job: abc". */
  subtitle?: ReactNode;
  /** Text to append for a `line` message, or null to skip it. Defaults to `text` (or `data`) with a trailing newline. */
  parseLine?: (msg: JobStreamMessage) => string | null;
  /** Called once with the final status when a `job_complete` message arrives. */
  onComplete?: (status: string) => void;
}

type JobStatus =
  | { kind: 'connecting' }
  | { kind: 'streaming' }
  | { kind: 'complete'; status: string }
  | { kind: 'error' }
  | { kind: 'closed' };

/** Takes `text` (or `data`) and makes sure each chunk ends in a newline. */
function defaultParseLine(msg: JobStreamMessage): string | null {
  const chunk = msg.text ?? msg.data ?? '';
  return chunk.endsWith('\n') ? chunk : chunk + '\n';
}

/** Live log of a background job streamed over a WebSocket. */
export function JobStreamModal({
  isOpen,
  onClose,
  title,
  wsPath,
  subtitle,
  parseLine = defaultParseLine,
  onComplete,
}: JobStreamModalProps) {
  const [output, setOutput] = useState('');
  const [status, setStatus] = useState<JobStatus>({ kind: 'connecting' });
  const outputRef = useRef<HTMLPreElement | null>(null);

  // Latest callbacks without making them effect dependencies, so a parent
  // re-render does not reopen the socket.
  const parseLineRef = useRef(parseLine);
  const onCompleteRef = useRef(onComplete);
  useEffect(() => {
    parseLineRef.current = parseLine;
    onCompleteRef.current = onComplete;
  });

  // Reset the streamed output/status when a new stream is about to open.
  const streamKey = `${isOpen}|${wsPath}`;
  const [prevStreamKey, setPrevStreamKey] = useState(streamKey);
  if (streamKey !== prevStreamKey) {
    setPrevStreamKey(streamKey);
    if (isOpen && wsPath) {
      setOutput('');
      setStatus({ kind: 'connecting' });
    }
  }

  useEffect(() => {
    if (!isOpen || !wsPath) return;

    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const ws = new WebSocket(`${protocol}//${window.location.host}/ws/${wsPath}`);

    ws.onopen = () => setStatus({ kind: 'streaming' });

    ws.onmessage = (event) => {
      let msg: JobStreamMessage;
      try {
        msg = JSON.parse(event.data);
      } catch {
        return;
      }
      if (msg.type === 'line') {
        const text = parseLineRef.current(msg);
        if (text) setOutput((prev) => prev + text);
      } else if (msg.type === 'job_complete') {
        const final = msg.status || 'completed';
        setStatus({ kind: 'complete', status: final });
        ws.close();
        onCompleteRef.current?.(final);
      }
    };

    ws.onerror = () => setStatus({ kind: 'error' });

    ws.onclose = () => setStatus((prev) => (prev.kind === 'streaming' ? { kind: 'closed' } : prev));

    return () => {
      // Detach handlers before close so buffered messages or the synthetic
      // onclose cannot bleed the previous job's output into the next one.
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
  }, [isOpen, wsPath]);

  useEffect(() => {
    const el = outputRef.current;
    if (el) el.scrollTop = el.scrollHeight;
  }, [output]);

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(output);
    } catch {
      /* ignore - clipboard not available */
    }
  };

  return (
    <Modal isOpen={isOpen} onClose={onClose} title={title}>
      <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <span style={{ fontSize: '0.85em', color: 'var(--text-muted)' }}>{subtitle}</span>
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
      text = 'Connected - streaming output…';
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
  return <div style={{ textAlign: 'center', color, fontWeight: bold ? 600 : 400 }}>{text}</div>;
}
