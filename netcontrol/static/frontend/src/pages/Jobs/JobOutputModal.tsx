import { useEffect, useRef, useState } from 'react';

import { Modal } from '@/components/Modal';
import {
  useCancelJob,
  useJob,
  useJobEvents,
  useRerunJobLive,
  useRetryJob,
  type JobEvent,
} from '@/api/jobs';

import { formatTime, priorityColor, priorityLabel } from './helpers';

interface Props {
  jobId: number | null;
  onClose: () => void;
  onRetried?: (newJobId: number) => void;
}

interface LiveEvent {
  level?: string;
  message: string;
  host?: string;
  timestamp?: string;
}

export function JobOutputModal({ jobId, onClose, onRetried }: Props) {
  const isOpen = jobId != null;
  const jobQuery = useJob(jobId);
  const eventsQuery = useJobEvents(jobId);
  const cancelMut = useCancelJob();
  const retryMut = useRetryJob();
  const rerunMut = useRerunJobLive();

  const [liveEvents, setLiveEvents] = useState<LiveEvent[]>([]);
  const [liveStatus, setLiveStatus] = useState<string | null>(null);
  const [wsState, setWsState] = useState<'idle' | 'connecting' | 'open' | 'closed' | 'error'>('idle');
  const [confirmRunLive, setConfirmRunLive] = useState(false);
  const [confirmCancel, setConfirmCancel] = useState(false);
  const wsRef = useRef<WebSocket | null>(null);
  const outputRef = useRef<HTMLDivElement | null>(null);

  // reset on open or jobId change
  useEffect(() => {
    setLiveEvents([]);
    setLiveStatus(null);
    setWsState('idle');
    setConfirmRunLive(false);
    setConfirmCancel(false);
  }, [jobId, isOpen]);

  const job = jobQuery.data;
  const isLive = job && (job.status === 'running' || job.status === 'queued');

  useEffect(() => {
    if (!isOpen || !jobId || !isLive) return;
    setWsState('connecting');
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const ws = new WebSocket(`${protocol}//${window.location.host}/ws/jobs/${jobId}`);
    wsRef.current = ws;
    ws.onopen = () => setWsState('open');
    ws.onmessage = (e) => {
      try {
        const data = JSON.parse(e.data);
        if (data.type === 'job_complete') {
          setLiveStatus(data.status || 'completed');
          ws.close();
        } else {
          setLiveEvents((prev) => {
            const next = [...prev, {
              level: data.level || 'info',
              message: data.message ?? '',
              host: data.host,
              timestamp: data.timestamp,
            }];
            // Cap to last 5000 lines so long-running jobs don't blow memory.
            return next.length > 5000 ? next.slice(-5000) : next;
          });
        }
      } catch {
        /* ignore */
      }
    };
    ws.onerror = () => setWsState('error');
    ws.onclose = () => setWsState((s) => (s === 'open' ? 'closed' : s));
    return () => {
      wsRef.current = null;
      ws.onopen = null;
      ws.onmessage = null;
      ws.onerror = null;
      ws.onclose = null;
      try { ws.close(); } catch { /* ignore */ }
    };
  }, [isOpen, jobId, isLive]);

  // auto-scroll
  useEffect(() => {
    const el = outputRef.current;
    if (el) el.scrollTop = el.scrollHeight;
  }, [liveEvents.length, eventsQuery.data]);

  const historicalEvents: JobEvent[] = eventsQuery.data ?? [];
  const effectiveStatus = liveStatus || job?.status || '';
  const isFinished = effectiveStatus && !['running', 'queued'].includes(effectiveStatus);
  const isDry = Boolean(job?.dry_run);

  function handleCancel() {
    if (!jobId) return;
    setConfirmCancel(true);
  }

  function confirmCancelJob() {
    if (!jobId) return;
    cancelMut.mutate(jobId, {
      onSuccess: () => setConfirmCancel(false),
      onError: (e) => { setConfirmCancel(false); alert((e as Error).message); },
    });
  }

  function handleRetry() {
    if (!jobId) return;
    retryMut.mutate(jobId, {
      onSuccess: (r) => { onRetried?.(r.job_id); },
      onError: (e) => alert((e as Error).message),
    });
  }

  function handleRunLive() {
    if (!jobId) return;
    setConfirmRunLive(true);
  }

  function confirmRunLiveJob() {
    if (!jobId) return;
    rerunMut.mutate(jobId, {
      onSuccess: (r) => { setConfirmRunLive(false); onRetried?.(r.job_id); },
      onError: (e) => { setConfirmRunLive(false); alert((e as Error).message); },
    });
  }

  function handleCopyOutput() {
    const lines = [
      ...historicalEvents.map((e) => `[${formatTime(e.timestamp)}] ${e.host ? e.host + ': ' : ''}${e.message}`),
      ...liveEvents.map((e) => `[${formatTime(e.timestamp)}] ${e.host ? e.host + ': ' : ''}${e.message}`),
    ].join('\n');
    navigator.clipboard.writeText(lines).catch(() => alert('Copy failed'));
  }

  return (
    <Modal isOpen={isOpen} onClose={onClose} title={`Job #${jobId ?? ''}`} size="large">
      {jobQuery.isPending && <p className="text-muted">Loading…</p>}
      {jobQuery.error && <p style={{ color: 'var(--danger)' }}>Failed: {(jobQuery.error as Error).message}</p>}
      {job && (
        <>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', flexWrap: 'wrap', marginBottom: '0.5rem' }}>
            <span className="badge" style={{ background: isDry ? 'var(--warning)' : 'var(--danger, #dc3545)', color: isDry ? '#000' : '#fff', fontWeight: 600 }}>
              {isDry ? 'DRY RUN' : 'LIVE'}
            </span>
            <span className={`status-badge status-${effectiveStatus}`}>{effectiveStatus}</span>
            {job.priority != null && job.priority !== 2 && (
              <span className="badge" style={{ background: `var(--${priorityColor(job.priority)})`, color: '#fff' }}>
                {priorityLabel(job.priority)}
              </span>
            )}
            {wsState === 'connecting' && <span className="text-muted">Connecting…</span>}
            {wsState === 'open' && <span style={{ color: 'var(--success)' }}>Streaming</span>}
            {wsState === 'error' && <span style={{ color: 'var(--danger)' }}>WebSocket error</span>}
          </div>

          <div
            ref={outputRef}
            style={{
              background: 'var(--bg-secondary)',
              padding: '0.75rem',
              borderRadius: 8,
              fontFamily: 'var(--font-mono)',
              fontSize: '0.82rem',
              maxHeight: 480,
              overflowY: 'auto',
              whiteSpace: 'pre-wrap',
              border: '1px solid var(--border)',
            }}
          >
            {historicalEvents.map((e, i) => (
              <div key={`h-${i}`} className={`job-output-line ${e.level || 'info'}`}>
                [{formatTime(e.timestamp)}] {e.host ? `${e.host}: ` : ''}{e.message}
              </div>
            ))}
            {liveEvents.map((e, i) => (
              <div key={`l-${i}`} className={`job-output-line ${e.level || 'info'}`}>
                [{formatTime(e.timestamp)}] {e.host ? `${e.host}: ` : ''}{e.message}
              </div>
            ))}
            {liveStatus && (
              <div className="job-output-line success" style={{ marginTop: '0.5rem', fontWeight: 600 }}>
                [Job Complete] Status: {liveStatus}
              </div>
            )}
            {historicalEvents.length === 0 && liveEvents.length === 0 && (
              <div className="text-muted">No output yet…</div>
            )}
          </div>

          <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.5rem', marginTop: '0.75rem', flexWrap: 'wrap' }}>
            <button className="btn btn-sm btn-secondary" onClick={handleCopyOutput}>Copy Output</button>
            {!isFinished && (
              <button className="btn btn-sm btn-danger" onClick={handleCancel}>Cancel Job</button>
            )}
            {(effectiveStatus === 'failed' || effectiveStatus === 'cancelled') && (
              <button className="btn btn-sm btn-primary" onClick={handleRetry}>Retry</button>
            )}
            {isFinished && isDry && (
              <button className="btn btn-sm btn-danger" onClick={handleRunLive}>Run Live</button>
            )}
            <button className="btn btn-sm btn-secondary" onClick={onClose}>Close</button>
          </div>
        </>
      )}
      <Modal
        isOpen={confirmRunLive}
        onClose={() => { if (!rerunMut.isPending) setConfirmRunLive(false); }}
        title="Run Live?"
      >
        <p style={{ margin: '0 0 0.5rem' }}>
          This will re-run the same job with dry run disabled.
        </p>
        <p style={{ margin: '0 0 1rem', color: 'var(--danger)', fontWeight: 600 }}>
          Changes will be applied to devices.
        </p>
        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.5rem' }}>
          <button
            type="button"
            className="btn btn-secondary"
            onClick={() => setConfirmRunLive(false)}
            disabled={rerunMut.isPending}
          >
            Cancel
          </button>
          <button
            type="button"
            className="btn btn-danger"
            onClick={confirmRunLiveJob}
            disabled={rerunMut.isPending}
            autoFocus
          >
            {rerunMut.isPending ? 'Starting…' : 'Run Live'}
          </button>
        </div>
      </Modal>
      <Modal
        isOpen={confirmCancel}
        onClose={() => { if (!cancelMut.isPending) setConfirmCancel(false); }}
        title="Cancel Job?"
      >
        <p style={{ margin: '0 0 1rem' }}>Cancel this job?</p>
        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.5rem' }}>
          <button
            type="button"
            className="btn btn-secondary"
            onClick={() => setConfirmCancel(false)}
            disabled={cancelMut.isPending}
          >
            Keep Running
          </button>
          <button
            type="button"
            className="btn btn-danger"
            onClick={confirmCancelJob}
            disabled={cancelMut.isPending}
            autoFocus
          >
            {cancelMut.isPending ? 'Cancelling…' : 'Cancel Job'}
          </button>
        </div>
      </Modal>
    </Modal>
  );
}
