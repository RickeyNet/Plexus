import { useEffect, useRef, useState } from 'react';

import { Badge, StatusBadge } from '@/components/Badge';
import { BusyButton } from '@/components/BusyButton';
import { EmptyState } from '@/components/EmptyState';
import { LoadingState } from '@/components/LoadingState';
import { Modal } from '@/components/Modal';
import { QueryError } from '@/components/QueryError';
import { useDialogs } from '@/components/DialogProvider-context';
import {
  useCancelJob,
  useJob,
  useJobEvents,
  useRerunJobLive,
  useRetryJob,
  type JobEvent,
} from '@/api/jobs';
import { formatBackendTime } from '@/lib/datetime';

import { priorityLabel, priorityTone } from './helpers';

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
  const { alert } = useDialogs();
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

  // reset on jobId change. (isOpen is derived from jobId, so depending
  // on both would run this twice per open and clear freshly-arrived
  // live events.)
  const [prevJobId, setPrevJobId] = useState(jobId);
  if (jobId !== prevJobId) {
    setPrevJobId(jobId);
    setLiveEvents([]);
    setLiveStatus(null);
    setWsState('idle');
    setConfirmRunLive(false);
    setConfirmCancel(false);
  }

  const job = jobQuery.data;
  const isLive = job && (job.status === 'running' || job.status === 'queued');

  // Seed the "connecting" state in render whenever a (re)connect is about
  // to happen, so the synchronous transition stays out of the effect body.
  // Mirrors the effect's gate + dep list: any change to isOpen/jobId/isLive
  // that lands on a connectable state starts a fresh connection.
  const shouldConnect = Boolean(isOpen && jobId && isLive);
  const connectKey = shouldConnect ? `${jobId}` : null;
  const [prevConnectKey, setPrevConnectKey] = useState(connectKey);
  if (connectKey !== prevConnectKey) {
    setPrevConnectKey(connectKey);
    if (connectKey) setWsState('connecting');
  }

  useEffect(() => {
    if (!isOpen || !jobId || !isLive) return;
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

  // Single source of truth for the output area.  The WebSocket handler
  // replays the entire persisted backlog on connect and then streams
  // new events, so once any live event has arrived `liveEvents` is the
  // complete log (including for a job that finished while the modal was
  // open).  Fall back to the REST history only when no WS delivered
  // anything - i.e. the modal opened on an already-finished job, where
  // the WS effect (gated on isLive) never connects.  Rendering both
  // concatenated is what produced the duplicated/tripled output.
  const historicalEvents: JobEvent[] = eventsQuery.data ?? [];
  const showLive = liveEvents.length > 0 || wsState === 'open' || wsState === 'connecting';
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
      onError: (e) => { setConfirmCancel(false); void alert({ message: (e as Error).message, variant: 'error' }); },
    });
  }

  function handleRetry() {
    if (!jobId) return;
    retryMut.mutate(jobId, {
      onSuccess: (r) => { onRetried?.(r.job_id); },
      onError: (e) => { void alert({ message: (e as Error).message, variant: 'error' }); },
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
      onError: (e) => { setConfirmRunLive(false); void alert({ message: (e as Error).message, variant: 'error' }); },
    });
  }

  function handleCopyOutput() {
    // Mirror the single-source render so the clipboard doesn't get the
    // duplicated history+live concatenation either.
    const src = showLive ? liveEvents : historicalEvents;
    const lines = src
      .map((e) => `[${formatBackendTime(e.timestamp, '')}] ${e.host ? e.host + ': ' : ''}${e.message}`)
      .join('\n');
    navigator.clipboard.writeText(lines).catch(() => { void alert('Copy failed'); });
  }

  return (
    <Modal
      isOpen={isOpen}
      onClose={onClose}
      title={`Job #${jobId ?? ''}`}
      size="large"
      footer={
        <>
          <button type="button" className="btn btn-secondary" onClick={onClose}>Close</button>
          {job && (
            <>
              <button type="button" className="btn btn-secondary" onClick={handleCopyOutput}>Copy Output</button>
              {!isFinished && (
                <button type="button" className="btn btn-danger" onClick={handleCancel}>Cancel Job</button>
              )}
              {(effectiveStatus === 'failed' || effectiveStatus === 'cancelled') && (
                <BusyButton className="btn btn-primary" busy={retryMut.isPending} busyLabel="Retrying…" onClick={handleRetry}>
                  Retry
                </BusyButton>
              )}
              {isFinished && isDry && (
                <button type="button" className="btn btn-danger" onClick={handleRunLive}>Run Live</button>
              )}
            </>
          )}
        </>
      }
    >
      {jobQuery.error && !job ? (
        <QueryError what="job" query={jobQuery} />
      ) : (
        jobQuery.isPending && <LoadingState />
      )}
      {job && (
        <>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', flexWrap: 'wrap', marginBottom: '0.5rem' }}>
            <Badge tone={isDry ? 'warning' : 'danger'} solid>
              {isDry ? 'Dry run' : 'Live'}
            </Badge>
            <StatusBadge status={effectiveStatus} />
            {job.priority != null && job.priority !== 2 && (
              <Badge tone={priorityTone(job.priority)}>{priorityLabel(job.priority)}</Badge>
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
            {showLive
              ? liveEvents.map((e, i) => (
                  <div key={`l-${i}`} className={`job-output-line ${e.level || 'info'}`}>
                    [{formatBackendTime(e.timestamp, '')}] {e.host ? `${e.host}: ` : ''}{e.message}
                  </div>
                ))
              : historicalEvents.map((e, i) => (
                  <div key={`h-${i}`} className={`job-output-line ${e.level || 'info'}`}>
                    [{formatBackendTime(e.timestamp, '')}] {e.host ? `${e.host}: ` : ''}{e.message}
                  </div>
                ))}
            {liveStatus && (
              <div className="job-output-line success" style={{ marginTop: '0.5rem', fontWeight: 600 }}>
                [Job Complete] Status: {liveStatus}
              </div>
            )}
            {!showLive && eventsQuery.error && !eventsQuery.data ? (
              <QueryError what="job output" query={eventsQuery} />
            ) : (
              (showLive ? liveEvents.length === 0 : historicalEvents.length === 0) && (
                <EmptyState compact message="No output yet…" />
              )
            )}
          </div>
        </>
      )}
      <Modal
        isOpen={confirmRunLive}
        onClose={() => { if (!rerunMut.isPending) setConfirmRunLive(false); }}
        title="Run job live"
        size="small"
        footer={
          <>
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
          </>
        }
      >
        <p style={{ margin: '0 0 0.5rem' }}>
          This will re-run job #{jobId} with dry run disabled.
        </p>
        <p style={{ margin: 0, color: 'var(--danger)', fontWeight: 600 }}>
          Changes will be applied to devices.
        </p>
      </Modal>
      <Modal
        isOpen={confirmCancel}
        onClose={() => { if (!cancelMut.isPending) setConfirmCancel(false); }}
        title="Cancel job"
        size="small"
        footer={
          <>
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
          </>
        }
      >
        <p style={{ margin: 0 }}>Cancel job #{jobId}?</p>
      </Modal>
    </Modal>
  );
}
