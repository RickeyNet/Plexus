import { useEffect, useMemo, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useQueryClient } from '@tanstack/react-query';

import { Modal } from '@/components/Modal';
import {
  streamPollNow,
  useMonitoringPollHistory,
  useMonitoringPolls,
  useMonitoringSummary,
  type MonitoringPoll,
  type PollNowEvent,
} from '@/api/monitoring';
import { formatTimestamp, formatUptime } from './helpers';

interface ProgressLine {
  ok: boolean;
  hostname: string;
  detail: string;
}

interface PollProgress {
  active: boolean;
  total: number;
  completed: number;
  title: string;
  failed: boolean;
  log: ProgressLine[];
}

const initialProgress: PollProgress = {
  active: false,
  total: 0,
  completed: 0,
  title: '',
  failed: false,
  log: [],
};

export function DevicesTab() {
  const qc = useQueryClient();
  const navigate = useNavigate();
  const summary = useMonitoringSummary();
  const polls = useMonitoringPolls();
  const [query, setQuery] = useState('');
  const [progress, setProgress] = useState<PollProgress>(initialProgress);
  const [historyHost, setHistoryHost] = useState<{ id: number; hostname: string } | null>(null);
  const pollAbortRef = useRef<AbortController | null>(null);
  const resetTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    return () => {
      pollAbortRef.current?.abort();
      if (resetTimerRef.current) clearTimeout(resetTimerRef.current);
    };
  }, []);

  const filtered = useMemo(() => {
    const list = polls.data ?? [];
    const q = query.trim().toLowerCase();
    if (!q) return list;
    return list.filter(
      (p) =>
        (p.hostname ?? '').toLowerCase().includes(q) ||
        (p.ip_address ?? '').toLowerCase().includes(q),
    );
  }, [polls.data, query]);

  async function pollNow() {
    pollAbortRef.current?.abort();
    if (resetTimerRef.current) {
      clearTimeout(resetTimerRef.current);
      resetTimerRef.current = null;
    }
    const controller = new AbortController();
    pollAbortRef.current = controller;
    setProgress({ ...initialProgress, active: true, title: 'Starting poll…' });
    try {
      await streamPollNow((event: PollNowEvent) => {
        setProgress((prev) => {
          if (event.type === 'start') {
            return { ...prev, total: event.total_hosts ?? 0, title: `Polling ${event.total_hosts} device(s)…` };
          }
          if (event.type === 'host_done' || event.type === 'host_error') {
            const ok = event.type === 'host_done' && event.status === 'ok';
            const details: string[] = [];
            if (event.cpu != null) details.push(`CPU ${event.cpu}%`);
            if (event.memory != null) details.push(`Mem ${event.memory}%`);
            if (event.alerts && event.alerts > 0) details.push(`${event.alerts} alert${event.alerts !== 1 ? 's' : ''}`);
            const detail = event.type === 'host_error' ? 'error' : details.join(', ');
            return {
              ...prev,
              completed: event.completed ?? prev.completed,
              total: event.total_hosts ?? prev.total,
              log: [...prev.log, { ok, hostname: event.hostname ?? '', detail }],
            };
          }
          if (event.type === 'done') {
            return { ...prev, completed: prev.total, title: `Poll complete: ${event.hosts_polled} polled, ${event.alerts_created} alerts, ${event.errors} errors` };
          }
          return prev;
        });
      }, controller.signal);
      if (controller.signal.aborted) return;
      qc.invalidateQueries({ queryKey: ['monitoring-polls'] });
      qc.invalidateQueries({ queryKey: ['monitoring-summary'] });
      qc.invalidateQueries({ queryKey: ['monitoring-alerts'] });
      resetTimerRef.current = setTimeout(() => {
        resetTimerRef.current = null;
        setProgress(initialProgress);
      }, 8000);
    } catch (e) {
      if (controller.signal.aborted) return;
      setProgress((p) => ({ ...p, failed: true, title: `Poll failed: ${(e as Error).message}` }));
    } finally {
      if (pollAbortRef.current === controller) pollAbortRef.current = null;
    }
  }

  return (
    <div>
      <SummaryCards />

      <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center', marginBottom: '0.75rem', flexWrap: 'wrap' }}>
        <input
          className="form-input"
          placeholder="Search devices…"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          style={{ flex: 1, minWidth: 200 }}
        />
        <button className="btn btn-primary" onClick={pollNow} disabled={progress.active && !progress.failed && progress.completed < progress.total}>
          {progress.active && !progress.failed && progress.completed < progress.total ? 'Polling…' : 'Poll Now'}
        </button>
        <button className="btn btn-secondary" onClick={() => { polls.refetch(); summary.refetch(); }}>Refresh</button>
      </div>

      {progress.active && (
        <div className="card" style={{ padding: '0.75rem 1rem', marginBottom: '0.75rem' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.5rem' }}>
            <strong>{progress.title}</strong>
            <span className="text-muted" style={{ fontSize: '0.85em' }}>{progress.completed} / {progress.total}</span>
          </div>
          <div style={{ background: 'var(--bg-secondary)', borderRadius: 4, height: 6, overflow: 'hidden' }}>
            <div
              style={{
                width: `${progress.total ? Math.min((progress.completed / progress.total) * 100, 100) : 0}%`,
                height: '100%',
                background: progress.failed ? 'var(--danger)' : 'var(--primary)',
                transition: 'width 0.2s',
              }}
            />
          </div>
          {progress.log.length > 0 && (
            <div style={{ marginTop: '0.5rem', maxHeight: 180, overflow: 'auto', fontSize: '0.85em', fontFamily: 'monospace' }}>
              {progress.log.map((l, i) => (
                <div key={i}>
                  <span style={{ color: l.ok ? 'var(--success)' : 'var(--danger)' }}>{l.ok ? '✓' : '✗'}</span>{' '}
                  {l.hostname}{l.detail ? ` - ${l.detail}` : ''}
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {polls.isPending && <div className="text-muted">Loading…</div>}
      {polls.error && <div style={{ color: 'var(--danger)' }}>Error: {(polls.error as Error).message}</div>}
      {polls.data && filtered.length === 0 && (
        <div className="empty-state">No monitoring data - click Poll Now to begin.</div>
      )}

      <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
        {filtered.map((p) => (
          <PollRow
            key={p.host_id}
            poll={p}
            onDetail={() => navigate(`/devices/${p.host_id}`)}
            onHistory={() => setHistoryHost({ id: p.host_id, hostname: p.hostname ?? '' })}
          />
        ))}
      </div>

      {historyHost && (
        <HostHistoryModal
          hostId={historyHost.id}
          hostname={historyHost.hostname}
          onClose={() => setHistoryHost(null)}
        />
      )}
    </div>
  );
}

function SummaryCards() {
  const { data: s } = useMonitoringSummary();
  const items = [
    { label: 'Hosts', value: s?.monitored_hosts ?? '-' },
    { label: 'Avg CPU', value: s?.avg_cpu != null ? `${s.avg_cpu}%` : '-', danger: s?.avg_cpu != null && s.avg_cpu >= 80 },
    { label: 'Avg Mem', value: s?.avg_memory != null ? `${s.avg_memory}%` : '-', danger: s?.avg_memory != null && s.avg_memory >= 80 },
    { label: 'IF Up', value: s?.interfaces_up ?? '-' },
    { label: 'IF Down', value: s?.interfaces_down ?? '-', warning: (s?.interfaces_down ?? 0) > 0 },
    { label: 'VPN Up', value: s?.vpn_tunnels_up ?? '-' },
    { label: 'VPN Down', value: s?.vpn_tunnels_down ?? '-', warning: (s?.vpn_tunnels_down ?? 0) > 0 },
    { label: 'Routes', value: s?.total_routes ?? '-' },
    { label: 'Open Alerts', value: s?.open_alerts ?? '-', danger: (s?.open_alerts ?? 0) > 0 },
  ];
  return (
    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(110px, 1fr))', gap: '0.5rem', marginBottom: '0.75rem' }}>
      {items.map((it) => (
        <div key={it.label} className="card" style={{ padding: '0.5rem 0.75rem', textAlign: 'center' }}>
          <div className="text-muted" style={{ fontSize: '0.75em' }}>{it.label}</div>
          <div style={{ fontWeight: 600, fontSize: '1.1em', color: it.danger ? 'var(--danger)' : it.warning ? 'var(--warning)' : '' }}>
            {it.value}
          </div>
        </div>
      ))}
    </div>
  );
}

function PollRow({ poll, onDetail, onHistory }: { poll: MonitoringPoll; onDetail: () => void; onHistory: () => void }) {
  const cpuColor = poll.cpu_percent == null ? 'text-muted' : poll.cpu_percent >= 90 ? 'danger' : poll.cpu_percent >= 70 ? 'warning' : 'success';
  const memColor = poll.memory_percent == null ? 'text-muted' : poll.memory_percent >= 90 ? 'danger' : poll.memory_percent >= 70 ? 'warning' : 'success';
  const statusDot = poll.poll_status === 'error' ? 'danger' : 'success';
  const cpuVal = poll.cpu_percent != null ? `${poll.cpu_percent}%` : 'N/A';
  const memVal = poll.memory_percent != null ? `${poll.memory_percent}%` : 'N/A';
  return (
    <div className="card" style={{ padding: '1rem' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '0.5rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <span style={{ width: 8, height: 8, borderRadius: '50%', background: `var(--${statusDot})`, display: 'inline-block' }} />
          <strong>{poll.hostname || 'Unknown'}</strong>
          <span className="text-muted" style={{ fontSize: '0.85em' }}>{poll.ip_address}</span>
          <span className="text-muted" style={{ fontSize: '0.8em' }}>{poll.device_type}</span>
        </div>
        <div style={{ display: 'flex', gap: '0.4rem' }}>
          <button className="btn btn-sm btn-secondary" onClick={onDetail}>Detail</button>
          <button className="btn btn-sm btn-secondary" onClick={onHistory}>History</button>
        </div>
      </div>
      <div style={{ display: 'flex', gap: '1.5rem', marginTop: '0.75rem', flexWrap: 'wrap', fontSize: '0.9em' }}>
        <div><span className="text-muted">CPU:</span> <span style={{ color: `var(--${cpuColor})`, fontWeight: 600 }}>{cpuVal}</span></div>
        <div>
          <span className="text-muted">Memory:</span>{' '}
          <span style={{ color: `var(--${memColor})`, fontWeight: 600 }}>{memVal}</span>
          {poll.memory_used_mb != null && poll.memory_total_mb != null && (
            <span className="text-muted" style={{ fontSize: '0.85em' }}> ({poll.memory_used_mb}/{poll.memory_total_mb} MB)</span>
          )}
        </div>
        <div>
          <span className="text-muted">Interfaces:</span>{' '}
          <span style={{ color: 'var(--success)' }}>{poll.if_up_count} up</span>
          {poll.if_down_count > 0 && <> / <span style={{ color: 'var(--danger)' }}>{poll.if_down_count} down</span></>}
          {poll.if_admin_down > 0 && <> / <span className="text-muted">{poll.if_admin_down} admin-down</span></>}
        </div>
        <div>
          <span className="text-muted">VPN:</span>{' '}
          <span style={{ color: 'var(--success)' }}>{poll.vpn_tunnels_up} up</span>
          {poll.vpn_tunnels_down > 0 && <> / <span style={{ color: 'var(--danger)' }}>{poll.vpn_tunnels_down} down</span></>}
        </div>
        <div><span className="text-muted">Routes:</span> {poll.route_count}</div>
        <div><span className="text-muted">Uptime:</span> {formatUptime(poll.uptime_seconds)}</div>
      </div>
      <div className="text-muted" style={{ marginTop: '0.4rem', fontSize: '0.8em' }}>Last poll: {formatTimestamp(poll.polled_at)}</div>
    </div>
  );
}

function HostHistoryModal({ hostId, hostname, onClose }: { hostId: number; hostname: string; onClose: () => void }) {
  const history = useMonitoringPollHistory(hostId, 50);
  return (
    <Modal isOpen onClose={onClose} title={`${hostname} - Poll History`} size="large">
      {history.isPending && <div className="text-muted">Loading…</div>}
      {history.error && <div style={{ color: 'var(--danger)' }}>Error: {(history.error as Error).message}</div>}
      {history.data && (history.data.length === 0 ? (
        <div className="empty-state">No history available</div>
      ) : (
        <div style={{ maxHeight: 400, overflow: 'auto' }}>
          <table style={{ width: '100%', fontSize: '0.85em', borderCollapse: 'collapse' }}>
            <thead>
              <tr style={{ borderBottom: '2px solid var(--border-color)' }}>
                <th style={{ textAlign: 'left', padding: '4px 8px' }}>Time</th>
                <th style={{ textAlign: 'right', padding: '4px 8px' }}>CPU</th>
                <th style={{ textAlign: 'right', padding: '4px 8px' }}>Memory</th>
                <th style={{ textAlign: 'center', padding: '4px 8px' }}>IF Up/Down</th>
                <th style={{ textAlign: 'center', padding: '4px 8px' }}>VPN Up/Down</th>
                <th style={{ textAlign: 'right', padding: '4px 8px' }}>Routes</th>
                <th style={{ textAlign: 'center', padding: '4px 8px' }}>Status</th>
              </tr>
            </thead>
            <tbody>
              {history.data.map((p, idx) => (
                <tr key={idx} style={{ borderBottom: '1px solid var(--border-color)' }}>
                  <td style={{ padding: '4px 8px' }}>{formatTimestamp(p.polled_at)}</td>
                  <td style={{ padding: '4px 8px', textAlign: 'right' }}>{p.cpu_percent != null ? `${p.cpu_percent}%` : '-'}</td>
                  <td style={{ padding: '4px 8px', textAlign: 'right' }}>{p.memory_percent != null ? `${p.memory_percent}%` : '-'}</td>
                  <td style={{ padding: '4px 8px', textAlign: 'center' }}>{p.if_up_count}/{p.if_down_count}</td>
                  <td style={{ padding: '4px 8px', textAlign: 'center' }}>{p.vpn_tunnels_up}/{p.vpn_tunnels_down}</td>
                  <td style={{ padding: '4px 8px', textAlign: 'right' }}>{p.route_count}</td>
                  <td style={{ padding: '4px 8px', textAlign: 'center', color: p.poll_status === 'error' ? 'var(--danger)' : 'var(--success)' }}>
                    {p.poll_status === 'error' ? 'err' : 'ok'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ))}
    </Modal>
  );
}
