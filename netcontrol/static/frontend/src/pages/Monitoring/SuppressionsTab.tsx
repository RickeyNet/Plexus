import { useState, type FormEvent } from 'react';

import { Modal } from '@/components/Modal';
import { useInventoryGroupsFull } from '@/api/inventory';
import {
  useAlertSuppressions,
  useCreateSuppression,
  useDeleteSuppression,
  type AlertSuppression,
  type SuppressionCreate,
} from '@/api/monitoring';
import { parseBackendDate } from '@/pages/Dashboard/helpers';
import { formatTimestamp } from './helpers';

export function SuppressionsTab() {
  const suppressions = useAlertSuppressions();
  const deleteMut = useDeleteSuppression();
  const [showCreate, setShowCreate] = useState(false);
  const now = new Date();

  function handleDelete(s: AlertSuppression) {
    if (!confirm(`Delete suppression '${s.name}'?`)) return;
    deleteMut.mutate(s.id, { onError: (e) => alert((e as Error).message) });
  }

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'flex-end', marginBottom: '0.75rem' }}>
        <button className="btn btn-primary" onClick={() => setShowCreate(true)}>+ New Suppression</button>
      </div>

      {suppressions.isPending && <div className="text-muted">Loading…</div>}
      {suppressions.error && <div style={{ color: 'var(--danger)' }}>Error: {(suppressions.error as Error).message}</div>}
      {suppressions.data && (suppressions.data.length === 0 ? (
        <div className="empty-state">No suppressions</div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.4rem' }}>
          {suppressions.data.map((s) => {
            const ends = parseBackendDate(s.ends_at) ?? new Date(NaN);
            const starts = parseBackendDate(s.starts_at) ?? new Date(NaN);
            const isActive = ends > now && starts <= now;
            const status = isActive ? 'Active' : ends <= now ? 'Expired' : 'Scheduled';
            const statusColor = isActive ? 'success' : 'text-muted';
            const scope = s.hostname ? `Host: ${s.hostname}` : s.group_name ? `Group: ${s.group_name}` : 'Global';
            return (
              <div key={s.id} className="card" style={{ padding: '0.75rem 1rem', opacity: isActive ? 1 : 0.5 }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '0.4rem' }}>
                  <div>
                    <span style={{ color: `var(--${statusColor})`, fontSize: '0.8em', fontWeight: 600, textTransform: 'uppercase' }}>{status}</span>
                    <strong style={{ marginLeft: '0.4rem' }}>{s.name || 'Unnamed'}</strong>
                    <span className="text-muted" style={{ fontSize: '0.85em', marginLeft: '0.5rem' }}>
                      {scope} · {s.metric ? `Metric: ${s.metric}` : 'All metrics'}
                    </span>
                  </div>
                  <button className="btn btn-sm btn-danger" onClick={() => handleDelete(s)}>Delete</button>
                </div>
                <div className="text-muted" style={{ marginTop: '0.3rem', fontSize: '0.85em' }}>
                  {formatTimestamp(s.starts_at)} - {formatTimestamp(s.ends_at)}
                  {s.reason && ` · Reason: ${s.reason}`}
                  {s.created_by && ` · By ${s.created_by}`}
                </div>
              </div>
            );
          })}
        </div>
      ))}

      <CreateSuppressionModal isOpen={showCreate} onClose={() => setShowCreate(false)} />
    </div>
  );
}

function toLocalInput(d: Date): string {
  const pad = (n: number) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

function CreateSuppressionModal({ isOpen, onClose }: { isOpen: boolean; onClose: () => void }) {
  const createMut = useCreateSuppression();
  const groups = useInventoryGroupsFull(true);
  const allHosts = (groups.data ?? []).flatMap((g) => (g.hosts ?? []).map((h) => ({ ...h, group_name: g.name })));

  const now = new Date();
  const [name, setName] = useState('');
  const [starts, setStarts] = useState(toLocalInput(now));
  const [ends, setEnds] = useState(toLocalInput(new Date(now.getTime() + 2 * 3600_000)));
  const [groupId, setGroupId] = useState('');
  const [hostId, setHostId] = useState('');
  const [metric, setMetric] = useState('');
  const [reason, setReason] = useState('');

  function handleSubmit(e: FormEvent) {
    e.preventDefault();
    if (!starts) {
      alert('Start time is required');
      return;
    }
    if (!ends) {
      alert('End time is required');
      return;
    }
    const startsDate = new Date(starts);
    const endsDate = new Date(ends);
    if (Number.isNaN(startsDate.getTime()) || Number.isNaN(endsDate.getTime())) {
      alert('Invalid start or end time');
      return;
    }
    const data: SuppressionCreate = {
      name: name.trim(),
      starts_at: startsDate.toISOString().replace('T', ' ').slice(0, 19),
      ends_at: endsDate.toISOString().replace('T', ' ').slice(0, 19),
      metric: metric || undefined,
      reason: reason.trim() || undefined,
    };
    if (hostId) data.host_id = parseInt(hostId, 10);
    else if (groupId) data.group_id = parseInt(groupId, 10);

    createMut.mutate(data, {
      onSuccess: () => {
        setName(''); setReason(''); setHostId(''); setGroupId(''); setMetric('');
        onClose();
      },
      onError: (e) => alert((e as Error).message),
    });
  }

  return (
    <Modal isOpen={isOpen} onClose={onClose} title="Create Alert Suppression">
      <form onSubmit={handleSubmit}>
        <div className="form-group">
          <label className="form-label">Name</label>
          <input className="form-input" value={name} onChange={(e) => setName(e.target.value)} placeholder="e.g. Maintenance Window" required />
        </div>
        <div style={{ display: 'flex', gap: '0.5rem' }}>
          <div className="form-group" style={{ flex: 1 }}>
            <label className="form-label">Starts At</label>
            <input className="form-input" type="datetime-local" value={starts} onChange={(e) => setStarts(e.target.value)} />
          </div>
          <div className="form-group" style={{ flex: 1 }}>
            <label className="form-label">Ends At</label>
            <input className="form-input" type="datetime-local" value={ends} onChange={(e) => setEnds(e.target.value)} required />
          </div>
        </div>
        <div className="form-group">
          <label className="form-label">Scope: Group</label>
          <select className="form-select" value={groupId} onChange={(e) => setGroupId(e.target.value)}>
            <option value="">All Groups</option>
            {(groups.data ?? []).map((g) => (
              <option key={g.id} value={g.id}>{g.name}</option>
            ))}
          </select>
        </div>
        <div className="form-group">
          <label className="form-label">Scope: Host (overrides group)</label>
          <select className="form-select" value={hostId} onChange={(e) => setHostId(e.target.value)}>
            <option value="">All Hosts</option>
            {allHosts.map((h) => (
              <option key={h.id} value={h.id}>{h.hostname} ({h.ip_address})</option>
            ))}
          </select>
        </div>
        <div className="form-group">
          <label className="form-label">Metric (blank = all)</label>
          <select className="form-select" value={metric} onChange={(e) => setMetric(e.target.value)}>
            <option value="">All Metrics</option>
            <option value="cpu">CPU</option>
            <option value="memory">Memory</option>
            <option value="interface_down">Interfaces Down</option>
            <option value="vpn_down">VPN Down</option>
            <option value="route_churn">Route Churn</option>
          </select>
        </div>
        <div className="form-group">
          <label className="form-label">Reason</label>
          <textarea className="form-input" rows={2} value={reason} onChange={(e) => setReason(e.target.value)} />
        </div>
        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.5rem' }}>
          <button type="button" className="btn btn-secondary" onClick={onClose}>Cancel</button>
          <button type="submit" className="btn btn-primary" disabled={createMut.isPending}>
            {createMut.isPending ? 'Creating…' : 'Create'}
          </button>
        </div>
      </form>
    </Modal>
  );
}
