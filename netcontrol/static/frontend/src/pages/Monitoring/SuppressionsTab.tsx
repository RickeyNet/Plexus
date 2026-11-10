import { useId, useState, type FormEvent } from 'react';

import { Callout } from '@/components/Callout';
import { DeleteButton } from '@/components/DeleteButton';
import { EmptyState } from '@/components/EmptyState';
import { FieldError } from '@/components/FieldError';
import { LoadingState } from '@/components/LoadingState';
import { Modal } from '@/components/Modal';
import { QueryError } from '@/components/QueryError';
import { useDialogs } from '@/components/DialogProvider-context';
import { groupLabel, useInventoryGroupsFull } from '@/api/inventory';
import {
  useAlertSuppressions,
  useCreateSuppression,
  useDeleteSuppression,
  type AlertSuppression,
  type SuppressionCreate,
} from '@/api/monitoring';
import { formatBackendDateTime, parseBackendDate, toLocalInputValue } from '@/lib/datetime';
import { usePendingKeys } from '@/lib/usePendingKeys';

import { INACTIVE_OPACITY } from './helpers';

export function SuppressionsTab() {
  const { confirm, alert } = useDialogs();
  const suppressions = useAlertSuppressions();
  const deleteMut = useDeleteSuppression();
  const [showCreate, setShowCreate] = useState(false);
  const deleting = usePendingKeys<number>();
  const now = new Date();

  async function handleDelete(s: AlertSuppression) {
    if (!(await confirm({ title: 'Delete alert suppression', message: `Delete suppression '${s.name}'?`, confirmLabel: 'Delete' }))) return;
    await deleting.run(s.id, async () => {
      try {
        await deleteMut.mutateAsync(s.id);
      } catch (e) {
        void alert({ message: (e as Error).message, variant: 'error' });
      }
    });
  }

  return (
    <div>
      <div className="toolbar" style={{ justifyContent: 'flex-end' }}>
        <button className="btn btn-primary" onClick={() => setShowCreate(true)}>+ New Suppression</button>
      </div>

      {suppressions.error && !suppressions.data ? (
        <QueryError what="suppressions" query={suppressions} />
      ) : (
        suppressions.isPending && <LoadingState />
      )}
      {suppressions.data && (suppressions.data.length === 0 ? (
        <EmptyState message="No suppressions" />
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.4rem' }}>
          {suppressions.data.map((s) => {
            const ends = parseBackendDate(s.ends_at) ?? new Date(NaN);
            const starts = parseBackendDate(s.starts_at) ?? new Date(NaN);
            const isActive = ends > now && starts <= now;
            const status = isActive ? 'Active' : ends <= now ? 'Expired' : 'Scheduled';
            const statusColor = isActive ? 'success' : 'text-muted';
            // Only the description of an inactive window is dimmed; its Delete button stays full strength.
            const dim = isActive ? 1 : INACTIVE_OPACITY;
            const scope = s.hostname ? `Host: ${s.hostname}` : s.group_name ? `Group: ${s.group_name}` : 'Global';
            return (
              <div key={s.id} className="card card-sm">
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '0.4rem' }}>
                  <div style={{ opacity: dim }}>
                    <span style={{ color: `var(--${statusColor})`, fontSize: '0.8em', fontWeight: 600, textTransform: 'uppercase' }}>{status}</span>
                    <strong style={{ marginLeft: '0.4rem' }}>{s.name || 'Unnamed'}</strong>
                    <span className="text-muted" style={{ fontSize: '0.85em', marginLeft: '0.5rem' }}>
                      {scope} · {s.metric ? `Metric: ${s.metric}` : 'All metrics'}
                    </span>
                  </div>
                  <DeleteButton busy={deleting.isPending(s.id)} onClick={() => void handleDelete(s)} />
                </div>
                <div className="text-muted" style={{ marginTop: '0.3rem', fontSize: '0.85em', opacity: dim }}>
                  {formatBackendDateTime(s.starts_at)} - {formatBackendDateTime(s.ends_at)}
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

function CreateSuppressionModal({ isOpen, onClose }: { isOpen: boolean; onClose: () => void }) {
  const formId = useId();
  const createMut = useCreateSuppression();
  const groups = useInventoryGroupsFull(true);
  const allHosts = (groups.data ?? []).flatMap((g) => (g.hosts ?? []).map((h) => ({ ...h, group_name: groupLabel(g) })));

  const now = new Date();
  const [name, setName] = useState('');
  const [starts, setStarts] = useState(toLocalInputValue(now));
  const [ends, setEnds] = useState(toLocalInputValue(new Date(now.getTime() + 2 * 3600_000)));
  const [groupId, setGroupId] = useState('');
  const [hostId, setHostId] = useState('');
  const [metric, setMetric] = useState('');
  const [reason, setReason] = useState('');
  const [startsError, setStartsError] = useState('');
  const [endsError, setEndsError] = useState('');
  const [saveError, setSaveError] = useState('');

  function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setSaveError('');
    const startsDate = new Date(starts);
    const endsDate = new Date(ends);
    const startsErr = !starts ? 'Start time is required' : Number.isNaN(startsDate.getTime()) ? 'Invalid start time' : '';
    const endsErr = !ends
      ? 'End time is required'
      : Number.isNaN(endsDate.getTime())
        ? 'Invalid end time'
        : !startsErr && endsDate <= startsDate
          ? 'End time must be after the start time'
          : '';
    setStartsError(startsErr);
    setEndsError(endsErr);
    if (startsErr || endsErr) return;
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
      onError: (e) => { setSaveError((e as Error).message); },
    });
  }

  return (
    <Modal
      isOpen={isOpen}
      onClose={onClose}
      title="Create Alert Suppression"
      footer={
        <>
          <button type="button" className="btn btn-secondary" onClick={onClose}>Cancel</button>
          <button type="submit" form={formId} className="btn btn-primary" disabled={createMut.isPending}>
            {createMut.isPending ? 'Creating…' : 'Create'}
          </button>
        </>
      }
    >
      <form id={formId} onSubmit={handleSubmit}>
        {saveError && <Callout tone="danger">{saveError}</Callout>}
        <div className="form-group">
          <label className="form-label" htmlFor={`${formId}-name`}>Name</label>
          <input id={`${formId}-name`} className="form-input" value={name} onChange={(e) => setName(e.target.value)} placeholder="e.g. Maintenance Window" required />
        </div>
        <div style={{ display: 'flex', gap: '0.5rem' }}>
          <div className="form-group" style={{ flex: 1 }}>
            <label className="form-label" htmlFor={`${formId}-starts-at`}>Starts At</label>
            <input
              id={`${formId}-starts-at`}
              className="form-input"
              type="datetime-local"
              value={starts}
              onChange={(e) => { setStarts(e.target.value); setStartsError(''); setEndsError(''); }}
              aria-invalid={!!startsError}
            />
            <FieldError>{startsError}</FieldError>
          </div>
          <div className="form-group" style={{ flex: 1 }}>
            <label className="form-label" htmlFor={`${formId}-ends-at`}>Ends At</label>
            <input
              id={`${formId}-ends-at`}
              className="form-input"
              type="datetime-local"
              value={ends}
              min={starts || undefined}
              onChange={(e) => { setEnds(e.target.value); setEndsError(''); }}
              aria-invalid={!!endsError}
              required
            />
            <FieldError>{endsError}</FieldError>
          </div>
        </div>
        <div className="form-group">
          <label className="form-label" htmlFor={`${formId}-scope-group`}>Scope: Group</label>
          <select id={`${formId}-scope-group`} className="form-select" value={groupId} onChange={(e) => setGroupId(e.target.value)}>
            <option value="">All Groups</option>
            {(groups.data ?? []).map((g) => (
              <option key={g.id} value={g.id}>{groupLabel(g)}</option>
            ))}
          </select>
        </div>
        <div className="form-group">
          <label className="form-label" htmlFor={`${formId}-scope-host`}>Scope: Host (overrides group)</label>
          <select id={`${formId}-scope-host`} className="form-select" value={hostId} onChange={(e) => setHostId(e.target.value)}>
            <option value="">All Hosts</option>
            {allHosts.map((h) => (
              <option key={h.id} value={h.id}>{h.hostname} ({h.ip_address})</option>
            ))}
          </select>
        </div>
        <div className="form-group">
          <label className="form-label" htmlFor={`${formId}-metric`}>Metric (blank = all)</label>
          <select id={`${formId}-metric`} className="form-select" value={metric} onChange={(e) => setMetric(e.target.value)}>
            <option value="">All Metrics</option>
            <option value="cpu">CPU</option>
            <option value="memory">Memory</option>
            <option value="interface_down">Interfaces Down</option>
            <option value="vpn_down">VPN Down</option>
            <option value="route_churn">Route Churn</option>
          </select>
        </div>
        <div className="form-group">
          <label className="form-label" htmlFor={`${formId}-reason`}>Reason</label>
          <textarea id={`${formId}-reason`} className="form-input" rows={2} value={reason} onChange={(e) => setReason(e.target.value)} />
        </div>
      </form>
    </Modal>
  );
}
