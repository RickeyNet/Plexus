import { useMemo, useState, type FormEvent } from 'react';

import { Modal } from '@/components/Modal';
import { useDialogs } from '@/components/DialogProvider-context';
import { groupLabel, useInventoryGroupsFull } from '@/api/inventory';
import {
  useCreateSlaTarget,
  useDeleteSlaTarget,
  useSlaTargets,
  useUpdateSlaTarget,
  type SlaTarget,
  type SlaTargetCreate,
} from '@/api/monitoring';

// SLA targets are configuration (Monitoring -> Configure -> SLA Targets); the
// SLA tab reports host compliance against them.

const METRIC_LABELS: Record<string, string> = {
  uptime: 'Uptime %',
  latency: 'Latency (ms)',
  jitter: 'Jitter (ms)',
  packet_loss: 'Packet Loss %',
};

export function SlaTargetsTab() {
  const targets = useSlaTargets().data ?? [];
  const { confirm, alert } = useDialogs();
  const deleteMut = useDeleteSlaTarget();
  const [editing, setEditing] = useState<SlaTarget | null>(null);
  const [creating, setCreating] = useState(false);

  async function handleDelete(t: SlaTarget) {
    if (!(await confirm(`Delete SLA target '${t.name}'?`))) return;
    deleteMut.mutate(t.id, { onError: (e) => { void alert({ message: (e as Error).message, variant: 'error' }); } });
  }

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'flex-end', marginBottom: '0.75rem' }}>
        <button className="btn btn-primary" onClick={() => setCreating(true)}>+ New Target</button>
      </div>
      {targets.length === 0 ? (
        <div className="empty-state">No SLA targets defined</div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
          {targets.map((t) => {
            const scope = t.host_name ? `Host: ${t.host_name}` : t.group_name ? `Group: ${t.group_name}` : 'Global';
            return (
              <div key={t.id} className="card" style={{ padding: '0.75rem 1rem' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '0.5rem' }}>
                  <div>
                    <strong>{t.name}</strong>
                    {!t.enabled && <span className="text-muted" style={{ fontSize: '0.8em', marginLeft: '0.5rem' }}>(disabled)</span>}
                  </div>
                  <div style={{ display: 'flex', gap: '0.4rem' }}>
                    <button className="btn btn-sm btn-secondary" onClick={() => setEditing(t)}>Edit</button>
                    <button className="btn btn-sm btn-danger" onClick={() => handleDelete(t)}>Delete</button>
                  </div>
                </div>
                <div style={{ display: 'flex', gap: '1.5rem', marginTop: '0.5rem', fontSize: '0.9em', flexWrap: 'wrap' }}>
                  <div><span className="text-muted">Metric:</span> {METRIC_LABELS[t.metric] ?? t.metric}</div>
                  <div><span className="text-muted">Target:</span> <strong style={{ color: 'var(--success)' }}>{t.target_value}</strong></div>
                  <div><span className="text-muted">Warning:</span> <strong style={{ color: 'var(--warning)' }}>{t.warning_value}</strong></div>
                  <div><span className="text-muted">Scope:</span> {scope}</div>
                </div>
              </div>
            );
          })}
        </div>
      )}

      <SlaTargetFormModal
        target={editing}
        isCreate={creating}
        onClose={() => { setEditing(null); setCreating(false); }}
      />
    </div>
  );
}

function SlaTargetFormModal({ target, isCreate, onClose }: { target: SlaTarget | null; isCreate: boolean; onClose: () => void }) {
  const { alert } = useDialogs();
  const isOpen = isCreate || target != null;
  const createMut = useCreateSlaTarget();
  const updateMut = useUpdateSlaTarget();
  const groups = useInventoryGroupsFull(true);
  const allHosts = useMemo(
    () => (groups.data ?? []).flatMap((g) => (g.hosts ?? []).map((h) => ({ ...h, group_name: groupLabel(g) }))),
    [groups.data],
  );

  const [name, setName] = useState('');
  const [metric, setMetric] = useState('uptime');
  const [targetValue, setTargetValue] = useState('99.9');
  const [warningValue, setWarningValue] = useState('99.0');
  const [scope, setScope] = useState<'global' | 'group' | 'host'>('global');
  const [groupId, setGroupId] = useState('');
  const [hostId, setHostId] = useState('');

  const [prevTarget, setPrevTarget] = useState(target);
  const [prevIsCreate, setPrevIsCreate] = useState(isCreate);
  if (target !== prevTarget || isCreate !== prevIsCreate) {
    setPrevTarget(target);
    setPrevIsCreate(isCreate);
    if (target) {
      setName(target.name);
      setMetric(target.metric);
      setTargetValue(String(target.target_value));
      setWarningValue(String(target.warning_value));
      if (target.host_id != null) { setScope('host'); setHostId(String(target.host_id)); setGroupId(''); }
      else if (target.group_id != null) { setScope('group'); setGroupId(String(target.group_id)); setHostId(''); }
      else { setScope('global'); setHostId(''); setGroupId(''); }
    } else if (isCreate) {
      setName(''); setMetric('uptime'); setTargetValue('99.9'); setWarningValue('99.0');
      setScope('global'); setGroupId(''); setHostId('');
    }
  }

  function handleSubmit(e: FormEvent) {
    e.preventDefault();
    if (!name.trim()) { void alert('Name is required'); return; }
    const data: SlaTargetCreate = {
      name: name.trim(),
      metric,
      target_value: parseFloat(targetValue) || 0,
      warning_value: parseFloat(warningValue) || 0,
      host_id: scope === 'host' ? (Number.isFinite(parseInt(hostId, 10)) ? parseInt(hostId, 10) : null) : null,
      group_id: scope === 'group' ? (Number.isFinite(parseInt(groupId, 10)) ? parseInt(groupId, 10) : null) : null,
    };
    if (target) {
      updateMut.mutate({ id: target.id, data }, {
        onSuccess: onClose,
        onError: (e) => { void alert({ message: (e as Error).message, variant: 'error' }); },
      });
    } else {
      createMut.mutate(data, {
        onSuccess: onClose,
        onError: (e) => { void alert({ message: (e as Error).message, variant: 'error' }); },
      });
    }
  }

  const pending = createMut.isPending || updateMut.isPending;

  return (
    <Modal isOpen={isOpen} onClose={onClose} title={target ? 'Edit SLA Target' : 'New SLA Target'}>
      <form onSubmit={handleSubmit}>
        <div className="form-group">
          <label className="form-label">Name</label>
          <input className="form-input" value={name} onChange={(e) => setName(e.target.value)} required />
        </div>
        <div className="form-group">
          <label className="form-label">Metric</label>
          <select className="form-select" value={metric} onChange={(e) => setMetric(e.target.value)}>
            <option value="uptime">Uptime %</option>
            <option value="latency">Latency (ms)</option>
            <option value="jitter">Jitter (ms)</option>
            <option value="packet_loss">Packet Loss %</option>
          </select>
        </div>
        <div style={{ display: 'flex', gap: '0.5rem' }}>
          <div className="form-group" style={{ flex: 1 }}>
            <label className="form-label">Target</label>
            <input className="form-input" type="number" step="0.01" value={targetValue} onChange={(e) => setTargetValue(e.target.value)} />
          </div>
          <div className="form-group" style={{ flex: 1 }}>
            <label className="form-label">Warning</label>
            <input className="form-input" type="number" step="0.01" value={warningValue} onChange={(e) => setWarningValue(e.target.value)} />
          </div>
        </div>
        <div className="form-group">
          <label className="form-label">Scope</label>
          <select className="form-select" value={scope} onChange={(e) => setScope(e.target.value as 'global' | 'group' | 'host')}>
            <option value="global">Global (all hosts)</option>
            <option value="group">Group</option>
            <option value="host">Host</option>
          </select>
        </div>
        {scope === 'group' && (
          <div className="form-group">
            <label className="form-label">Group</label>
            <select className="form-select" value={groupId} onChange={(e) => setGroupId(e.target.value)}>
              <option value="">Select group…</option>
              {(groups.data ?? []).map((g) => (
                <option key={g.id} value={g.id}>{groupLabel(g)}</option>
              ))}
            </select>
          </div>
        )}
        {scope === 'host' && (
          <div className="form-group">
            <label className="form-label">Host</label>
            <select className="form-select" value={hostId} onChange={(e) => setHostId(e.target.value)}>
              <option value="">Select host…</option>
              {allHosts.map((h) => (
                <option key={h.id} value={h.id}>{h.hostname} ({h.group_name})</option>
              ))}
            </select>
          </div>
        )}
        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.5rem' }}>
          <button type="button" className="btn btn-secondary" onClick={onClose}>Cancel</button>
          <button type="submit" className="btn btn-primary" disabled={pending}>
            {pending ? 'Saving…' : 'Save'}
          </button>
        </div>
      </form>
    </Modal>
  );
}
