import { useState, type FormEvent } from 'react';

import { Modal } from '@/components/Modal';
import { useDialogs } from '@/components/DialogProvider-context';
import { useInventoryGroupsFull } from '@/api/inventory';
import {
  useAlertRules,
  useCreateAlertRule,
  useDeleteAlertRule,
  useUpdateAlertRule,
  type AlertRule,
  type AlertRuleCreate,
} from '@/api/monitoring';
import { useNotificationChannels } from '@/api/settings';
import { severityColor } from './helpers';

function parseChannelIds(raw?: string | null): string[] {
  if (!raw) return [];
  try {
    const parsed = JSON.parse(raw);
    if (Array.isArray(parsed)) return parsed.map((x) => String(x));
  } catch {
    return raw.split(',').map((s) => s.trim()).filter(Boolean);
  }
  return [];
}

export function RulesTab() {
  const { confirm, alert } = useDialogs();
  const rules = useAlertRules();
  const deleteMut = useDeleteAlertRule();
  const updateMut = useUpdateAlertRule();
  const channelsQuery = useNotificationChannels();
  const channelName = new Map<string, string>(
    (channelsQuery.data?.channels ?? []).map((c) => [c.id, c.name || c.id]),
  );
  const [showCreate, setShowCreate] = useState(false);

  function toggleEnabled(r: AlertRule) {
    updateMut.mutate({ id: r.id, data: { enabled: !r.enabled } }, {
      onError: (e) => { void alert({ message: (e as Error).message, variant: 'error' }); },
    });
  }

  async function handleDelete(r: AlertRule) {
    if (!(await confirm(`Delete rule '${r.name}'?`))) return;
    deleteMut.mutate(r.id, { onError: (e) => { void alert({ message: (e as Error).message, variant: 'error' }); } });
  }

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'flex-end', marginBottom: '0.75rem' }}>
        <button className="btn btn-primary" onClick={() => setShowCreate(true)}>+ New Rule</button>
      </div>

      {rules.isPending && <div className="text-muted">Loading…</div>}
      {rules.error && <div style={{ color: 'var(--danger)' }}>Error: {(rules.error as Error).message}</div>}
      {rules.data && (rules.data.length === 0 ? (
        <div className="empty-state">No alert rules defined</div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.4rem' }}>
          {rules.data.map((r) => {
            const sev = severityColor(r.severity);
            const scope = r.hostname ? `Host: ${r.hostname}` : r.group_name ? `Group: ${r.group_name}` : 'All hosts';
            return (
              <div key={r.id} className="card" style={{ padding: '0.75rem 1rem', opacity: r.enabled ? 1 : 0.5 }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '0.4rem' }}>
                  <div>
                    <span
                      className="badge"
                      style={{ background: `var(--${sev})`, color: 'white', fontSize: '0.75em', padding: '2px 8px', borderRadius: 3, textTransform: 'uppercase' }}
                    >
                      {r.severity}
                    </span>
                    <strong style={{ marginLeft: '0.4rem' }}>{r.name || 'Unnamed'}</strong>
                    <span className="text-muted" style={{ fontSize: '0.85em', marginLeft: '0.5rem' }}>
                      {r.metric} {r.operator} {r.value}
                    </span>
                    {!r.enabled && <span className="text-muted" style={{ fontSize: '0.75em', marginLeft: '0.3rem' }}>(disabled)</span>}
                  </div>
                  <div style={{ display: 'flex', gap: '0.4rem' }}>
                    <button className="btn btn-sm btn-secondary" onClick={() => toggleEnabled(r)}>
                      {r.enabled ? 'Disable' : 'Enable'}
                    </button>
                    <button className="btn btn-sm btn-danger" onClick={() => handleDelete(r)}>Delete</button>
                  </div>
                </div>
                <div className="text-muted" style={{ marginTop: '0.3rem', fontSize: '0.85em' }}>
                  {scope} · Cooldown: {r.cooldown_minutes}m
                  {r.escalate_after_minutes > 0 && ` · Escalate to ${r.escalate_to} after ${r.escalate_after_minutes}m`}
                  {(() => {
                    const ids = parseChannelIds(r.channel_ids);
                    const names = ids.map((id) => channelName.get(id) ?? id);
                    return ` · Notify: ${names.length ? names.join(', ') : 'default channels'}`;
                  })()}
                  {r.description && <><br />{r.description}</>}
                </div>
              </div>
            );
          })}
        </div>
      ))}

      <CreateRuleModal isOpen={showCreate} onClose={() => setShowCreate(false)} />
    </div>
  );
}

function CreateRuleModal({ isOpen, onClose }: { isOpen: boolean; onClose: () => void }) {
  const { alert } = useDialogs();
  const createMut = useCreateAlertRule();
  const groups = useInventoryGroupsFull(true);
  const channelsQuery = useNotificationChannels();
  const channels = channelsQuery.data?.channels ?? [];
  const [name, setName] = useState('');
  const [metric, setMetric] = useState('cpu');
  const [operator, setOperator] = useState('>=');
  const [value, setValue] = useState('90');
  const [severity, setSeverity] = useState('warning');
  const [cooldown, setCooldown] = useState('15');
  const [escalateAfter, setEscalateAfter] = useState('0');
  const [groupId, setGroupId] = useState('');
  const [hostId, setHostId] = useState('');
  const [description, setDescription] = useState('');
  const [channelIds, setChannelIds] = useState<string[]>([]);

  const allHosts = (groups.data ?? []).flatMap((g) => (g.hosts ?? []).map((h) => ({ ...h, group_name: g.name })));

  function handleSubmit(e: FormEvent) {
    e.preventDefault();
    const data: AlertRuleCreate = {
      name: name.trim(),
      metric,
      operator,
      value: parseFloat(value) || 0,
      severity,
      cooldown_minutes: parseInt(cooldown, 10) || 15,
      escalate_after_minutes: parseInt(escalateAfter, 10) || 0,
      escalate_to: 'critical',
      description: description.trim(),
    };
    if (hostId) data.host_id = parseInt(hostId, 10);
    else if (groupId) data.group_id = parseInt(groupId, 10);
    if (channelIds.length) data.channel_ids = channelIds;

    createMut.mutate(data, {
      onSuccess: () => {
        setName(''); setValue('90'); setDescription(''); setHostId(''); setGroupId(''); setChannelIds([]);
        onClose();
      },
      onError: (e) => { void alert({ message: (e as Error).message, variant: 'error' }); },
    });
  }

  return (
    <Modal isOpen={isOpen} onClose={onClose} title="Create Alert Rule">
      <form onSubmit={handleSubmit}>
        <div className="form-group">
          <label className="form-label">Name</label>
          <input className="form-input" value={name} onChange={(e) => setName(e.target.value)} placeholder="e.g. High CPU Warning" required />
        </div>
        <div className="form-group">
          <label className="form-label">Metric</label>
          <select className="form-select" value={metric} onChange={(e) => setMetric(e.target.value)}>
            <option value="cpu">CPU %</option>
            <option value="memory">Memory %</option>
            <option value="interface_down">Interfaces Down</option>
            <option value="vpn_down">VPN Tunnels Down</option>
            <option value="route_count">Route Count</option>
            <option value="uptime">Uptime (seconds)</option>
          </select>
        </div>
        <div style={{ display: 'flex', gap: '0.5rem' }}>
          <div className="form-group" style={{ flex: 1 }}>
            <label className="form-label">Operator</label>
            <select className="form-select" value={operator} onChange={(e) => setOperator(e.target.value)}>
              <option value=">=">{'>='}</option>
              <option value=">">{'>'}</option>
              <option value="<=">{'<='}</option>
              <option value="<">{'<'}</option>
            </select>
          </div>
          <div className="form-group" style={{ flex: 1 }}>
            <label className="form-label">Value</label>
            <input className="form-input" type="number" step="0.1" value={value} onChange={(e) => setValue(e.target.value)} />
          </div>
        </div>
        <div className="form-group">
          <label className="form-label">Severity</label>
          <select className="form-select" value={severity} onChange={(e) => setSeverity(e.target.value)}>
            <option value="warning">Warning</option>
            <option value="critical">Critical</option>
          </select>
        </div>
        <div style={{ display: 'flex', gap: '0.5rem' }}>
          <div className="form-group" style={{ flex: 1 }}>
            <label className="form-label">Cooldown (min)</label>
            <input className="form-input" type="number" min="1" max="1440" value={cooldown} onChange={(e) => setCooldown(e.target.value)} />
          </div>
          <div className="form-group" style={{ flex: 1 }}>
            <label className="form-label">Escalate After (min, 0=off)</label>
            <input className="form-input" type="number" min="0" max="1440" value={escalateAfter} onChange={(e) => setEscalateAfter(e.target.value)} />
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
          <label className="form-label">Notification Channels</label>
          {channels.length === 0 ? (
            <div className="text-muted" style={{ fontSize: '0.82em' }}>
              No channels configured. Add them under Settings → Notifications. Until then, alerts
              only appear in-app.
            </div>
          ) : (
            <>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.2rem' }}>
                {channels.map((c) => (
                  <label key={c.id} style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', fontSize: '0.88em' }}>
                    <input
                      type="checkbox"
                      checked={channelIds.includes(c.id)}
                      onChange={(e) =>
                        setChannelIds((prev) =>
                          e.target.checked ? [...prev, c.id] : prev.filter((x) => x !== c.id),
                        )
                      }
                    />
                    <span>
                      {c.name || c.id}{' '}
                      <span className="text-muted">({c.type}{c.enabled ? '' : ', disabled'})</span>
                    </span>
                  </label>
                ))}
              </div>
              <div className="text-muted" style={{ fontSize: '0.78em', marginTop: '0.25rem' }}>
                Leave all unchecked to use the default channel set from Settings → Notifications.
              </div>
            </>
          )}
        </div>
        <div className="form-group">
          <label className="form-label">Description</label>
          <textarea className="form-input" rows={2} value={description} onChange={(e) => setDescription(e.target.value)} />
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

