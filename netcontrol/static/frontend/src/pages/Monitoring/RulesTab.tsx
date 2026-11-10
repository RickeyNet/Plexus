import { useId, useState, type FormEvent } from 'react';

import { SeverityBadge } from '@/components/Badge';
import { BusyButton } from '@/components/BusyButton';
import { Callout } from '@/components/Callout';
import { DeleteButton } from '@/components/DeleteButton';
import { EmptyState } from '@/components/EmptyState';
import { LoadingState } from '@/components/LoadingState';
import { Modal } from '@/components/Modal';
import { QueryError } from '@/components/QueryError';
import { useDialogs } from '@/components/DialogProvider-context';
import { groupLabel, useInventoryGroupsFull } from '@/api/inventory';
import {
  useAlertRules,
  useCreateAlertRule,
  useDeleteAlertRule,
  useUpdateAlertRule,
  type AlertRule,
  type AlertRuleCreate,
} from '@/api/monitoring';
import { useNotificationChannels } from '@/api/settings';
import { usePendingKeys } from '@/lib/usePendingKeys';

import { INACTIVE_OPACITY } from './helpers';

const METRIC_OPTIONS: { value: string; label: string }[] = [
  { value: 'cpu', label: 'CPU %' },
  { value: 'memory', label: 'Memory %' },
  { value: 'interface_down', label: 'Interfaces Down' },
  { value: 'vpn_down', label: 'VPN Tunnels Down' },
  { value: 'route_count', label: 'Route Count' },
  { value: 'uptime', label: 'Uptime (seconds)' },
];
const OPERATOR_OPTIONS = ['>=', '>', '<=', '<', '==', '!='];
const SEVERITY_OPTIONS: { value: string; label: string }[] = [
  { value: 'warning', label: 'Warning' },
  { value: 'critical', label: 'Critical' },
];

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
  const [creating, setCreating] = useState(false);
  const [editing, setEditing] = useState<AlertRule | null>(null);
  const toggling = usePendingKeys<number>();
  const deleting = usePendingKeys<number>();

  function toggleEnabled(r: AlertRule) {
    return toggling.run(r.id, async () => {
      try {
        await updateMut.mutateAsync({ id: r.id, data: { enabled: !r.enabled } });
      } catch (e) {
        void alert({ message: (e as Error).message, variant: 'error' });
      }
    });
  }

  async function handleDelete(r: AlertRule) {
    if (!(await confirm({ title: 'Delete alert rule', message: `Delete rule '${r.name}'?`, confirmLabel: 'Delete' }))) return;
    await deleting.run(r.id, async () => {
      try {
        await deleteMut.mutateAsync(r.id);
      } catch (e) {
        void alert({ message: (e as Error).message, variant: 'error' });
      }
    });
  }

  return (
    <div>
      <div className="toolbar" style={{ justifyContent: 'flex-end' }}>
        <button className="btn btn-primary" onClick={() => setCreating(true)}>+ New Rule</button>
      </div>

      {rules.error && !rules.data ? (
        <QueryError what="alert rules" query={rules} />
      ) : (
        rules.isPending && <LoadingState />
      )}
      {rules.data && (rules.data.length === 0 ? (
        <EmptyState message="No alert rules defined" />
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.4rem' }}>
          {rules.data.map((r) => {
            const scope = r.hostname ? `Host: ${r.hostname}` : r.group_name ? `Group: ${r.group_name}` : 'All hosts';
            // Only the description of a disabled rule is dimmed; its buttons stay full strength.
            const dim = r.enabled ? 1 : INACTIVE_OPACITY;
            return (
              <div key={r.id} className="card card-sm">
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '0.4rem' }}>
                  <div style={{ opacity: dim }}>
                    <SeverityBadge severity={r.severity} />
                    <strong style={{ marginLeft: '0.4rem' }}>{r.name || 'Unnamed'}</strong>
                    <span className="text-muted" style={{ fontSize: '0.85em', marginLeft: '0.5rem' }}>
                      {r.metric} {r.operator} {r.value}
                    </span>
                    {!r.enabled && <span className="text-muted" style={{ fontSize: '0.75em', marginLeft: '0.3rem' }}>(disabled)</span>}
                  </div>
                  <div style={{ display: 'flex', gap: '0.4rem' }}>
                    <button className="btn btn-sm btn-secondary" onClick={() => setEditing(r)}>Edit</button>
                    <BusyButton className="btn btn-sm btn-secondary" busy={toggling.isPending(r.id)} onClick={() => void toggleEnabled(r)}>
                      {r.enabled ? 'Disable' : 'Enable'}
                    </BusyButton>
                    <DeleteButton busy={deleting.isPending(r.id)} onClick={() => void handleDelete(r)} />
                  </div>
                </div>
                <div className="text-muted" style={{ marginTop: '0.3rem', fontSize: '0.85em', opacity: dim }}>
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

      <RuleFormModal
        rule={editing}
        isCreate={creating}
        onClose={() => { setEditing(null); setCreating(false); }}
      />
    </div>
  );
}

// Create (rule == null, isCreate) or edit (rule set) an alert rule.
function RuleFormModal({ rule, isCreate, onClose }: { rule: AlertRule | null; isCreate: boolean; onClose: () => void }) {
  const formId = useId();
  const isOpen = isCreate || rule != null;
  const [saveError, setSaveError] = useState('');
  const createMut = useCreateAlertRule();
  const updateMut = useUpdateAlertRule();
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

  const allHosts = (groups.data ?? []).flatMap((g) => (g.hosts ?? []).map((h) => ({ ...h, group_name: groupLabel(g) })));

  // Load the form when the modal opens for another rule (or for a new one).
  const [prevRule, setPrevRule] = useState(rule);
  const [prevIsCreate, setPrevIsCreate] = useState(isCreate);
  if (rule !== prevRule || isCreate !== prevIsCreate) {
    setPrevRule(rule);
    setPrevIsCreate(isCreate);
    setSaveError('');
    if (rule) {
      setName(rule.name);
      setMetric(rule.metric);
      setOperator(rule.operator);
      setValue(String(rule.value));
      setSeverity(rule.severity);
      setCooldown(String(rule.cooldown_minutes));
      setEscalateAfter(String(rule.escalate_after_minutes));
      setHostId(rule.host_id != null ? String(rule.host_id) : '');
      setGroupId(rule.host_id == null && rule.group_id != null ? String(rule.group_id) : '');
      setDescription(rule.description ?? '');
      setChannelIds(parseChannelIds(rule.channel_ids));
    } else if (isCreate) {
      setName(''); setMetric('cpu'); setOperator('>='); setValue('90'); setSeverity('warning');
      setCooldown('15'); setEscalateAfter('0'); setHostId(''); setGroupId(''); setDescription('');
      setChannelIds([]);
    }
  }

  // A rule made through the API can carry a value the lists below do not offer; keep it selectable.
  const metricOptions = METRIC_OPTIONS.some((o) => o.value === metric)
    ? METRIC_OPTIONS
    : [...METRIC_OPTIONS, { value: metric, label: metric }];
  const severityOptions = SEVERITY_OPTIONS.some((o) => o.value === severity)
    ? SEVERITY_OPTIONS
    : [...SEVERITY_OPTIONS, { value: severity, label: severity }];
  const operatorOptions = OPERATOR_OPTIONS.includes(operator) ? OPERATOR_OPTIONS : [...OPERATOR_OPTIONS, operator];

  function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setSaveError('');
    const data: AlertRuleCreate = {
      name: name.trim(),
      metric,
      operator,
      value: parseFloat(value) || 0,
      severity,
      cooldown_minutes: parseInt(cooldown, 10) || 15,
      escalate_after_minutes: parseInt(escalateAfter, 10) || 0,
      escalate_to: rule?.escalate_to || 'critical',
      description: description.trim(),
    };
    const onError = (err: Error) => { setSaveError(err.message); };
    if (rule) {
      // An edit sends every field, so a cleared scope or channel list is saved too.
      data.host_id = hostId ? parseInt(hostId, 10) : null;
      data.group_id = !hostId && groupId ? parseInt(groupId, 10) : null;
      data.channel_ids = channelIds;
      updateMut.mutate({ id: rule.id, data }, { onSuccess: onClose, onError });
      return;
    }
    if (hostId) data.host_id = parseInt(hostId, 10);
    else if (groupId) data.group_id = parseInt(groupId, 10);
    if (channelIds.length) data.channel_ids = channelIds;
    createMut.mutate(data, { onSuccess: onClose, onError });
  }

  const pending = createMut.isPending || updateMut.isPending;

  return (
    <Modal
      isOpen={isOpen}
      onClose={onClose}
      title={rule ? 'Edit Alert Rule' : 'Create Alert Rule'}
      footer={
        <>
          <button type="button" className="btn btn-secondary" onClick={onClose}>Cancel</button>
          <button type="submit" form={formId} className="btn btn-primary" disabled={pending}>
            {pending ? 'Saving…' : rule ? 'Save' : 'Create'}
          </button>
        </>
      }
    >
      <form id={formId} onSubmit={handleSubmit}>
        {saveError && <Callout tone="danger">{saveError}</Callout>}
        <div className="form-group">
          <label className="form-label" htmlFor={`${formId}-name`}>Name</label>
          <input id={`${formId}-name`} className="form-input" value={name} onChange={(e) => setName(e.target.value)} placeholder="e.g. High CPU Warning" required />
        </div>
        <div className="form-group">
          <label className="form-label" htmlFor={`${formId}-metric`}>Metric</label>
          <select id={`${formId}-metric`} className="form-select" value={metric} onChange={(e) => setMetric(e.target.value)}>
            {metricOptions.map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}
          </select>
        </div>
        <div style={{ display: 'flex', gap: '0.5rem' }}>
          <div className="form-group" style={{ flex: 1 }}>
            <label className="form-label" htmlFor={`${formId}-operator`}>Operator</label>
            <select id={`${formId}-operator`} className="form-select" value={operator} onChange={(e) => setOperator(e.target.value)}>
              {operatorOptions.map((o) => <option key={o} value={o}>{o}</option>)}
            </select>
          </div>
          <div className="form-group" style={{ flex: 1 }}>
            <label className="form-label" htmlFor={`${formId}-value`}>Value</label>
            <input id={`${formId}-value`} className="form-input" type="number" step="0.1" value={value} onChange={(e) => setValue(e.target.value)} />
          </div>
        </div>
        <div className="form-group">
          <label className="form-label" htmlFor={`${formId}-severity`}>Severity</label>
          <select id={`${formId}-severity`} className="form-select" value={severity} onChange={(e) => setSeverity(e.target.value)}>
            {severityOptions.map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}
          </select>
        </div>
        <div style={{ display: 'flex', gap: '0.5rem' }}>
          <div className="form-group" style={{ flex: 1 }}>
            <label className="form-label" htmlFor={`${formId}-cooldown`}>Cooldown (min)</label>
            <input id={`${formId}-cooldown`} className="form-input" type="number" min="1" max="1440" value={cooldown} onChange={(e) => setCooldown(e.target.value)} />
          </div>
          <div className="form-group" style={{ flex: 1 }}>
            <label className="form-label" htmlFor={`${formId}-escalate-after`}>Escalate After (min, 0=off)</label>
            <input id={`${formId}-escalate-after`} className="form-input" type="number" min="0" max="1440" value={escalateAfter} onChange={(e) => setEscalateAfter(e.target.value)} />
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
          <span className="form-label" id={`${formId}-channels`}>Notification Channels</span>
          {channels.length === 0 ? (
            <div className="text-muted" style={{ fontSize: '0.82em' }}>
              No channels configured. Add them under Settings → Notifications. Until then, alerts
              only appear in-app.
            </div>
          ) : (
            <>
              <div
                role="group"
                aria-labelledby={`${formId}-channels`}
                style={{ display: 'flex', flexDirection: 'column', gap: '0.2rem' }}
              >
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
          <label className="form-label" htmlFor={`${formId}-description`}>Description</label>
          <textarea id={`${formId}-description`} className="form-input" rows={2} value={description} onChange={(e) => setDescription(e.target.value)} />
        </div>
      </form>
    </Modal>
  );
}

