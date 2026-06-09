import { useState } from 'react';

import { useDialogs } from '@/components/DialogProvider-context';
import {
  NotificationChannel,
  NotificationChannelStats,
  NotificationChannelType,
  useCreateNotificationChannel,
  useDeleteNotificationChannel,
  useNotificationChannels,
  useSetNotificationDefaults,
  useTestNotificationChannel,
  useUpdateNotificationChannel,
} from '@/api/settings';

const TYPES: NotificationChannelType[] = ['email', 'pagerduty', 'webhook', 'teams'];
const TYPE_LABELS: Record<string, string> = {
  email: 'Email (SMTP)',
  pagerduty: 'PagerDuty',
  webhook: 'Webhook (JSON)',
  teams: 'Microsoft Teams',
};
const SEVERITIES = ['info', 'warning', 'critical'];

const EMPTY_CHANNEL: NotificationChannel = {
  id: '',
  name: '',
  enabled: true,
  type: 'webhook',
  severity_floor: 'warning',
  queue_size: 1000,
  max_retries: 4,
  backoff_base: 1.0,
  backoff_cap: 60.0,
  smtp_host: '',
  smtp_port: 587,
  smtp_use_tls: true,
  smtp_use_ssl: false,
  smtp_username: '',
  smtp_password: '',
  mail_from: '',
  mail_to: '',
  routing_key: '',
  webhook_url: '',
  webhook_auth_header: '',
  webhook_auth_value: '',
  verify_tls: true,
  teams_webhook_url: '',
};

const SETUP_GUIDE: Record<NotificationChannelType, React.ReactNode> = {
  email: (
    <ol style={{ margin: 0, paddingLeft: '1.2rem', lineHeight: 1.6 }}>
      <li>
        Click <strong>Add Channel</strong> and set <strong>Type</strong> to{' '}
        <em>Email (SMTP)</em>.
      </li>
      <li>
        Enter the <strong>SMTP host</strong> and <strong>port</strong>: <code>587</code> with{' '}
        <strong>STARTTLS</strong> checked, <code>465</code> with <strong>Implicit TLS (SMTPS)</strong>{' '}
        checked, or <code>25</code> for an unauthenticated internal relay.
      </li>
      <li>
        Set the <strong>From address</strong> and one or more comma-separated{' '}
        <strong>Recipients</strong>.
      </li>
      <li>
        Provide an <strong>SMTP username/password</strong> if your server requires authentication
        (leave both blank for an open relay). An existing password stays set while masked as
        ••••••••.
      </li>
      <li>
        <strong>Save</strong>, then click <strong>Test</strong> on the row to send a test message.
      </li>
    </ol>
  ),
  pagerduty: (
    <ol style={{ margin: 0, paddingLeft: '1.2rem', lineHeight: 1.6 }}>
      <li>
        In PagerDuty, open the target <strong>Service → Integrations → Add integration</strong> and
        choose <strong>Events API v2</strong>.
      </li>
      <li>
        Copy that integration&apos;s <strong>Integration/Routing Key</strong> (32 characters).
      </li>
      <li>
        In Plexus, <strong>Add Channel</strong>, set <strong>Type</strong> to <em>PagerDuty</em>, and
        paste the key into <strong>Integration / routing key</strong>.
      </li>
      <li>
        Repeated occurrences of the same alert reuse its dedup key, so they collapse onto one
        incident instead of paging repeatedly.
      </li>
      <li>
        <strong>Save</strong>, then <strong>Test</strong> to trigger (and auto-resolve) a sample
        incident.
      </li>
    </ol>
  ),
  webhook: (
    <ol style={{ margin: 0, paddingLeft: '1.2rem', lineHeight: 1.6 }}>
      <li>
        <strong>Add Channel</strong> and set <strong>Type</strong> to <em>Webhook (JSON)</em>.
      </li>
      <li>
        Enter the receiving <strong>Webhook URL</strong> (HTTPS recommended). Plexus{' '}
        <code>POST</code>s a JSON body describing the alert per delivery.
      </li>
      <li>
        Optionally set an <strong>Auth header name</strong> and <strong>value</strong> (for example{' '}
        <code>Authorization</code> / <code>Bearer …</code>) if your endpoint requires one.
      </li>
      <li>
        Leave <strong>Verify TLS certificate</strong> checked; uncheck it only for an internal
        endpoint with a self-signed certificate.
      </li>
      <li>
        <strong>Save</strong>, then <strong>Test</strong> to POST a sample payload.
      </li>
    </ol>
  ),
  teams: (
    <ol style={{ margin: 0, paddingLeft: '1.2rem', lineHeight: 1.6 }}>
      <li>
        In Microsoft Teams, on the target channel choose <strong>••• → Connectors</strong> (or{' '}
        <strong>Workflows</strong>), then add an <strong>Incoming Webhook</strong>.
      </li>
      <li>
        Name it, click <strong>Create</strong>, and copy the generated webhook URL.
      </li>
      <li>
        In Plexus, <strong>Add Channel</strong>, set <strong>Type</strong> to{' '}
        <em>Microsoft Teams</em>, and paste it into <strong>Teams incoming webhook URL</strong>.
        Plexus posts a MessageCard.
      </li>
      <li>
        <strong>Save</strong>, then <strong>Test</strong> to post a sample card to the channel.
      </li>
    </ol>
  ),
};

function SetupInstructions() {
  const [tab, setTab] = useState<NotificationChannelType>('email');
  return (
    <details
      style={{
        marginBottom: '0.75rem',
        border: '1px solid var(--border)',
        borderRadius: 'var(--radius, 6px)',
        padding: '0.5rem 0.75rem',
        background: 'var(--surface-2, rgba(255,255,255,0.02))',
      }}
    >
      <summary style={{ cursor: 'pointer', fontWeight: 600 }}>
        How to set up each channel type
      </summary>
      <div
        style={{
          display: 'flex',
          gap: '0.4rem',
          flexWrap: 'wrap',
          margin: '0.75rem 0',
        }}
      >
        {TYPES.map((t) => (
          <button
            key={t}
            type="button"
            className={`btn btn-sm ${tab === t ? 'btn-primary' : 'btn-ghost'}`}
            onClick={() => setTab(t)}
          >
            {TYPE_LABELS[t]}
          </button>
        ))}
      </div>
      <div style={{ fontSize: '0.85rem' }}>{SETUP_GUIDE[tab]}</div>
      <p className="text-muted" style={{ fontSize: '0.8rem', marginTop: '0.75rem', marginBottom: 0 }}>
        For every type: <strong>Severity floor</strong> drops alerts below the chosen level; check{' '}
        <strong>Default</strong> on a saved channel so it receives alerts not tied to a rule; and
        assign channels to specific alerts under <strong>Monitoring → Rules</strong>.
      </p>
    </details>
  );
}

function channelTarget(c: NotificationChannel): string {
  switch (c.type) {
    case 'email':
      return `${c.mail_to} via ${c.smtp_host}:${c.smtp_port}`;
    case 'pagerduty':
      return 'PagerDuty Events API v2';
    case 'webhook':
      return c.webhook_url;
    case 'teams':
      return c.teams_webhook_url;
    default:
      return '';
  }
}

export function NotificationsTab() {
  const { confirm } = useDialogs();
  const query = useNotificationChannels();
  const createMut = useCreateNotificationChannel();
  const updateMut = useUpdateNotificationChannel();
  const deleteMut = useDeleteNotificationChannel();
  const testMut = useTestNotificationChannel();
  const defaultsMut = useSetNotificationDefaults();
  const [editing, setEditing] = useState<NotificationChannel | null>(null);
  const [status, setStatus] = useState<{ kind: 'success' | 'error'; message: string } | null>(null);
  const [testResults, setTestResults] = useState<Record<string, { ok: boolean; error: string }>>(
    {},
  );

  if (query.isLoading) return <p className="text-muted">Loading…</p>;
  if (query.isError)
    return (
      <div className="error">
        Failed to load notification channels: {(query.error as Error).message}
      </div>
    );

  const channels = query.data?.channels ?? [];
  const defaults = query.data?.default_channel_ids ?? [];
  const statsById = new Map<string, NotificationChannelStats>(
    (query.data?.stats ?? []).map((s) => [s.id, s]),
  );

  const onSave = () => {
    if (!editing) return;
    setStatus(null);
    const isEdit = Boolean(editing.id) && channels.some((c) => c.id === editing.id);
    if (isEdit) {
      updateMut.mutate(
        { id: editing.id, data: editing },
        {
          onSuccess: () => {
            setEditing(null);
            setStatus({ kind: 'success', message: `Channel ${editing.name || editing.id} saved.` });
          },
          onError: (err) =>
            setStatus({ kind: 'error', message: `Failed to save channel: ${(err as Error).message}` }),
        },
      );
    } else {
      createMut.mutate(editing, {
        onSuccess: (saved) => {
          setEditing(null);
          setStatus({ kind: 'success', message: `Channel ${saved?.name || saved?.id || ''} created.` });
        },
        onError: (err) =>
          setStatus({ kind: 'error', message: `Failed to create channel: ${(err as Error).message}` }),
      });
    }
  };

  const onDelete = async (c: NotificationChannel) => {
    if (
      !(await confirm(
        `Delete notification channel "${c.name || c.id}"? Alerts will stop being delivered to it.`,
      ))
    )
      return;
    deleteMut.mutate(c.id, {
      onSuccess: () => setStatus({ kind: 'success', message: `Channel ${c.name || c.id} deleted.` }),
      onError: (err) =>
        setStatus({ kind: 'error', message: `Failed to delete channel: ${(err as Error).message}` }),
    });
  };

  const onTest = (c: NotificationChannel) => {
    testMut.mutate(c.id, {
      onSuccess: (res) => setTestResults((prev) => ({ ...prev, [c.id]: res })),
      onError: (err) =>
        setTestResults((prev) => ({ ...prev, [c.id]: { ok: false, error: (err as Error).message } })),
    });
  };

  const toggleDefault = (id: string) => {
    const next = defaults.includes(id) ? defaults.filter((d) => d !== id) : [...defaults, id];
    defaultsMut.mutate(next, {
      onError: (err) =>
        setStatus({ kind: 'error', message: `Failed to update defaults: ${(err as Error).message}` }),
    });
  };

  return (
    <div className="card" style={{ padding: '1rem' }}>
      <div
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          marginBottom: '0.75rem',
          flexWrap: 'wrap',
          gap: '0.5rem',
        }}
      >
        <h3 style={{ margin: 0 }}>Alert Notification Channels</h3>
        <button className="btn btn-sm btn-primary" onClick={() => setEditing({ ...EMPTY_CHANNEL })}>
          Add Channel
        </button>
      </div>

      <p className="text-muted" style={{ fontSize: '0.85rem', marginBottom: '0.75rem' }}>
        Deliver monitoring alerts to email, PagerDuty, a generic JSON webhook, or a Microsoft Teams
        incoming webhook. Each newly raised alert is fanned out to its rule&apos;s assigned channels
        (set per rule under Monitoring → Rules); alerts with no rule — built-in thresholds, baseline
        deviations, route churn — go to the <strong>default</strong> channels selected below.
        Repeated occurrences of the same alert are de-duplicated and do not re-notify.
      </p>

      <SetupInstructions />

      {channels.length === 0 ? (
        <p className="text-muted">No channels configured. Add one to start delivering alerts.</p>
      ) : (
        <div style={{ overflowX: 'auto' }}>
          <table className="table" style={{ width: '100%', minWidth: '760px' }}>
            <thead>
              <tr>
                <th>Default</th>
                <th>Name</th>
                <th>Type</th>
                <th>Target</th>
                <th>Floor</th>
                <th>State</th>
                <th>Queue</th>
                <th>Delivered</th>
                <th>Dropped</th>
                <th style={{ minWidth: '160px' }}>Last Error / Test</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {channels.map((c) => {
                const st = statsById.get(c.id);
                const result = testResults[c.id];
                return (
                  <tr key={c.id}>
                    <td style={{ textAlign: 'center' }}>
                      <input
                        type="checkbox"
                        checked={defaults.includes(c.id)}
                        onChange={() => toggleDefault(c.id)}
                        title="Use this channel for alerts not tied to a rule"
                      />
                    </td>
                    <td>{c.name || c.id}</td>
                    <td>{TYPE_LABELS[c.type] ?? c.type}</td>
                    <td
                      style={{
                        fontFamily: 'monospace',
                        fontSize: '0.8rem',
                        maxWidth: '240px',
                        overflow: 'hidden',
                        textOverflow: 'ellipsis',
                        whiteSpace: 'nowrap',
                      }}
                      title={channelTarget(c)}
                    >
                      {channelTarget(c)}
                    </td>
                    <td>{c.severity_floor}</td>
                    <td>
                      <span className={`badge ${c.enabled ? 'badge-success' : 'badge-info'}`}>
                        {c.enabled ? 'Enabled' : 'Disabled'}
                      </span>
                    </td>
                    <td>{st ? `${st.queue_depth}/${st.queue_size}` : '-'}</td>
                    <td>{st?.delivered ?? 0}</td>
                    <td>{(st?.dropped_queue_full ?? 0) + (st?.dropped_below_severity ?? 0)}</td>
                    <td
                      style={{
                        fontFamily: 'monospace',
                        fontSize: '0.78rem',
                        color: result && result.ok ? 'var(--success, green)' : 'var(--text-muted)',
                        maxWidth: '220px',
                        overflow: 'hidden',
                        textOverflow: 'ellipsis',
                        whiteSpace: 'nowrap',
                      }}
                      title={result ? result.error : st?.last_error || ''}
                    >
                      {result
                        ? result.ok
                          ? 'Test OK'
                          : `Test failed: ${result.error}`
                        : st?.last_error || ''}
                    </td>
                    <td style={{ whiteSpace: 'nowrap' }}>
                      <button className="btn btn-xs btn-ghost" onClick={() => onTest(c)}>
                        Test
                      </button>{' '}
                      <button className="btn btn-xs btn-ghost" onClick={() => setEditing({ ...c })}>
                        Edit
                      </button>{' '}
                      <button className="btn btn-xs btn-danger" onClick={() => onDelete(c)}>
                        Delete
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

      {status && (
        <div
          className={status.kind === 'success' ? 'success' : 'error'}
          style={{ marginTop: '0.75rem' }}
        >
          {status.message}
        </div>
      )}

      {editing && (
        <ChannelEditor
          channel={editing}
          existing={channels}
          onChange={setEditing}
          onCancel={() => setEditing(null)}
          onSave={onSave}
          saving={createMut.isPending || updateMut.isPending}
        />
      )}
    </div>
  );
}

interface ChannelEditorProps {
  channel: NotificationChannel;
  existing: NotificationChannel[];
  onChange: (next: NotificationChannel) => void;
  onCancel: () => void;
  onSave: () => void;
  saving: boolean;
}

function ChannelEditor({ channel, existing, onChange, onCancel, onSave, saving }: ChannelEditorProps) {
  const isEdit = Boolean(channel.id) && existing.some((c) => c.id === channel.id);
  const set = <K extends keyof NotificationChannel>(key: K, value: NotificationChannel[K]) =>
    onChange({ ...channel, [key]: value });

  return (
    <div
      style={{
        marginTop: '1rem',
        padding: '0.75rem',
        border: '1px solid var(--border)',
        borderRadius: 'var(--radius, 6px)',
        background: 'var(--surface-2, rgba(255,255,255,0.02))',
      }}
    >
      <h4 style={{ marginTop: 0 }}>{isEdit ? 'Edit Channel' : 'New Channel'}</h4>

      <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.75rem' }}>
        <div className="form-group" style={{ flex: '1 1 220px' }}>
          <label className="form-label">Name</label>
          <input
            className="form-input"
            value={channel.name}
            onChange={(e) => set('name', e.target.value)}
            placeholder="e.g. On-call PagerDuty"
          />
        </div>
        <div className="form-group" style={{ flex: '0 1 200px' }}>
          <label className="form-label">Type</label>
          <select
            className="form-input"
            value={channel.type}
            onChange={(e) => set('type', e.target.value as NotificationChannelType)}
            disabled={isEdit}
          >
            {TYPES.map((t) => (
              <option key={t} value={t}>
                {TYPE_LABELS[t]}
              </option>
            ))}
          </select>
        </div>
        <div className="form-group" style={{ flex: '0 1 160px' }}>
          <label className="form-label">Severity floor</label>
          <select
            className="form-input"
            value={channel.severity_floor}
            onChange={(e) => set('severity_floor', e.target.value)}
          >
            {SEVERITIES.map((s) => (
              <option key={s} value={s}>
                {s}
              </option>
            ))}
          </select>
        </div>
        <label
          className="form-group"
          style={{ display: 'inline-flex', alignItems: 'center', gap: '0.4rem', marginTop: '1.4rem' }}
        >
          <input
            type="checkbox"
            checked={channel.enabled}
            onChange={(e) => set('enabled', e.target.checked)}
          />
          <span>Enabled</span>
        </label>
      </div>

      {channel.type === 'email' && (
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.75rem', marginTop: '0.5rem' }}>
          <div className="form-group" style={{ flex: '1 1 240px' }}>
            <label className="form-label">SMTP host</label>
            <input
              className="form-input"
              value={channel.smtp_host}
              onChange={(e) => set('smtp_host', e.target.value)}
              placeholder="smtp.example.com"
            />
          </div>
          <div className="form-group" style={{ flex: '0 1 120px' }}>
            <label className="form-label">SMTP port</label>
            <input
              type="number"
              className="form-input"
              min={1}
              max={65535}
              value={channel.smtp_port}
              onChange={(e) => set('smtp_port', Number(e.target.value))}
            />
          </div>
          <div className="form-group" style={{ flex: '1 1 240px' }}>
            <label className="form-label">From address</label>
            <input
              className="form-input"
              value={channel.mail_from}
              onChange={(e) => set('mail_from', e.target.value)}
              placeholder="plexus-alerts@example.com"
            />
          </div>
          <div className="form-group" style={{ flex: '1 1 100%' }}>
            <label className="form-label">Recipients (comma separated)</label>
            <input
              className="form-input"
              value={channel.mail_to}
              onChange={(e) => set('mail_to', e.target.value)}
              placeholder="oncall@example.com, noc@example.com"
            />
          </div>
          <div className="form-group" style={{ flex: '1 1 240px' }}>
            <label className="form-label">SMTP username (optional)</label>
            <input
              className="form-input"
              value={channel.smtp_username}
              onChange={(e) => set('smtp_username', e.target.value)}
              autoComplete="off"
            />
          </div>
          <div className="form-group" style={{ flex: '1 1 240px' }}>
            <label className="form-label">SMTP password (optional)</label>
            <input
              type="password"
              className="form-input"
              value={channel.smtp_password}
              onChange={(e) => set('smtp_password', e.target.value)}
              placeholder="Leave masked (••••••••) to keep existing"
              autoComplete="new-password"
            />
          </div>
          <label
            className="form-group"
            style={{ display: 'inline-flex', alignItems: 'center', gap: '0.4rem', marginTop: '1.4rem' }}
          >
            <input
              type="checkbox"
              checked={channel.smtp_use_tls}
              onChange={(e) => set('smtp_use_tls', e.target.checked)}
            />
            <span>STARTTLS</span>
          </label>
          <label
            className="form-group"
            style={{ display: 'inline-flex', alignItems: 'center', gap: '0.4rem', marginTop: '1.4rem' }}
          >
            <input
              type="checkbox"
              checked={channel.smtp_use_ssl}
              onChange={(e) => set('smtp_use_ssl', e.target.checked)}
            />
            <span>Implicit TLS (SMTPS)</span>
          </label>
        </div>
      )}

      {channel.type === 'pagerduty' && (
        <div style={{ marginTop: '0.5rem' }}>
          <div className="form-group" style={{ flex: '1 1 100%' }}>
            <label className="form-label">Integration / routing key</label>
            <input
              className="form-input"
              type="password"
              value={channel.routing_key}
              onChange={(e) => set('routing_key', e.target.value)}
              placeholder="Events API v2 integration key (32 chars)"
              autoComplete="off"
            />
            <div className="text-muted" style={{ fontSize: '0.78rem', marginTop: '0.2rem' }}>
              From a PagerDuty service&apos;s Events API v2 integration. The alert dedup key is reused
              so repeated alerts collapse onto one incident. Leave masked (••••••••) to keep the
              stored key.
            </div>
          </div>
        </div>
      )}

      {channel.type === 'webhook' && (
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.75rem', marginTop: '0.5rem' }}>
          <div className="form-group" style={{ flex: '1 1 100%' }}>
            <label className="form-label">Webhook URL</label>
            <input
              className="form-input"
              value={channel.webhook_url}
              onChange={(e) => set('webhook_url', e.target.value)}
              placeholder="https://example.com/hooks/plexus"
            />
          </div>
          <div className="form-group" style={{ flex: '1 1 220px' }}>
            <label className="form-label">Auth header name (optional)</label>
            <input
              className="form-input"
              value={channel.webhook_auth_header}
              onChange={(e) => set('webhook_auth_header', e.target.value)}
              placeholder="Authorization"
            />
          </div>
          <div className="form-group" style={{ flex: '1 1 220px' }}>
            <label className="form-label">Auth header value (optional)</label>
            <input
              type="password"
              className="form-input"
              value={channel.webhook_auth_value}
              onChange={(e) => set('webhook_auth_value', e.target.value)}
              placeholder="Bearer … (leave masked to keep)"
              autoComplete="off"
            />
          </div>
          <label
            className="form-group"
            style={{ display: 'inline-flex', alignItems: 'center', gap: '0.4rem', marginTop: '1.4rem' }}
          >
            <input
              type="checkbox"
              checked={channel.verify_tls}
              onChange={(e) => set('verify_tls', e.target.checked)}
            />
            <span>Verify TLS certificate</span>
          </label>
        </div>
      )}

      {channel.type === 'teams' && (
        <div style={{ marginTop: '0.5rem' }}>
          <div className="form-group" style={{ flex: '1 1 100%' }}>
            <label className="form-label">Teams incoming webhook URL</label>
            <input
              className="form-input"
              value={channel.teams_webhook_url}
              onChange={(e) => set('teams_webhook_url', e.target.value)}
              placeholder="https://outlook.office.com/webhook/…"
            />
            <div className="text-muted" style={{ fontSize: '0.78rem', marginTop: '0.2rem' }}>
              Create an &quot;Incoming Webhook&quot; connector on the target Teams channel and paste
              its URL here. Posts a MessageCard.
            </div>
          </div>
        </div>
      )}

      <details style={{ marginTop: '0.5rem' }}>
        <summary style={{ cursor: 'pointer' }}>Advanced (queue, retry, backoff)</summary>
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.75rem', marginTop: '0.5rem' }}>
          <div className="form-group" style={{ flex: '0 1 160px' }}>
            <label className="form-label">Queue size</label>
            <input
              type="number"
              className="form-input"
              min={10}
              max={100000}
              value={channel.queue_size}
              onChange={(e) => set('queue_size', Number(e.target.value))}
            />
          </div>
          <div className="form-group" style={{ flex: '0 1 160px' }}>
            <label className="form-label">Max retries</label>
            <input
              type="number"
              className="form-input"
              min={0}
              max={20}
              value={channel.max_retries}
              onChange={(e) => set('max_retries', Number(e.target.value))}
            />
          </div>
          <div className="form-group" style={{ flex: '0 1 160px' }}>
            <label className="form-label">Backoff base (s)</label>
            <input
              type="number"
              className="form-input"
              min={0.1}
              max={30}
              step="0.1"
              value={channel.backoff_base}
              onChange={(e) => set('backoff_base', Number(e.target.value))}
            />
          </div>
          <div className="form-group" style={{ flex: '0 1 160px' }}>
            <label className="form-label">Backoff cap (s)</label>
            <input
              type="number"
              className="form-input"
              min={1}
              max={600}
              value={channel.backoff_cap}
              onChange={(e) => set('backoff_cap', Number(e.target.value))}
            />
          </div>
        </div>
      </details>

      <div style={{ marginTop: '0.75rem', display: 'flex', gap: '0.5rem' }}>
        <button className="btn btn-primary" onClick={onSave} disabled={saving}>
          {saving ? 'Saving…' : isEdit ? 'Save Changes' : 'Create Channel'}
        </button>
        <button className="btn btn-ghost" onClick={onCancel} disabled={saving}>
          Cancel
        </button>
      </div>
    </div>
  );
}
