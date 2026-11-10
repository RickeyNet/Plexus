import { useId, useState } from 'react';

import { Badge } from '@/components/Badge';
import { DataTable } from '@/components/DataTable';
import { useDialogs } from '@/components/DialogProvider-context';
import { EmptyState } from '@/components/EmptyState';
import { LoadingState } from '@/components/LoadingState';
import { QueryError } from '@/components/QueryError';
import { TabBar } from '@/components/TabBar';
import { usePendingKeys } from '@/lib/usePendingKeys';
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

import {
  DeliveryStatsCells,
  NoticeCallout,
  RetryFields,
  RowActionsCell,
  TargetEditorModal,
  TargetTestsProvider,
  TestResultBadge,
} from './DeliveryTargets';
import { CheckboxField, CheckboxRow, FormRow, NumberField, TextField } from './FormFields';
import { AutoSaveNote } from './SaveBar';
import type { FormStatus } from './StatusLine';
import { isDirty } from './unsaved-context';

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
        background: 'rgba(from var(--text) r g b / 0.04)',
      }}
    >
      <summary style={{ cursor: 'pointer', fontWeight: 600 }}>
        How to set up each channel type
      </summary>
      <TabBar
        size="sm"
        tabs={TYPES.map((t) => ({ key: t, label: TYPE_LABELS[t] }))}
        active={tab}
        onChange={setTab}
        aria-label="Channel type"
      />
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

interface EditorState {
  draft: NotificationChannel;
  saved: NotificationChannel;
}

export function NotificationsTab() {
  const { confirm } = useDialogs();
  const query = useNotificationChannels();
  const createMut = useCreateNotificationChannel();
  const updateMut = useUpdateNotificationChannel();
  const deleteMut = useDeleteNotificationChannel();
  const testMut = useTestNotificationChannel();
  const defaultsMut = useSetNotificationDefaults();
  const deleting = usePendingKeys<string>();
  const [editor, setEditor] = useState<EditorState | null>(null);
  const [saveError, setSaveError] = useState<string | null>(null);
  const [notice, setNotice] = useState<FormStatus | null>(null);

  if (query.isError && !query.data)
    return (
      <QueryError what="notification channels" query={query} />
    );
  if (!query.data) return <LoadingState />;

  const channels = query.data.channels ?? [];
  const defaults = query.data.default_channel_ids ?? [];
  const statsById = new Map<string, NotificationChannelStats>(
    (query.data.stats ?? []).map((s) => [s.id, s]),
  );

  const openEditor = (c: NotificationChannel) => {
    setSaveError(null);
    setEditor({ draft: { ...c }, saved: { ...c } });
  };

  const onSave = () => {
    if (!editor) return;
    const editing = editor.draft;
    setSaveError(null);
    const isEdit = Boolean(editing.id) && channels.some((c) => c.id === editing.id);
    if (isEdit) {
      updateMut.mutate(
        { id: editing.id, data: editing },
        {
          onSuccess: () => {
            setEditor(null);
            setNotice({ kind: 'success', message: `Channel ${editing.name || editing.id} saved.` });
          },
          onError: (err) => setSaveError(`Failed to save channel: ${(err as Error).message}`),
        },
      );
    } else {
      createMut.mutate(editing, {
        onSuccess: (saved) => {
          setEditor(null);
          setNotice({ kind: 'success', message: `Channel ${saved?.name || saved?.id || ''} created.` });
        },
        onError: (err) => setSaveError(`Failed to create channel: ${(err as Error).message}`),
      });
    }
  };

  const onDelete = async (c: NotificationChannel) => {
    if (
      !(await confirm({
        title: 'Delete notification channel',
        message: `Delete notification channel "${c.name || c.id}"? Alerts will stop being delivered to it.`,
        confirmLabel: 'Delete',
      }))
    )
      return;
    await deleting.run(c.id, async () => {
      try {
        await deleteMut.mutateAsync(c.id);
        setNotice({ kind: 'success', message: `Channel ${c.name || c.id} deleted.` });
      } catch (err) {
        setNotice({ kind: 'error', message: `Failed to delete channel: ${(err as Error).message}` });
      }
    });
  };

  const toggleDefault = (c: NotificationChannel) => {
    const name = c.name || c.id;
    const adding = !defaults.includes(c.id);
    const next = adding ? [...defaults, c.id] : defaults.filter((d) => d !== c.id);
    defaultsMut.mutate(next, {
      onSuccess: () =>
        setNotice({
          kind: 'success',
          message: adding
            ? `Default channels updated: ${name} now receives alerts not tied to a rule.`
            : `Default channels updated: ${name} no longer receives alerts not tied to a rule.`,
        }),
      onError: (err) =>
        setNotice({ kind: 'error', message: `Failed to update default channels: ${(err as Error).message}` }),
    });
  };

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'flex-end', marginBottom: 'var(--space-3)' }}>
        <button className="btn btn-sm btn-primary" onClick={() => openEditor({ ...EMPTY_CHANNEL })}>
          Add Channel
        </button>
      </div>

      <SetupInstructions />

      <NoticeCallout notice={notice} onDismiss={() => setNotice(null)} />

      {channels.length === 0 ? (
        <EmptyState compact message="No channels configured. Add one to start delivering alerts." />
      ) : (
        <>
          <AutoSaveNote>
            The Default checkbox applies immediately. Other changes are saved from each
            channel&apos;s Edit dialog.
          </AutoSaveNote>
          <TargetTestsProvider
            send={(id) => testMut.mutateAsync(id)}
            sentMessage={(name) => `Test notification sent to ${name}.`}
            onOutcome={setNotice}
          >
            {(tests) => (
              <DataTable compact aria-label="Notification channels">
                <thead>
                  <tr>
                    <th title="Applies immediately: default channels receive alerts not tied to a rule">
                      Default
                    </th>
                    <th>Name</th>
                    <th>Type</th>
                    <th>Target</th>
                    <th>Floor</th>
                    <th>State</th>
                    <th>Queue</th>
                    <th>Delivered</th>
                    <th>Dropped</th>
                    <th>Last error</th>
                    <th>Last test</th>
                    <th aria-label="Actions"></th>
                  </tr>
                </thead>
                <tbody>
                  {channels.map((c) => {
                    const name = c.name || c.id;
                    return (
                      <tr key={c.id}>
                        <td>
                          <input
                            type="checkbox"
                            checked={defaults.includes(c.id)}
                            disabled={defaultsMut.isPending}
                            onChange={() => toggleDefault(c)}
                            title="Use this channel for alerts not tied to a rule (applies immediately)"
                            aria-label={`Default channel: ${name}`}
                          />
                        </td>
                        <td>{name}</td>
                        <td>{TYPE_LABELS[c.type] ?? c.type}</td>
                        <td>
                          <span className="form-mono delivery-cell-truncate" title={channelTarget(c)}>
                            {channelTarget(c)}
                          </span>
                        </td>
                        <td>{c.severity_floor}</td>
                        <td>
                          <Badge tone={c.enabled ? 'success' : 'info'} size="sm">
                            {c.enabled ? 'Enabled' : 'Disabled'}
                          </Badge>
                        </td>
                        <DeliveryStatsCells stats={statsById.get(c.id)} />
                        <td>
                          <TestResultBadge result={tests.result(c.id)} />
                        </td>
                        <RowActionsCell
                          name={name}
                          testing={tests.isPending(c.id)}
                          deleting={deleting.isPending(c.id)}
                          onTest={() => void tests.test(c.id, name)}
                          onEdit={() => openEditor(c)}
                          onDelete={() => void onDelete(c)}
                        />
                      </tr>
                    );
                  })}
                </tbody>
              </DataTable>
            )}
          </TargetTestsProvider>
        </>
      )}

      {editor && (
        <ChannelEditor
          channel={editor.draft}
          dirty={isDirty(editor.draft, editor.saved)}
          existing={channels}
          onChange={(draft) => setEditor({ ...editor, draft })}
          onClose={() => setEditor(null)}
          onSave={onSave}
          saving={createMut.isPending || updateMut.isPending}
          error={saveError}
        />
      )}
    </div>
  );
}

interface ChannelEditorProps {
  channel: NotificationChannel;
  dirty: boolean;
  existing: NotificationChannel[];
  onChange: (next: NotificationChannel) => void;
  onClose: () => void;
  onSave: () => void;
  saving: boolean;
  error: string | null;
}

function ChannelEditor({ channel, dirty, existing, onChange, onClose, onSave, saving, error }: ChannelEditorProps) {
  const isEdit = Boolean(channel.id) && existing.some((c) => c.id === channel.id);
  const fid = useId();
  const set = <K extends keyof NotificationChannel>(key: K, value: NotificationChannel[K]) =>
    onChange({ ...channel, [key]: value });

  return (
    <TargetEditorModal
      title={isEdit ? 'Edit Channel' : 'New Channel'}
      formName="Notification channel"
      dirty={dirty}
      saving={saving}
      primaryLabel={isEdit ? 'Save Changes' : 'Create Channel'}
      error={error}
      onSave={onSave}
      onClose={onClose}
    >
      <FormRow>
        <TextField
          label="Name"
          flex="1 1 220px"
          value={channel.name}
          onChange={(v) => set('name', v)}
          placeholder="e.g. On-call PagerDuty"
        />
        <div className="form-group" style={{ flex: '0 1 200px' }}>
          <label className="form-label" htmlFor={`${fid}-type`}>Type</label>
          <select
            id={`${fid}-type`}
            className="form-select"
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
          <label className="form-label" htmlFor={`${fid}-severity-floor`}>Severity floor</label>
          <select
            id={`${fid}-severity-floor`}
            className="form-select"
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
        <CheckboxField inRow label="Enabled" checked={channel.enabled} onChange={(v) => set('enabled', v)} />
      </FormRow>

      {channel.type === 'email' && (
        <>
          <FormRow>
            <TextField
              label="SMTP host"
              flex="1 1 240px"
              value={channel.smtp_host}
              onChange={(v) => set('smtp_host', v)}
              placeholder="smtp.example.com"
            />
            <NumberField
              label="SMTP port"
              flex="0 1 120px"
              min={1}
              max={65535}
              value={channel.smtp_port}
              onChange={(v) => set('smtp_port', v)}
            />
            <TextField
              label="From address"
              flex="1 1 240px"
              value={channel.mail_from}
              onChange={(v) => set('mail_from', v)}
              placeholder="plexus-alerts@example.com"
            />
          </FormRow>
          <TextField
            label="Recipients (comma separated)"
            value={channel.mail_to}
            onChange={(v) => set('mail_to', v)}
            placeholder="oncall@example.com, noc@example.com"
          />
          <FormRow>
            <TextField
              label="SMTP username (optional)"
              flex="1 1 240px"
              value={channel.smtp_username}
              onChange={(v) => set('smtp_username', v)}
              autoComplete="off"
            />
            <TextField
              label="SMTP password (optional)"
              type="password"
              flex="1 1 240px"
              value={channel.smtp_password}
              onChange={(v) => set('smtp_password', v)}
              placeholder="Leave masked (••••••••) to keep existing"
              autoComplete="new-password"
            />
          </FormRow>
          <CheckboxRow>
            <CheckboxField label="STARTTLS" checked={channel.smtp_use_tls} onChange={(v) => set('smtp_use_tls', v)} />
            <CheckboxField
              label="Implicit TLS (SMTPS)"
              checked={channel.smtp_use_ssl}
              onChange={(v) => set('smtp_use_ssl', v)}
            />
          </CheckboxRow>
        </>
      )}

      {channel.type === 'pagerduty' && (
        <TextField
          label="Integration / routing key"
          type="password"
          value={channel.routing_key}
          onChange={(v) => set('routing_key', v)}
          placeholder="Events API v2 integration key (32 chars)"
          autoComplete="off"
          help={
            <>
              From a PagerDuty service&apos;s Events API v2 integration. The alert dedup key is reused
              so repeated alerts collapse onto one incident. Leave masked (••••••••) to keep the
              stored key.
            </>
          }
        />
      )}

      {channel.type === 'webhook' && (
        <>
          <TextField
            label="Webhook URL"
            value={channel.webhook_url}
            onChange={(v) => set('webhook_url', v)}
            placeholder="https://example.com/hooks/plexus"
          />
          <FormRow>
            <TextField
              label="Auth header name (optional)"
              flex="1 1 220px"
              value={channel.webhook_auth_header}
              onChange={(v) => set('webhook_auth_header', v)}
              placeholder="Authorization"
            />
            <TextField
              label="Auth header value (optional)"
              type="password"
              flex="1 1 220px"
              value={channel.webhook_auth_value}
              onChange={(v) => set('webhook_auth_value', v)}
              placeholder="Bearer … (leave masked to keep)"
              autoComplete="off"
            />
          </FormRow>
          <CheckboxRow>
            <CheckboxField
              label="Verify TLS certificate"
              checked={channel.verify_tls}
              onChange={(v) => set('verify_tls', v)}
            />
          </CheckboxRow>
        </>
      )}

      {channel.type === 'teams' && (
        <TextField
          label="Teams incoming webhook URL"
          value={channel.teams_webhook_url}
          onChange={(v) => set('teams_webhook_url', v)}
          placeholder="https://outlook.office.com/webhook/…"
          help={
            <>
              Create an &quot;Incoming Webhook&quot; connector on the target Teams channel and paste
              its URL here. Posts a MessageCard.
            </>
          }
        />
      )}

      <RetryFields value={channel} onChange={(k, v) => set(k, v)} noun="alert" />
    </TargetEditorModal>
  );
}
