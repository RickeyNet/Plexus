import { useState } from 'react';

import {
  useMerakiAlertSettings,
  usePollMerakiAlerts,
  useUpdateMerakiAlertSettings,
  type MerakiAlertSettingsUpdate,
} from '@/api/merakiAlerts';
import { BusyButton } from '@/components/BusyButton';
import { Callout } from '@/components/Callout';
import { CopyButton } from '@/components/CopyButton';
import { useDialogs } from '@/components/DialogProvider-context';
import { FieldError } from '@/components/FieldError';
import { QueryError } from '@/components/QueryError';
import { formatBackendDateTime } from '@/lib/datetime';

const SECRET_MIN = 16;

/** A random shared secret (32 URL-safe characters) for the Meraki HTTP server. */
function randomSecret(): string {
  const bytes = new Uint8Array(24);
  crypto.getRandomValues(bytes);
  return btoa(String.fromCharCode(...bytes)).replace(/\+/g, '-').replace(/\//g, '_');
}

/**
 * Near-real-time Meraki alerts (administrators only): the assurance-alert
 * poll and the optional webhook receiver. The secret is write-only; the
 * server only says whether one is set. See docs/meraki-alerts.md.
 */
export function MerakiAlertsSettings() {
  const settings = useMerakiAlertSettings(true);
  const save = useUpdateMerakiAlertSettings();
  const poll = usePollMerakiAlerts();
  const { confirm } = useDialogs();
  const data = settings.data ?? null;
  const config = data?.config ?? null;

  const [pollEnabled, setPollEnabled] = useState(true);
  const [seconds, setSeconds] = useState(60);
  const [secret, setSecret] = useState('');
  const [secretError, setSecretError] = useState<string | null>(null);
  const [saveError, setSaveError] = useState<string | null>(null);
  const [prevConfig, setPrevConfig] = useState(config);
  // Re-seed the editable fields when the stored settings load or change.
  if (config !== prevConfig) {
    setPrevConfig(config);
    setPollEnabled(Boolean(config?.poll_enabled));
    setSeconds(config?.interval_seconds ?? 60);
  }

  const minSeconds = data?.min_interval_seconds ?? 30;
  const maxSeconds = data?.max_interval_seconds ?? 3600;
  const receiverUrl = `${window.location.origin}${data?.webhook_path ?? '/api/webhooks/meraki'}`;
  const pollDirty = config !== null && (pollEnabled !== config.poll_enabled || seconds !== config.interval_seconds);

  async function update(body: MerakiAlertSettingsUpdate): Promise<boolean> {
    setSaveError(null);
    try {
      await save.mutateAsync(body);
      return true;
    } catch (err) {
      setSaveError(`Could not save the Meraki alert settings: ${err instanceof Error ? err.message : String(err)}`);
      return false;
    }
  }

  async function handleSaveSecret() {
    if (secret.length < SECRET_MIN || secret !== secret.trim()) {
      setSecretError(`Use at least ${SECRET_MIN} characters with no leading or trailing spaces.`);
      return;
    }
    if (await update({ webhook_secret: secret })) setSecret('');
  }

  async function handleClearSecret() {
    const ok = await confirm({
      title: 'Clear webhook secret',
      message:
        'The receiver will answer 404 to every delivery until a new secret is set. Meraki disables an HTTP server ' +
        'whose deliveries keep failing, so remove it from the Meraki dashboard too if you are not setting a new one.',
      confirmLabel: 'Clear Secret',
    });
    if (ok) await update({ clear_webhook_secret: true });
  }

  function toggleSource(id: number, polled: boolean) {
    const excluded = new Set(config?.excluded_sources ?? []);
    if (polled) excluded.delete(id);
    else excluded.add(id);
    void update({ excluded_sources: [...excluded] });
  }

  if (settings.error && !data) return <QueryError what="the Meraki alert settings" query={settings} />;

  return (
    <details className="card card-sm">
      <summary style={{ cursor: 'pointer' }}>
        Meraki alerts{' '}
        <span className="text-muted" style={{ fontSize: '0.85em' }}>
          {config
            ? `poll ${config.poll_enabled ? `every ${config.interval_seconds}s` : 'off'}, webhook ${data?.webhook_active ? 'on' : 'off'}`
            : 'loading…'}
        </span>
      </summary>

      <div className="stack stack-sm" style={{ marginTop: '0.75rem' }}>
        {saveError && <Callout tone="danger">{saveError}</Callout>}

        <div style={{ display: 'flex', gap: '1rem', alignItems: 'center', flexWrap: 'wrap' }}>
          <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', margin: 0 }}>
            <input type="checkbox" checked={pollEnabled} disabled={!config} onChange={(e) => setPollEnabled(e.target.checked)} />
            Poll assurance alerts
          </label>
          <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', margin: 0 }}>
            Every
            <input
              className="form-input"
              type="number"
              style={{ width: '6rem' }}
              min={minSeconds}
              max={maxSeconds}
              value={seconds}
              disabled={!config}
              onChange={(e) => setSeconds(parseInt(e.target.value, 10) || minSeconds)}
            />
            seconds
          </label>
          <BusyButton
            className="btn btn-secondary btn-sm"
            busy={save.isPending}
            disabled={!pollDirty}
            onClick={() => void update({ poll_enabled: pollEnabled, interval_seconds: seconds })}
          >
            Save
          </BusyButton>
          <BusyButton className="btn btn-secondary btn-sm" busy={poll.isPending} busyLabel="Polling…" onClick={() => poll.mutate()}>
            Poll Now
          </BusyButton>
        </div>
        <div className="text-muted" style={{ fontSize: '0.85em' }}>
          One API call per organization per poll ({minSeconds} to {maxSeconds} seconds), outbound only. Last poll:{' '}
          {formatBackendDateTime(data?.status.last_poll_at || null)}
          {data?.status.last_poll_error ? ` (${data.status.last_poll_error})` : ''}.
        </div>

        {(data?.sources.length ?? 0) > 0 && (
          <table className="data-table">
            <thead>
              <tr>
                <th>Poll</th>
                <th>Organization</th>
                <th>Last success</th>
                <th>Last error</th>
              </tr>
            </thead>
            <tbody>
              {data?.sources.map((s) => (
                <tr key={s.id}>
                  <td>
                    <input
                      type="checkbox"
                      aria-label={`Poll Meraki alerts of ${s.name}`}
                      checked={!s.excluded}
                      disabled={save.isPending}
                      onChange={(e) => toggleSource(s.id, e.target.checked)}
                    />
                  </td>
                  <td>
                    {s.name}
                    {!s.has_api_key && <span className="text-muted" style={{ fontSize: '0.85em' }}> no API key</span>}
                  </td>
                  <td style={{ whiteSpace: 'nowrap' }}>{formatBackendDateTime(s.last_ok_at || null)}</td>
                  <td>{s.last_error || '-'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}

        <h4 style={{ margin: '0.5rem 0 0' }}>Webhook receiver</h4>
        <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center', flexWrap: 'wrap' }}>
          <code style={{ wordBreak: 'break-all' }}>{receiverUrl}</code>
          <CopyButton text={receiverUrl} label="Copy URL" />
        </div>
        <div className="text-muted" style={{ fontSize: '0.85em' }}>
          Paste this as the HTTP server URL in the Meraki dashboard (Network-wide &gt; Alerts). It must be the publicly
          reachable HTTPS address of Plexus with a publicly trusted certificate; Meraki cannot reach an internal URL.
          The receiver answers 404 until a shared secret is set.
        </div>

        <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'flex-start', flexWrap: 'wrap' }}>
          <div style={{ flex: '1 1 18rem' }}>
            <label className="form-label" htmlFor="meraki-webhook-secret">
              Shared secret {config?.webhook_secret_configured ? '(set; enter a new one to rotate)' : '(not set)'}
            </label>
            <input
              id="meraki-webhook-secret"
              className="form-input"
              type="text"
              autoComplete="off"
              spellCheck={false}
              value={secret}
              aria-invalid={!!secretError}
              onChange={(e) => { setSecret(e.target.value); setSecretError(null); }}
            />
            {secretError && <FieldError>{secretError}</FieldError>}
          </div>
          <div style={{ display: 'flex', gap: '0.5rem', alignSelf: 'flex-end', flexWrap: 'wrap' }}>
            <button type="button" className="btn btn-secondary btn-sm" onClick={() => { setSecret(randomSecret()); setSecretError(null); }}>
              Generate
            </button>
            {secret && <CopyButton text={secret} />}
            <BusyButton className="btn btn-primary btn-sm" busy={save.isPending} disabled={!secret} onClick={() => void handleSaveSecret()}>
              {config?.webhook_secret_configured ? 'Rotate Secret' : 'Set Secret'}
            </BusyButton>
            {config?.webhook_secret_configured && (
              <>
                <BusyButton
                  className="btn btn-secondary btn-sm"
                  busy={save.isPending}
                  onClick={() => void update({ webhook_enabled: !config.webhook_enabled })}
                >
                  {config.webhook_enabled ? 'Turn Off' : 'Turn On'}
                </BusyButton>
                <BusyButton className="btn btn-danger btn-sm" busy={save.isPending} onClick={() => void handleClearSecret()}>
                  Clear Secret
                </BusyButton>
              </>
            )}
          </div>
        </div>
        <div className="text-muted" style={{ fontSize: '0.85em' }}>
          Copy the secret before saving: it is stored encrypted and never shown again. Enter the same value as the
          shared secret of the HTTP server in Meraki. Receiver {data?.webhook_active ? 'on' : 'off'}. Last delivery:{' '}
          {formatBackendDateTime(data?.status.last_webhook_at || null)}; last test webhook:{' '}
          {formatBackendDateTime(data?.status.last_test_at || null)}; rejected (wrong secret):{' '}
          {data?.status.webhooks_rejected ?? 0}; for organizations with no source here:{' '}
          {data?.status.unknown_org_events ?? 0}
          {data?.status.last_webhook_error ? `; last error: ${data.status.last_webhook_error}` : ''}.
        </div>
      </div>
    </details>
  );
}
