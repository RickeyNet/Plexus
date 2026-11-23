import { useState } from 'react';

import {
  usePollVendorAlerts,
  useUpdateVendorAlertSettings,
  useVendorAlertSettings,
  type VendorAlertSettingsUpdate,
} from '@/api/vendorAlerts';
import { Callout } from '@/components/Callout';
import { QueryError } from '@/components/QueryError';
import { feedStatusText } from '@/pages/Monitoring/alertFeed';
import { vendorAlertFeedText } from '@/pages/Monitoring/vendorAlertFeeds';

import { AlertFeedPollSettings } from './AlertFeedPollSettings';

/**
 * One vendor alert feed's settings (administrators only): the poll of each
 * source, its per-source opt-out and status, the parts that can be switched
 * off (AWS, Azure) and whether IPS events are kept (Cato). Mounted under
 * Topology > Sources for Cato and under Cloud Visibility for AWS and Azure.
 * See docs/cato-alerts.md and docs/cloud-alerts.md.
 */
export function VendorAlertsSettings({ provider }: { provider: string }) {
  const settings = useVendorAlertSettings(provider, true);
  const save = useUpdateVendorAlertSettings(provider);
  const poll = usePollVendorAlerts(provider);
  const [saveError, setSaveError] = useState<string | null>(null);
  const text = vendorAlertFeedText(provider);
  const data = settings.data ?? null;
  const config = data?.config ?? null;
  const parts = data?.parts ?? [];

  async function update(body: VendorAlertSettingsUpdate): Promise<boolean> {
    setSaveError(null);
    try {
      await save.mutateAsync(body);
      return true;
    } catch (err) {
      setSaveError(`Could not save the ${text.title} settings: ${err instanceof Error ? err.message : String(err)}`);
      return false;
    }
  }

  function togglePart(key: string, enabled: boolean) {
    const off = new Set(config?.disabled_parts ?? []);
    if (enabled) off.delete(key);
    else off.add(key);
    void update({ disabled_parts: [...off] });
  }

  if (settings.error && !data) return <QueryError what={`the ${text.title} settings`} query={settings} />;

  return (
    <details className="card card-sm">
      <summary style={{ cursor: 'pointer' }}>
        {text.title}{' '}
        <span className="text-muted" style={{ fontSize: '0.85em' }}>
          {config ? `${config.poll_enabled ? `every ${config.interval_seconds}s` : 'off'}` : 'loading…'}
        </span>
      </summary>

      <div className="stack stack-sm" style={{ marginTop: '0.75rem' }}>
        {saveError && <Callout tone="danger">{saveError}</Callout>}
        {data?.description && (
          <div className="text-muted" style={{ fontSize: '0.85em' }}>
            {data.description}
          </div>
        )}
        <AlertFeedPollSettings
          config={config}
          minSeconds={data?.min_interval_seconds ?? 30}
          maxSeconds={data?.max_interval_seconds ?? 3600}
          lastPollAt={data?.status.last_poll_at ?? ''}
          lastPollError={data?.status.last_poll_error ?? ''}
          sources={(data?.sources ?? []).map((s) => ({ ...s, status: feedStatusText(s.feed_status) }))}
          saving={save.isPending}
          polling={poll.isPending}
          onUpdate={update}
          onPoll={() => poll.mutate()}
          pollLabel={text.pollLabel}
          costNote={text.costNote}
          sourceHeading={text.sourceHeading}
          vendor={text.vendor}
        />
        {parts.map((part) => (
          <label key={part.key} style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', margin: 0 }}>
            <input
              type="checkbox"
              checked={part.enabled}
              disabled={!config || save.isPending}
              onChange={(e) => togglePart(part.key, e.target.checked)}
            />
            {part.label}
          </label>
        ))}
        {text.securityEvents && (
          <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', margin: 0 }}>
            <input
              type="checkbox"
              checked={Boolean(config?.security_events)}
              disabled={!config || save.isPending}
              onChange={(e) => void update({ security_events: e.target.checked })}
            />
            Keep IPS events as security events
          </label>
        )}
      </div>
    </details>
  );
}
