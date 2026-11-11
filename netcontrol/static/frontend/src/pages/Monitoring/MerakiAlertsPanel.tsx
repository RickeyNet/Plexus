import { useState } from 'react';

import { useAuthStatus } from '@/api/auth';
import { useMerakiAlerts, usePollMerakiAlerts } from '@/api/merakiAlerts';
import { SeverityBadge } from '@/components/Badge';
import { BusyButton } from '@/components/BusyButton';
import { useDialogs } from '@/components/DialogProvider-context';
import { LoadingState } from '@/components/LoadingState';
import { QueryError } from '@/components/QueryError';
import { formatBackendDateTime } from '@/lib/datetime';

const VIA_LABELS: Record<string, string> = {
  monitoring: 'Host alert',
  notification: 'Notified',
  topology: 'Already notified (availability)',
};

/**
 * Meraki alerts from the assurance-alert poll and the webhook receiver,
 * deduplicated across both. Raised on the server like other monitoring
 * alerts; the poll and webhook settings are under Topology > Sources.
 */
export function MerakiAlertsPanel() {
  const [includeResolved, setIncludeResolved] = useState(false);
  const alerts = useMerakiAlerts(includeResolved);
  const poll = usePollMerakiAlerts();
  const { data: auth } = useAuthStatus();
  const { alert } = useDialogs();
  const rows = alerts.data?.alerts ?? [];

  function handlePoll() {
    poll.mutate(undefined, {
      onSuccess: (r) => {
        const text = r.ok
          ? `Polled ${r.polled} organization(s): ${r.new ?? 0} new, ${r.resolved ?? 0} resolved.`
          : r.error
            ? `Poll failed: ${r.error}.`
            : `Polled ${r.polled} organization(s); ${r.failed ?? 0} failed. See Topology > Sources for the error.`;
        void alert(text);
      },
      onError: (e) => { void alert({ message: e.message, variant: 'error' }); },
    });
  }

  return (
    <div style={{ marginTop: '1.5rem' }}>
      <h3 style={{ marginBottom: '0.5rem' }}>Meraki alerts</h3>
      <p className="text-muted" style={{ marginTop: 0, fontSize: '0.85em' }}>
        Alerts from the Meraki dashboard, polled every minute and, when the webhook receiver is set up, pushed as they
        happen. The same alert from both paths is one row; it closes when Meraki resolves it.
      </p>
      <div className="toolbar">
        <label className="text-muted" style={{ display: 'flex', gap: '0.3rem', alignItems: 'center' }}>
          <input type="checkbox" checked={includeResolved} onChange={(e) => setIncludeResolved(e.target.checked)} />
          Show resolved
        </label>
        {auth?.role === 'admin' && (
          <BusyButton className="btn btn-sm btn-secondary" busy={poll.isPending} busyLabel="Polling…" onClick={handlePoll}>
            Poll Now
          </BusyButton>
        )}
      </div>

      {alerts.error && !alerts.data ? (
        <QueryError what="Meraki alerts" query={alerts} />
      ) : alerts.isPending ? (
        <LoadingState />
      ) : !rows.length ? (
        <div className="empty-state">No Meraki alerts - add a Meraki organization with an API key under Topology.</div>
      ) : (
        <div style={{ maxHeight: 520, overflow: 'auto' }}>
          <table className="data-table">
            <thead>
              <tr>
                <th>Severity</th>
                <th>Alert</th>
                <th>Device / network</th>
                <th>Organization</th>
                <th>Started</th>
                <th>Last seen</th>
                <th>Via</th>
                <th>Plexus</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((a) => (
                <tr key={a.alert_key} style={a.status === 'resolved' ? { opacity: 0.6 } : undefined}>
                  <td>
                    <SeverityBadge severity={a.severity} />
                    {a.status === 'resolved' && <span className="text-muted" style={{ fontSize: '0.8em', marginLeft: '0.3rem' }}>resolved</span>}
                  </td>
                  <td style={{ minWidth: 220 }}>
                    {a.title}
                    {a.message && a.message !== a.title && (
                      <div className="text-muted" style={{ fontSize: '0.85em' }}>{a.message}</div>
                    )}
                  </td>
                  <td>
                    {a.device_name || a.device_serial || '-'}
                    <span className="text-muted" style={{ fontSize: '0.85em' }}> {a.network_name}</span>
                  </td>
                  <td>{a.org_name || a.org_ref}</td>
                  <td style={{ whiteSpace: 'nowrap' }}>{formatBackendDateTime(a.started_at)}</td>
                  <td style={{ whiteSpace: 'nowrap' }}>
                    {formatBackendDateTime(a.status === 'resolved' ? a.resolved_at : a.last_seen)}
                  </td>
                  <td>{a.seen_via.join(', ')}</td>
                  <td style={{ fontSize: '0.85em' }}>{VIA_LABELS[a.alert_via] ?? (a.severity === 'info' ? 'Listed only' : '-')}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
