import { useMemo, useState } from 'react';

import { Badge, SeverityBadge } from '@/components/Badge';
import { useDialogs } from '@/components/DialogProvider-context';
import {
  useAcknowledgeAlert,
  useBulkAcknowledgeAlerts,
  useMonitoringAlerts,
  type MonitoringAlert,
} from '@/api/monitoring';
import { LoadingState } from '@/components/LoadingState';
import { formatBackendDateTime } from '@/lib/datetime';
import { severityTone, toneColor } from '@/lib/severity';
import { RouteSnapshotsModal } from './RouteSnapshotsModal';

// Route churn used to be its own tab; it is the alert list filtered to this
// metric, plus a per-host route history action.
const ROUTE_CHURN = 'route_churn';

export function AlertsTab() {
  const { alert } = useDialogs();
  const [severity, setSeverity] = useState('');
  const [ackFilter, setAckFilter] = useState<'all' | 'open' | 'ack'>('open');
  const [query, setQuery] = useState('');
  const [routeChurnOnly, setRouteChurnOnly] = useState(false);
  const [selected, setSelected] = useState<Set<number>>(new Set());
  const [historyHost, setHistoryHost] = useState<{ id: number; hostname: string } | null>(null);

  const ackParam = ackFilter === 'open' ? false : ackFilter === 'ack' ? true : null;
  const alerts = useMonitoringAlerts({ acknowledged: ackParam, severity: severity || undefined, limit: 200 });
  const ackMut = useAcknowledgeAlert();
  const bulkMut = useBulkAcknowledgeAlerts();

  const filtered = useMemo(() => {
    let list = alerts.data ?? [];
    if (routeChurnOnly) list = list.filter((a) => a.metric === ROUTE_CHURN);
    const q = query.trim().toLowerCase();
    if (!q) return list;
    return list.filter(
      (a) =>
        (a.hostname ?? '').toLowerCase().includes(q) ||
        (a.message ?? '').toLowerCase().includes(q) ||
        (a.metric ?? '').toLowerCase().includes(q),
    );
  }, [alerts.data, query, routeChurnOnly]);

  const unackedIds = useMemo(() => filtered.filter((a) => !a.acknowledged).map((a) => a.id), [filtered]);
  const visibleSelected = useMemo(() => {
    const set = new Set(unackedIds);
    return [...selected].filter((id) => set.has(id));
  }, [selected, unackedIds]);

  function toggleSelect(id: number, checked: boolean) {
    setSelected((prev) => {
      const next = new Set(prev);
      if (checked) next.add(id);
      else next.delete(id);
      return next;
    });
  }

  function toggleSelectAll(checked: boolean) {
    setSelected(checked ? new Set(unackedIds) : new Set());
  }

  function bulkAck(ids: number[]) {
    if (!ids.length) return;
    bulkMut.mutate(ids, {
      onSuccess: () => setSelected(new Set()),
      onError: (e) => { void alert({ message: (e as Error).message, variant: 'error' }); },
    });
  }

  return (
    <div>
      <div className="toolbar">
        <input
          className="form-input form-input-sm"
          placeholder="Search alerts…"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          style={{ flex: 1, minWidth: 200 }}
        />
        <select className="form-select form-select-sm" value={severity} onChange={(e) => setSeverity(e.target.value)}>
          <option value="">All severities</option>
          <option value="critical">Critical</option>
          <option value="warning">Warning</option>
          <option value="info">Info</option>
        </select>
        <select className="form-select form-select-sm" value={ackFilter} onChange={(e) => setAckFilter(e.target.value as 'all' | 'open' | 'ack')}>
          <option value="open">Unacknowledged</option>
          <option value="ack">Acknowledged</option>
          <option value="all">All</option>
        </select>
        <button
          type="button"
          className={`btn btn-sm ${routeChurnOnly ? 'btn-primary' : 'btn-ghost'}`}
          aria-pressed={routeChurnOnly}
          onClick={() => setRouteChurnOnly((v) => !v)}
        >
          Route churn
        </button>
      </div>

      {alerts.isPending && <LoadingState />}
      {alerts.error && <div style={{ color: 'var(--danger)' }}>Error: {(alerts.error as Error).message}</div>}
      {alerts.data && filtered.length === 0 && (
        <div className="empty-state">
          {routeChurnOnly
            ? 'No route churn alerts. They are generated when a route table changes between polling cycles.'
            : 'No alerts'}
        </div>
      )}

      {unackedIds.length > 0 && (
        <div className="toolbar">
          <label style={{ display: 'flex', alignItems: 'center', gap: '0.3rem', cursor: 'pointer', fontSize: '0.9em' }}>
            <input
              type="checkbox"
              checked={visibleSelected.length > 0 && visibleSelected.length === unackedIds.length}
              onChange={(e) => toggleSelectAll(e.target.checked)}
            />
            Select all ({unackedIds.length})
          </label>
          <button
            className="btn btn-sm btn-primary"
            disabled={visibleSelected.length === 0 || bulkMut.isPending}
            onClick={() => bulkAck(visibleSelected)}
          >
            Acknowledge Selected ({visibleSelected.length})
          </button>
          <button
            className="btn btn-sm btn-secondary"
            disabled={bulkMut.isPending}
            onClick={() => bulkAck(unackedIds)}
          >
            Acknowledge All ({unackedIds.length})
          </button>
        </div>
      )}

      <div style={{ display: 'flex', flexDirection: 'column', gap: '0.4rem' }}>
        {filtered.map((a) => (
          <AlertRow
            key={a.id}
            alert={a}
            checked={selected.has(a.id)}
            onToggle={(c) => toggleSelect(a.id, c)}
            onAck={() => ackMut.mutate(a.id, { onError: (e) => { void alert({ message: (e as Error).message, variant: 'error' }); } })}
            onRouteHistory={
              a.metric === ROUTE_CHURN
                ? () => setHistoryHost({ id: a.host_id, hostname: a.hostname ?? '' })
                : undefined
            }
          />
        ))}
      </div>

      {historyHost && (
        <RouteSnapshotsModal
          hostId={historyHost.id}
          hostname={historyHost.hostname}
          onClose={() => setHistoryHost(null)}
        />
      )}
    </div>
  );
}

function AlertRow({
  alert,
  checked,
  onToggle,
  onAck,
  onRouteHistory,
}: {
  alert: MonitoringAlert;
  checked: boolean;
  onToggle: (checked: boolean) => void;
  onAck: () => void;
  /** Set for route_churn alerts: opens the host's route-table history. */
  onRouteHistory?: () => void;
}) {
  const occurrences = alert.occurrence_count ?? 1;
  return (
    <div className="card card-sm" style={{ borderLeft: `3px solid ${toneColor(severityTone(alert.severity))}` }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '0.4rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
          {!alert.acknowledged && (
            <input type="checkbox" checked={checked} onChange={(e) => onToggle(e.target.checked)} />
          )}
          <SeverityBadge severity={alert.severity} />
          {alert.escalated && (
            <Badge tone="danger" solid size="sm">
              Escalated
            </Badge>
          )}
          {occurrences > 1 && (
            <Badge size="sm" title={`Seen ${occurrences} times`}>
              {occurrences}x
            </Badge>
          )}
          <strong>{alert.hostname}</strong>
          <span className="text-muted" style={{ fontSize: '0.85em' }}>{alert.metric}</span>
        </div>
        <div style={{ display: 'flex', gap: '0.4rem', alignItems: 'center' }}>
          {onRouteHistory && (
            <button className="btn btn-sm btn-secondary" onClick={onRouteHistory}>Route history</button>
          )}
          {alert.acknowledged ? (
            <span style={{ color: 'var(--success)', fontSize: '0.8em' }}>
              Acknowledged{alert.acknowledged_by ? ` by ${alert.acknowledged_by}` : ''}
            </span>
          ) : (
            <button className="btn btn-sm btn-secondary" onClick={onAck}>Acknowledge</button>
          )}
        </div>
      </div>
      <div style={{ marginTop: '0.3rem', fontSize: '0.9em' }}>{alert.message}</div>
      <div className="text-muted" style={{ marginTop: '0.2rem', fontSize: '0.8em' }}>
        Created: {formatBackendDateTime(alert.created_at)}
        {occurrences > 1 && ` · Last seen: ${formatBackendDateTime(alert.last_seen_at)}`}
        {alert.rule_id ? ` · Rule #${alert.rule_id}` : ''}
      </div>
    </div>
  );
}
