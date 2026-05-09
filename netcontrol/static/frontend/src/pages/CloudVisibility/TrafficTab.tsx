import { useEffect, useRef, useState } from 'react';

import {
  useCloudTrafficMetricSummary,
  useCloudTrafficMetricTimeline,
  useCloudTrafficMetricTopResources,
  useCloudTrafficSyncConfig,
  useCloudTrafficSyncCursors,
  useTriggerCloudTrafficPull,
  useUpdateCloudTrafficSyncConfig,
} from '@/api/cloud';
import type { CloudFilterState } from './CloudVisibility';
import { formatCount, formatMetricValue, formatTimestamp } from './helpers';
import { SyncControls } from './SyncControls';

interface Props {
  filter: CloudFilterState;
}

export function TrafficTab({ filter }: Props) {
  const [hours, setHours] = useState(24);
  const [limit, setLimit] = useState(20);
  const [bucketMinutes, setBucketMinutes] = useState(5);
  const [actionMsg, setActionMsg] = useState<string | null>(null);

  const params = {
    provider: filter.provider || undefined,
    account_id: filter.accountId,
    hours,
    limit,
    bucket_minutes: bucketMinutes,
  };

  const summary = useCloudTrafficMetricSummary(params);
  const resources = useCloudTrafficMetricTopResources(params);
  const timeline = useCloudTrafficMetricTimeline(params);
  const syncConfig = useCloudTrafficSyncConfig();
  const syncCursors = useCloudTrafficSyncCursors();
  const updateConfig = useUpdateCloudTrafficSyncConfig();
  const triggerPull = useTriggerCloudTrafficPull();

  const s = summary.data?.summary ?? {};
  const rList = resources.data?.resources ?? [];
  const tlList = timeline.data?.timeline ?? [];

  const flashTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  useEffect(() => () => {
    if (flashTimerRef.current) clearTimeout(flashTimerRef.current);
  }, []);

  function flash(msg: string) {
    setActionMsg(msg);
    if (flashTimerRef.current) clearTimeout(flashTimerRef.current);
    flashTimerRef.current = setTimeout(() => {
      flashTimerRef.current = null;
      setActionMsg(null);
    }, 6000);
  }

  return (
    <div>
      <div className="card" style={{ padding: '0.75rem', marginBottom: '0.75rem' }}>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '0.75rem' }}>
          <label>Window
            <select className="form-select" value={hours} onChange={(e) => setHours(parseInt(e.target.value, 10))}>
              <option value={1}>Last 1 hour</option>
              <option value={6}>Last 6 hours</option>
              <option value={24}>Last 24 hours</option>
              <option value={72}>Last 72 hours</option>
              <option value={168}>Last 7 days</option>
            </select>
          </label>
          <label>Resource Limit
            <input className="form-input" type="number" min={5} max={200} value={limit} onChange={(e) => setLimit(parseInt(e.target.value, 10) || 20)} />
          </label>
          <label>Timeline Bucket
            <select className="form-select" value={bucketMinutes} onChange={(e) => setBucketMinutes(parseInt(e.target.value, 10))}>
              <option value={1}>1 minute</option>
              <option value={5}>5 minutes</option>
              <option value={15}>15 minutes</option>
              <option value={30}>30 minutes</option>
              <option value={60}>60 minutes</option>
            </select>
          </label>
        </div>
      </div>

      <h3 style={{ margin: '0.25rem 0 0.5rem' }}>Traffic Sync Controls</h3>
      <SyncControls
        kind="Traffic"
        config={syncConfig.data?.config ?? null}
        status={syncConfig.data?.status ?? null}
        cursors={syncCursors.data?.cursors ?? []}
        selectedAccountId={filter.accountId}
        isSaving={updateConfig.isPending}
        isPulling={triggerPull.isPending}
        onSave={async (cfg) => {
          await updateConfig.mutateAsync(cfg);
          flash('Cloud traffic sync config saved');
        }}
        onPullAll={async () => {
          const r = await triggerPull.mutateAsync(null);
          flash(`Traffic pull complete: ${Number(r?.ingested ?? r?.total_ingested ?? 0).toLocaleString()} ingested`);
        }}
        onPullSelected={async () => {
          if (!filter.accountId) return;
          const r = await triggerPull.mutateAsync(filter.accountId);
          flash(`Traffic pull complete for selected account: ${Number(r?.ingested ?? r?.total_ingested ?? 0).toLocaleString()} ingested`);
        }}
      />
      {actionMsg && (
        <div className="card" style={{ padding: '0.6rem 0.85rem', marginBottom: '0.6rem', borderLeft: '3px solid var(--success)' }}>
          {actionMsg}
        </div>
      )}

      <h3 style={{ margin: '0.25rem 0 0.5rem' }}>Cloud Traffic Metrics</h3>
      {summary.isPending && <div className="text-muted">Loading…</div>}
      {summary.error && <div style={{ color: 'var(--danger)' }}>Error: {(summary.error as Error).message}</div>}
      <div className="drift-summary-grid" style={{ marginBottom: '1rem' }}>
        <Card label="Samples" value={formatCount(s.sample_count)} />
        <Card label="Metric Names" value={formatCount(s.metric_count)} />
        <Card label="Resources" value={formatCount(s.resource_count)} />
        <Card label="Total Value" value={formatMetricValue(s.total_value)} />
        <Card label="Average Value" value={formatMetricValue(s.avg_value)} />
        <Card label="Last Seen" value={formatTimestamp(s.last_seen)} small />
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: '1rem', marginBottom: '1rem' }}>
        <div>
          <h4 style={{ margin: '0 0 0.45rem' }}>Top Resources</h4>
          {!rList.length ? (
            <div className="card" style={{ padding: '1rem' }}><p className="text-muted" style={{ margin: 0 }}>No traffic metric resources for current filters.</p></div>
          ) : (
            <div style={{ overflowX: 'auto' }}>
              <table className="chart-table">
                <thead>
                  <tr><th>Resource</th><th>Total Value</th><th>Average</th><th>Samples</th></tr>
                </thead>
                <tbody>
                  {rList.map((row, i) => (
                    <tr key={i}>
                      <td>{row.resource_uid || '-'}</td>
                      <td>{formatMetricValue(row.total_value)}</td>
                      <td>{formatMetricValue(row.avg_value)}</td>
                      <td>{formatCount(row.sample_count)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
        <div>
          <h4 style={{ margin: '0 0 0.45rem' }}>Metric Timeline</h4>
          {!tlList.length ? (
            <div className="card" style={{ padding: '1rem' }}><p className="text-muted" style={{ margin: 0 }}>No timeline data available for current filters.</p></div>
          ) : (
            <div style={{ overflowX: 'auto' }}>
              <table className="chart-table">
                <thead>
                  <tr><th>Bucket</th><th>Total Value</th><th>Average</th><th>Samples</th></tr>
                </thead>
                <tbody>
                  {tlList.map((row, i) => (
                    <tr key={i}>
                      <td>{formatTimestamp(row.bucket)}</td>
                      <td>{formatMetricValue(row.total_value)}</td>
                      <td>{formatMetricValue(row.avg_value)}</td>
                      <td>{formatCount(row.sample_count)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

function Card({ label, value, small }: { label: string; value: string | number; small?: boolean }) {
  return (
    <div className="drift-summary-card">
      <div className="drift-summary-value" style={small ? { fontSize: '1rem' } : undefined}>{value}</div>
      <div className="drift-summary-label">{label}</div>
    </div>
  );
}
