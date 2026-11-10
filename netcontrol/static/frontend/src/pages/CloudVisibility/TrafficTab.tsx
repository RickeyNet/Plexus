import { useEffect, useRef, useState } from 'react';

import {
  type CloudPullResult,
  useCloudTrafficMetricSummary,
  useCloudTrafficMetricTimeline,
  useCloudTrafficMetricTopResources,
  useCloudTrafficSyncConfig,
  useCloudTrafficSyncCursors,
  useTriggerCloudTrafficPull,
  useUpdateCloudTrafficSyncConfig,
} from '@/api/cloud';
import { Callout } from '@/components/Callout';
import { LoadingState } from '@/components/LoadingState';
import { StatGrid, StatTile } from '@/components/StatTile';
import { formatBackendDateTime, formatBackendTime } from '@/lib/datetime';
import type { CloudFilterState } from './CloudVisibility';
import { formatCount, formatMetricValue, pullOutcome } from './helpers';
import { SyncControls } from './SyncControls';

interface Props {
  filter: CloudFilterState;
}

export function TrafficTab({ filter }: Props) {
  const [hours, setHours] = useState(24);
  const [limit, setLimit] = useState(20);
  const [bucketMinutes, setBucketMinutes] = useState(5);
  const [actionMsg, setActionMsg] = useState<{ kind: 'success' | 'error'; text: string } | null>(null);

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

  function flash(kind: 'success' | 'error', text: string) {
    setActionMsg({ kind, text });
    if (flashTimerRef.current) clearTimeout(flashTimerRef.current);
    flashTimerRef.current = setTimeout(() => {
      flashTimerRef.current = null;
      setActionMsg(null);
    }, 8000);
  }

  function showPull(label: string, r: CloudPullResult | undefined) {
    const outcome = pullOutcome(label, r);
    flash(outcome.kind, outcome.text);
  }

  return (
    <div className="stack">
      <div className="card card-sm">
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

      <div className="stack stack-sm">
        <h3 style={{ margin: 0 }}>Traffic Sync Controls</h3>
        <SyncControls
          kind="Traffic"
          config={syncConfig.data?.config ?? null}
          status={syncConfig.data?.status ?? null}
          cursors={syncCursors.data?.cursors ?? []}
          selectedAccountId={filter.accountId}
          isSaving={updateConfig.isPending}
          isPulling={triggerPull.isPending}
          onSave={async (cfg) => {
            try {
              await updateConfig.mutateAsync(cfg);
              flash('success', 'Cloud traffic sync config saved');
            } catch (e) {
              flash('error', `Saving traffic sync config failed: ${(e as Error).message}`);
            }
          }}
          onPullAll={async () => {
            try {
              showPull('Traffic pull', await triggerPull.mutateAsync(null));
            } catch (e) {
              flash('error', `Traffic pull failed: ${(e as Error).message}`);
            }
          }}
          onPullSelected={async () => {
            if (!filter.accountId) return;
            try {
              showPull('Traffic pull (selected account)', await triggerPull.mutateAsync(filter.accountId));
            } catch (e) {
              flash('error', `Traffic pull failed: ${(e as Error).message}`);
            }
          }}
        />
      </div>
      {actionMsg && (
        <Callout tone={actionMsg.kind === 'success' ? 'success' : 'danger'}>{actionMsg.text}</Callout>
      )}

      <div className="stack stack-sm">
        <h3 style={{ margin: 0 }}>
          Cloud Traffic Metrics
          {summary.dataUpdatedAt > 0 && (
            <small className="text-muted" style={{ marginLeft: '0.6rem', fontWeight: 400 }}>
              Updated {formatBackendTime(summary.dataUpdatedAt)}
            </small>
          )}
        </h3>
        {summary.isPending && <LoadingState />}
        {summary.error && <div style={{ color: 'var(--danger)' }}>Error: {(summary.error as Error).message}</div>}
        <StatGrid compact>
          <StatTile label="Samples" value={formatCount(s.sample_count)} />
          <StatTile label="Metric Names" value={formatCount(s.metric_count)} />
          <StatTile label="Resources" value={formatCount(s.resource_count)} />
          <StatTile label="Total Value" value={formatMetricValue(s.total_value)} />
          <StatTile label="Average Value" value={formatMetricValue(s.avg_value)} />
          <StatTile label="Last Seen" value={formatBackendDateTime(s.last_seen)} />
        </StatGrid>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: 'var(--space-4)' }}>
        <div>
          <h4 style={{ margin: '0 0 0.45rem' }}>Top Resources</h4>
          {resources.isPending ? (
            <div className="card"><LoadingState variant="inline" /></div>
          ) : resources.error ? (
            <div className="card"><p style={{ margin: 0, color: 'var(--danger)' }}>Failed to load top resources: {(resources.error as Error).message}</p></div>
          ) : !rList.length ? (
            <div className="card"><p className="text-muted" style={{ margin: 0 }}>No traffic metric resources for current filters.</p></div>
          ) : (
            <div style={{ overflowX: 'auto' }}>
              <table className="data-table">
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
          {timeline.isPending ? (
            <div className="card"><LoadingState variant="inline" /></div>
          ) : timeline.error ? (
            <div className="card"><p style={{ margin: 0, color: 'var(--danger)' }}>Failed to load timeline: {(timeline.error as Error).message}</p></div>
          ) : !tlList.length ? (
            <div className="card"><p className="text-muted" style={{ margin: 0 }}>No timeline data available for current filters.</p></div>
          ) : (
            <div style={{ overflowX: 'auto' }}>
              <table className="data-table">
                <thead>
                  <tr><th>Bucket</th><th>Total Value</th><th>Average</th><th>Samples</th></tr>
                </thead>
                <tbody>
                  {tlList.map((row, i) => (
                    <tr key={i}>
                      <td>{formatBackendDateTime(row.bucket)}</td>
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

