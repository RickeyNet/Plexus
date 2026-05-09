import { useEffect, useRef, useState } from 'react';

import {
  useCloudFlowSummary,
  useCloudFlowSyncConfig,
  useCloudFlowSyncCursors,
  useCloudFlowTimeline,
  useCloudFlowTopTalkers,
  useTriggerCloudFlowPull,
  useUpdateCloudFlowSyncConfig,
} from '@/api/cloud';
import type { CloudFilterState } from './CloudVisibility';
import { formatBytes, formatCount, formatTimestamp } from './helpers';
import { SyncControls } from './SyncControls';

interface Props {
  filter: CloudFilterState;
}

export function FlowTab({ filter }: Props) {
  const [hours, setHours] = useState(24);
  const [direction, setDirection] = useState<'src' | 'dst'>('src');
  const [limit, setLimit] = useState(20);
  const [bucketMinutes, setBucketMinutes] = useState(5);
  const [actionMsg, setActionMsg] = useState<string | null>(null);

  const params = {
    provider: filter.provider || undefined,
    account_id: filter.accountId,
    hours,
    direction,
    limit,
    bucket_minutes: bucketMinutes,
  };

  const summary = useCloudFlowSummary(params);
  const talkers = useCloudFlowTopTalkers(params);
  const timeline = useCloudFlowTimeline(params);
  const syncConfig = useCloudFlowSyncConfig();
  const syncCursors = useCloudFlowSyncCursors();
  const updateConfig = useUpdateCloudFlowSyncConfig();
  const triggerPull = useTriggerCloudFlowPull();

  const s = summary.data?.summary ?? {};
  const tList = talkers.data?.talkers ?? [];
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
          <label>Flow Hours
            <select className="form-select" value={hours} onChange={(e) => setHours(parseInt(e.target.value, 10))}>
              <option value={1}>Last 1 hour</option>
              <option value={6}>Last 6 hours</option>
              <option value={24}>Last 24 hours</option>
              <option value={72}>Last 72 hours</option>
              <option value={168}>Last 7 days</option>
            </select>
          </label>
          <label>Top Talkers
            <select className="form-select" value={direction} onChange={(e) => setDirection(e.target.value as 'src' | 'dst')}>
              <option value="src">Source IP</option>
              <option value="dst">Destination IP</option>
            </select>
          </label>
          <label>Talker Limit
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

      <h3 style={{ margin: '0.25rem 0 0.5rem' }}>Flow Sync Controls</h3>
      <SyncControls
        kind="Flow"
        config={syncConfig.data?.config ?? null}
        status={syncConfig.data?.status ?? null}
        cursors={syncCursors.data?.cursors ?? []}
        selectedAccountId={filter.accountId}
        isSaving={updateConfig.isPending}
        isPulling={triggerPull.isPending}
        onSave={async (cfg) => {
          await updateConfig.mutateAsync(cfg);
          flash('Cloud flow sync config saved');
        }}
        onPullAll={async () => {
          const r = await triggerPull.mutateAsync(null);
          flash(`Cloud flow pull complete: ${Number(r?.ingested ?? r?.total_ingested ?? 0).toLocaleString()} ingested`);
        }}
        onPullSelected={async () => {
          if (!filter.accountId) return;
          const r = await triggerPull.mutateAsync(filter.accountId);
          flash(`Cloud flow pull complete for selected account: ${Number(r?.ingested ?? r?.total_ingested ?? 0).toLocaleString()} ingested`);
        }}
      />
      {actionMsg && (
        <div className="card" style={{ padding: '0.6rem 0.85rem', marginBottom: '0.6rem', borderLeft: '3px solid var(--success)' }}>
          {actionMsg}
        </div>
      )}

      <h3 style={{ margin: '0.25rem 0 0.5rem' }}>Cloud Flow Analytics</h3>
      {summary.isPending && <div className="text-muted">Loading…</div>}
      {summary.error && <div style={{ color: 'var(--danger)' }}>Error: {(summary.error as Error).message}</div>}
      <div className="drift-summary-grid" style={{ marginBottom: '1rem' }}>
        <Card label="Flows" value={formatCount(s.flow_count)} />
        <Card label="Total Bytes" value={formatBytes(s.total_bytes)} />
        <Card label="Total Packets" value={formatCount(s.total_packets)} />
        <Card label="Unique Sources" value={formatCount(s.unique_sources)} />
        <Card label="Unique Destinations" value={formatCount(s.unique_destinations)} />
        <Card label="Last Seen" value={formatTimestamp(s.last_seen)} small />
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: '1rem', marginBottom: '1rem' }}>
        <div>
          <h4 style={{ margin: '0 0 0.45rem' }}>Top Talkers</h4>
          {!tList.length ? (
            <div className="card" style={{ padding: '1rem' }}><p className="text-muted" style={{ margin: 0 }}>No flow talkers found for current filters.</p></div>
          ) : (
            <div style={{ overflowX: 'auto' }}>
              <table className="chart-table">
                <thead>
                  <tr><th>{direction === 'dst' ? 'Destination IP' : 'Source IP'}</th><th>Bytes</th><th>Packets</th><th>Flows</th></tr>
                </thead>
                <tbody>
                  {tList.map((row, i) => (
                    <tr key={i}>
                      <td>{row.ip || '-'}</td>
                      <td>{formatBytes(row.total_bytes)}</td>
                      <td>{formatCount(row.total_packets)}</td>
                      <td>{formatCount(row.flow_count)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
        <div>
          <h4 style={{ margin: '0 0 0.45rem' }}>Traffic Timeline</h4>
          {!tlList.length ? (
            <div className="card" style={{ padding: '1rem' }}><p className="text-muted" style={{ margin: 0 }}>No timeline data available for current filters.</p></div>
          ) : (
            <div style={{ overflowX: 'auto' }}>
              <table className="chart-table">
                <thead>
                  <tr><th>Bucket</th><th>Bytes</th><th>Packets</th><th>Flows</th></tr>
                </thead>
                <tbody>
                  {tlList.map((row, i) => (
                    <tr key={i}>
                      <td>{formatTimestamp(row.bucket)}</td>
                      <td>{formatBytes(row.total_bytes)}</td>
                      <td>{formatCount(row.total_packets)}</td>
                      <td>{formatCount(row.flow_count)}</td>
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
