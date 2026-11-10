import { useEffect, useRef, useState } from 'react';

import {
  type CloudPullResult,
  useCloudFlowSummary,
  useCloudFlowSyncConfig,
  useCloudFlowSyncCursors,
  useCloudFlowTimeline,
  useCloudFlowTopTalkers,
  useTriggerCloudFlowPull,
  useUpdateCloudFlowSyncConfig,
} from '@/api/cloud';
import { Callout } from '@/components/Callout';
import { LoadingState } from '@/components/LoadingState';
import { StatGrid, StatTile } from '@/components/StatTile';
import { formatBackendDateTime, formatBackendTime } from '@/lib/datetime';
import type { CloudFilterState } from './CloudVisibility';
import { formatBytes, formatCount, pullOutcome } from './helpers';
import { SyncControls } from './SyncControls';

interface Props {
  filter: CloudFilterState;
}

export function FlowTab({ filter }: Props) {
  const [hours, setHours] = useState(24);
  const [direction, setDirection] = useState<'src' | 'dst'>('src');
  const [limit, setLimit] = useState(20);
  const [bucketMinutes, setBucketMinutes] = useState(5);
  const [actionMsg, setActionMsg] = useState<{ kind: 'success' | 'error'; text: string } | null>(null);

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

      <div className="stack stack-sm">
        <h3 style={{ margin: 0 }}>Flow Sync Controls</h3>
        <SyncControls
          kind="Flow"
          config={syncConfig.data?.config ?? null}
          status={syncConfig.data?.status ?? null}
          cursors={syncCursors.data?.cursors ?? []}
          selectedAccountId={filter.accountId}
          isSaving={updateConfig.isPending}
          isPulling={triggerPull.isPending}
          onSave={async (cfg) => {
            try {
              await updateConfig.mutateAsync(cfg);
              flash('success', 'Cloud flow sync config saved');
            } catch (e) {
              flash('error', `Saving flow sync config failed: ${(e as Error).message}`);
            }
          }}
          onPullAll={async () => {
            try {
              showPull('Cloud flow pull', await triggerPull.mutateAsync(null));
            } catch (e) {
              flash('error', `Cloud flow pull failed: ${(e as Error).message}`);
            }
          }}
          onPullSelected={async () => {
            if (!filter.accountId) return;
            try {
              showPull('Cloud flow pull (selected account)', await triggerPull.mutateAsync(filter.accountId));
            } catch (e) {
              flash('error', `Cloud flow pull failed: ${(e as Error).message}`);
            }
          }}
        />
      </div>
      {actionMsg && (
        <Callout tone={actionMsg.kind === 'success' ? 'success' : 'danger'}>{actionMsg.text}</Callout>
      )}

      <div className="stack stack-sm">
        <h3 style={{ margin: 0 }}>
          Cloud Flow Analytics
          {summary.dataUpdatedAt > 0 && (
            <small className="text-muted" style={{ marginLeft: '0.6rem', fontWeight: 400 }}>
              Updated {formatBackendTime(summary.dataUpdatedAt)}
            </small>
          )}
        </h3>
        {summary.isPending && <LoadingState />}
        {summary.error && <div style={{ color: 'var(--danger)' }}>Error: {(summary.error as Error).message}</div>}
        <StatGrid compact>
          <StatTile label="Flows" value={formatCount(s.flow_count)} />
          <StatTile label="Total Bytes" value={formatBytes(s.total_bytes)} />
          <StatTile label="Total Packets" value={formatCount(s.total_packets)} />
          <StatTile label="Unique Sources" value={formatCount(s.unique_sources)} />
          <StatTile label="Unique Destinations" value={formatCount(s.unique_destinations)} />
          <StatTile label="Last Seen" value={formatBackendDateTime(s.last_seen)} />
        </StatGrid>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: 'var(--space-4)' }}>
        <div>
          <h4 style={{ margin: '0 0 0.45rem' }}>Top Talkers</h4>
          {talkers.isPending ? (
            <div className="card"><LoadingState variant="inline" /></div>
          ) : talkers.error ? (
            <div className="card"><p style={{ margin: 0, color: 'var(--danger)' }}>Failed to load top talkers: {(talkers.error as Error).message}</p></div>
          ) : !tList.length ? (
            <div className="card"><p className="text-muted" style={{ margin: 0 }}>No flow talkers found for current filters.</p></div>
          ) : (
            <div style={{ overflowX: 'auto' }}>
              <table className="data-table">
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
                  <tr><th>Bucket</th><th>Bytes</th><th>Packets</th><th>Flows</th></tr>
                </thead>
                <tbody>
                  {tlList.map((row, i) => (
                    <tr key={i}>
                      <td>{formatBackendDateTime(row.bucket)}</td>
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

