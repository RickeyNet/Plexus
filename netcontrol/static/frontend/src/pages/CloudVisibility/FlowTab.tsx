import { useId, useMemo, useState } from 'react';

import {
  useCloudFlowSummary,
  useCloudFlowSyncConfig,
  useCloudFlowSyncCursors,
  useCloudFlowTimeline,
  useCloudFlowTopTalkers,
  useTriggerCloudFlowPull,
  useUpdateCloudFlowSyncConfig,
} from '@/api/cloud';
import { StatGrid, StatTile } from '@/components/StatTile';
import { formatBackendDateTime, formatBackendTime } from '@/lib/datetime';
import { TimeSeriesChart } from '@/lib/echart';
import { timelineSeries, useAnalyticsFilters } from './analytics';
import { AnalyticsFilterField, AnalyticsFilters, AnalyticsSection } from './AnalyticsParts';
import type { CloudFilterState } from './CloudVisibility';
import { formatBytes, formatCount } from './helpers';
import { SyncControls } from './SyncControls';

interface Props {
  filter: CloudFilterState;
}

export function FlowTab({ filter }: Props) {
  const fid = useId();
  const filters = useAnalyticsFilters();
  const [direction, setDirection] = useState<'src' | 'dst'>('src');

  const params = {
    provider: filter.provider || undefined,
    account_id: filter.accountId,
    hours: filters.hours,
    direction,
    limit: filters.limit,
    bucket_minutes: filters.bucketMinutes,
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
  const tlList = timeline.data?.timeline;
  // Bytes only: packets and flows are orders of magnitude smaller and would
  // flatten to the axis on a shared scale; they are in the tiles and table.
  const series = useMemo(
    () => [timelineSeries('Bytes', tlList ?? [], (row) => row.total_bytes)],
    [tlList],
  );

  return (
    <div className="stack">
      <AnalyticsFilters filters={filters} limitLabel="Top talkers shown">
        <AnalyticsFilterField>
          <label className="form-label" htmlFor={`${fid}-direction`}>Rank talkers by</label>
          <select
            id={`${fid}-direction`}
            className="form-select"
            value={direction}
            onChange={(e) => setDirection(e.target.value as 'src' | 'dst')}
          >
            <option value="src">Source IP</option>
            <option value="dst">Destination IP</option>
          </select>
        </AnalyticsFilterField>
      </AnalyticsFilters>

      <AnalyticsSection
        level="h3"
        title={
          <>
            Cloud flow analytics
            {summary.dataUpdatedAt > 0 && (
              <small className="text-muted" style={{ marginLeft: 'var(--space-2)', fontWeight: 400 }}>
                Updated {formatBackendTime(summary.dataUpdatedAt)}
              </small>
            )}
          </>
        }
        query={summary}
        what="flow summary"
      >
        <StatGrid compact>
          <StatTile label="Flows" value={formatCount(s.flow_count)} />
          <StatTile label="Total Bytes" value={formatBytes(s.total_bytes)} />
          <StatTile label="Total Packets" value={formatCount(s.total_packets)} />
          <StatTile label="Unique Sources" value={formatCount(s.unique_sources)} />
          <StatTile label="Unique Destinations" value={formatCount(s.unique_destinations)} />
          <StatTile label="Last Seen" value={formatBackendDateTime(s.last_seen)} />
        </StatGrid>
      </AnalyticsSection>

      <AnalyticsSection
        title="Traffic over time"
        query={timeline}
        what="flow timeline"
        empty={!series[0].data.length && 'No timeline data for the current filters.'}
      >
        <div className="card">
          <TimeSeriesChart series={series} area valueFormatter={formatBytes} height={300} />
        </div>
      </AnalyticsSection>

      <AnalyticsSection
        title="Top talkers"
        query={talkers}
        what="top talkers"
        empty={!tList.length && 'No flow talkers for the current filters.'}
      >
        <div style={{ overflowX: 'auto' }}>
          <table className="data-table">
            <thead>
              <tr><th>{direction === 'dst' ? 'Destination IP' : 'Source IP'}</th><th>Bytes</th><th>Packets</th><th>Flows</th></tr>
            </thead>
            <tbody>
              {tList.map((row, i) => (
                <tr key={row.ip || `unknown-${i}`}>
                  <td>{row.ip || '-'}</td>
                  <td>{formatBytes(row.total_bytes)}</td>
                  <td>{formatCount(row.total_packets)}</td>
                  <td>{formatCount(row.flow_count)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </AnalyticsSection>

      <SyncControls
        kind="Flow"
        syncConfig={syncConfig}
        syncCursors={syncCursors}
        updateConfig={updateConfig}
        triggerPull={triggerPull}
        selectedAccountId={filter.accountId}
      />
    </div>
  );
}
