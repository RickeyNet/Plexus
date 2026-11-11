import { useMemo } from 'react';

import {
  useCloudTrafficMetricSummary,
  useCloudTrafficMetricTimeline,
  useCloudTrafficMetricTopResources,
  useCloudTrafficSyncConfig,
  useCloudTrafficSyncCursors,
  useTriggerCloudTrafficPull,
  useUpdateCloudTrafficSyncConfig,
} from '@/api/cloud';
import { StatGrid, StatTile } from '@/components/StatTile';
import { formatBackendDateTime, formatBackendTime } from '@/lib/datetime';
import { TimeSeriesChart } from '@/lib/echart';
import { timelineSeries, useAnalyticsFilters } from './analytics';
import { AnalyticsFilters, AnalyticsSection } from './AnalyticsParts';
import type { CloudFilterState } from './CloudVisibility';
import { formatCount, formatMetricValue } from './helpers';
import { SyncControls } from './SyncControls';

interface Props {
  filter: CloudFilterState;
}

export function TrafficTab({ filter }: Props) {
  const filters = useAnalyticsFilters();

  const params = {
    provider: filter.provider || undefined,
    account_id: filter.accountId,
    hours: filters.hours,
    limit: filters.limit,
    bucket_minutes: filters.bucketMinutes,
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
  const tlList = timeline.data?.timeline;
  // Total per bucket only: the per-sample average is far smaller and would
  // flatten to the axis on a shared scale; it is in the tiles and table.
  const series = useMemo(
    () => [timelineSeries('Total value', tlList ?? [], (row) => row.total_value)],
    [tlList],
  );

  return (
    <div className="stack">
      <AnalyticsFilters filters={filters} limitLabel="Top resources shown" />

      <AnalyticsSection
        level="h3"
        title={
          <>
            Cloud traffic metrics
            {summary.dataUpdatedAt > 0 && (
              <small className="text-muted" style={{ marginLeft: 'var(--space-2)', fontWeight: 400 }}>
                Updated {formatBackendTime(summary.dataUpdatedAt)}
              </small>
            )}
          </>
        }
        query={summary}
        what="traffic metric summary"
      >
        <StatGrid compact>
          <StatTile label="Samples" value={formatCount(s.sample_count)} />
          <StatTile label="Metric Names" value={formatCount(s.metric_count)} />
          <StatTile label="Resources" value={formatCount(s.resource_count)} />
          <StatTile label="Total Value" value={formatMetricValue(s.total_value)} />
          <StatTile label="Average Value" value={formatMetricValue(s.avg_value)} />
          <StatTile label="Last Seen" value={formatBackendDateTime(s.last_seen)} />
        </StatGrid>
      </AnalyticsSection>

      <AnalyticsSection
        title="Metric total over time"
        query={timeline}
        what="traffic metric timeline"
        empty={!series[0].data.length && 'No timeline data for the current filters.'}
      >
        <div className="card">
          <TimeSeriesChart series={series} area valueFormatter={formatMetricValue} height={300} />
        </div>
      </AnalyticsSection>

      <AnalyticsSection
        title="Top resources"
        query={resources}
        what="top resources"
        empty={!rList.length && 'No traffic metric resources for the current filters.'}
      >
        <div style={{ overflowX: 'auto' }}>
          <table className="data-table">
            <thead>
              <tr><th>Resource</th><th>Total Value</th><th>Average</th><th>Samples</th></tr>
            </thead>
            <tbody>
              {rList.map((row, i) => (
                <tr key={row.resource_uid || `unknown-${i}`}>
                  <td>{row.resource_uid || '-'}</td>
                  <td>{formatMetricValue(row.total_value)}</td>
                  <td>{formatMetricValue(row.avg_value)}</td>
                  <td>{formatCount(row.sample_count)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </AnalyticsSection>

      <SyncControls
        kind="Traffic"
        syncConfig={syncConfig}
        syncCursors={syncCursors}
        updateConfig={updateConfig}
        triggerPull={triggerPull}
        selectedAccountId={filter.accountId}
      />
    </div>
  );
}
