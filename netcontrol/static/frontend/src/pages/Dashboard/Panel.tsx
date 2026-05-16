import { useMemo } from 'react';

import {
  type Annotation,
  type DashboardPanel,
  type MetricSample,
  useAnnotations,
  useMetricsQuery,
} from '@/api/dashboard';
import { BarChart, GaugeChart, HeatmapChart, TimeSeriesChart } from '@/lib/echart';

import { parseBackendDate } from './helpers';

interface PanelMetricQuery {
  metric?: string;
  host?: string;
  group?: string;
}

function parseQuery(json: string | undefined): PanelMetricQuery {
  if (!json) return {};
  try {
    return JSON.parse(json) as PanelMetricQuery;
  } catch {
    return {};
  }
}

function resolveVariables(value: string | undefined, vars: Record<string, string>): string {
  if (!value) return '';
  return value.replace(/\$([a-zA-Z_][a-zA-Z0-9_]*)/g, (_, name) =>
    Object.prototype.hasOwnProperty.call(vars, name) ? vars[name] : `$${name}`,
  );
}

interface PanelProps {
  panel: DashboardPanel;
  variables: Record<string, string>;
  range: string;
  editing: boolean;
  onEdit: (panel: DashboardPanel) => void;
  onDelete: (panel: DashboardPanel) => void;
}

export function Panel({ panel, variables, range, editing, onEdit, onDelete }: PanelProps) {
  const raw = parseQuery(panel.metric_query_json);
  const metric = resolveVariables(raw.metric ?? 'cpu_percent', variables) || 'cpu_percent';
  const host = resolveVariables(raw.host ?? '*', variables) || '*';
  const group = raw.group ? resolveVariables(raw.group, variables) : null;
  const groupNum = group && group !== '*' ? Number(group) : null;
  const queryRange = range === 'custom' ? '24h' : range;

  const query = useMetricsQuery({
    metric,
    host,
    range: queryRange,
    group: groupNum != null && Number.isFinite(groupNum) ? groupNum : null,
  });

  // Legacy parity: deployment/config/alert markers only overlay line charts.
  const isLine = !['gauge', 'bar', 'heatmap', 'table'].includes(panel.chart_type);
  const annotationsQuery = useAnnotations({
    host,
    range: queryRange,
    enabled: isLine,
  });

  const items = query.data?.data ?? [];

  const gridStyle: React.CSSProperties = {
    gridColumn: `span ${panel.grid_w || 6}`,
    gridRow: `span ${panel.grid_h || 4}`,
  };

  return (
    <div className={`dashboard-panel${editing ? ' editing' : ''}`} style={gridStyle}>
      <div className="panel-header">
        <span className="panel-title">{panel.title || 'Untitled'}</span>
        {editing && (
          <div className="panel-actions" style={{ display: 'flex', gap: '0.25rem' }}>
            <button
              className="btn btn-sm btn-secondary"
              title="Edit"
              onClick={() => onEdit(panel)}
            >
              ✎
            </button>
            <button
              className="btn btn-sm btn-danger"
              title="Remove"
              onClick={() => onDelete(panel)}
            >
              ×
            </button>
          </div>
        )}
      </div>
      <div className="panel-chart-container">
        <PanelBody
          chartType={panel.chart_type}
          metric={metric}
          items={items}
          isPending={query.isPending}
          error={query.error}
          annotations={annotationsQuery.data}
        />
      </div>
    </div>
  );
}

interface PanelBodyProps {
  chartType: string;
  metric: string;
  items: MetricSample[];
  isPending: boolean;
  error: unknown;
  annotations?: Annotation[];
}

function PanelBody({ chartType, metric, items, isPending, error, annotations }: PanelBodyProps) {
  if (isPending) {
    return <div className="skeleton skeleton-card" style={{ height: '100%' }} />;
  }
  if (error) {
    return (
      <p className="text-muted" style={{ padding: '1rem' }}>
        Error: {(error as Error).message}
      </p>
    );
  }

  if (chartType === 'gauge') {
    const avg = items.length
      ? items.reduce((s, d) => s + (d.val_avg ?? d.value ?? 0), 0) / items.length
      : 0;
    return <GaugeChart value={avg} title={metric} />;
  }

  if (chartType === 'bar') {
    const grouped = groupByHost(items);
    const labels = Object.keys(grouped);
    const values = labels.map((h) => {
      const arr = grouped[h];
      const sum = arr.reduce((s, d) => s + (d.val_avg ?? d.value ?? 0), 0);
      return arr.length ? Math.round((sum / arr.length) * 10) / 10 : 0;
    });
    return <BarChart categories={labels} values={values} rotateLabels={labels.length > 6 ? 30 : 0} />;
  }

  if (chartType === 'heatmap') {
    return <HeatmapPanelBody items={items} />;
  }

  if (chartType === 'table') {
    return <TablePanelBody items={items} metric={metric} />;
  }

  // Default: line
  const grouped = groupByHost(items);
  const series = Object.entries(grouped).map(([hostname, pts]) => ({
    name: hostname,
    data: pts.map((d) => ({
      time: d.sampled_at ?? d.period_start ?? '',
      value: d.val_avg ?? d.value ?? 0,
    })),
  }));
  return (
    <TimeSeriesChart
      series={series.length ? series : [{ name: metric, data: [] }]}
      area
      annotations={annotations}
    />
  );
}

function HeatmapPanelBody({ items }: { items: MetricSample[] }) {
  const { xLabels, yLabels, data } = useMemo(() => {
    if (!items.length) return { xLabels: [] as string[], yLabels: [] as string[], data: [] as [number, number, number][] };
    const grouped = groupByHost(items);
    const hostNames = Object.keys(grouped);
    const timeSet = new Set<string>();
    for (const d of items) {
      const t = d.sampled_at ?? d.period_start;
      if (t) timeSet.add(t);
    }
    const times = [...timeSet].sort();
    const cells: [number, number, number][] = [];
    times.forEach((t, ti) => {
      hostNames.forEach((h, hi) => {
        const pt = grouped[h].find((d) => (d.sampled_at ?? d.period_start) === t);
        const v = pt ? Math.round(((pt.val_avg ?? pt.value ?? 0) as number) * 10) / 10 : 0;
        cells.push([ti, hi, v]);
      });
    });
    return {
      xLabels: times.map((t) => {
        const d = parseBackendDate(t);
        return d ? d.toLocaleTimeString() : t;
      }),
      yLabels: hostNames,
      data: cells,
    };
  }, [items]);

  if (!items.length) {
    return <p className="text-muted" style={{ padding: '1rem' }}>No data</p>;
  }
  return <HeatmapChart xLabels={xLabels} yLabels={yLabels} data={data} />;
}

function TablePanelBody({ items, metric }: { items: MetricSample[]; metric: string }) {
  if (!items.length) {
    return <p className="text-muted" style={{ padding: '1rem' }}>No data</p>;
  }
  return (
    <div style={{ overflow: 'auto', height: '100%' }}>
      <table className="data-table" style={{ width: '100%' }}>
        <thead>
          <tr>
            <th>Host</th>
            <th>Time</th>
            <th>{metric}</th>
          </tr>
        </thead>
        <tbody>
          {items.map((d, i) => (
            <tr key={`${d.host_id ?? d.hostname ?? '-'}-${d.sampled_at ?? d.period_start ?? i}`}>
              <td>{d.hostname ?? `host-${d.host_id ?? '?'}`}</td>
              <td>
                {(() => {
                  const parsed = parseBackendDate(d.sampled_at ?? d.period_start);
                  return parsed ? parsed.toLocaleString() : '-';
                })()}
              </td>
              <td>{(d.val_avg ?? d.value ?? 0).toFixed(2)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function groupByHost(items: MetricSample[]): Record<string, MetricSample[]> {
  const map: Record<string, MetricSample[]> = {};
  for (const d of items) {
    const key = d.hostname ?? `host-${d.host_id ?? '?'}`;
    if (!map[key]) map[key] = [];
    map[key].push(d);
  }
  return map;
}
