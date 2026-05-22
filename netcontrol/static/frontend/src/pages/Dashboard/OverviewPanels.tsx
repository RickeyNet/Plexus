import { useEffect, useMemo, useRef } from 'react';
import { Link } from 'react-router-dom';
import { echarts } from '@/lib/echart-core';
import { DataSet, Network } from 'vis-network/standalone';
import type { Edge as VisEdge, Node as VisNode } from 'vis-network';

import type { DeviceHealth } from '@/api/dashboard';
import { useTopology } from '@/api/topology';

import { classifyDeviceHealth, type HealthStatus } from './helpers';

const HEALTH_COLORS: Record<HealthStatus, string> = {
  healthy: '#4caf50',
  warning: '#ff9800',
  critical: '#f44336',
  down: '#b71c1c',
  unknown: '#9e9e9e',
};

const HEALTH_LABELS: Record<HealthStatus, string> = {
  healthy: 'Good',
  warning: 'Moderate',
  critical: 'Bad',
  down: 'Down',
  unknown: 'Unknown',
};

export function OverviewPanels({ devices }: { devices: DeviceHealth[] }) {
  return (
    <div className="dashboard-overview-grid">
      <div className="glass-card card dashboard-overview-card">
        <h3 className="dashboard-overview-title">Overall Health</h3>
        <HealthDonut devices={devices} />
      </div>
      <div className="glass-card card dashboard-overview-card">
        <div className="dashboard-overview-header">
          <h3 className="dashboard-overview-title">Network Topology</h3>
          <Link to="/topology" className="dashboard-overview-link">
            Open full view →
          </Link>
        </div>
        <TopologyMiniMap devices={devices} />
      </div>
    </div>
  );
}

function HealthDonut({ devices }: { devices: DeviceHealth[] }) {
  const ref = useRef<HTMLDivElement>(null);

  const buckets = useMemo(() => {
    const counts: Record<HealthStatus, number> = {
      healthy: 0,
      warning: 0,
      critical: 0,
      down: 0,
      unknown: 0,
    };
    for (const d of devices) counts[classifyDeviceHealth(d)]++;
    return counts;
  }, [devices]);

  const total = devices.length;

  useEffect(() => {
    if (!ref.current) return;
    const chart = echarts.init(ref.current, undefined, { renderer: 'canvas' });

    // Merge critical + down into one "Bad" slice, matching the SolarWinds
    // four-bucket layout (Good / Moderate / Bad / Unknown).
    const badCount = buckets.critical + buckets.down;
    const slices = [
      { name: HEALTH_LABELS.healthy, value: buckets.healthy, itemStyle: { color: HEALTH_COLORS.healthy } },
      { name: HEALTH_LABELS.warning, value: buckets.warning, itemStyle: { color: HEALTH_COLORS.warning } },
      { name: HEALTH_LABELS.critical, value: badCount, itemStyle: { color: HEALTH_COLORS.critical } },
      { name: HEALTH_LABELS.unknown, value: buckets.unknown, itemStyle: { color: HEALTH_COLORS.unknown } },
    ];
    const hasData = slices.some((s) => s.value > 0);

    chart.setOption({
      animation: false,
      tooltip: { trigger: 'item', formatter: '{b}: {c} ({d}%)' },
      legend: {
        orient: 'vertical',
        right: 8,
        top: 'center',
        textStyle: { color: 'var(--text)' },
        formatter: (name: string) => {
          const slice = slices.find((s) => s.name === name);
          return `${name}  ${slice ? slice.value : 0}`;
        },
      },
      series: [
        {
          type: 'pie',
          radius: ['58%', '78%'],
          center: ['35%', '50%'],
          avoidLabelOverlap: false,
          label: {
            show: true,
            position: 'center',
            formatter: () => (hasData ? `{val|${formatCount(total)}}\n{lbl|Devices}` : '{lbl|No data}'),
            rich: {
              val: { fontSize: 28, fontWeight: 600, color: 'var(--text)', lineHeight: 32 },
              lbl: { fontSize: 12, color: 'var(--text-muted)' },
            },
          },
          labelLine: { show: false },
          data: hasData ? slices : [{ name: 'No data', value: 1, itemStyle: { color: 'var(--border)' } }],
          silent: !hasData,
        },
      ],
    });

    const onResize = () => chart.resize();
    window.addEventListener('resize', onResize);
    return () => {
      window.removeEventListener('resize', onResize);
      chart.dispose();
    };
  }, [buckets, total]);

  return <div ref={ref} style={{ width: '100%', height: 240 }} />;
}

function formatCount(n: number): string {
  if (n >= 1000) return `${(n / 1000).toFixed(1)}k`;
  return String(n);
}

function TopologyMiniMap({ devices }: { devices: DeviceHealth[] }) {
  const { data, isPending } = useTopology(null);
  const containerRef = useRef<HTMLDivElement>(null);
  const networkRef = useRef<Network | null>(null);

  // Index device health by IP and hostname so we can color topology nodes
  // even when the topology API returns id-only entries.
  const healthByKey = useMemo(() => {
    const m = new Map<string, HealthStatus>();
    for (const d of devices) {
      const status = classifyDeviceHealth(d);
      if (d.ip_address) m.set(d.ip_address.toLowerCase(), status);
      if (d.hostname) m.set(d.hostname.toLowerCase(), status);
    }
    return m;
  }, [devices]);

  useEffect(() => {
    if (!containerRef.current || !data) return;

    const nodes: VisNode[] = data.nodes.map((n) => {
      const key = (n.ip ?? '').toLowerCase() || (n.label ?? '').toLowerCase();
      const status = healthByKey.get(key) ?? 'unknown';
      const color = HEALTH_COLORS[status];
      return {
        id: n.id as never,
        label: n.label,
        title: `${n.label}${n.ip ? ` (${n.ip})` : ''} - ${HEALTH_LABELS[status]}`,
        shape: 'dot',
        size: 12,
        color: { background: color, border: color, highlight: { background: color, border: '#fff' } },
        font: { color: 'var(--text-muted)', size: 10 },
      };
    });

    const edges: VisEdge[] = data.edges.map((e) => ({
      id: e.id as never,
      from: e.from as never,
      to: e.to as never,
      color: { color: 'var(--border-light)', opacity: 0.6 },
      width: 1,
      smooth: { enabled: true, type: 'continuous', roundness: 0.3 },
    }));

    const network = new Network(
      containerRef.current,
      { nodes: new DataSet(nodes), edges: new DataSet(edges) },
      {
        autoResize: true,
        interaction: {
          dragNodes: false,
          dragView: false,
          zoomView: false,
          selectable: false,
          hover: true,
        },
        physics: {
          enabled: true,
          stabilization: { iterations: 150, fit: true },
          barnesHut: { gravitationalConstant: -3000, springLength: 80, avoidOverlap: 0.6 },
        },
        nodes: { borderWidth: 1, shadow: false },
        edges: { shadow: false },
      },
    );
    networkRef.current = network;
    network.once('stabilizationIterationsDone', () => network.fit({ animation: false }));

    return () => {
      network.destroy();
      networkRef.current = null;
    };
  }, [data, healthByKey]);

  const isEmpty = !isPending && (!data || data.nodes.length === 0);

  return (
    <div className="dashboard-topology-mini">
      <div
        ref={containerRef}
        style={{ width: '100%', height: 240, opacity: isEmpty ? 0.3 : 1 }}
      />
      {isEmpty && (
        <div className="dashboard-topology-empty">
          <p style={{ margin: 0, color: 'var(--text-muted)' }}>
            No topology data yet. Run discovery from the Topology page.
          </p>
        </div>
      )}
      <MiniMapLegend />
    </div>
  );
}

function MiniMapLegend() {
  const items: HealthStatus[] = ['healthy', 'warning', 'critical', 'unknown'];
  return (
    <div className="dashboard-topology-legend">
      {items.map((s) => (
        <span key={s} className="dashboard-topology-legend-item">
          <span
            className="dashboard-topology-legend-dot"
            style={{ background: HEALTH_COLORS[s] }}
          />
          {HEALTH_LABELS[s]}
        </span>
      ))}
    </div>
  );
}
