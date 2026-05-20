import { useMemo, useState } from 'react';
import { Link } from 'react-router-dom';

import type { DeviceHealth } from '@/api/dashboard';

import { classifyDeviceHealth, type HealthStatus } from './helpers';

const HEALTH_COLORS: Record<HealthStatus, string> = {
  healthy: '#4caf50',
  warning: '#ff9800',
  critical: '#f44336',
  down: '#b71c1c',
  unknown: '#9e9e9e',
};

const HEALTH_LABELS: Record<HealthStatus, string> = {
  healthy: 'Healthy',
  warning: 'Warning',
  critical: 'Critical',
  down: 'Down',
  unknown: 'Unknown',
};

type Filter = 'all' | HealthStatus;

const FILTERS: { value: Filter; label: string }[] = [
  { value: 'all', label: 'All' },
  { value: 'critical', label: 'Bad' },
  { value: 'warning', label: 'Warn' },
  { value: 'healthy', label: 'Good' },
  { value: 'unknown', label: '?' },
];

const SEVERITY_ORDER: Record<HealthStatus, number> = {
  down: 0,
  critical: 1,
  warning: 2,
  unknown: 3,
  healthy: 4,
};

export function DevicesGridPanel({ devices }: { devices: DeviceHealth[] }) {
  const [filter, setFilter] = useState<Filter>('all');

  const classified = useMemo(
    () => devices.map((d) => ({ device: d, status: classifyDeviceHealth(d) })),
    [devices],
  );

  // Worst-first so problems jump out at the top-left of the grid.
  const sorted = useMemo(
    () =>
      [...classified].sort(
        (a, b) => SEVERITY_ORDER[a.status] - SEVERITY_ORDER[b.status],
      ),
    [classified],
  );

  const filtered = useMemo(() => {
    if (filter === 'all') return sorted;
    if (filter === 'critical')
      return sorted.filter((e) => e.status === 'critical' || e.status === 'down');
    return sorted.filter((e) => e.status === filter);
  }, [sorted, filter]);

  const counts = useMemo(() => {
    const c: Record<HealthStatus, number> = {
      healthy: 0,
      warning: 0,
      critical: 0,
      down: 0,
      unknown: 0,
    };
    for (const e of classified) c[e.status]++;
    return c;
  }, [classified]);

  return (
    <div className="glass-card card dashboard-overview-card">
      <div className="dashboard-overview-header">
        <h3 className="dashboard-overview-title">Devices</h3>
        <div className="dashboard-range-tabs" role="tablist" aria-label="Filter">
          {FILTERS.map((f) => (
            <button
              key={f.value}
              role="tab"
              aria-selected={filter === f.value}
              className={`dashboard-range-tab${filter === f.value ? ' active' : ''}`}
              onClick={() => setFilter(f.value)}
            >
              {f.label}
            </button>
          ))}
        </div>
      </div>

      {devices.length === 0 ? (
        <div className="dashboard-response-empty">
          <p style={{ margin: 0, color: 'var(--text-muted)' }}>
            No monitored devices yet.
          </p>
        </div>
      ) : (
        <>
          <div className="dashboard-devices-grid">
            {filtered.map((e, i) => (
              <DeviceTile
                key={`${e.device.host_id ?? '-'}-${e.device.hostname ?? '-'}-${i}`}
                device={e.device}
                status={e.status}
              />
            ))}
          </div>
          <div className="dashboard-topology-legend" style={{ marginTop: '0.75rem' }}>
            <LegendDot status="healthy" count={counts.healthy} />
            <LegendDot status="warning" count={counts.warning} />
            <LegendDot status="critical" count={counts.critical + counts.down} />
            <LegendDot status="unknown" count={counts.unknown} />
          </div>
        </>
      )}
    </div>
  );
}

function DeviceTile({ device, status }: { device: DeviceHealth; status: HealthStatus }) {
  const color = HEALTH_COLORS[status];
  const label = (device.hostname ?? device.ip_address ?? '?').slice(0, 2).toUpperCase();
  const tooltip = [
    device.hostname ?? device.ip_address ?? 'unknown',
    HEALTH_LABELS[status],
    device.cpu_percent != null ? `CPU ${Math.round(device.cpu_percent)}%` : null,
    device.memory_percent != null ? `Mem ${Math.round(device.memory_percent)}%` : null,
  ]
    .filter(Boolean)
    .join(' · ');

  const tile = (
    <div
      className="dashboard-devices-tile"
      style={{ background: color }}
      title={tooltip}
      aria-label={tooltip}
    >
      <span>{label}</span>
    </div>
  );

  return device.host_id != null ? (
    <Link to={`/devices/${device.host_id}`} className="dashboard-devices-tile-link">
      {tile}
    </Link>
  ) : (
    tile
  );
}

function LegendDot({ status, count }: { status: HealthStatus; count: number }) {
  return (
    <span className="dashboard-topology-legend-item">
      <span
        className="dashboard-topology-legend-dot"
        style={{ background: HEALTH_COLORS[status] }}
      />
      {HEALTH_LABELS[status]} {count}
    </span>
  );
}
