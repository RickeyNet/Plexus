import { useMemo } from 'react';
import { Link } from 'react-router';

import type { DeviceHealth } from '@/api/dashboard';
import { SegmentedControl } from '@/components/SegmentedControl';
import { useParamFilter } from '@/lib/useLinkedParam';

import {
  DEVICES_FILTER_PARAM,
  DEVICE_HEALTH_FILTERS,
  type DeviceHealthFilter,
  countDeviceHealthFilters,
  deviceHealthFilterOf,
  parseDeviceHealthFilter,
} from './dashboardLinks';
import { HEALTH_COLORS, HEALTH_LABELS, SEVERITY_ORDER, classifyDeviceHealth, type HealthStatus } from './helpers';

// 'critical' is the merged critical + down bucket.
type Filter = 'all' | DeviceHealthFilter;

export function DevicesGridPanel({ devices }: { devices: DeviceHealth[] }) {
  // The filter lives in the URL (`?devices=`), so the donut and the Needs
  // attention rows link here with a bucket selected.
  const [linked, setLinked] = useParamFilter(DEVICES_FILTER_PARAM, parseDeviceHealthFilter);
  const filter: Filter = linked ?? 'all';
  const setFilter = (next: Filter) => setLinked(next === 'all' ? null : next);

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
    return sorted.filter((e) => deviceHealthFilterOf(e.status) === filter);
  }, [sorted, filter]);

  // Each chip carries its count, so the grid needs no separate legend.
  const filters = useMemo<{ key: Filter; label: string }[]>(() => {
    const counts = countDeviceHealthFilters(devices);
    return [
      { key: 'all', label: `All ${devices.length}` },
      ...DEVICE_HEALTH_FILTERS.map((f) => ({ key: f.key, label: `${f.label} ${counts[f.key]}` })),
    ];
  }, [devices]);

  return (
    <div className="glass-card card dashboard-overview-card">
      <div className="dashboard-overview-header">
        <h3 className="dashboard-overview-title">Devices</h3>
        <SegmentedControl options={filters} value={filter} onChange={setFilter} size="xs" aria-label="Filter" />
      </div>

      {devices.length === 0 ? (
        <div className="dashboard-response-empty">
          <p style={{ margin: 0, color: 'var(--text-muted)' }}>
            No monitored devices yet.
          </p>
        </div>
      ) : (
        <div className="dashboard-devices-grid">
          {filtered.map((e, i) => (
            <DeviceTile
              key={`${e.device.host_id ?? '-'}-${e.device.hostname ?? '-'}-${i}`}
              device={e.device}
              status={e.status}
            />
          ))}
        </div>
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
