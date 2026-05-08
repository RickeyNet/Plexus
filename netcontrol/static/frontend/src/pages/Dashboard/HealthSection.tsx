import { useMemo, useState } from 'react';

import type { DashboardGroup, DashboardMonitoring, DeviceHealth } from '@/api/dashboard';

import {
  classifyDeviceHealth,
  formatUptime,
  type HealthStatus,
  sortDevices,
  type SortBy,
  timeAgo,
} from './helpers';

interface HealthSectionProps {
  monitoring: DashboardMonitoring;
  devices: DeviceHealth[];
  groups: DashboardGroup[];
}

export function HealthSection({ monitoring, devices, groups }: HealthSectionProps) {
  const [groupFilter, setGroupFilter] = useState('');
  const [sortBy, setSortBy] = useState<SortBy>('severity');

  const filtered = useMemo(() => {
    const base = groupFilter ? devices.filter((d) => String(d.group_id) === groupFilter) : devices;
    return sortDevices(base, sortBy);
  }, [devices, groupFilter, sortBy]);

  return (
    <div className="section" id="network-health-section">
      <div className="page-header" style={{ marginBottom: '1rem' }}>
        <h3>Network Health Overview</h3>
        <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
          <select
            className="form-select"
            style={{ minWidth: '160px', fontSize: '0.85rem' }}
            value={groupFilter}
            onChange={(e) => setGroupFilter(e.target.value)}
          >
            <option value="">All Groups</option>
            {groups.map((g) => (
              <option key={g.id} value={String(g.id)}>
                {g.name}
              </option>
            ))}
          </select>
          <select
            className="form-select"
            style={{ minWidth: '140px', fontSize: '0.85rem' }}
            value={sortBy}
            onChange={(e) => setSortBy(e.target.value as SortBy)}
          >
            <option value="severity">Severity</option>
            <option value="name">Name A-Z</option>
            <option value="cpu">CPU Usage</option>
            <option value="memory">Memory Usage</option>
          </select>
        </div>
      </div>

      <HealthSummaryTiles monitoring={monitoring} devices={filtered} />

      <div className="device-health-table-wrap" style={{ marginTop: '1rem' }}>
        <DeviceHealthTable devices={filtered} />
      </div>
    </div>
  );
}

function HealthSummaryTiles({ monitoring, devices }: { monitoring: DashboardMonitoring; devices: DeviceHealth[] }) {
  const counts = useMemo(() => {
    const c: Record<HealthStatus, number> = { healthy: 0, warning: 0, critical: 0, down: 0, unknown: 0 };
    for (const d of devices) c[classifyDeviceHealth(d)]++;
    return c;
  }, [devices]);

  const total = devices.length;
  const openAlerts = monitoring.open_alerts ?? 0;

  return (
    <div className="health-summary-tiles">
      <Tile iconClass="healthy" valueColor="#4caf50" value={counts.healthy} label="Healthy">
        <polyline points="20 6 9 17 4 12" />
      </Tile>
      <Tile iconClass="warning" valueColor="#ff9800" value={counts.warning} label="Warning">
        <path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z" />
        <line x1="12" y1="9" x2="12" y2="13" />
        <line x1="12" y1="17" x2="12.01" y2="17" />
      </Tile>
      <Tile iconClass="critical" valueColor="#f44336" value={counts.critical + counts.down} label="Critical / Down">
        <circle cx="12" cy="12" r="10" />
        <line x1="15" y1="9" x2="9" y2="15" />
        <line x1="9" y1="9" x2="15" y2="15" />
      </Tile>
      <Tile iconClass="unknown" valueColor="#9e9e9e" value={counts.unknown} label="Unknown">
        <circle cx="12" cy="12" r="10" />
        <path d="M9.09 9a3 3 0 015.83 1c0 2-3 3-3 3" />
        <line x1="12" y1="17" x2="12.01" y2="17" />
      </Tile>
      <Tile iconClass="info" value={total} label="Total Monitored">
        <rect x="2" y="3" width="20" height="14" rx="2" ry="2" />
        <line x1="8" y1="21" x2="16" y2="21" />
        <line x1="12" y1="17" x2="12" y2="21" />
      </Tile>
      <Tile
        iconClass={openAlerts > 0 ? 'critical' : 'healthy'}
        valueColor={openAlerts > 0 ? '#f44336' : '#4caf50'}
        value={openAlerts}
        label="Open Alerts"
      >
        <path d="M18 8A6 6 0 006 8c0 7-3 9-3 9h18s-3-2-3-9" />
        <path d="M13.73 21a2 2 0 01-3.46 0" />
      </Tile>
    </div>
  );
}

interface TileProps {
  iconClass: string;
  valueColor?: string;
  value: number;
  label: string;
  children: React.ReactNode;
}

function Tile({ iconClass, valueColor, value, label, children }: TileProps) {
  return (
    <div className="health-tile">
      <div className={`health-tile-icon ${iconClass}`}>
        <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          {children}
        </svg>
      </div>
      <div className="health-tile-value" style={valueColor ? { color: valueColor } : undefined}>
        {value}
      </div>
      <div className="health-tile-label">{label}</div>
    </div>
  );
}

function UsageBar({ pct }: { pct: number | null | undefined }) {
  if (pct == null) return <span className="text-muted">N/A</span>;
  const clamped = Math.min(Math.max(pct, 0), 100);
  const level = clamped >= 90 ? 'high' : clamped >= 70 ? 'medium' : 'low';
  return (
    <div className="usage-bar-wrap">
      <div className="usage-bar">
        <div className={`usage-bar-fill ${level}`} style={{ width: `${clamped}%` }} />
      </div>
      <span className="usage-bar-pct">{Math.round(clamped)}%</span>
    </div>
  );
}

function DeviceHealthTable({ devices }: { devices: DeviceHealth[] }) {
  if (!devices.length) {
    return (
      <div className="empty-state">
        <p>No monitored devices yet</p>
      </div>
    );
  }

  return (
    <table className="device-health-table">
      <thead>
        <tr>
          <th>Status</th>
          <th>Hostname</th>
          <th>IP Address</th>
          <th>Group</th>
          <th>Model</th>
          <th>CPU</th>
          <th>Memory</th>
          <th>Interfaces</th>
          <th>Response</th>
          <th>Uptime</th>
          <th>Last Poll</th>
        </tr>
      </thead>
      <tbody>
        {devices.map((d, i) => {
          const health = classifyDeviceHealth(d);
          const statusLabel =
            health === 'healthy'
              ? 'Up'
              : health === 'warning'
                ? 'Warning'
                : health === 'critical'
                  ? 'Critical'
                  : health === 'down'
                    ? 'Down'
                    : 'Unknown';
          const dotClass = health === 'healthy' ? 'up' : health;
          const statusClass = health === 'healthy' ? 'up' : health;
          return (
            <tr key={`${d.hostname ?? '-'}-${d.ip_address ?? '-'}-${i}`}>
              <td>
                <div className={`device-health-status status-${statusClass}`}>
                  <span className={`status-dot ${dotClass}`} />
                  {statusLabel}
                </div>
              </td>
              <td>
                <strong>{d.hostname ?? '-'}</strong>
              </td>
              <td>{d.ip_address ?? '-'}</td>
              <td>{d.group_name ?? '-'}</td>
              <td>{d.model ?? d.device_type ?? '-'}</td>
              <td>
                <UsageBar pct={d.cpu_percent} />
              </td>
              <td>
                <UsageBar pct={d.memory_percent} />
              </td>
              <td>
                {d.if_up_count != null ? (
                  <>
                    <span style={{ color: '#4caf50' }}>{d.if_up_count}▲</span>
                    {' / '}
                    <span style={{ color: '#f44336' }}>{d.if_down_count ?? 0}▼</span>
                  </>
                ) : (
                  '-'
                )}
              </td>
              <td>{d.response_time_ms != null ? `${Math.round(d.response_time_ms)}ms` : '-'}</td>
              <td>{formatUptime(d.uptime_seconds)}</td>
              <td title={d.polled_at ?? ''}>{timeAgo(d.polled_at)}</td>
            </tr>
          );
        })}
      </tbody>
    </table>
  );
}
