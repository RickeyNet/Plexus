import { useMemo, useState } from 'react';

import type { DashboardGroup, DeviceHealth } from '@/api/dashboard';
import { formatRelativeTime } from '@/lib/datetime';
import { useParamFilter } from '@/lib/useLinkedParam';

import {
  DEVICE_HEALTH_FILTERS,
  HEALTH_GROUP_PARAM,
  HEALTH_STATUS_PARAM,
  deviceHealthFilterOf,
  parseDeviceHealthFilter,
  parseGroupKey,
} from './dashboardLinks';
import {
  HEALTH_LABELS,
  ISSUE_ANCHORS,
  classifyDeviceHealth,
  deviceGroupKey,
  formatUptime,
  groupDevices,
  sortDevices,
  type SortBy,
} from './helpers';

interface HealthSectionProps {
  devices: DeviceHealth[];
  groups: DashboardGroup[];
}

export function HealthSection({ devices, groups }: HealthSectionProps) {
  // Both filters live in the URL (`?group=`, `?health=`), so the Group
  // Health tiles link here with them selected.
  const [linkedGroup, setGroupFilter] = useParamFilter(HEALTH_GROUP_PARAM, parseGroupKey);
  const [healthFilter, setHealthFilter] = useParamFilter(HEALTH_STATUS_PARAM, parseDeviceHealthFilter);
  const [sortBy, setSortBy] = useState<SortBy>('severity');

  // Every group a device can be in (Ungrouped too), so a linked group always has its option.
  const groupOptions = useMemo(() => groupDevices(groups, devices), [groups, devices]);
  // A group this list does not have (deleted, or a bad link) is ignored.
  const groupFilter = linkedGroup && groupOptions.some((g) => g.key === linkedGroup) ? linkedGroup : '';

  const filtered = useMemo(() => {
    const base = devices.filter(
      (d) =>
        (!groupFilter || deviceGroupKey(d) === groupFilter) &&
        (!healthFilter || deviceHealthFilterOf(classifyDeviceHealth(d)) === healthFilter),
    );
    return sortDevices(base, sortBy);
  }, [devices, groupFilter, healthFilter, sortBy]);

  return (
    <div className="glass-card card dashboard-overview-card stack" id={ISSUE_ANCHORS.health}>
      <div className="toolbar">
        <h3 className="dashboard-overview-title" style={{ margin: 0 }}>Network Health Overview</h3>
        <span className="text-muted" style={{ fontSize: '0.8rem' }}>
          {filtered.length} {filtered.length === 1 ? 'device' : 'devices'}
        </span>
        <span className="toolbar-spacer" />
        <select
          className="form-select form-select-sm"
          style={{ minWidth: '160px' }}
          aria-label="Filter by group"
          value={groupFilter}
          onChange={(e) => setGroupFilter(e.target.value || null)}
        >
          <option value="">All Groups</option>
          {groupOptions.map((g) => (
            <option key={g.key} value={g.key}>
              {g.name}
            </option>
          ))}
        </select>
        <select
          className="form-select form-select-sm"
          style={{ minWidth: '140px' }}
          aria-label="Filter by status"
          value={healthFilter ?? ''}
          onChange={(e) => setHealthFilter(e.target.value || null)}
        >
          <option value="">All Statuses</option>
          {DEVICE_HEALTH_FILTERS.map((f) => (
            <option key={f.key} value={f.key}>
              {f.label}
            </option>
          ))}
        </select>
        <select
          className="form-select form-select-sm"
          style={{ minWidth: '140px' }}
          aria-label="Sort devices"
          value={sortBy}
          onChange={(e) => setSortBy(e.target.value as SortBy)}
        >
          <option value="severity">Severity</option>
          <option value="name">Name A-Z</option>
          <option value="cpu">CPU Usage</option>
          <option value="memory">Memory Usage</option>
        </select>
      </div>

      <div className="device-health-table-wrap">
        <DeviceHealthTable
          devices={filtered}
          emptyMessage={devices.length > 0 ? 'No devices match these filters' : 'No monitored devices yet'}
        />
      </div>
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

function DeviceHealthTable({ devices, emptyMessage }: { devices: DeviceHealth[]; emptyMessage: string }) {
  if (!devices.length) {
    return (
      <div className="empty-state">
        <p>{emptyMessage}</p>
      </div>
    );
  }

  return (
    <table className="data-table table-sticky">
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
          const statusLabel = HEALTH_LABELS[health];
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
                    <span style={{ color: 'var(--success)' }}>{d.if_up_count}▲</span>
                    {' / '}
                    <span style={{ color: 'var(--danger)' }}>{d.if_down_count ?? 0}▼</span>
                  </>
                ) : (
                  '-'
                )}
              </td>
              <td>{d.response_time_ms != null ? `${Math.round(d.response_time_ms)}ms` : '-'}</td>
              <td>{formatUptime(d.uptime_seconds)}</td>
              <td title={d.polled_at ?? ''}>{formatRelativeTime(d.polled_at)}</td>
            </tr>
          );
        })}
      </tbody>
    </table>
  );
}
