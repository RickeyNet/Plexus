import { useMemo } from 'react';

import type { DashboardGroup, DeviceHealth } from '@/api/dashboard';

import { classifyDeviceHealth, type HealthStatus } from './helpers';

const TILE_COLORS: Record<HealthStatus, string> = {
  healthy: '#4caf50',
  warning: '#ff9800',
  critical: '#f44336',
  down: '#b71c1c',
  unknown: '#9e9e9e',
};

interface GroupRollup {
  id: number | string;
  name: string;
  total: number;
  healthy: number;
  warning: number;
  bad: number;
  unknown: number;
}

interface GroupHealthPanelProps {
  groups: DashboardGroup[];
  devices: DeviceHealth[];
}

export function GroupHealthPanel({ groups, devices }: GroupHealthPanelProps) {
  const rollups = useMemo<GroupRollup[]>(() => {
    const byGroup = new Map<number | string, GroupRollup>();

    for (const g of groups) {
      byGroup.set(g.id, {
        id: g.id,
        name: g.name,
        total: 0,
        healthy: 0,
        warning: 0,
        bad: 0,
        unknown: 0,
      });
    }

    const UNGROUPED_KEY = '__ungrouped__';

    for (const d of devices) {
      const key = d.group_id ?? UNGROUPED_KEY;
      let bucket = byGroup.get(key);
      if (!bucket) {
        bucket = {
          id: key,
          name: d.group_name || (key === UNGROUPED_KEY ? 'Ungrouped' : `Group ${key}`),
          total: 0,
          healthy: 0,
          warning: 0,
          bad: 0,
          unknown: 0,
        };
        byGroup.set(key, bucket);
      }
      bucket.total += 1;
      const status = classifyDeviceHealth(d);
      if (status === 'healthy') bucket.healthy += 1;
      else if (status === 'warning') bucket.warning += 1;
      else if (status === 'critical' || status === 'down') bucket.bad += 1;
      else bucket.unknown += 1;
    }

    return Array.from(byGroup.values())
      .filter((r) => r.total > 0)
      .sort((a, b) => {
        // Groups with problems first, then by size, then alphabetical.
        const aBad = a.bad + a.warning;
        const bBad = b.bad + b.warning;
        if (aBad !== bBad) return bBad - aBad;
        if (a.total !== b.total) return b.total - a.total;
        return a.name.localeCompare(b.name);
      });
  }, [groups, devices]);

  if (rollups.length === 0) {
    return (
      <div className="glass-card card dashboard-overview-card">
        <h3 className="dashboard-overview-title">Group Health</h3>
        <div className="dashboard-response-empty">
          <p style={{ margin: 0, color: 'var(--text-muted)' }}>
            No device groups with polled devices yet.
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="glass-card card dashboard-overview-card">
      <h3 className="dashboard-overview-title">Group Health</h3>
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fill, minmax(200px, 1fr))',
          gap: 12,
        }}
      >
        {rollups.map((r) => (
          <GroupTile key={r.id} rollup={r} />
        ))}
      </div>
    </div>
  );
}

function GroupTile({ rollup }: { rollup: GroupRollup }) {
  const okPct = rollup.total > 0 ? (rollup.healthy / rollup.total) * 100 : 0;
  const accent =
    rollup.bad > 0 ? TILE_COLORS.critical : rollup.warning > 0 ? TILE_COLORS.warning : TILE_COLORS.healthy;

  return (
    <div
      style={{
        border: '1px solid var(--border)',
        borderLeft: `3px solid ${accent}`,
        borderRadius: 6,
        padding: '10px 12px',
        background: 'var(--bg-secondary, transparent)',
      }}
    >
      <div
        style={{
          display: 'flex',
          alignItems: 'baseline',
          justifyContent: 'space-between',
          gap: 8,
          marginBottom: 6,
        }}
      >
        <span
          style={{
            fontWeight: 600,
            color: 'var(--text)',
            overflow: 'hidden',
            textOverflow: 'ellipsis',
            whiteSpace: 'nowrap',
          }}
          title={rollup.name}
        >
          {rollup.name}
        </span>
        <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>
          {rollup.healthy} / {rollup.total}
        </span>
      </div>

      <div
        style={{
          display: 'flex',
          height: 6,
          borderRadius: 3,
          overflow: 'hidden',
          background: 'var(--border-light, var(--border))',
          marginBottom: 8,
        }}
        aria-label={`${okPct.toFixed(0)}% healthy`}
      >
        <Bar value={rollup.healthy} total={rollup.total} color={TILE_COLORS.healthy} />
        <Bar value={rollup.warning} total={rollup.total} color={TILE_COLORS.warning} />
        <Bar value={rollup.bad} total={rollup.total} color={TILE_COLORS.critical} />
        <Bar value={rollup.unknown} total={rollup.total} color={TILE_COLORS.unknown} />
      </div>

      <div style={{ display: 'flex', gap: 10, fontSize: 12, color: 'var(--text-muted)' }}>
        {rollup.warning > 0 && (
          <span>
            <Dot color={TILE_COLORS.warning} /> {rollup.warning} warn
          </span>
        )}
        {rollup.bad > 0 && (
          <span>
            <Dot color={TILE_COLORS.critical} /> {rollup.bad} down
          </span>
        )}
        {rollup.unknown > 0 && (
          <span>
            <Dot color={TILE_COLORS.unknown} /> {rollup.unknown} unknown
          </span>
        )}
        {rollup.warning === 0 && rollup.bad === 0 && rollup.unknown === 0 && (
          <span>
            <Dot color={TILE_COLORS.healthy} /> all healthy
          </span>
        )}
      </div>
    </div>
  );
}

function Bar({ value, total, color }: { value: number; total: number; color: string }) {
  if (value <= 0 || total <= 0) return null;
  return <span style={{ flexBasis: `${(value / total) * 100}%`, background: color }} />;
}

function Dot({ color }: { color: string }) {
  return (
    <span
      style={{
        display: 'inline-block',
        width: 8,
        height: 8,
        borderRadius: '50%',
        background: color,
        marginRight: 4,
        verticalAlign: 'middle',
      }}
    />
  );
}
