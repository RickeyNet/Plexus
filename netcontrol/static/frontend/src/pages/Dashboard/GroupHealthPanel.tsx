import { useMemo } from 'react';

import type { DashboardGroup, DeviceHealth } from '@/api/dashboard';

import {
  CRITICAL_DOWN_LABEL,
  HEALTH_COLORS,
  HEALTH_LABELS,
  PANEL_BODY_STYLE,
  countDeviceHealth,
} from './helpers';

const TILE_COLORS = HEALTH_COLORS;

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
    const byGroup = new Map<number | string, { name: string; devices: DeviceHealth[] }>();
    for (const g of groups) byGroup.set(g.id, { name: g.name, devices: [] });

    const UNGROUPED_KEY = '__ungrouped__';

    for (const d of devices) {
      const key = d.group_id ?? UNGROUPED_KEY;
      let bucket = byGroup.get(key);
      if (!bucket) {
        bucket = {
          name: d.group_name || (key === UNGROUPED_KEY ? 'Ungrouped' : `Group ${key}`),
          devices: [],
        };
        byGroup.set(key, bucket);
      }
      bucket.devices.push(d);
    }

    return Array.from(byGroup, ([id, { name, devices: members }]) => {
      const c = countDeviceHealth(members);
      return {
        id,
        name,
        total: members.length,
        healthy: c.healthy,
        warning: c.warning,
        bad: c.critical + c.down,
        unknown: c.unknown,
      };
    })
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
        <div className="dashboard-response-empty" style={PANEL_BODY_STYLE}>
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
          alignContent: 'start',
          gap: 12,
          // Same body height as the Overall Health donut beside it; scroll the rest.
          ...PANEL_BODY_STYLE,
          overflowY: 'auto',
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
        background: 'var(--bg-secondary)',
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
          background: 'var(--border-light)',
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
            <Dot color={TILE_COLORS.warning} /> {rollup.warning} {HEALTH_LABELS.warning}
          </span>
        )}
        {rollup.bad > 0 && (
          <span>
            <Dot color={TILE_COLORS.critical} /> {rollup.bad} {CRITICAL_DOWN_LABEL}
          </span>
        )}
        {rollup.unknown > 0 && (
          <span>
            <Dot color={TILE_COLORS.unknown} /> {rollup.unknown} {HEALTH_LABELS.unknown}
          </span>
        )}
        {rollup.warning === 0 && rollup.bad === 0 && rollup.unknown === 0 && (
          <span>
            <Dot color={TILE_COLORS.healthy} /> All healthy
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
