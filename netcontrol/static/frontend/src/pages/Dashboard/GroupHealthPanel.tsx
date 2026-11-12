import { useMemo } from 'react';

import type { DashboardGroup, DeviceHealth } from '@/api/dashboard';

import { CountLink } from './CountLink';
import { type DeviceHealthFilter, countDeviceHealthFilters, countNoun, healthTableLink } from './dashboardLinks';
import { CRITICAL_DOWN_LABEL, HEALTH_COLORS, HEALTH_LABELS, PANEL_BODY_STYLE, groupDevices } from './helpers';

const TILE_COLORS = HEALTH_COLORS;

interface GroupRollup {
  /** deviceGroupKey of its devices, the health table's group filter value. */
  key: string;
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
    return groupDevices(groups, devices).map(({ key, name, devices: members }) => {
      const c = countDeviceHealthFilters(members);
      return {
        key,
        name,
        total: members.length,
        healthy: c.healthy,
        warning: c.warning,
        bad: c.critical,
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
          <GroupTile key={r.key} rollup={r} />
        ))}
      </div>
    </div>
  );
}

function GroupTile({ rollup }: { rollup: GroupRollup }) {
  const okPct = rollup.total > 0 ? (rollup.healthy / rollup.total) * 100 : 0;
  // Each count opens the health table filtered to this group (and its bucket).
  const link = (health: DeviceHealthFilter | null, n: number) => (n > 0 ? healthTableLink({ group: rollup.key, health }) : null);
  const linkLabel = (n: number, what: string) => `Show ${countNoun(n, `${what}device`, `${what}devices`)} in ${rollup.name}`;
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
        <CountLink
          to={link(null, rollup.total)}
          label={linkLabel(rollup.total, '')}
          className="dashboard-group-name"
        >
          {rollup.name}
        </CountLink>
        <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>
          <CountLink to={link('healthy', rollup.healthy)} label={linkLabel(rollup.healthy, 'healthy ')}>
            {rollup.healthy}
          </CountLink>
          {' / '}
          <CountLink to={link(null, rollup.total)} label={linkLabel(rollup.total, '')}>
            {rollup.total}
          </CountLink>
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
          <CountLink to={link('warning', rollup.warning)} label={linkLabel(rollup.warning, 'warning ')}>
            <Dot color={TILE_COLORS.warning} /> {rollup.warning} {HEALTH_LABELS.warning}
          </CountLink>
        )}
        {rollup.bad > 0 && (
          <CountLink to={link('critical', rollup.bad)} label={linkLabel(rollup.bad, 'critical or down ')}>
            <Dot color={TILE_COLORS.critical} /> {rollup.bad} {CRITICAL_DOWN_LABEL}
          </CountLink>
        )}
        {rollup.unknown > 0 && (
          <CountLink to={link('unknown', rollup.unknown)} label={linkLabel(rollup.unknown, 'unknown ')}>
            <Dot color={TILE_COLORS.unknown} /> {rollup.unknown} {HEALTH_LABELS.unknown}
          </CountLink>
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
