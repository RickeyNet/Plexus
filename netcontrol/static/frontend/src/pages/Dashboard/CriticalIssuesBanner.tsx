import { useMemo } from 'react';
import { useNavigate } from 'react-router';

import { useLatestConfigBackupsPerHost } from '@/api/configuration';
import type { DashboardAlert, DashboardTopology, DeviceHealth } from '@/api/dashboard';
import type { TopologySource } from '@/api/meraki';

import { rollUpBackups } from './backupRollup';
import { ISSUE_ANCHORS, classifyDeviceHealth } from './helpers';
import {
  SOURCES_LINK,
  TOPOLOGY_AVAILABILITY_LINK,
  describeProblem,
  sourceLabel,
  summarizeSources,
} from './sourceHealth';

type IssueSeverity = 'critical' | 'warning';

interface Issue {
  key: string;
  count: number;
  label: string;
  detail: string;
  severity: IssueSeverity;
  /** A Dashboard panel anchor (ISSUE_ANCHORS) to scroll to, or `to` another page. */
  target: string | { to: string };
}

const SEVERITY_COLORS: Record<IssueSeverity, string> = {
  critical: '#f44336',
  warning: '#ff9800',
};

interface Props {
  devices: DeviceHealth[];
  alerts: DashboardAlert[];
  /** Topology sources; empty for users without the topology feature. */
  sources?: TopologySource[];
  /** Absent for users without the monitoring feature. */
  topology?: DashboardTopology;
}

// At-a-glance triage of everything currently wrong on the dashboard, so a burst
// of errors can be sourced without scrolling and guessing. Each issue is a chip
// that scrolls to the panel with the detail. Renders nothing when all clear.
export function CriticalIssuesBanner({ devices, alerts, sources = [], topology }: Props) {
  const backups = useLatestConfigBackupsPerHost();

  const issues = useMemo<Issue[]>(() => {
    const out: Issue[] = [];

    // ── Unreachable / critically-degraded devices ───────────────────────────
    const down = devices.filter((d) => classifyDeviceHealth(d) === 'down');
    const critical = devices.filter((d) => classifyDeviceHealth(d) === 'critical');
    if (down.length > 0) {
      out.push({
        key: 'devices-down',
        count: down.length,
        label: down.length === 1 ? 'device unreachable' : 'devices unreachable',
        detail: hostList(down),
        severity: 'critical',
        target: ISSUE_ANCHORS.devices,
      });
    }
    if (critical.length > 0) {
      out.push({
        key: 'devices-critical',
        count: critical.length,
        label: critical.length === 1 ? 'device critical' : 'devices critical',
        detail: hostList(critical),
        severity: 'critical',
        target: ISSUE_ANCHORS.devices,
      });
    }

    // ── Interfaces down ─────────────────────────────────────────────────────
    const withDownIfaces = devices.filter((d) => (d.if_down_count ?? 0) > 0);
    const downIfaceTotal = withDownIfaces.reduce(
      (sum, d) => sum + (d.if_down_count ?? 0),
      0,
    );
    if (downIfaceTotal > 0) {
      out.push({
        key: 'interfaces-down',
        count: downIfaceTotal,
        label:
          downIfaceTotal === 1
            ? `interface down on ${withDownIfaces.length} ${pluralHost(withDownIfaces.length)}`
            : `interfaces down on ${withDownIfaces.length} ${pluralHost(withDownIfaces.length)}`,
        detail: withDownIfaces
          .map((d) => `${hostLabel(d)} (${d.if_down_count})`)
          .join(', '),
        severity: 'warning',
        target: ISSUE_ANCHORS.devices,
      });
    }

    // ── Failed backups ──────────────────────────────────────────────────────
    const failed = rollUpBackups(backups.data ?? [], devices).filter(
      (r) => r.state === 'failed',
    );
    if (failed.length > 0) {
      out.push({
        key: 'backups-failed',
        count: failed.length,
        label: failed.length === 1 ? 'backup failed' : 'backups failed',
        detail: failed.map((r) => r.hostname).join(', '),
        severity: 'critical',
        target: ISSUE_ANCHORS.backups,
      });
    }

    // ── Critical alerts ─────────────────────────────────────────────────────
    const critAlerts = alerts.filter((a) => {
      const sev = (a.severity ?? '').toLowerCase();
      return sev === 'critical' || sev === 'error';
    });
    if (critAlerts.length > 0) {
      out.push({
        key: 'alerts-critical',
        count: critAlerts.length,
        label: critAlerts.length === 1 ? 'critical alert' : 'critical alerts',
        detail: critAlerts
          .slice(0, 8)
          .map((a) => `${a.hostname ?? '-'}: ${a.message ?? a.metric ?? '-'}`)
          .join('\n'),
        severity: 'critical',
        target: ISSUE_ANCHORS.alerts,
      });
    }

    // ── Down / degraded integration entities ────────────────────────────────
    // Most have no inventory host, so they are not among the alerts above.
    const counts = topology?.entity_counts;
    const problems = topology?.problems ?? [];
    for (const state of ['down', 'degraded'] as const) {
      const count = counts?.[state] ?? 0;
      if (count === 0) continue;
      const shown = problems.filter((p) => p.state === state).slice(0, 8);
      const more = count - shown.length;
      out.push({
        key: `topology-${state}`,
        count,
        label: count === 1 ? `integration entity ${state}` : `integration entities ${state}`,
        detail: [...shown.map(describeProblem), ...(more > 0 ? [`and ${more} more`] : [])].join('\n'),
        severity: state === 'down' ? 'critical' : 'warning',
        target: { to: TOPOLOGY_AVAILABILITY_LINK },
      });
    }

    // ── Topology sources ────────────────────────────────────────────────────
    const health = summarizeSources(sources);
    const sourceIssues = [
      { key: 'failed', list: health.failed, one: 'source collection failed', many: 'source collections failed', severity: 'critical' },
      { key: 'partial', list: health.partial, one: 'source collected partially', many: 'sources collected partially', severity: 'warning' },
      { key: 'stale', list: health.stale, one: 'source not collected recently', many: 'sources not collected recently', severity: 'warning' },
      { key: 'warnings', list: health.warnings, one: 'source with collection warnings', many: 'sources with collection warnings', severity: 'warning' },
    ] as const;
    for (const { key, list, one, many, severity } of sourceIssues) {
      if (list.length === 0) continue;
      out.push({
        key: `sources-${key}`,
        count: list.length,
        label: list.length === 1 ? one : many,
        detail: list
          .map((s) => (s.message ? `${sourceLabel(s)} - ${s.message}` : sourceLabel(s)))
          .join('\n'),
        severity,
        target: { to: SOURCES_LINK },
      });
    }

    // Critical chips first, then by count descending.
    return out.sort((a, b) => {
      if (a.severity !== b.severity) return a.severity === 'critical' ? -1 : 1;
      return b.count - a.count;
    });
  }, [devices, alerts, backups.data, sources, topology]);

  if (issues.length === 0) return null;

  return (
    <div
      className="glass-card card"
      style={{ borderColor: 'var(--danger)', marginBottom: '1rem' }}
    >
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: '0.5rem',
          marginBottom: '0.6rem',
        }}
      >
        <WarningIcon />
        <strong>Needs attention</strong>
        <span style={{ color: 'var(--text-muted)', fontSize: '0.85em' }}>
          {issues.length} {issues.length === 1 ? 'issue' : 'issues'} detected
        </span>
      </div>
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.5rem' }}>
        {issues.map((issue) => (
          <IssueChip key={issue.key} issue={issue} />
        ))}
      </div>
    </div>
  );
}

function IssueChip({ issue }: { issue: Issue }) {
  const navigate = useNavigate();
  const color = SEVERITY_COLORS[issue.severity];
  const { target } = issue;
  return (
    <button
      type="button"
      title={issue.detail || undefined}
      onClick={() => (typeof target === 'string' ? scrollToAnchor(target) : navigate(target.to))}
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        gap: '0.45rem',
        padding: '0.3rem 0.7rem',
        borderRadius: 999,
        border: `1px solid ${color}`,
        background: `color-mix(in srgb, ${color} 12%, transparent)`,
        color: 'var(--text)',
        cursor: 'pointer',
        fontSize: '0.85em',
      }}
    >
      <span
        style={{
          width: 8,
          height: 8,
          borderRadius: '50%',
          background: color,
          flex: '0 0 auto',
        }}
      />
      <strong>{issue.count}</strong>
      <span>{issue.label}</span>
    </button>
  );
}

function WarningIcon() {
  return (
    <svg
      width="18"
      height="18"
      viewBox="0 0 24 24"
      fill="none"
      stroke="var(--danger)"
      strokeWidth={2}
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      <path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" />
      <line x1="12" y1="9" x2="12" y2="13" />
      <line x1="12" y1="17" x2="12.01" y2="17" />
    </svg>
  );
}

function scrollToAnchor(id: string) {
  const el = document.getElementById(id);
  if (!el) return;
  el.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function hostLabel(d: DeviceHealth): string {
  return d.hostname ?? d.ip_address ?? `Host ${d.host_id ?? '?'}`;
}

function hostList(devices: DeviceHealth[]): string {
  return devices.map(hostLabel).join(', ');
}

function pluralHost(n: number): string {
  return n === 1 ? 'host' : 'hosts';
}
