import { useMemo } from 'react';

import { useLatestConfigBackupsPerHost } from '@/api/configuration';
import type { DashboardAlert, DeviceHealth } from '@/api/dashboard';

import { rollUpBackups } from './backupRollup';
import { classifyDeviceHealth } from './helpers';

// Anchor ids the chips scroll to. The Dashboard wraps each target panel in a
// div carrying the matching id (see Dashboard.tsx).
export const ISSUE_ANCHORS = {
  devices: 'dashboard-devices',
  backups: 'dashboard-backups',
  alerts: 'dashboard-alerts',
} as const;

type IssueSeverity = 'critical' | 'warning';

interface Issue {
  key: string;
  count: number;
  label: string;
  detail: string;
  severity: IssueSeverity;
  target: string;
}

const SEVERITY_COLORS: Record<IssueSeverity, string> = {
  critical: '#f44336',
  warning: '#ff9800',
};

interface Props {
  devices: DeviceHealth[];
  alerts: DashboardAlert[];
}

// At-a-glance triage of everything currently wrong on the dashboard, so a burst
// of errors can be sourced without scrolling and guessing. Each issue is a chip
// that scrolls to the panel with the detail. Renders nothing when all clear.
export function CriticalIssuesBanner({ devices, alerts }: Props) {
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

    // Critical chips first, then by count descending.
    return out.sort((a, b) => {
      if (a.severity !== b.severity) return a.severity === 'critical' ? -1 : 1;
      return b.count - a.count;
    });
  }, [devices, alerts, backups.data]);

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
  const color = SEVERITY_COLORS[issue.severity];
  return (
    <button
      type="button"
      title={issue.detail || undefined}
      onClick={() => scrollToAnchor(issue.target)}
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
