import { useMemo } from 'react';
import { useNavigate } from 'react-router';

import { useLatestConfigBackupsPerHost } from '@/api/configuration';
import type { DashboardAlert, DashboardTopology, DeviceHealth } from '@/api/dashboard';
import type { TopologySource } from '@/api/meraki';

import { type Issue, buildIssues, issueSummary, watchedSummary } from './criticalIssues';

interface Props {
  devices: DeviceHealth[];
  alerts: DashboardAlert[];
  /** Topology sources; empty for users without the topology feature. */
  sources?: TopologySource[];
  /** Absent for users without the monitoring feature. */
  topology?: DashboardTopology;
}

const NO_SOURCES: TopologySource[] = [];

// At-a-glance triage of everything currently wrong, so a burst of errors can
// be sourced without scrolling and guessing. Each issue is a row that names
// what is affected and goes to the panel or page with the detail. With
// nothing wrong it says so, as long as something is being watched.
export function CriticalIssuesBanner({ devices, alerts, sources = NO_SOURCES, topology }: Props) {
  const backups = useLatestConfigBackupsPerHost();

  const issues = useMemo(
    () => buildIssues({ devices, alerts, backups: backups.data ?? [], sources, topology }),
    [devices, alerts, backups.data, sources, topology],
  );

  if (issues.length === 0) {
    const watched = watchedSummary({ devices, sources, topology });
    // Nothing watched yet is not "all clear"; neither is a backup check
    // that has not answered.
    if (!watched || backups.isPending) return null;
    return (
      <div className="glass-card card dashboard-issues dashboard-issues-clear" role="status">
        <CheckIcon />
        <strong>All clear</strong>
        <span className="text-muted">Nothing needs attention across {watched}.</span>
      </div>
    );
  }

  return (
    <div className="glass-card card dashboard-issues">
      <div className="dashboard-issues-header">
        <WarningIcon />
        <strong>Needs attention</strong>
        <span className="text-muted">
          {issues.length} {issues.length === 1 ? 'issue' : 'issues'} detected
        </span>
      </div>
      <ul className="dashboard-issues-list">
        {issues.map((issue) => (
          <li key={issue.key}>
            <IssueRow issue={issue} />
          </li>
        ))}
      </ul>
    </div>
  );
}

function IssueRow({ issue }: { issue: Issue }) {
  const navigate = useNavigate();
  const { target } = issue;
  return (
    <button
      type="button"
      className={`dashboard-issue dashboard-issue-${issue.severity}`}
      // The row names the first few; the tooltip lists every one it has.
      title={issue.items.join('\n') || undefined}
      onClick={() => (typeof target === 'string' ? scrollToAnchor(target) : navigate(target.to))}
    >
      <span className="dashboard-issue-dot" aria-hidden="true" />
      <span className="dashboard-issue-label">
        <strong>{issue.count}</strong> {issue.label}
      </span>
      <span className="dashboard-issue-detail text-muted">{issueSummary(issue)}</span>
      <span className="dashboard-issue-action">{issue.action} →</span>
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

function CheckIcon() {
  return (
    <svg
      width="18"
      height="18"
      viewBox="0 0 24 24"
      fill="none"
      stroke="var(--success)"
      strokeWidth={2}
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      <polyline points="20 6 9 17 4 12" />
    </svg>
  );
}

function scrollToAnchor(id: string) {
  const el = document.getElementById(id);
  if (!el) return;
  el.scrollIntoView({ behavior: 'smooth', block: 'start' });
}
