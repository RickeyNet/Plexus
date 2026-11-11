import { useMemo, useState, type ReactNode } from 'react';

import { useAuthStatus } from '@/api/auth';
import {
  ComplianceAssignment,
  ComplianceHostStatus,
  ComplianceProfile,
  ComplianceScanResult,
  useComplianceAssignments,
  useComplianceHostStatus,
  useComplianceProfiles,
  useComplianceScanResults,
  useComplianceSummary,
  useDeleteAssignment,
  useDeleteProfile,
  useLoadBuiltinProfiles,
  useMerakiSummary,
  useScanAssignmentNow,
  useUpdateAssignment,
} from '@/api/compliance';
import { SeverityBadge, StatusBadge } from '@/components/Badge';
import { BusyButton } from '@/components/BusyButton';
import { DataTable } from '@/components/DataTable';
import { DeleteButton } from '@/components/DeleteButton';
import { EmptyState } from '@/components/EmptyState';
import { LoadingState } from '@/components/LoadingState';
import { PageHeader } from '@/components/PageHeader';
import { PageHelp } from '@/components/PageHelp';
import { QueryError } from '@/components/QueryError';
import { useDialogs } from '@/components/DialogProvider-context';
import { ShowMoreButton } from '@/components/ShowMoreButton';
import { SortableTh } from '@/components/SortableTh';
import { SummaryStrip } from '@/components/SummaryStrip';
import { TabBar } from '@/components/TabBar';
import { complianceStatusRank } from '@/lib/severity';
import { visibleTabs } from '@/lib/tabGating';
import { usePathTab } from '@/lib/usePathTab';
import { usePendingKeys } from '@/lib/usePendingKeys';
import { useShowMore } from '@/lib/useShowMore';
import {
  compareDate,
  compareNumber,
  compareText,
  passRatio,
  useTableSort,
  type Comparator,
  type SortDir,
  type SortState,
} from '@/lib/useTableSort';

import { AuditContent } from '@/pages/Audit/Audit';
import { formatBackendDateTime, formatInterval, parseBackendDate } from '@/lib/datetime';

import { AssignProfileModal, EditProfileModal, NewProfileModal } from './ProfileModals';
import { FindingsModal } from './FindingsModal';
import { HostScanProgress } from './HostScanProgress';
import { MerakiTab } from './MerakiTab';
import { RunScanModal } from './RunScanModal';
import { RESULTS_TABLE_MAX_HEIGHT } from './scanHelpers';

type Tab = 'profiles' | 'assignments' | 'results' | 'status' | 'meraki' | 'audit';

// Each tab is gated on the feature its API needs. The CIS Audit tab (the
// former /audit page) is served by the audit router, which is gated on
// `reports`; the sidebar shows Compliance for either feature.
const TABS: { key: Tab; label: string; feature: string }[] = [
  { key: 'profiles', label: 'Profiles', feature: 'compliance' },
  { key: 'assignments', label: 'Assignments', feature: 'compliance' },
  { key: 'results', label: 'Scan Results', feature: 'compliance' },
  { key: 'status', label: 'Host Status', feature: 'compliance' },
  { key: 'meraki', label: 'Meraki', feature: 'compliance' },
  { key: 'audit', label: 'CIS Audit', feature: 'reports' },
];
const TAB_KEYS = TABS.map((t) => t.key);

const TAB_HELP: Record<Tab, { title: string; text: string }> = {
  profiles: {
    title: 'Compliance Profiles',
    text: 'A profile is a named set of rules - text patterns the running config must match (or must not match). Build your own or load the built-in CIS/STIG-style profiles to start.',
  },
  assignments: {
    title: 'Profile Assignments',
    text: 'Bind a profile to an inventory group on a schedule. Assignments are how scans actually happen - without one, profiles just sit there.',
  },
  results: {
    title: 'Scan Results',
    text: 'Per-scan outcome rows: which host, which profile, how many rules passed, when it ran. Click into a result with violations to see the exact failing lines.',
  },
  status: {
    title: 'Per-Host Compliance Status',
    text: 'Latest status for each host across all profiles assigned to it. Use this when you want to answer "is this device clean?" without digging through scan history.',
  },
  meraki: {
    title: 'Meraki Organizations',
    text: 'Meraki has no running config, so profiles carry rules of type "meraki" that check the Dashboard API configuration: DHCP server policy (DHCP snooping), port access policies (port security), BPDU/root guard, storm control, IPS/AMP, SSID security, dashboard login security. Assign such a profile to an organization registered on the Topology page; scans use its stored API key, read-only, and report per organization, network, switch and SSID. Load Built-in adds four Meraki baselines.',
  },
  audit: {
    title: 'CIS Security Audit',
    text: 'A built-in rule engine that grades the live inventory - not just configs - against CIS-Controls-mapped checks: configuration drift, port hygiene, VLAN consistency and security posture. Run it on demand or on a schedule, then review findings by severity and mute the ones you accept.',
  },
};

// Sortable columns of the host Scan Results and Host Status tables. Status
// sorts worst first (non-compliant, error, compliant), score by pass ratio.
type HostSortKey = 'status' | 'host' | 'ip' | 'profile' | 'score' | 'scanned';

const HOST_COMPARATORS: Record<HostSortKey, Comparator<ComplianceHostStatus>> = {
  status: (a, b) => complianceStatusRank(a.status) - complianceStatusRank(b.status),
  host: (a, b) => compareText(a.hostname, b.hostname),
  ip: (a, b) => compareText(a.ip_address, b.ip_address),
  profile: (a, b) => compareText(a.profile_name, b.profile_name),
  score: (a, b) => compareNumber(passRatio(a.passed_rules, a.total_rules), passRatio(b.passed_rules, b.total_rules)),
  scanned: (a, b) => compareDate(a.scanned_at, b.scanned_at),
};
const HOST_FIRST_DIR: Partial<Record<HostSortKey, SortDir>> = { scanned: 'desc' };
const byHostname: Comparator<ComplianceHostStatus> = (a, b) =>
  compareText(a.hostname, b.hostname) || compareText(a.profile_name, b.profile_name);

export function Compliance() {
  const { alert } = useDialogs();
  const { data: auth } = useAuthStatus();

  const shownTabs = visibleTabs(TABS, auth);
  const [shownTab, selectTab] = usePathTab(
    '/compliance',
    TAB_KEYS,
    'profiles',
    auth ? shownTabs.map((t) => t.key) : undefined,
  );
  const isAudit = shownTab === 'audit';

  const [query, setQuery] = useState('');
  const [showNewProfile, setShowNewProfile] = useState(false);
  const [editProfileId, setEditProfileId] = useState<number | null>(null);
  const [assignProfileId, setAssignProfileId] = useState<number | null>(null);
  const [showRunScan, setShowRunScan] = useState(false);
  const [findingsResultId, setFindingsResultId] = useState<number | null>(null);

  const summary = useComplianceSummary();
  const profiles = useComplianceProfiles();
  const assignments = useComplianceAssignments();
  const results = useComplianceScanResults(200);
  const status = useComplianceHostStatus();
  const merakiSummary = useMerakiSummary();
  const loadBuiltin = useLoadBuiltinProfiles();

  return (
    <div>
      <PageHeader title="Compliance">
        {!isAudit && (
          <>
            <button className="btn btn-sm btn-primary" onClick={() => setShowRunScan(true)}>
              Run Scan
            </button>
            <button className="btn btn-sm btn-secondary" onClick={() => setShowNewProfile(true)}>
              New Profile
            </button>
            <button
              className="btn btn-sm btn-secondary"
              onClick={() => {
                loadBuiltin.mutate(undefined, {
                  onSuccess: (res) => {
                    if (res.loaded > 0) {
                      void alert({
                        title: 'Built-in profiles loaded',
                        message: `Loaded ${res.loaded} built-in profile(s).${res.skipped > 0 ? ` ${res.skipped} already existed.` : ''}`,
                      });
                    } else {
                      void alert({
                        title: 'Built-in profiles loaded',
                        message: `All ${res.total_available} built-in profiles already loaded.`,
                      });
                    }
                  },
                  onError: (e) =>
                    void alert({
                      title: 'Load failed',
                      message: (e as Error).message,
                      variant: 'error',
                    }),
                });
              }}
              disabled={loadBuiltin.isPending}
            >
              {loadBuiltin.isPending ? 'Loading…' : 'Load Built-in'}
            </button>
          </>
        )}
      </PageHeader>

      <PageHelp
        pageKey="compliance"
        title="Policy Compliance Auditing"
        text="Define compliance rules and run audits against your devices. Check configurations against security policies, best practices, and industry standards."
      />

      {!isAudit && (
        <div style={{ marginBottom: 'var(--space-4)' }}>
          <ComplianceSummaryStrip summary={summary.data} meraki={merakiSummary.data} />
        </div>
      )}

      {/* The audit tab has its own severity / category filters, so no search box. */}
      <TabBar
        tabs={shownTabs}
        active={shownTab}
        onChange={selectTab}
        aria-label="Compliance sections"
        trailing={
          !isAudit && (
            <input
              className="form-input"
              placeholder="Search…"
              aria-label="Search compliance"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              style={{ maxWidth: 240 }}
            />
          )
        }
      />

      <PageHelp pageKey={`compliance.${shownTab}`} title={TAB_HELP[shownTab].title} text={TAB_HELP[shownTab].text} />

      <div className="stack stack-sm">
        {shownTab === 'profiles' &&
          (profiles.isError && !profiles.data ? (
            <QueryError what="compliance profiles" query={profiles} />
          ) : (
            <ProfilesTab
              profiles={profiles.data || []}
              loading={profiles.isLoading}
              query={query}
              onEdit={setEditProfileId}
              onAssign={setAssignProfileId}
            />
          ))}
        {shownTab === 'assignments' &&
          (assignments.isError && !assignments.data ? (
            <QueryError what="compliance assignments" query={assignments} />
          ) : (
            <AssignmentsTab
              assignments={assignments.data || []}
              loading={assignments.isLoading}
              query={query}
              onShowResults={() => selectTab('results')}
            />
          ))}
        {shownTab === 'results' &&
          (results.isError && !results.data ? (
            <QueryError what="scan results" query={results} />
          ) : (
            <ResultsTab
              results={results.data || []}
              loading={results.isLoading}
              query={query}
              onShowFindings={setFindingsResultId}
            />
          ))}
        {shownTab === 'status' &&
          (status.isError && !status.data ? (
            <QueryError what="host compliance status" query={status} />
          ) : (
            <StatusTab status={status.data || []} loading={status.isLoading} query={query} />
          ))}
        {shownTab === 'meraki' && <MerakiTab query={query} />}
        {shownTab === 'audit' && <AuditContent />}
      </div>

      {showNewProfile && <NewProfileModal onClose={() => setShowNewProfile(false)} />}
      {editProfileId != null && (
        <EditProfileModal
          profileId={editProfileId}
          onClose={() => setEditProfileId(null)}
        />
      )}
      {assignProfileId != null && (
        <AssignProfileModal
          profileId={assignProfileId}
          onClose={() => setAssignProfileId(null)}
        />
      )}
      {showRunScan && <RunScanModal onClose={() => setShowRunScan(false)} />}
      {findingsResultId != null && (
        <FindingsModal
          resultId={findingsResultId}
          onClose={() => setFindingsResultId(null)}
          onRescan={(newId) => setFindingsResultId(newId)}
        />
      )}
    </div>
  );
}

function ComplianceSummaryStrip({
  summary,
  meraki,
}: {
  summary?: { total_profiles?: number; active_assignments?: number; hosts_scanned?: number; hosts_non_compliant?: number; last_scan_at?: string | null };
  meraki?: { active_assignments: number; targets_scanned: number; targets_non_compliant: number; last_scan_at: string | null };
}) {
  const lastHost = parseBackendDate(summary?.last_scan_at);
  const lastMeraki = parseBackendDate(meraki?.last_scan_at);
  const last =
    lastHost && lastMeraki ? (lastHost > lastMeraki ? lastHost : lastMeraki) : lastHost || lastMeraki;
  const items: { label: string; value: string }[] = [
    { label: 'Profiles', value: String(summary?.total_profiles ?? '-') },
    {
      label: 'Assignments',
      value: `${summary?.active_assignments ?? '-'}${meraki && meraki.active_assignments > 0 ? ` + ${meraki.active_assignments} Meraki` : ''}`,
    },
    { label: 'Hosts scanned', value: String(summary?.hosts_scanned ?? '-') },
    { label: 'Non-compliant', value: String(summary?.hosts_non_compliant ?? '-') },
    { label: 'Meraki targets', value: String(meraki?.targets_scanned ?? '-') },
    { label: 'Meraki non-compliant', value: String(meraki?.targets_non_compliant ?? '-') },
    {
      label: 'Last scan',
      value: formatBackendDateTime(last, 'Never'),
    },
  ];
  return <SummaryStrip items={items} />;
}

function ProfilesTab({
  profiles,
  loading,
  query,
  onEdit,
  onAssign,
}: {
  profiles: ComplianceProfile[];
  loading: boolean;
  query: string;
  onEdit: (id: number) => void;
  onAssign: (id: number) => void;
}) {
  const { confirm, alert } = useDialogs();
  const remove = useDeleteProfile();
  const deleting = usePendingKeys<number>();
  const filtered = useMemo(() => {
    if (!query.trim()) return profiles;
    const q = query.toLowerCase();
    return profiles.filter(
      (p) =>
        p.name.toLowerCase().includes(q) ||
        (p.description || '').toLowerCase().includes(q),
    );
  }, [profiles, query]);

  if (loading) return <LoadingState text="Loading profiles…" />;
  if (!filtered.length) {
    return (
      <p className="text-muted">No compliance profiles. Click "New Profile" to create one.</p>
    );
  }

  return (
    <>
      {filtered.map((p) => {
        let rules: { name?: string; pattern?: string }[];
        try {
          rules = JSON.parse(p.rules || '[]');
        } catch {
          rules = [];
        }
        const ruleNames = rules.map((r) => r.name || r.pattern || '?').join(', ');
        return (
          <div key={p.id} className="card">
            <div
              style={{
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
                flexWrap: 'wrap',
                gap: '0.5rem',
              }}
            >
              <div>
                <strong>{p.name}</strong>
                <SeverityBadge severity={p.severity} style={{ marginLeft: '0.5rem' }} />
                <span
                  style={{
                    marginLeft: '0.5rem',
                    fontSize: '0.85em',
                    color: 'var(--text-muted)',
                  }}
                >
                  {rules.length} rules, {p.assignment_count || 0} assignments
                </span>
              </div>
              <div style={{ display: 'flex', gap: '0.4rem' }}>
                <button className="btn btn-sm btn-secondary" onClick={() => onEdit(p.id)}>
                  Edit
                </button>
                <button className="btn btn-sm btn-secondary" onClick={() => onAssign(p.id)}>
                  Assign
                </button>
                <DeleteButton
                  busy={deleting.isPending(p.id)}
                  onClick={async () => {
                    if (
                      await confirm({
                        title: 'Delete compliance profile',
                        message: `Delete compliance profile "${p.name}" and all its assignments and scan results?`,
                        confirmLabel: 'Delete',
                      })
                    ) {
                      await deleting.run(p.id, async () => {
                        try {
                          await remove.mutateAsync(p.id);
                        } catch (e) {
                          void alert({
                            title: 'Delete failed',
                            message: (e as Error).message,
                            variant: 'error',
                          });
                        }
                      });
                    }
                  }}
                />
              </div>
            </div>
            {p.description && (
              <div
                style={{
                  marginTop: '0.5rem',
                  fontSize: '0.9em',
                  color: 'var(--text-muted)',
                }}
              >
                {p.description}
              </div>
            )}
            {rules.length > 0 && (
              <div
                className="line-clamp-2"
                title={ruleNames}
                style={{
                  marginTop: '0.5rem',
                  fontSize: '0.85em',
                  color: 'var(--text-muted)',
                }}
              >
                Rules: {ruleNames}
              </div>
            )}
          </div>
        );
      })}
    </>
  );
}

function AssignmentsTab({
  assignments,
  loading,
  query,
  onShowResults,
}: {
  assignments: ComplianceAssignment[];
  loading: boolean;
  query: string;
  onShowResults: () => void;
}) {
  const { confirm, alert } = useDialogs();
  const toggle = useUpdateAssignment();
  const remove = useDeleteAssignment();
  const scanNow = useScanAssignmentNow();
  const pending = usePendingKeys<string>();
  // The scan started last; it runs server-side and reports in a banner.
  const [jobId, setJobId] = useState<string | null>(null);

  const filtered = useMemo(() => {
    if (!query.trim()) return assignments;
    const q = query.toLowerCase();
    return assignments.filter(
      (a) =>
        (a.profile_name || '').toLowerCase().includes(q) ||
        (a.group_name || '').toLowerCase().includes(q),
    );
  }, [assignments, query]);

  // Shown above the list (and above an empty search result: the scan keeps going).
  const progress = jobId && (
    <HostScanProgress jobId={jobId} onDismiss={() => setJobId(null)} onShowResults={onShowResults} />
  );

  if (loading) return <LoadingState text="Loading assignments…" />;
  if (!filtered.length) {
    return (
      <>
        {progress}
        <EmptyState compact message="No compliance assignments. Assign a profile to an inventory group to start scanning." />
      </>
    );
  }

  return (
    <>
      {progress}
      {filtered.map((a) => {
        const lastScan = formatBackendDateTime(a.last_scan_at, 'Never');
        return (
          <div key={a.id} className="card">
            <div
              style={{
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
                flexWrap: 'wrap',
                gap: '0.5rem',
              }}
            >
              <div>
                <strong>{a.profile_name || '?'}</strong>
                <span
                  style={{
                    marginLeft: '0.5rem',
                    fontSize: '0.85em',
                    color: 'var(--text-muted)',
                  }}
                >
                  → {a.group_name || '?'} ({a.host_count || 0} hosts)
                </span>
              </div>
              <div style={{ display: 'flex', gap: '0.4rem' }}>
                <BusyButton
                  className="btn btn-sm btn-primary"
                  title="Scan all hosts in this assignment now"
                  busy={pending.isPending(`scan:${a.id}`)}
                  busyLabel="Starting…"
                  onClick={async () => {
                    if (
                      await confirm({
                        title: 'Run compliance scan',
                        message: `Scan all hosts in group "${a.group_name || '?'}" against profile "${a.profile_name || '?'}" now? The scan runs in the background; progress shows above the list.`,
                        confirmLabel: 'Scan now',
                        confirmVariant: 'primary',
                      })
                    ) {
                      await pending.run(`scan:${a.id}`, async () => {
                        try {
                          const res = await scanNow.mutateAsync(a.id);
                          setJobId(res.job_id);
                        } catch (e) {
                          void alert({
                            title: 'Scan failed to start',
                            message: `Assignment scan failed to start: ${(e as Error).message}`,
                            variant: 'error',
                          });
                        }
                      });
                    }
                  }}
                >
                  Scan Now
                </BusyButton>
                <BusyButton
                  className="btn btn-sm btn-secondary"
                  busy={pending.isPending(`toggle:${a.id}`)}
                  onClick={() =>
                    void pending.run(`toggle:${a.id}`, async () => {
                      try {
                        await toggle.mutateAsync({ id: a.id, data: { enabled: !a.enabled } });
                      } catch (e) {
                        void alert({
                          title: 'Update failed',
                          message: (e as Error).message,
                          variant: 'error',
                        });
                      }
                    })
                  }
                >
                  {a.enabled ? 'Disable' : 'Enable'}
                </BusyButton>
                <DeleteButton
                  busy={pending.isPending(`delete:${a.id}`)}
                  onClick={async () => {
                    if (
                      await confirm({
                        title: 'Delete compliance assignment',
                        message: `Delete the assignment of profile "${a.profile_name || '?'}" to group "${a.group_name || '?'}"?`,
                        confirmLabel: 'Delete',
                      })
                    ) {
                      await pending.run(`delete:${a.id}`, async () => {
                        try {
                          await remove.mutateAsync(a.id);
                        } catch (e) {
                          void alert({
                            title: 'Delete failed',
                            message: (e as Error).message,
                            variant: 'error',
                          });
                        }
                      });
                    }
                  }}
                />
              </div>
            </div>
            <div
              style={{
                marginTop: '0.5rem',
                fontSize: '0.85em',
                color: 'var(--text-muted)',
              }}
            >
              {a.enabled ? (
                <span style={{ color: 'var(--success)' }}>Enabled</span>
              ) : (
                <span>Disabled</span>
              )}{' '}
              · Every {formatInterval(a.interval_seconds)} · Last scan: {lastScan}
            </div>
          </div>
        );
      })}
    </>
  );
}

function ResultsTab({
  results,
  loading,
  query,
  onShowFindings,
}: {
  results: ComplianceScanResult[];
  loading: boolean;
  query: string;
  onShowFindings: (id: number) => void;
}) {
  const filtered = useMemo(() => {
    if (!query.trim()) return results;
    const q = query.toLowerCase();
    return results.filter(
      (r) =>
        (r.hostname || '').toLowerCase().includes(q) ||
        (r.profile_name || '').toLowerCase().includes(q),
    );
  }, [results, query]);

  if (loading) return <LoadingState text="Loading scan results…" />;
  if (!filtered.length) {
    return <EmptyState compact message="No scan results yet. Run a compliance scan." />;
  }

  return (
    <HostResultsTable
      rows={filtered}
      rowKey={(r) => r.id}
      initialSort={{ key: 'scanned', dir: 'desc' }}
      label="Compliance scan results"
      action={(r) =>
        r.failed_rules > 0 && (
          <button className="btn btn-sm btn-secondary" onClick={() => onShowFindings(r.id)}>
            View {r.failed_rules} violation(s)
          </button>
        )
      }
    />
  );
}

function StatusTab({
  status,
  loading,
  query,
}: {
  status: ComplianceHostStatus[];
  loading: boolean;
  query: string;
}) {
  const filtered = useMemo(() => {
    if (!query.trim()) return status;
    const q = query.toLowerCase();
    return status.filter(
      (s) =>
        (s.hostname || '').toLowerCase().includes(q) ||
        (s.profile_name || '').toLowerCase().includes(q),
    );
  }, [status, query]);

  if (loading) return <LoadingState text="Loading host status…" />;
  if (!filtered.length) {
    return <EmptyState compact message="No compliance status data. Scan some hosts first." />;
  }

  return (
    <HostResultsTable
      rows={filtered}
      rowKey={(s) => `${s.hostname ?? ''}|${s.ip_address ?? ''}|${s.profile_name ?? ''}`}
      initialSort={{ key: 'status', dir: 'asc' }}
      label="Per-host compliance status"
    />
  );
}

/**
 * Host compliance rows (scan results or latest status per host) as a
 * sortable table, rendered in pages of 200 after filtering and sorting.
 */
function HostResultsTable<T extends ComplianceHostStatus>({
  rows,
  rowKey,
  initialSort,
  label,
  action,
}: {
  rows: T[];
  rowKey: (row: T) => string | number;
  initialSort: SortState<HostSortKey>;
  label: string;
  /** Trailing action cell; omit for a table without one. */
  action?: (row: T) => ReactNode;
}) {
  const { rows: sorted, sort, toggle } = useTableSort<T, HostSortKey>(rows, HOST_COMPARATORS, initialSort, {
    firstDir: HOST_FIRST_DIR,
    tieBreak: byHostname,
  });
  const { visible, hiddenCount, showMore } = useShowMore(sorted);
  const th = (key: HostSortKey, text: string) => (
    <SortableTh sortKey={key} sort={sort} onSort={toggle}>
      {text}
    </SortableTh>
  );

  return (
    <>
      <DataTable compact stickyHeader maxHeight={RESULTS_TABLE_MAX_HEIGHT} aria-label={label}>
        <thead>
          <tr>
            {th('status', 'Status')}
            {th('host', 'Host')}
            {th('ip', 'IP')}
            {th('profile', 'Profile')}
            {th('score', 'Score')}
            {th('scanned', 'Scanned')}
            {action && <th aria-label="Actions" />}
          </tr>
        </thead>
        <tbody>
          {visible.map((r) => (
            <tr key={rowKey(r)}>
              <td>
                <StatusBadge status={r.status} kind="compliance" size="sm" />
              </td>
              <td>
                <strong>{r.hostname || '?'}</strong>
              </td>
              <td className="text-muted">{r.ip_address || '-'}</td>
              <td>{r.profile_name || '?'}</td>
              <td style={{ whiteSpace: 'nowrap' }}>
                {r.passed_rules}/{r.total_rules} passed
              </td>
              <td style={{ whiteSpace: 'nowrap' }}>{formatBackendDateTime(r.scanned_at)}</td>
              {action && <td style={{ whiteSpace: 'nowrap', textAlign: 'right' }}>{action(r)}</td>}
            </tr>
          ))}
        </tbody>
      </DataTable>
      <ShowMoreButton hiddenCount={hiddenCount} onClick={showMore} style={{ alignSelf: 'flex-start' }} />
    </>
  );
}
