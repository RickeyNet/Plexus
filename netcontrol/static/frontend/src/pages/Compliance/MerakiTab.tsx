import { useMemo, useState, type ReactNode } from 'react';

import {
  MerakiAssignment,
  MerakiResult,
  useDeleteMerakiAssignment,
  useMerakiAssignments,
  useMerakiResults,
  useMerakiStatus,
  useScanMerakiAssignmentNow,
  useUpdateMerakiAssignment,
} from '@/api/compliance';
import { Badge, StatusBadge } from '@/components/Badge';
import { BusyButton } from '@/components/BusyButton';
import { DataTable } from '@/components/DataTable';
import { DeleteButton } from '@/components/DeleteButton';
import { useDialogs } from '@/components/DialogProvider-context';
import { EmptyState } from '@/components/EmptyState';
import { LoadingState } from '@/components/LoadingState';
import { QueryError } from '@/components/QueryError';
import { SegmentedControl } from '@/components/SegmentedControl';
import { ShowMoreButton } from '@/components/ShowMoreButton';
import { SortableTh } from '@/components/SortableTh';
import { formatBackendDateTime, formatInterval } from '@/lib/datetime';
import { complianceStatusRank } from '@/lib/severity';
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

import { MerakiAssignModal } from './MerakiAssignModal';
import { MerakiFindingsModal } from './MerakiFindingsModal';
import { MerakiScanProgress } from './MerakiScanProgress';
import { MERAKI_KIND_SHORT_LABEL } from './merakiHelpers';
import { RESULTS_TABLE_MAX_HEIGHT } from './scanHelpers';

// Sortable columns of the Target Status and Scan Results tables. Status sorts
// worst first (non-compliant, error, compliant), score by pass ratio.
type TargetSortKey = 'status' | 'target' | 'org' | 'profile' | 'score' | 'scanned';

const TARGET_COMPARATORS: Record<TargetSortKey, Comparator<MerakiResult>> = {
  status: (a, b) => complianceStatusRank(a.status) - complianceStatusRank(b.status),
  target: (a, b) => compareText(a.target_name, b.target_name),
  org: (a, b) => compareText(a.org_name, b.org_name),
  profile: (a, b) => compareText(a.profile_name, b.profile_name),
  score: (a, b) => compareNumber(passRatio(a.passed_rules, a.total_rules), passRatio(b.passed_rules, b.total_rules)),
  scanned: (a, b) => compareDate(a.scanned_at, b.scanned_at),
};
const TARGET_FIRST_DIR: Partial<Record<TargetSortKey, SortDir>> = { scanned: 'desc' };
const byTargetName: Comparator<MerakiResult> = (a, b) =>
  compareText(a.org_name, b.org_name) ||
  compareText(a.target_name, b.target_name) ||
  compareText(a.profile_name, b.profile_name);

type View = 'assignments' | 'status' | 'results';

const VIEWS: { key: View; label: string }[] = [
  { key: 'assignments', label: 'Assignments' },
  { key: 'status', label: 'Target Status' },
  { key: 'results', label: 'Scan Results' },
];

/**
 * Meraki organizations scanned against profiles with "meraki" rules: the
 * assignments (with Scan Now as a background job), the latest status per
 * target (organization / network / switch) and the recent results.
 */
export function MerakiTab({ query }: { query: string }) {
  const [view, setView] = useState<View>('assignments');
  const [showAssign, setShowAssign] = useState(false);
  const [jobId, setJobId] = useState<string | null>(null);
  const [findingsId, setFindingsId] = useState<number | null>(null);
  const [scanFilter, setScanFilter] = useState<string | null>(null);

  const assignments = useMerakiAssignments();
  const status = useMerakiStatus();
  const results = useMerakiResults(500);

  return (
    <div className="stack stack-sm">
      <div className="toolbar">
        <SegmentedControl options={VIEWS} value={view} onChange={setView} aria-label="Meraki view" />
        <span className="toolbar-spacer" />
        <button type="button" className="btn btn-sm btn-secondary" onClick={() => setShowAssign(true)}>
          Assign to Organization
        </button>
      </div>

      {jobId && (
        <MerakiScanProgress
          jobId={jobId}
          onDismiss={() => setJobId(null)}
          onShowResults={(scanId) => {
            setScanFilter(scanId);
            setView('results');
          }}
        />
      )}

      {view === 'assignments' &&
        (assignments.isError && !assignments.data ? (
          <QueryError what="Meraki assignments" query={assignments} />
        ) : (
          <AssignmentsView
            assignments={assignments.data || []}
            loading={assignments.isLoading}
            query={query}
            onScanStarted={setJobId}
          />
        ))}
      {view === 'status' &&
        (status.isError && !status.data ? (
          <QueryError what="Meraki target status" query={status} />
        ) : (
          <StatusView
            status={status.data || []}
            loading={status.isLoading}
            query={query}
            onShowFindings={setFindingsId}
          />
        ))}
      {view === 'results' &&
        (results.isError && !results.data ? (
          <QueryError what="Meraki scan results" query={results} />
        ) : (
          <ResultsView
            results={results.data || []}
            loading={results.isLoading}
            query={query}
            scanFilter={scanFilter}
            onClearScanFilter={() => setScanFilter(null)}
            onShowFindings={setFindingsId}
          />
        ))}

      {showAssign && <MerakiAssignModal onClose={() => setShowAssign(false)} />}
      {findingsId != null && (
        <MerakiFindingsModal resultId={findingsId} onClose={() => setFindingsId(null)} />
      )}
    </div>
  );
}

function AssignmentsView({
  assignments,
  loading,
  query,
  onScanStarted,
}: {
  assignments: MerakiAssignment[];
  loading: boolean;
  query: string;
  onScanStarted: (jobId: string) => void;
}) {
  const { confirm, alert } = useDialogs();
  const toggle = useUpdateMerakiAssignment();
  const remove = useDeleteMerakiAssignment();
  const scanNow = useScanMerakiAssignmentNow();
  const pending = usePendingKeys<string>();

  const filtered = useMemo(() => {
    if (!query.trim()) return assignments;
    const q = query.toLowerCase();
    return assignments.filter(
      (a) =>
        (a.profile_name || '').toLowerCase().includes(q) ||
        (a.org_name || '').toLowerCase().includes(q),
    );
  }, [assignments, query]);

  if (loading) return <LoadingState text="Loading Meraki assignments…" />;
  if (!filtered.length) {
    return (
      <EmptyState compact message="No Meraki assignments. Load the built-in profiles (Meraki Switch / Security Appliance /
        Wireless / Dashboard baselines) and assign one to a Meraki organization registered on the
        Topology page." />
    );
  }

  return (
    <>
      {filtered.map((a) => {
        const lastColor =
          a.last_scan_status === 'compliant'
            ? 'success'
            : a.last_scan_status === 'non-compliant'
              ? 'danger'
              : a.last_scan_status
                ? 'warning'
                : 'text-muted';
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
                <span style={{ marginLeft: '0.5rem', fontSize: '0.85em', color: 'var(--text-muted)' }}>
                  → {a.org_name || '?'}
                </span>
                {!a.org_has_api_key && (
                  <span className="badge badge-warning" style={{ marginLeft: '0.5rem' }}>
                    {a.org_identifier === 'sample' ? 'demo data' : 'no API key'}
                  </span>
                )}
              </div>
              <div style={{ display: 'flex', gap: '0.4rem' }}>
                <BusyButton
                  className="btn btn-sm btn-primary"
                  title="Collect this organization's configuration and evaluate the profile now"
                  busy={pending.isPending(`scan:${a.id}`)}
                  disabled={a.scanning}
                  onClick={() =>
                    void pending.run(`scan:${a.id}`, async () => {
                      try {
                        const res = await scanNow.mutateAsync(a.id);
                        onScanStarted(res.job_id);
                      } catch (e) {
                        void alert({
                          title: 'Scan failed to start',
                          message: (e as Error).message,
                          variant: 'error',
                        });
                      }
                    })
                  }
                >
                  {a.scanning ? 'Scanning…' : 'Scan Now'}
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
                        title: 'Delete Meraki assignment',
                        message: `Delete the assignment of profile "${a.profile_name || '?'}" to organization "${a.org_name || '?'}"? Past results are kept.`,
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
            <div style={{ marginTop: '0.5rem', fontSize: '0.85em', color: 'var(--text-muted)' }}>
              {a.enabled ? <span style={{ color: 'var(--success)' }}>Enabled</span> : <span>Disabled</span>} ·
              Every {formatInterval(a.interval_seconds)} · Last scan: {formatBackendDateTime(a.last_scan_at, 'Never')}
              {a.last_scan_status && (
                <>
                  {' '}
                  ·{' '}
                  <span style={{ color: lastColor === 'text-muted' ? undefined : `var(--${lastColor})` }}>
                    {a.last_scan_status}
                  </span>
                  {a.last_scan_message ? ` - ${a.last_scan_message}` : ''}
                </>
              )}
            </div>
          </div>
        );
      })}
    </>
  );
}

/** Target cell: kind badge, name, and model / network where they apply. */
function TargetCell({ r }: { r: MerakiResult }) {
  const detail = [
    r.model,
    (r.target_kind === 'device' || r.target_kind === 'ssid') && r.network_name ? `in ${r.network_name}` : '',
  ]
    .filter(Boolean)
    .join(' ');
  return (
    <>
      <Badge size="sm" style={{ marginRight: '0.5rem' }}>
        {MERAKI_KIND_SHORT_LABEL[r.target_kind] || r.target_kind}
      </Badge>
      <strong>{r.target_name || '?'}</strong>
      {detail && (
        <span style={{ marginLeft: '0.5rem', fontSize: '0.85em', color: 'var(--text-muted)' }}>{detail}</span>
      )}
    </>
  );
}

function matchesQuery(r: MerakiResult, query: string): boolean {
  if (!query.trim()) return true;
  const q = query.toLowerCase();
  return (
    (r.target_name || '').toLowerCase().includes(q) ||
    (r.network_name || '').toLowerCase().includes(q) ||
    (r.org_name || '').toLowerCase().includes(q) ||
    (r.profile_name || '').toLowerCase().includes(q) ||
    (r.model || '').toLowerCase().includes(q) ||
    (r.serial || '').toLowerCase().includes(q)
  );
}

function StatusView({
  status,
  loading,
  query,
  onShowFindings,
}: {
  status: MerakiResult[];
  loading: boolean;
  query: string;
  onShowFindings: (id: number) => void;
}) {
  const [onlyFailing, setOnlyFailing] = useState(false);
  const filtered = useMemo(
    () => status.filter((r) => matchesQuery(r, query) && (!onlyFailing || r.status !== 'compliant')),
    [status, query, onlyFailing],
  );

  if (loading) return <LoadingState text="Loading target status…" />;
  if (!status.length) {
    return <EmptyState compact message="No Meraki targets scanned yet. Run a scan from an assignment." />;
  }

  return (
    <>
      <label style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', fontSize: '0.85em' }}>
        <input type="checkbox" checked={onlyFailing} onChange={(e) => setOnlyFailing(e.target.checked)} />
        Only non-compliant or unreadable
      </label>
      {filtered.length === 0 ? (
        <EmptyState compact message="Nothing matches." />
      ) : (
        <MerakiResultsTable
          rows={filtered}
          initialSort={{ key: 'status', dir: 'asc' }}
          label="Meraki target status"
          action={(r) =>
            r.status !== 'compliant' && (
              <button className="btn btn-sm btn-secondary" onClick={() => onShowFindings(r.id)}>
                View findings
              </button>
            )
          }
        />
      )}
    </>
  );
}

function ResultsView({
  results,
  loading,
  query,
  scanFilter,
  onClearScanFilter,
  onShowFindings,
}: {
  results: MerakiResult[];
  loading: boolean;
  query: string;
  scanFilter: string | null;
  onClearScanFilter: () => void;
  onShowFindings: (id: number) => void;
}) {
  const filtered = useMemo(
    () => results.filter((r) => matchesQuery(r, query) && (!scanFilter || r.scan_id === scanFilter)),
    [results, query, scanFilter],
  );

  if (loading) return <LoadingState text="Loading scan results…" />;
  if (!results.length) return <EmptyState compact message="No Meraki scan results yet." />;

  return (
    <>
      {scanFilter && (
        <div style={{ fontSize: '0.85em', display: 'flex', gap: 'var(--space-2)', alignItems: 'center' }}>
          Showing one scan ({filtered.length} target(s)).
          <button className="btn btn-sm btn-ghost" onClick={onClearScanFilter}>
            Show all
          </button>
        </div>
      )}
      {filtered.length === 0 ? (
        <EmptyState compact message="Nothing matches." />
      ) : (
        <MerakiResultsTable
          rows={filtered}
          initialSort={{ key: 'scanned', dir: 'desc' }}
          label="Meraki scan results"
          action={(r) => (
            <button className="btn btn-sm btn-secondary" onClick={() => onShowFindings(r.id)}>
              {r.failed_rules > 0 ? `View ${r.failed_rules} violation(s)` : 'View findings'}
            </button>
          )}
        />
      )}
    </>
  );
}

/**
 * Meraki target rows (latest status or scan results) as a sortable table,
 * rendered in pages of 200 after filtering and sorting.
 */
function MerakiResultsTable({
  rows,
  initialSort,
  label,
  action,
}: {
  rows: MerakiResult[];
  initialSort: SortState<TargetSortKey>;
  label: string;
  action: (row: MerakiResult) => ReactNode;
}) {
  const { rows: sorted, sort, toggle } = useTableSort(rows, TARGET_COMPARATORS, initialSort, {
    firstDir: TARGET_FIRST_DIR,
    tieBreak: byTargetName,
  });
  const { visible, hiddenCount, showMore } = useShowMore(sorted);
  const th = (key: TargetSortKey, text: string) => (
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
            {th('target', 'Target')}
            {th('org', 'Organization')}
            {th('profile', 'Profile')}
            {th('score', 'Score')}
            {th('scanned', 'Scanned')}
            <th aria-label="Actions" />
          </tr>
        </thead>
        <tbody>
          {visible.map((r) => (
            <tr key={r.id}>
              <td>
                <StatusBadge status={r.status} kind="compliance" size="sm" />
              </td>
              <td>
                <TargetCell r={r} />
              </td>
              <td>{r.org_name || '?'}</td>
              <td>{r.profile_name || '?'}</td>
              <td style={{ whiteSpace: 'nowrap' }}>
                {r.passed_rules}/{r.total_rules} passed
                {r.unreadable_rules > 0 && (
                  <span className="text-muted"> ({r.unreadable_rules} unreadable)</span>
                )}
              </td>
              <td style={{ whiteSpace: 'nowrap' }}>{formatBackendDateTime(r.scanned_at)}</td>
              <td style={{ whiteSpace: 'nowrap', textAlign: 'right' }}>{action(r)}</td>
            </tr>
          ))}
        </tbody>
      </DataTable>
      <ShowMoreButton hiddenCount={hiddenCount} onClick={showMore} style={{ alignSelf: 'flex-start' }} />
    </>
  );
}
