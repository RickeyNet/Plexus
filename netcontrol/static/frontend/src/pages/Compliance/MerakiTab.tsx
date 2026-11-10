import { useMemo, useState } from 'react';

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
import { DeleteButton } from '@/components/DeleteButton';
import { useDialogs } from '@/components/DialogProvider-context';
import { EmptyState } from '@/components/EmptyState';
import { LoadingState } from '@/components/LoadingState';
import { TabBar } from '@/components/TabBar';
import { formatBackendDateTime } from '@/lib/datetime';
import { complianceStatusTone, toneColor } from '@/lib/severity';

import { MerakiAssignModal } from './MerakiAssignModal';
import { MerakiFindingsModal } from './MerakiFindingsModal';
import { MerakiScanProgress } from './MerakiScanProgress';

const KIND_LABEL: Record<string, string> = { org: 'Org', network: 'Network', device: 'Switch', ssid: 'SSID' };

const formatInterval = (seconds: number): string => {
  if (seconds % 86400 === 0) return `${seconds / 86400}d`;
  if (seconds % 3600 === 0) return `${seconds / 3600}h`;
  if (seconds % 60 === 0) return `${seconds / 60}m`;
  return `${seconds}s`;
};

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
      <TabBar
        size="sm"
        tabs={VIEWS}
        active={view}
        onChange={setView}
        aria-label="Meraki views"
        trailing={
          <button type="button" className="btn btn-sm btn-secondary" onClick={() => setShowAssign(true)}>
            Assign to Organization
          </button>
        }
      />

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

      {view === 'assignments' && (
        <AssignmentsView
          assignments={assignments.data || []}
          loading={assignments.isLoading}
          query={query}
          onScanStarted={setJobId}
        />
      )}
      {view === 'status' && (
        <StatusView
          status={status.data || []}
          loading={status.isLoading}
          query={query}
          onShowFindings={setFindingsId}
        />
      )}
      {view === 'results' && (
        <ResultsView
          results={results.data || []}
          loading={results.isLoading}
          query={query}
          scanFilter={scanFilter}
          onClearScanFilter={() => setScanFilter(null)}
          onShowFindings={setFindingsId}
        />
      )}

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
                <button
                  className="btn btn-sm btn-primary"
                  title="Collect this organization's configuration and evaluate the profile now"
                  disabled={scanNow.isPending || a.scanning}
                  onClick={() =>
                    scanNow.mutate(a.id, {
                      onSuccess: (res) => onScanStarted(res.job_id),
                      onError: (e) =>
                        void alert({
                          title: 'Scan failed to start',
                          message: (e as Error).message,
                          variant: 'error',
                        }),
                    })
                  }
                >
                  {a.scanning ? 'Scanning…' : 'Scan Now'}
                </button>
                <button
                  className="btn btn-sm btn-secondary"
                  onClick={() =>
                    toggle.mutate(
                      { id: a.id, data: { enabled: !a.enabled } },
                      {
                        onError: (e) =>
                          void alert({
                            title: 'Update failed',
                            message: (e as Error).message,
                            variant: 'error',
                          }),
                      },
                    )
                  }
                >
                  {a.enabled ? 'Disable' : 'Enable'}
                </button>
                <DeleteButton
                  onClick={async () => {
                    if (
                      await confirm({
                        title: 'Delete assignment?',
                        message: 'Delete this Meraki compliance assignment? Past results are kept.',
                        confirmLabel: 'Delete',
                      })
                    ) {
                      remove.mutate(a.id, {
                        onError: (e) =>
                          void alert({
                            title: 'Delete failed',
                            message: (e as Error).message,
                            variant: 'error',
                          }),
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

function TargetLine({ r }: { r: MerakiResult }) {
  return (
    <>
      <span className="badge badge-secondary" style={{ marginRight: '0.5rem' }}>
        {KIND_LABEL[r.target_kind] || r.target_kind}
      </span>
      <strong>{r.target_name || '?'}</strong>
      {r.model && (
        <span style={{ marginLeft: '0.5rem', fontSize: '0.85em', color: 'var(--text-muted)' }}>{r.model}</span>
      )}
      {(r.target_kind === 'device' || r.target_kind === 'ssid') && r.network_name && (
        <span style={{ marginLeft: '0.5rem', fontSize: '0.85em', color: 'var(--text-muted)' }}>
          in {r.network_name}
        </span>
      )}
      <span style={{ marginLeft: '0.5rem', fontSize: '0.85em', color: 'var(--text-muted)' }}>
        · {r.org_name || '?'} · {r.profile_name || '?'}
      </span>
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
      {filtered.length === 0 && <EmptyState compact message="Nothing matches." />}
      {filtered.map((r) => {
        const color = toneColor(complianceStatusTone(r.status));
        return (
          <div key={r.id} className="card card-sm">
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
                <span
                  style={{
                    display: 'inline-block',
                    width: 10,
                    height: 10,
                    borderRadius: '50%',
                    background: color,
                    marginRight: '0.5rem',
                  }}
                />
                <TargetLine r={r} />
              </div>
              <div style={{ fontSize: '0.85em', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <span style={{ color: color, fontWeight: 600 }}>{r.status}</span> · {r.passed_rules}/
                {r.total_rules} passed · {formatBackendDateTime(r.scanned_at)}
                {r.status !== 'compliant' && (
                  <button className="btn btn-sm btn-secondary" onClick={() => onShowFindings(r.id)}>
                    View findings
                  </button>
                )}
              </div>
            </div>
          </div>
        );
      })}
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
      {filtered.length === 0 && <EmptyState compact message="Nothing matches." />}
      {filtered.map((r) => {
        const color = toneColor(complianceStatusTone(r.status));
        return (
          <div key={r.id} className="card card-sm">
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
                <span style={{ color: color, fontWeight: 600, marginRight: '0.5rem' }}>{r.status}</span>
                <TargetLine r={r} />
              </div>
              <div style={{ fontSize: '0.85em', color: 'var(--text-muted)', display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
                {r.passed_rules}/{r.total_rules} passed
                {r.unreadable_rules > 0 ? ` (${r.unreadable_rules} unreadable)` : ''} · {formatBackendDateTime(r.scanned_at)}
                <button className="btn btn-sm btn-secondary" onClick={() => onShowFindings(r.id)}>
                  {r.failed_rules > 0 ? `View ${r.failed_rules} violation(s)` : 'View findings'}
                </button>
              </div>
            </div>
          </div>
        );
      })}
    </>
  );
}
