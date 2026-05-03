import { useMemo, useState } from 'react';

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
  useScanAssignmentNow,
  useUpdateAssignment,
} from '@/api/compliance';

import { AssignProfileModal, EditProfileModal, NewProfileModal } from './ProfileModals';
import { FindingsModal } from './FindingsModal';
import { RunScanModal } from './RunScanModal';

type Tab = 'profiles' | 'assignments' | 'results' | 'status';

const TABS: { id: Tab; label: string }[] = [
  { id: 'profiles', label: 'Profiles' },
  { id: 'assignments', label: 'Assignments' },
  { id: 'results', label: 'Scan Results' },
  { id: 'status', label: 'Host Status' },
];

const formatInterval = (seconds: number): string => {
  if (seconds % 86400 === 0) return `${seconds / 86400}d`;
  if (seconds % 3600 === 0) return `${seconds / 3600}h`;
  if (seconds % 60 === 0) return `${seconds / 60}m`;
  return `${seconds}s`;
};

export function Compliance() {
  const [tab, setTab] = useState<Tab>('profiles');
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
  const loadBuiltin = useLoadBuiltinProfiles();

  return (
    <div>
      <div
        className="page-header"
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          flexWrap: 'wrap',
          gap: '0.5rem',
          marginBottom: '0.75rem',
        }}
      >
        <h2 style={{ margin: 0 }}>Compliance</h2>
        <div style={{ display: 'flex', gap: '0.4rem' }}>
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
                    alert(
                      `Loaded ${res.loaded} built-in profile(s).${res.skipped > 0 ? ` ${res.skipped} already existed.` : ''}`,
                    );
                  } else {
                    alert(`All ${res.total_available} built-in profiles already loaded.`);
                  }
                },
                onError: (e) => alert((e as Error).message),
              });
            }}
            disabled={loadBuiltin.isPending}
          >
            {loadBuiltin.isPending ? 'Loading…' : 'Load Built-in'}
          </button>
        </div>
      </div>

      <SummaryStrip summary={summary.data} />

      <div className="card" style={{ marginTop: '0.75rem', padding: 0, overflow: 'hidden' }}>
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: '0.5rem',
            padding: '0.5rem 0.75rem',
            borderBottom: '1px solid var(--border)',
            flexWrap: 'wrap',
          }}
        >
          {TABS.map((t) => (
            <button
              key={t.id}
              className={`btn btn-sm ${tab === t.id ? 'btn-primary' : 'btn-ghost'}`}
              onClick={() => setTab(t.id)}
            >
              {t.label}
            </button>
          ))}
          <input
            className="form-input"
            placeholder="Search…"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            style={{ marginLeft: 'auto', maxWidth: 240 }}
          />
        </div>
        <div style={{ padding: '0.75rem' }}>
          {tab === 'profiles' && (
            <ProfilesTab
              profiles={profiles.data || []}
              loading={profiles.isLoading}
              query={query}
              onEdit={setEditProfileId}
              onAssign={setAssignProfileId}
            />
          )}
          {tab === 'assignments' && (
            <AssignmentsTab
              assignments={assignments.data || []}
              loading={assignments.isLoading}
              query={query}
            />
          )}
          {tab === 'results' && (
            <ResultsTab
              results={results.data || []}
              loading={results.isLoading}
              query={query}
              onShowFindings={setFindingsResultId}
            />
          )}
          {tab === 'status' && (
            <StatusTab status={status.data || []} loading={status.isLoading} query={query} />
          )}
        </div>
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

function SummaryStrip({ summary }: { summary?: { total_profiles?: number; active_assignments?: number; hosts_scanned?: number; hosts_non_compliant?: number; last_scan_at?: string | null } }) {
  const items: { label: string; value: string }[] = [
    { label: 'Profiles', value: String(summary?.total_profiles ?? '-') },
    { label: 'Assignments', value: String(summary?.active_assignments ?? '-') },
    { label: 'Hosts scanned', value: String(summary?.hosts_scanned ?? '-') },
    { label: 'Non-compliant', value: String(summary?.hosts_non_compliant ?? '-') },
    {
      label: 'Last scan',
      value: summary?.last_scan_at ? new Date(summary.last_scan_at + 'Z').toLocaleString() : 'Never',
    },
  ];
  return (
    <div className="card">
      <div
        className="card-body"
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(140px, 1fr))',
          gap: '0.5rem',
          padding: '0.75rem',
        }}
      >
        {items.map((it) => (
          <div key={it.label} style={{ display: 'flex', flexDirection: 'column' }}>
            <span style={{ color: 'var(--text-muted)', fontSize: '0.75rem' }}>{it.label}</span>
            <span style={{ fontWeight: 600 }}>{it.value}</span>
          </div>
        ))}
      </div>
    </div>
  );
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
  const remove = useDeleteProfile();
  const filtered = useMemo(() => {
    if (!query.trim()) return profiles;
    const q = query.toLowerCase();
    return profiles.filter(
      (p) =>
        p.name.toLowerCase().includes(q) ||
        (p.description || '').toLowerCase().includes(q),
    );
  }, [profiles, query]);

  if (loading) return <p className="text-muted">Loading profiles…</p>;
  if (!filtered.length) {
    return (
      <p className="text-muted">No compliance profiles. Click "New Profile" to create one.</p>
    );
  }

  return (
    <>
      {filtered.map((p) => {
        let rules: { name?: string; pattern?: string }[] = [];
        try {
          rules = JSON.parse(p.rules || '[]');
        } catch {
          rules = [];
        }
        const sevClass =
          p.severity === 'critical' ? 'danger' : p.severity === 'high' ? 'warning' : 'success';
        return (
          <div
            key={p.id}
            className="card"
            style={{ marginBottom: '0.75rem', padding: '1rem' }}
          >
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
                <span
                  className={`badge badge-${sevClass}`}
                  style={{ marginLeft: '0.5rem' }}
                >
                  {p.severity}
                </span>
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
                <button
                  className="btn btn-sm"
                  style={{ color: 'var(--danger)' }}
                  onClick={() => {
                    if (
                      confirm(
                        'Delete this compliance profile and all its assignments and scan results?',
                      )
                    ) {
                      remove.mutate(p.id, {
                        onError: (e) => alert((e as Error).message),
                      });
                    }
                  }}
                >
                  Delete
                </button>
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
                style={{
                  marginTop: '0.5rem',
                  fontSize: '0.85em',
                  color: 'var(--text-muted)',
                }}
              >
                Rules: {rules.map((r) => r.name || r.pattern || '?').join(', ')}
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
}: {
  assignments: ComplianceAssignment[];
  loading: boolean;
  query: string;
}) {
  const toggle = useUpdateAssignment();
  const remove = useDeleteAssignment();
  const scanNow = useScanAssignmentNow();

  const filtered = useMemo(() => {
    if (!query.trim()) return assignments;
    const q = query.toLowerCase();
    return assignments.filter(
      (a) =>
        (a.profile_name || '').toLowerCase().includes(q) ||
        (a.group_name || '').toLowerCase().includes(q),
    );
  }, [assignments, query]);

  if (loading) return <p className="text-muted">Loading assignments…</p>;
  if (!filtered.length) {
    return (
      <p className="text-muted">
        No compliance assignments. Assign a profile to an inventory group to start scanning.
      </p>
    );
  }

  return (
    <>
      {filtered.map((a) => {
        const lastScan = a.last_scan_at
          ? new Date(a.last_scan_at + 'Z').toLocaleString()
          : 'Never';
        return (
          <div
            key={a.id}
            className="card"
            style={{ marginBottom: '0.75rem', padding: '1rem' }}
          >
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
                <button
                  className="btn btn-sm btn-primary"
                  title="Scan all hosts in this assignment now"
                  onClick={() => {
                    if (
                      confirm(
                        'Scan all hosts in this assignment immediately? This may take a moment.',
                      )
                    ) {
                      scanNow.mutate(a.id, {
                        onSuccess: (res) => {
                          if (res.violations > 0) {
                            alert(
                              `Scan complete: ${res.hosts_scanned} hosts scanned, ${res.violations} non-compliant, ${res.errors} errors`,
                            );
                          } else if (res.errors > 0) {
                            alert(
                              `Scan complete: ${res.hosts_scanned} hosts scanned, ${res.errors} error(s)`,
                            );
                          } else {
                            alert(
                              `Scan complete: ${res.hosts_scanned} hosts scanned — all compliant!`,
                            );
                          }
                        },
                        onError: (e) =>
                          alert(`Assignment scan failed: ${(e as Error).message}`),
                      });
                    }
                  }}
                  disabled={scanNow.isPending}
                >
                  {scanNow.isPending ? 'Scanning…' : 'Scan Now'}
                </button>
                <button
                  className="btn btn-sm btn-secondary"
                  onClick={() =>
                    toggle.mutate(
                      { id: a.id, data: { enabled: !a.enabled } },
                      { onError: (e) => alert((e as Error).message) },
                    )
                  }
                >
                  {a.enabled ? 'Disable' : 'Enable'}
                </button>
                <button
                  className="btn btn-sm"
                  style={{ color: 'var(--danger)' }}
                  onClick={() => {
                    if (confirm('Delete this compliance assignment?')) {
                      remove.mutate(a.id, {
                        onError: (e) => alert((e as Error).message),
                      });
                    }
                  }}
                >
                  Delete
                </button>
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

  if (loading) return <p className="text-muted">Loading scan results…</p>;
  if (!filtered.length) {
    return <p className="text-muted">No scan results yet. Run a compliance scan.</p>;
  }

  return (
    <>
      {filtered.map((r) => {
        const color =
          r.status === 'compliant'
            ? 'success'
            : r.status === 'error'
              ? 'danger'
              : 'warning';
        const scanned = r.scanned_at ? new Date(r.scanned_at + 'Z').toLocaleString() : '-';
        return (
          <div
            key={r.id}
            className="card"
            style={{ marginBottom: '0.75rem', padding: '1rem' }}
          >
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
                <span style={{ color: `var(--${color})`, fontWeight: 600 }}>{r.status}</span>
                <strong style={{ marginLeft: '0.5rem' }}>{r.hostname || '?'}</strong>
                <span
                  style={{
                    marginLeft: '0.5rem',
                    fontSize: '0.85em',
                    color: 'var(--text-muted)',
                  }}
                >
                  {r.ip_address || ''}
                </span>
                <span
                  style={{
                    marginLeft: '0.5rem',
                    fontSize: '0.85em',
                    color: 'var(--text-muted)',
                  }}
                >
                  Profile: {r.profile_name || '?'}
                </span>
              </div>
              <div style={{ fontSize: '0.85em', color: 'var(--text-muted)' }}>
                {r.passed_rules}/{r.total_rules} passed · {scanned}
              </div>
            </div>
            {r.failed_rules > 0 && (
              <div style={{ marginTop: '0.5rem' }}>
                <button
                  className="btn btn-sm btn-secondary"
                  onClick={() => onShowFindings(r.id)}
                >
                  View {r.failed_rules} violation(s)
                </button>
              </div>
            )}
          </div>
        );
      })}
    </>
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

  if (loading) return <p className="text-muted">Loading host status…</p>;
  if (!filtered.length) {
    return <p className="text-muted">No compliance status data. Scan some hosts first.</p>;
  }

  return (
    <>
      {filtered.map((s, i) => {
        const color =
          s.status === 'compliant'
            ? 'success'
            : s.status === 'error'
              ? 'danger'
              : 'warning';
        const scanned = s.scanned_at ? new Date(s.scanned_at + 'Z').toLocaleString() : '-';
        return (
          <div
            key={i}
            className="card"
            style={{ marginBottom: '0.75rem', padding: '1rem' }}
          >
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
                    background: `var(--${color})`,
                    marginRight: '0.5rem',
                  }}
                />
                <strong>{s.hostname || '?'}</strong>
                <span
                  style={{
                    marginLeft: '0.5rem',
                    fontSize: '0.85em',
                    color: 'var(--text-muted)',
                  }}
                >
                  {s.ip_address || ''}
                </span>
                <span
                  style={{
                    marginLeft: '0.5rem',
                    fontSize: '0.85em',
                    color: 'var(--text-muted)',
                  }}
                >
                  · {s.profile_name || '?'}
                </span>
              </div>
              <div style={{ fontSize: '0.85em' }}>
                <span style={{ color: `var(--${color})`, fontWeight: 600 }}>{s.status}</span>{' '}
                · {s.passed_rules}/{s.total_rules} passed · {scanned}
              </div>
            </div>
          </div>
        );
      })}
    </>
  );
}
