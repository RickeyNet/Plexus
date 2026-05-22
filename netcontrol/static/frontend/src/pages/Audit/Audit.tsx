import { useMemo, useState } from 'react';

import {
  useAuditRuns,
  useAuditFindings,
  useTriggerAuditRun,
  useAuditSchedules,
  useCreateAuditSchedule,
  useUpdateAuditSchedule,
  useDeleteAuditSchedule,
  useRunScheduleNow,
  useAuditOverrides,
  useCreateAuditOverride,
  useDeleteAuditOverride,
  type AuditRunSummary,
  type AuditFinding,
  type AuditSchedule,
  type AuditOverrideMode,
  type AuditSeverity,
} from '@/api/audit';

const SEVERITY_BADGE: Record<AuditSeverity, string> = {
  critical: 'badge-danger',
  high: 'badge-danger',
  medium: 'badge-warning',
  low: 'badge-info',
  info: 'badge-muted',
};

// Display order for severities (critical first). Used to sort within a
// category group and to render the filter chips in a stable order.
const SEVERITY_ORDER: AuditSeverity[] = [
  'critical',
  'high',
  'medium',
  'low',
  'info',
];

const SEVERITY_RANK: Record<AuditSeverity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

const CATEGORY_LABEL: Record<string, string> = {
  config: 'Configuration drift',
  port: 'Port hygiene',
  vlan: 'VLAN consistency',
  security: 'Security posture',
};

function statusBadge(status?: string) {
  if (status === 'success') return 'badge-success';
  if (status === 'partial') return 'badge-warning';
  if (status === 'failed') return 'badge-danger';
  if (status === 'running') return 'badge-info';
  return 'badge-muted';
}

function severityCounts(run: AuditRunSummary) {
  const parts: { label: string; count: number; cls: string }[] = [
    { label: 'Critical', count: run.findings_critical, cls: 'badge-danger' },
    { label: 'High', count: run.findings_high, cls: 'badge-danger' },
    { label: 'Medium', count: run.findings_medium, cls: 'badge-warning' },
    { label: 'Low', count: run.findings_low, cls: 'badge-info' },
    { label: 'Info', count: run.findings_info, cls: 'badge-muted' },
  ];
  return parts.filter((p) => p.count > 0);
}

export function Audit() {
  const runs = useAuditRuns();
  const trigger = useTriggerAuditRun();
  const [selectedRunId, setSelectedRunId] = useState<number | null>(null);
  const findings = useAuditFindings(selectedRunId);

  const runList: AuditRunSummary[] = runs.data?.runs ?? [];

  return (
    <div style={{ padding: '1rem', display: 'grid', gap: '1rem' }}>
      <div
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
        }}
      >
        <h2 style={{ margin: 0 }}>Network Audit</h2>
        <button
          className="btn btn-primary"
          disabled={trigger.isPending}
          onClick={() => trigger.mutate()}
        >
          {trigger.isPending ? 'Running…' : 'Run audit now'}
        </button>
      </div>

      {trigger.error && (
        <div
          className="card"
          style={{ padding: '0.75rem', color: 'var(--danger)' }}
        >
          Run failed: {(trigger.error as Error).message}
        </div>
      )}

      <SchedulesCard />

      <OverridesCard />

      <section className="card" style={{ padding: '1rem' }}>
        <h3 style={{ marginTop: 0 }}>Recent runs</h3>
        {runs.isPending && <p className="text-muted">Loading…</p>}
        {runs.error && (
          <p style={{ color: 'var(--danger)' }}>
            Error: {(runs.error as Error).message}
          </p>
        )}
        {!runs.isPending && runList.length === 0 && (
          <p className="text-muted">
            No audit runs yet. Click "Run audit now" to evaluate your inventory.
          </p>
        )}
        {runList.length > 0 && (
          <table className="data-table">
            <thead>
              <tr>
                <th>ID</th>
                <th>Status</th>
                <th>Started</th>
                <th>Hosts</th>
                <th>Findings</th>
                <th>Severity</th>
              </tr>
            </thead>
            <tbody>
              {runList.map((r) => (
                <tr
                  key={r.id}
                  style={{
                    cursor: 'pointer',
                    background:
                      selectedRunId === r.id
                        ? 'var(--surface-hover, rgba(255,255,255,0.04))'
                        : undefined,
                  }}
                  onClick={() => setSelectedRunId(r.id)}
                >
                  <td>#{r.id}</td>
                  <td>
                    <span className={`badge ${statusBadge(r.status)}`}>
                      {r.status}
                    </span>
                  </td>
                  <td>
                    {r.started_at
                      ? new Date(r.started_at).toLocaleString()
                      : '-'}
                  </td>
                  <td>{r.host_count}</td>
                  <td>{r.findings_total}</td>
                  <td>
                    <div style={{ display: 'flex', gap: '0.25rem', flexWrap: 'wrap' }}>
                      {severityCounts(r).map((p) => (
                        <span key={p.label} className={`badge ${p.cls}`}>
                          {p.label}: {p.count}
                        </span>
                      ))}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>

      {selectedRunId != null && (
        <section className="card" style={{ padding: '1rem' }}>
          <h3 style={{ marginTop: 0 }}>Findings - run #{selectedRunId}</h3>
          {findings.isPending && <p className="text-muted">Loading findings…</p>}
          {findings.error && (
            <p style={{ color: 'var(--danger)' }}>
              Error: {(findings.error as Error).message}
            </p>
          )}
          {findings.data && findings.data.findings.length === 0 && (
            <p className="text-muted">No findings for this run.</p>
          )}
          {findings.data && findings.data.findings.length > 0 && (
            <FindingsView findings={findings.data.findings} />
          )}
        </section>
      )}
    </div>
  );
}

// ── Findings view with filtering + per-category grouping ─────────────────

function FindingsView({ findings }: { findings: AuditFinding[] }) {
  const [severityFilter, setSeverityFilter] = useState<AuditSeverity | null>(
    null,
  );
  const [categoryFilter, setCategoryFilter] = useState<string | null>(null);
  const [collapsed, setCollapsed] = useState<Record<string, boolean>>({});

  // Severity totals across all findings (drive filter chip labels)
  const severityTotals = useMemo(() => {
    const counts: Record<AuditSeverity, number> = {
      critical: 0, high: 0, medium: 0, low: 0, info: 0,
    };
    for (const f of findings) counts[f.severity]++;
    return counts;
  }, [findings]);

  // Available categories in stable order: known categories first, then
  // any unknown ones the backend introduces, sorted alphabetically.
  const categories = useMemo(() => {
    const seen = new Set<string>();
    for (const f of findings) seen.add(f.category || 'other');
    const known = Object.keys(CATEGORY_LABEL).filter((c) => seen.has(c));
    const extras = [...seen]
      .filter((c) => !(c in CATEGORY_LABEL))
      .sort();
    return [...known, ...extras];
  }, [findings]);

  // Apply filters
  const filtered = useMemo(() => {
    return findings.filter((f) => {
      if (severityFilter && f.severity !== severityFilter) return false;
      if (categoryFilter && (f.category || 'other') !== categoryFilter) {
        return false;
      }
      return true;
    });
  }, [findings, severityFilter, categoryFilter]);

  // Bucket filtered findings by category, sorted by severity within each
  const byCategory = useMemo(() => {
    const buckets = new Map<string, AuditFinding[]>();
    for (const f of filtered) {
      const cat = f.category || 'other';
      const arr = buckets.get(cat) ?? [];
      arr.push(f);
      buckets.set(cat, arr);
    }
    for (const arr of buckets.values()) {
      arr.sort((a, b) => {
        const sev = SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity];
        if (sev !== 0) return sev;
        return (a.rule_id || '').localeCompare(b.rule_id || '');
      });
    }
    return buckets;
  }, [filtered]);

  const toggleCategory = (cat: string) =>
    setCollapsed((prev) => ({ ...prev, [cat]: !prev[cat] }));

  return (
    <div style={{ display: 'grid', gap: '1rem' }}>
      <FilterBar
        severityTotals={severityTotals}
        severityFilter={severityFilter}
        onSeverityChange={setSeverityFilter}
        categories={categories}
        categoryFilter={categoryFilter}
        onCategoryChange={setCategoryFilter}
        shown={filtered.length}
        total={findings.length}
      />

      {filtered.length === 0 ? (
        <p className="text-muted">No findings match the current filters.</p>
      ) : (
        categories
          .filter((cat) => byCategory.has(cat))
          .map((cat) => {
            const rows = byCategory.get(cat) ?? [];
            const isCollapsed = collapsed[cat] ?? false;
            return (
              <CategorySection
                key={cat}
                category={cat}
                findings={rows}
                collapsed={isCollapsed}
                onToggle={() => toggleCategory(cat)}
              />
            );
          })
      )}
    </div>
  );
}

function FilterBar(props: {
  severityTotals: Record<AuditSeverity, number>;
  severityFilter: AuditSeverity | null;
  onSeverityChange: (s: AuditSeverity | null) => void;
  categories: string[];
  categoryFilter: string | null;
  onCategoryChange: (c: string | null) => void;
  shown: number;
  total: number;
}) {
  const {
    severityTotals,
    severityFilter,
    onSeverityChange,
    categories,
    categoryFilter,
    onCategoryChange,
    shown,
    total,
  } = props;

  return (
    <div
      style={{
        display: 'flex',
        flexWrap: 'wrap',
        gap: '1rem',
        alignItems: 'center',
      }}
    >
      <div style={{ display: 'flex', gap: '0.25rem', flexWrap: 'wrap' }}>
        <FilterChip
          label="All"
          active={severityFilter === null}
          onClick={() => onSeverityChange(null)}
        />
        {SEVERITY_ORDER.filter((s) => severityTotals[s] > 0).map((s) => (
          <FilterChip
            key={s}
            label={`${s} (${severityTotals[s]})`}
            badgeClass={SEVERITY_BADGE[s]}
            active={severityFilter === s}
            onClick={() =>
              onSeverityChange(severityFilter === s ? null : s)
            }
          />
        ))}
      </div>

      {categories.length > 1 && (
        <div style={{ display: 'flex', gap: '0.25rem', flexWrap: 'wrap' }}>
          <FilterChip
            label="All categories"
            active={categoryFilter === null}
            onClick={() => onCategoryChange(null)}
          />
          {categories.map((cat) => (
            <FilterChip
              key={cat}
              label={CATEGORY_LABEL[cat] ?? cat}
              active={categoryFilter === cat}
              onClick={() =>
                onCategoryChange(categoryFilter === cat ? null : cat)
              }
            />
          ))}
        </div>
      )}

      <span
        className="text-muted"
        style={{ marginLeft: 'auto', fontSize: '0.85rem' }}
      >
        Showing {shown} of {total}
      </span>
    </div>
  );
}

function FilterChip(props: {
  label: string;
  active: boolean;
  onClick: () => void;
  badgeClass?: string;
}) {
  return (
    <button
      type="button"
      onClick={props.onClick}
      className={`badge ${props.badgeClass ?? 'badge-muted'}`}
      style={{
        cursor: 'pointer',
        border: props.active
          ? '1px solid var(--accent, #4d9bff)'
          : '1px solid transparent',
        opacity: props.active ? 1 : 0.7,
        textTransform: 'capitalize',
      }}
    >
      {props.label}
    </button>
  );
}

function CategorySection(props: {
  category: string;
  findings: AuditFinding[];
  collapsed: boolean;
  onToggle: () => void;
}) {
  const { category, findings, collapsed, onToggle } = props;
  const label = CATEGORY_LABEL[category] ?? category;

  // Per-category severity summary
  const sevSummary = useMemo(() => {
    const counts: Record<AuditSeverity, number> = {
      critical: 0, high: 0, medium: 0, low: 0, info: 0,
    };
    for (const f of findings) counts[f.severity]++;
    return SEVERITY_ORDER.filter((s) => counts[s] > 0).map((s) => ({
      sev: s,
      count: counts[s],
    }));
  }, [findings]);

  return (
    <div
      style={{
        border: '1px solid var(--border, rgba(255,255,255,0.1))',
        borderRadius: '4px',
      }}
    >
      <div
        onClick={onToggle}
        style={{
          padding: '0.6rem 0.75rem',
          display: 'flex',
          alignItems: 'center',
          gap: '0.75rem',
          cursor: 'pointer',
          background: 'var(--surface-hover, rgba(255,255,255,0.03))',
          borderBottom: collapsed
            ? 'none'
            : '1px solid var(--border, rgba(255,255,255,0.1))',
        }}
      >
        <span style={{ fontFamily: 'monospace', width: '1rem' }}>
          {collapsed ? '▶' : '▼'}
        </span>
        <strong style={{ flex: '0 0 auto' }}>{label}</strong>
        <span className="text-muted" style={{ fontSize: '0.85rem' }}>
          {findings.length} finding{findings.length === 1 ? '' : 's'}
        </span>
        <div
          style={{
            display: 'flex',
            gap: '0.25rem',
            flexWrap: 'wrap',
            marginLeft: 'auto',
          }}
        >
          {sevSummary.map(({ sev, count }) => (
            <span key={sev} className={`badge ${SEVERITY_BADGE[sev]}`}>
              {sev}: {count}
            </span>
          ))}
        </div>
      </div>
      {!collapsed && <FindingsTable findings={findings} />}
    </div>
  );
}

// ── Schedules card (Phase 5) ───────────────────────────────────────────────
//
// Schedule cadence strings reuse the reporting grammar -- if you change one
// here, change `reporting._parse_schedule_interval_seconds` too.
const SCHEDULE_PRESETS: { label: string; value: string }[] = [
  { label: 'Hourly', value: '@hourly' },
  { label: 'Every 6 hours', value: '6h' },
  { label: 'Daily', value: '@daily' },
  { label: 'Weekly', value: '@weekly' },
];

function SchedulesCard() {
  const schedules = useAuditSchedules();
  const update = useUpdateAuditSchedule();
  const remove = useDeleteAuditSchedule();
  const runNow = useRunScheduleNow();
  const [editing, setEditing] = useState<AuditSchedule | 'new' | null>(null);

  const rows = schedules.data?.schedules ?? [];

  return (
    <section className="card" style={{ padding: '1rem' }}>
      <div
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          marginBottom: '0.5rem',
        }}
      >
        <h3 style={{ margin: 0 }}>Schedules</h3>
        <button
          className="btn btn-secondary"
          onClick={() => setEditing('new')}
        >
          Add schedule
        </button>
      </div>

      {schedules.isPending && <p className="text-muted">Loading…</p>}
      {schedules.error && (
        <p style={{ color: 'var(--danger)' }}>
          Error: {(schedules.error as Error).message}
        </p>
      )}
      {!schedules.isPending && rows.length === 0 && (
        <p className="text-muted">
          No schedules configured. Schedules enqueue an audit run on a
          recurring cadence (e.g., daily, every 6 hours).
        </p>
      )}

      {rows.length > 0 && (
        <table className="data-table">
          <thead>
            <tr>
              <th>Name</th>
              <th>Cadence</th>
              <th>Enabled</th>
              <th>Last run</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {rows.map((s) => (
              <tr key={s.id}>
                <td>{s.name}</td>
                <td><code>{s.schedule || '-'}</code></td>
                <td>
                  <span
                    className={`badge ${
                      s.enabled ? 'badge-success' : 'badge-muted'
                    }`}
                  >
                    {s.enabled ? 'enabled' : 'paused'}
                  </span>
                </td>
                <td>
                  {s.last_run_at
                    ? new Date(s.last_run_at).toLocaleString()
                    : 'never'}
                </td>
                <td style={{ textAlign: 'right' }}>
                  <button
                    className="btn btn-sm"
                    disabled={runNow.isPending}
                    onClick={() => runNow.mutate(s.id)}
                  >
                    Run now
                  </button>
                  <button
                    className="btn btn-sm"
                    style={{ marginLeft: '0.25rem' }}
                    disabled={update.isPending}
                    onClick={() =>
                      update.mutate({
                        id: s.id,
                        payload: { enabled: !s.enabled },
                      })
                    }
                  >
                    {s.enabled ? 'Pause' : 'Resume'}
                  </button>
                  <button
                    className="btn btn-sm"
                    style={{ marginLeft: '0.25rem' }}
                    onClick={() => setEditing(s)}
                  >
                    Edit
                  </button>
                  <button
                    className="btn btn-sm btn-danger"
                    style={{ marginLeft: '0.25rem' }}
                    disabled={remove.isPending}
                    onClick={() => {
                      if (
                        confirm(`Delete schedule "${s.name}"?`)
                      ) {
                        remove.mutate(s.id);
                      }
                    }}
                  >
                    Delete
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      {editing !== null && (
        <ScheduleEditor
          schedule={editing === 'new' ? null : editing}
          onClose={() => setEditing(null)}
        />
      )}
    </section>
  );
}

function ScheduleEditor({
  schedule,
  onClose,
}: {
  schedule: AuditSchedule | null;
  onClose: () => void;
}) {
  const create = useCreateAuditSchedule();
  const update = useUpdateAuditSchedule();
  const [name, setName] = useState(schedule?.name ?? '');
  const [cadence, setCadence] = useState(schedule?.schedule ?? '@daily');
  const [enabled, setEnabled] = useState(schedule?.enabled ?? true);
  const [error, setError] = useState<string | null>(null);

  const isNew = schedule === null;
  const pending = create.isPending || update.isPending;

  const submit = async () => {
    setError(null);
    const trimmedName = name.trim();
    if (!trimmedName) {
      setError('Name is required');
      return;
    }
    try {
      if (isNew) {
        await create.mutateAsync({
          name: trimmedName,
          schedule: cadence.trim(),
          enabled,
        });
      } else {
        await update.mutateAsync({
          id: schedule!.id,
          payload: {
            name: trimmedName,
            schedule: cadence.trim(),
            enabled,
          },
        });
      }
      onClose();
    } catch (e) {
      setError((e as Error).message);
    }
  };

  return (
    <div
      role="dialog"
      aria-modal="true"
      style={{
        position: 'fixed',
        inset: 0,
        background: 'rgba(0,0,0,0.5)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        zIndex: 100,
      }}
      onClick={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div
        className="card"
        style={{ width: 420, padding: '1rem', display: 'grid', gap: '0.75rem' }}
      >
        <h3 style={{ margin: 0 }}>
          {isNew ? 'New schedule' : `Edit "${schedule!.name}"`}
        </h3>

        <label style={{ display: 'grid', gap: '0.25rem' }}>
          <span>Name</span>
          <input
            type="text"
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="e.g. Nightly compliance sweep"
          />
        </label>

        <label style={{ display: 'grid', gap: '0.25rem' }}>
          <span>Cadence</span>
          <div style={{ display: 'flex', gap: '0.25rem', flexWrap: 'wrap' }}>
            {SCHEDULE_PRESETS.map((p) => (
              <button
                type="button"
                key={p.value}
                className={`badge ${
                  cadence === p.value ? 'badge-info' : 'badge-muted'
                }`}
                style={{ cursor: 'pointer' }}
                onClick={() => setCadence(p.value)}
              >
                {p.label}
              </button>
            ))}
          </div>
          <input
            type="text"
            value={cadence}
            onChange={(e) => setCadence(e.target.value)}
            placeholder="@daily, 6h, 30m, ..."
          />
          <small className="text-muted">
            Accepts @hourly / @daily / @weekly / @monthly, or N[s|m|h|d|w].
          </small>
        </label>

        <label
          style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}
        >
          <input
            type="checkbox"
            checked={enabled}
            onChange={(e) => setEnabled(e.target.checked)}
          />
          <span>Enabled</span>
        </label>

        {error && (
          <p style={{ color: 'var(--danger)', margin: 0 }}>{error}</p>
        )}

        <div
          style={{
            display: 'flex',
            justifyContent: 'flex-end',
            gap: '0.5rem',
          }}
        >
          <button
            type="button"
            className="btn"
            onClick={onClose}
            disabled={pending}
          >
            Cancel
          </button>
          <button
            type="button"
            className="btn btn-primary"
            onClick={submit}
            disabled={pending}
          >
            {pending ? 'Saving…' : isNew ? 'Create' : 'Save'}
          </button>
        </div>
      </div>
    </div>
  );
}

function FindingsTable({ findings }: { findings: AuditFinding[] }) {
  const [muting, setMuting] = useState<AuditFinding | null>(null);
  return (
    <>
    <table className="data-table">
      <thead>
        <tr>
          <th>Severity</th>
          <th>Rule</th>
          <th>Host</th>
          <th>Title</th>
          <th>Detail</th>
          <th>CIS</th>
          <th></th>
        </tr>
      </thead>
      <tbody>
        {findings.map((f) => (
          <tr key={f.id}>
            <td>
              <span className={`badge ${SEVERITY_BADGE[f.severity]}`}>
                {f.severity}
              </span>
            </td>
            <td><code>{f.rule_id}</code></td>
            <td>{(f.evidence?.hostname as string | undefined) ?? f.host_id ?? '-'}</td>
            <td>{f.title}</td>
            <td style={{ maxWidth: 360, whiteSpace: 'pre-wrap' }}>
              {f.detail}
            </td>
            <td>{f.cis_control || '-'}</td>
            <td style={{ textAlign: 'right' }}>
              <button
                className="btn btn-sm"
                title="Suppress this rule from future runs"
                onClick={() => setMuting(f)}
              >
                Mute
              </button>
            </td>
          </tr>
        ))}
      </tbody>
    </table>
    {muting && (
      <MuteFindingDialog
        finding={muting}
        onClose={() => setMuting(null)}
      />
    )}
    </>
  );
}

// ── Overrides card + Mute dialog (Phase 6) ─────────────────────────────────

function OverridesCard() {
  const overrides = useAuditOverrides();
  const remove = useDeleteAuditOverride();
  const rows = overrides.data?.overrides ?? [];

  return (
    <section className="card" style={{ padding: '1rem' }}>
      <h3 style={{ marginTop: 0 }}>Suppressed findings</h3>
      {overrides.isPending && <p className="text-muted">Loading…</p>}
      {overrides.error && (
        <p style={{ color: 'var(--danger)' }}>
          Error: {(overrides.error as Error).message}
        </p>
      )}
      {!overrides.isPending && rows.length === 0 && (
        <p className="text-muted">
          No active overrides. Mute a finding from a run to silence a chronic
          false positive; muted findings still log to the summary so the count
          stays auditable.
        </p>
      )}
      {rows.length > 0 && (
        <table className="data-table">
          <thead>
            <tr>
              <th>Rule</th>
              <th>Host</th>
              <th>Mode</th>
              <th>Reason</th>
              <th>Expires</th>
              <th>Created</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {rows.map((o) => (
              <tr key={o.id}>
                <td><code>{o.rule_id}</code></td>
                <td>{o.host_id ?? <span className="text-muted">(all)</span>}</td>
                <td>
                  <span
                    className={`badge ${
                      o.mode === 'accept_risk'
                        ? 'badge-warning'
                        : 'badge-muted'
                    }`}
                  >
                    {o.mode}
                  </span>
                </td>
                <td style={{ maxWidth: 320, whiteSpace: 'pre-wrap' }}>
                  {o.reason || '-'}
                </td>
                <td>
                  {o.expires_at
                    ? new Date(o.expires_at).toLocaleString()
                    : <span className="text-muted">never</span>}
                </td>
                <td>
                  {o.created_at
                    ? new Date(o.created_at).toLocaleString()
                    : '-'}
                </td>
                <td style={{ textAlign: 'right' }}>
                  <button
                    className="btn btn-sm btn-danger"
                    disabled={remove.isPending}
                    onClick={() => {
                      if (confirm('Remove this override?')) {
                        remove.mutate(o.id);
                      }
                    }}
                  >
                    Remove
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </section>
  );
}

function MuteFindingDialog({
  finding,
  onClose,
}: {
  finding: AuditFinding;
  onClose: () => void;
}) {
  const create = useCreateAuditOverride();
  const [mode, setMode] = useState<AuditOverrideMode>('mute');
  const [scope, setScope] = useState<'host' | 'global'>('host');
  const [reason, setReason] = useState('');
  const [expiresAt, setExpiresAt] = useState('');

  const hostId = finding.host_id ?? null;

  function submit() {
    const payload = {
      rule_id: finding.rule_id,
      host_id: scope === 'host' ? hostId : null,
      mode,
      reason: reason.trim(),
      expires_at: expiresAt ? expiresAt.replace('T', ' ') + ':00' : null,
    };
    create.mutate(payload, { onSuccess: onClose });
  }

  return (
    <div
      onClick={onClose}
      style={{
        position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.5)',
        zIndex: 1000, display: 'flex', alignItems: 'center',
        justifyContent: 'center', padding: '1rem',
      }}
    >
      <div
        onClick={(e) => e.stopPropagation()}
        className="card"
        style={{ padding: '1.25rem', minWidth: 420, maxWidth: 560 }}
      >
        <h3 style={{ marginTop: 0 }}>Mute finding</h3>
        <p className="text-muted" style={{ marginTop: 0 }}>
          <code>{finding.rule_id}</code> - {finding.title}
        </p>

        <div style={{ display: 'grid', gap: '0.75rem' }}>
          <label style={{ display: 'grid', gap: '0.25rem' }}>
            <span>Scope</span>
            <div style={{ display: 'flex', gap: '0.5rem' }}>
              <button
                type="button"
                className={`btn btn-sm ${
                  scope === 'host' ? 'btn-primary' : ''
                }`}
                disabled={hostId == null}
                onClick={() => setScope('host')}
              >
                This host{hostId != null ? ` (#${hostId})` : ''}
              </button>
              <button
                type="button"
                className={`btn btn-sm ${
                  scope === 'global' ? 'btn-primary' : ''
                }`}
                onClick={() => setScope('global')}
              >
                All hosts
              </button>
            </div>
          </label>

          <label style={{ display: 'grid', gap: '0.25rem' }}>
            <span>Mode</span>
            <div style={{ display: 'flex', gap: '0.5rem' }}>
              <button
                type="button"
                className={`btn btn-sm ${
                  mode === 'mute' ? 'btn-primary' : ''
                }`}
                onClick={() => setMode('mute')}
              >
                Mute (false positive)
              </button>
              <button
                type="button"
                className={`btn btn-sm ${
                  mode === 'accept_risk' ? 'btn-primary' : ''
                }`}
                onClick={() => setMode('accept_risk')}
              >
                Accept risk
              </button>
            </div>
          </label>

          <label style={{ display: 'grid', gap: '0.25rem' }}>
            <span>Reason</span>
            <textarea
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              rows={3}
              placeholder="Why is this finding being suppressed?"
            />
          </label>

          <label style={{ display: 'grid', gap: '0.25rem' }}>
            <span>Expires (optional)</span>
            <input
              type="datetime-local"
              value={expiresAt}
              onChange={(e) => setExpiresAt(e.target.value)}
            />
            <span className="text-muted" style={{ fontSize: '0.8rem' }}>
              Leave blank for a permanent override.
            </span>
          </label>
        </div>

        {create.error && (
          <p style={{ color: 'var(--danger)' }}>
            {(create.error as Error).message}
          </p>
        )}

        <div
          style={{
            display: 'flex', gap: '0.5rem', justifyContent: 'flex-end',
            marginTop: '1rem',
          }}
        >
          <button type="button" className="btn" onClick={onClose}>
            Cancel
          </button>
          <button
            type="button"
            className="btn btn-primary"
            onClick={submit}
            disabled={create.isPending}
          >
            {create.isPending ? 'Saving…' : 'Mute'}
          </button>
        </div>
      </div>
    </div>
  );
}

