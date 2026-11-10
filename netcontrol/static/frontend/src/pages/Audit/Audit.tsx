import { useMemo, useState } from 'react';

import { Badge, SeverityBadge, StatusBadge } from '@/components/Badge';
import { BusyButton } from '@/components/BusyButton';
import { Callout } from '@/components/Callout';
import { useDialogs } from '@/components/DialogProvider-context';
import { EmptyState } from '@/components/EmptyState';
import { FieldError } from '@/components/FieldError';
import { LoadingState } from '@/components/LoadingState';
import { KebabMenu, MenuItem, MenuSeparator } from '@/components/Menu';
import { Modal } from '@/components/Modal';
import { QueryError } from '@/components/QueryError';
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
import { formatBackendDateTime } from '@/lib/datetime';
import { isCriticalSeverity, SEVERITY_LEVELS, severityRank, severityTone } from '@/lib/severity';
import { usePendingKeys } from '@/lib/usePendingKeys';
import { useShowMore } from '@/lib/useShowMore';

const CATEGORY_LABEL: Record<string, string> = {
  config: 'Configuration drift',
  port: 'Port hygiene',
  vlan: 'VLAN consistency',
  security: 'Security posture',
};

function severityCounts(run: AuditRunSummary) {
  const parts: { label: string; count: number; severity: AuditSeverity }[] = [
    { label: 'Critical', count: run.findings_critical, severity: 'critical' },
    { label: 'High', count: run.findings_high, severity: 'high' },
    { label: 'Medium', count: run.findings_medium, severity: 'medium' },
    { label: 'Low', count: run.findings_low, severity: 'low' },
    { label: 'Info', count: run.findings_info, severity: 'info' },
  ];
  return parts.filter((p) => p.count > 0);
}

// Body of the Compliance page's "CIS Audit" tab (formerly the standalone
// /audit page). The tab bar supplies the heading, so this starts with the
// run-now toolbar.
export function AuditContent() {
  const runs = useAuditRuns();
  const trigger = useTriggerAuditRun();
  const [selectedRunId, setSelectedRunId] = useState<number | null>(null);
  const findings = useAuditFindings(selectedRunId);

  const runList: AuditRunSummary[] = runs.data?.runs ?? [];

  return (
    <div className="stack">
      <div
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          gap: '0.5rem',
          flexWrap: 'wrap',
        }}
      >
        <span className="text-muted" style={{ fontSize: '0.9em' }}>
          Grades the live inventory against CIS-style checks: configuration drift, port hygiene, VLAN consistency and security posture.
        </span>
        <button
          className="btn btn-sm btn-primary"
          disabled={trigger.isPending}
          onClick={() => trigger.mutate()}
        >
          {trigger.isPending ? 'Running…' : 'Run audit now'}
        </button>
      </div>

      {trigger.error && (
        <div className="card card-sm" style={{ color: 'var(--danger)' }}>
          Run failed: {(trigger.error as Error).message}
        </div>
      )}

      <SchedulesCard />

      <OverridesCard />

      <section className="card">
        <h3 style={{ marginTop: 0 }}>Recent runs</h3>
        {runs.isError && !runs.data && (
          <QueryError what="audit runs" query={runs} />
        )}
        {runs.isPending && <LoadingState />}
        {runs.data && runList.length === 0 && (
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
                        ? 'var(--primary-soft)'
                        : undefined,
                  }}
                  onClick={() => setSelectedRunId(r.id)}
                >
                  <td>#{r.id}</td>
                  <td>
                    <StatusBadge status={r.status} />
                  </td>
                  <td>
                    {r.started_at
                      ? formatBackendDateTime(r.started_at)
                      : '-'}
                  </td>
                  <td>{r.host_count}</td>
                  <td>{r.findings_total}</td>
                  <td>
                    <div style={{ display: 'flex', gap: '0.25rem', flexWrap: 'wrap' }}>
                      {severityCounts(r).map((p) => (
                        <SeverityBadge key={p.label} severity={p.severity}>
                          {p.label}: {p.count}
                        </SeverityBadge>
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
        <section className="card">
          <h3 style={{ marginTop: 0 }}>Findings - run #{selectedRunId}</h3>
          {findings.isError && !findings.data && (
            <QueryError what="audit findings" query={findings} />
          )}
          {findings.isPending && <LoadingState text="Loading findings…" />}
          {findings.data && findings.data.findings.length === 0 && (
            <EmptyState compact message="No findings for this run." />
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
        const sev = severityRank(a.severity) - severityRank(b.severity);
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
        <EmptyState compact message="No findings match the current filters." />
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
        {SEVERITY_LEVELS.filter((s) => severityTotals[s] > 0).map((s) => (
          <FilterChip
            key={s}
            label={`${s} (${severityTotals[s]})`}
            severity={s}
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
  severity?: AuditSeverity;
}) {
  return (
    <Badge
      onClick={props.onClick}
      tone={severityTone(props.severity)}
      solid={isCriticalSeverity(props.severity)}
      style={{
        cursor: 'pointer',
        border: props.active
          ? '1px solid var(--primary)'
          : '1px solid transparent',
        opacity: props.active ? 1 : 0.7,
        textTransform: 'capitalize',
      }}
    >
      {props.label}
    </Badge>
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
    return SEVERITY_LEVELS.filter((s) => counts[s] > 0).map((s) => ({
      sev: s,
      count: counts[s],
    }));
  }, [findings]);

  return (
    <div
      style={{
        border: '1px solid var(--border)',
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
          background: 'rgba(from var(--text) r g b / 0.04)',
          borderBottom: collapsed
            ? 'none'
            : '1px solid var(--border)',
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
            <SeverityBadge key={sev} severity={sev}>
              {sev}: {count}
            </SeverityBadge>
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
  const { confirm, alert } = useDialogs();
  const schedules = useAuditSchedules();
  const update = useUpdateAuditSchedule();
  const remove = useDeleteAuditSchedule();
  const runNow = useRunScheduleNow();
  const pending = usePendingKeys<string>();
  const [editing, setEditing] = useState<AuditSchedule | 'new' | null>(null);

  const runRow = (key: string, task: () => Promise<unknown>) =>
    pending.run(key, async () => {
      try {
        await task();
      } catch (e) {
        void alert({ message: (e as Error).message, variant: 'error' });
      }
    });

  const rows = schedules.data?.schedules ?? [];

  return (
    <section className="card">
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

      {schedules.isError && !schedules.data && (
        <QueryError what="audit schedules" query={schedules} />
      )}
      {schedules.isPending && <LoadingState />}
      {schedules.data && rows.length === 0 && (
        <EmptyState compact message="No schedules configured. Schedules enqueue an audit run on a
          recurring cadence (e.g., daily, every 6 hours)." />
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
                      s.enabled ? 'badge-success' : 'badge-secondary'
                    }`}
                  >
                    {s.enabled ? 'enabled' : 'paused'}
                  </span>
                </td>
                <td>
                  {s.last_run_at
                    ? formatBackendDateTime(s.last_run_at)
                    : 'never'}
                </td>
                <td style={{ textAlign: 'right', whiteSpace: 'nowrap' }}>
                  <BusyButton
                    className="btn btn-sm"
                    busy={pending.isPending(`run:${s.id}`)}
                    onClick={() => void runRow(`run:${s.id}`, () => runNow.mutateAsync(s.id))}
                  >
                    Run now
                  </BusyButton>
                  <span style={{ marginLeft: '0.25rem' }}>
                    <KebabMenu label={`Actions for ${s.name}`}>
                      <MenuItem
                        disabled={pending.isPending(`toggle:${s.id}`)}
                        onSelect={() =>
                          void runRow(`toggle:${s.id}`, () =>
                            update.mutateAsync({
                              id: s.id,
                              payload: { enabled: !s.enabled },
                            }),
                          )
                        }
                      >
                        {s.enabled ? 'Pause' : 'Resume'}
                      </MenuItem>
                      <MenuItem onSelect={() => setEditing(s)}>Edit</MenuItem>
                      <MenuSeparator />
                      <MenuItem
                        danger
                        disabled={pending.isPending(`delete:${s.id}`)}
                        onSelect={async () => {
                          if (
                            await confirm({
                              title: 'Delete audit schedule',
                              message: `Delete schedule "${s.name}"?`,
                              confirmLabel: 'Delete',
                            })
                          ) {
                            await runRow(`delete:${s.id}`, () => remove.mutateAsync(s.id));
                          }
                        }}
                      >
                        Delete
                      </MenuItem>
                    </KebabMenu>
                  </span>
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
  const [nameError, setNameError] = useState('');
  const [error, setError] = useState<string | null>(null);

  const isNew = schedule === null;
  const pending = create.isPending || update.isPending;

  const submit = async () => {
    setError(null);
    const trimmedName = name.trim();
    if (!trimmedName) {
      setNameError('Name is required');
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
    <Modal
      isOpen
      onClose={onClose}
      title={isNew ? 'New schedule' : `Edit "${schedule!.name}"`}
      size="small"
      footer={
        <>
          <button
            type="button"
            className="btn btn-secondary"
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
        </>
      }
    >
      <div style={{ display: 'grid', gap: 'var(--space-3)' }}>
        <label style={{ display: 'grid', gap: '0.25rem' }}>
          <span>Name</span>
          <input
            type="text"
            value={name}
            onChange={(e) => {
              setName(e.target.value);
              setNameError('');
            }}
            aria-invalid={!!nameError}
            placeholder="e.g. Nightly compliance sweep"
          />
          <FieldError>{nameError}</FieldError>
        </label>

        <label style={{ display: 'grid', gap: '0.25rem' }}>
          <span>Cadence</span>
          <div style={{ display: 'flex', gap: '0.25rem', flexWrap: 'wrap' }}>
            {SCHEDULE_PRESETS.map((p) => (
              <button
                type="button"
                key={p.value}
                className={`badge ${
                  cadence === p.value ? 'badge-info' : 'badge-secondary'
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

        {error && <Callout tone="danger">{error}</Callout>}
      </div>
    </Modal>
  );
}

function FindingsTable({ findings }: { findings: AuditFinding[] }) {
  const [muting, setMuting] = useState<AuditFinding | null>(null);
  const { visible, hiddenCount, showMore } = useShowMore(findings);
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
        {visible.map((f) => (
          <tr key={f.id}>
            <td>
              <SeverityBadge severity={f.severity} />
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
    {hiddenCount > 0 && (
      <button
        type="button"
        className="btn btn-sm"
        style={{ marginTop: '0.5rem' }}
        onClick={showMore}
      >
        Show more ({hiddenCount.toLocaleString()} hidden)
      </button>
    )}
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
  const { confirm, alert } = useDialogs();
  const overrides = useAuditOverrides();
  const remove = useDeleteAuditOverride();
  const removing = usePendingKeys<number>();
  const rows = overrides.data?.overrides ?? [];

  return (
    <section className="card">
      <h3 style={{ marginTop: 0 }}>Suppressed findings</h3>
      {overrides.isError && !overrides.data && (
        <QueryError what="finding overrides" query={overrides} />
      )}
      {overrides.isPending && <LoadingState />}
      {overrides.data && rows.length === 0 && (
        <EmptyState compact message="No active overrides. Mute a finding from a run to silence a chronic
          false positive; muted findings still log to the summary so the count
          stays auditable." />
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
                        : 'badge-secondary'
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
                    ? formatBackendDateTime(o.expires_at)
                    : <span className="text-muted">never</span>}
                </td>
                <td>
                  {o.created_at
                    ? formatBackendDateTime(o.created_at)
                    : '-'}
                </td>
                <td style={{ textAlign: 'right' }}>
                  <BusyButton
                    className="btn btn-sm btn-danger"
                    busy={removing.isPending(o.id)}
                    onClick={async () => {
                      if (
                        await confirm({
                          title: 'Remove finding override',
                          message: `Remove the override for rule "${o.rule_id}"?`,
                          confirmLabel: 'Remove',
                        })
                      ) {
                        await removing.run(o.id, async () => {
                          try {
                            await remove.mutateAsync(o.id);
                          } catch (e) {
                            void alert({ message: (e as Error).message, variant: 'error' });
                          }
                        });
                      }
                    }}
                  >
                    Remove
                  </BusyButton>
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
    <Modal
      isOpen
      onClose={onClose}
      title="Mute finding"
      footer={
        <>
          <button type="button" className="btn btn-secondary" onClick={onClose}>
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
        </>
      }
    >
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
        <Callout tone="danger">
          {(create.error as Error).message}
        </Callout>
      )}
    </Modal>
  );
}

