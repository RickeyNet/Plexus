import { useMemo, useState } from 'react';

import {
  useAuditRuns,
  useAuditFindings,
  useTriggerAuditRun,
  type AuditRunSummary,
  type AuditFinding,
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
          <h3 style={{ marginTop: 0 }}>Findings — run #{selectedRunId}</h3>
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

function FindingsTable({ findings }: { findings: AuditFinding[] }) {
  return (
    <table className="data-table">
      <thead>
        <tr>
          <th>Severity</th>
          <th>Rule</th>
          <th>Host</th>
          <th>Title</th>
          <th>Detail</th>
          <th>CIS</th>
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
          </tr>
        ))}
      </tbody>
    </table>
  );
}
