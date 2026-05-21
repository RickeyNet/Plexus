import { useState } from 'react';

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
            <FindingsTable findings={findings.data.findings} />
          )}
        </section>
      )}
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
            <td>{f.evidence?.hostname as string | undefined ?? f.host_id ?? '-'}</td>
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
