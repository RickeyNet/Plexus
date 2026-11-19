import { useState } from 'react';
import type { UseMutationResult, UseQueryResult } from '@tanstack/react-query';

import type { CatoCheckFinding, CatoCheckRunResult } from '@/api/monitoring';
import { SeverityBadge } from '@/components/Badge';
import { useDialogs } from '@/components/DialogProvider-context';
import { LoadingState } from '@/components/LoadingState';
import { QueryError } from '@/components/QueryError';
import { sourceTypeLabel } from '@/pages/Topology/merakiHelpers';
import { formatBackendDateTime } from '@/lib/datetime';


export interface CatoCheckPanelProps {
  title: string;
  /** One or two sentences under the title: what is checked and when it runs. */
  description: string;
  /** What failed to load, for the error state, e.g. "Cato egress findings". */
  what: string;
  /** Shown when the check has no finding. */
  emptyText: string;
  /** Header of the column that names the cloud object a finding is about. */
  ruleHeader: string;
  /** The findings hook of the check, called with "include resolved". */
  useFindings: (includeResolved: boolean) => UseQueryResult<{ findings: CatoCheckFinding[] }>;
  /** The "run now" hook of the check. */
  useRun: () => UseMutationResult<CatoCheckRunResult, Error, void>;
}

/**
 * The findings of one server-side Cato check (Monitoring > Availability):
 * a "Show resolved" toggle, a Run Check button and the findings table. The
 * checks store their findings in one table, so they share this panel.
 */
export function CatoCheckPanel({ title, description, what, emptyText, ruleHeader, useFindings, useRun }: CatoCheckPanelProps) {
  const [includeResolved, setIncludeResolved] = useState(false);
  const findings = useFindings(includeResolved);
  const run = useRun();
  const { alert } = useDialogs();
  const rows = findings.data?.findings ?? [];

  function handleRun() {
    run.mutate(undefined, {
      onSuccess: (r) => {
        const text = r.ok
          ? `Check complete: ${r.findings} finding(s), ${r.warnings} warning(s), ${r.alerted} new alert(s).`
          : `Check failed: ${r.error ?? 'unknown error'}.`;
        void alert(text);
      },
      onError: (e) => { void alert({ message: e.message, variant: 'error' }); },
    });
  }

  return (
    <div style={{ marginTop: '1.5rem' }}>
      <h3 style={{ marginBottom: '0.5rem' }}>{title}</h3>
      <p className="text-muted" style={{ marginTop: 0, fontSize: '0.85em' }}>{description}</p>
      <div className="toolbar">
        <label className="text-muted" style={{ display: 'flex', gap: '0.3rem', alignItems: 'center' }}>
          <input type="checkbox" checked={includeResolved} onChange={(e) => setIncludeResolved(e.target.checked)} />
          Show resolved
        </label>
        <button className="btn btn-sm btn-secondary" onClick={handleRun} disabled={run.isPending}>
          {run.isPending ? 'Checking…' : 'Run Check'}
        </button>
      </div>

      {findings.error && !findings.data ? (
        <QueryError what={what} query={findings} />
      ) : findings.isPending ? (
        <LoadingState />
      ) : !rows.length ? (
        <div className="empty-state">{emptyText}</div>
      ) : (
        <div style={{ maxHeight: 520, overflow: 'auto' }}>
          <table className="data-table">
            <thead>
              <tr>
                <th>Severity</th>
                <th>Finding</th>
                <th>Cato account</th>
                <th>Resource</th>
                <th>Ports</th>
                <th>{ruleHeader}</th>
                <th>Detail</th>
                <th>Last seen</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((f) => (
                <tr key={f.finding_key} style={f.status === 'resolved' ? { opacity: 0.6 } : undefined}>
                  <td>
                    <SeverityBadge severity={f.severity} />
                    {f.status === 'resolved' && <span className="text-muted" style={{ fontSize: '0.8em', marginLeft: '0.3rem' }}>resolved</span>}
                  </td>
                  <td>{f.kind_label}</td>
                  <td>{f.cato_org_name || f.cato_org_ref}</td>
                  <td>
                    {f.provider ? (
                      <>
                        {f.resource_name || f.resource_id}
                        <span className="text-muted" style={{ fontSize: '0.85em' }}> {sourceTypeLabel(f.provider)} {f.public_ip || f.private_ip}</span>
                      </>
                    ) : '-'}
                  </td>
                  <td>{f.provider && (f.protocol || f.ports) ? `${f.protocol} ${f.ports}`.trim() : '-'}</td>
                  <td>{f.filter_name ? [f.filter_name, f.rule_name].filter(Boolean).join(': ') : '-'}</td>
                  <td style={{ fontSize: '0.85em', minWidth: 320 }}>{f.message}</td>
                  <td style={{ whiteSpace: 'nowrap' }}>{formatBackendDateTime(f.last_seen)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
