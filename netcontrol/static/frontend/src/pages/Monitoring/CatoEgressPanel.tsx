import { useState } from 'react';

import { useCatoEgressFindings, useRunCatoEgressCheck } from '@/api/monitoring';
import { useDialogs } from '@/components/DialogProvider-context';
import { severityBadgeClass } from '@/pages/Reports/helpers';
import { sourceTypeLabel } from '@/pages/Topology/merakiHelpers';

import { formatTimestamp } from './helpers';

/**
 * Cato egress vs cloud allow-lists: cloud filter rules (AWS security groups,
 * Azure NSGs, GCP firewall rules) that admit a Cato account's allocated IPs,
 * checked against the Cato network rule a connection to the protected public
 * address matches. Run on the server after every Cato collection and cloud
 * discovery; warnings alert like other monitoring alerts.
 */
export function CatoEgressPanel() {
  const [includeResolved, setIncludeResolved] = useState(false);
  const findings = useCatoEgressFindings(includeResolved);
  const run = useRunCatoEgressCheck();
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
      onError: (e) => { void alert({ message: (e as Error).message, variant: 'error' }); },
    });
  }

  return (
    <div style={{ marginTop: '1.5rem' }}>
      <h3 style={{ marginBottom: '0.5rem' }}>Cato egress vs cloud allow-lists</h3>
      <p className="text-muted" style={{ marginTop: 0, fontSize: '0.85em' }}>
        Cloud rules that allow a Cato account&apos;s allocated IPs, checked against the Cato network rule a connection
        to the protected public address takes. Runs after every Cato collection and cloud discovery.
      </p>
      <div className="toolbar">
        <label className="text-muted" style={{ display: 'flex', gap: '0.3rem', alignItems: 'center' }}>
          <input type="checkbox" checked={includeResolved} onChange={(e) => setIncludeResolved(e.target.checked)} />
          Show resolved
        </label>
        <button className="btn btn-sm btn-secondary" onClick={handleRun} disabled={run.isPending}>
          {run.isPending ? 'Checking…' : 'Run Check'}
        </button>
      </div>

      {findings.error && <p style={{ color: 'var(--danger)' }}>Failed to load the findings.</p>}

      {!rows.length ? (
        <div className="empty-state">
          {findings.isPending ? 'Loading…' : 'No findings - collect a Cato account and an AWS, Azure or GCP account.'}
        </div>
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
                <th>Cloud rule</th>
                <th>Detail</th>
                <th>Last seen</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((f) => (
                <tr key={f.finding_key} style={f.status === 'resolved' ? { opacity: 0.6 } : undefined}>
                  <td>
                    <span className={`badge ${severityBadgeClass(f.severity)}`}>{f.severity}</span>
                    {f.status === 'resolved' && <span className="text-muted" style={{ fontSize: '0.8em', marginLeft: '0.3rem' }}>resolved</span>}
                  </td>
                  <td>{f.kind_label}</td>
                  <td>{f.cato_org_name || f.cato_org_ref}</td>
                  <td>
                    {f.provider ? (
                      <>
                        {f.resource_name || f.resource_id}
                        <span className="text-muted" style={{ fontSize: '0.85em' }}> {sourceTypeLabel(f.provider)} {f.public_ip}</span>
                      </>
                    ) : '-'}
                  </td>
                  <td>{f.provider ? `${f.protocol} ${f.ports}` : '-'}</td>
                  <td>{f.filter_name ? `${f.filter_name}: ${f.rule_name}` : '-'}</td>
                  <td style={{ fontSize: '0.85em', minWidth: 320 }}>{f.message}</td>
                  <td style={{ whiteSpace: 'nowrap' }}>{formatTimestamp(f.last_seen)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
