import { Modal } from '@/components/Modal';
import { MerakiFinding, useMerakiResult } from '@/api/compliance';

import { MERAKI_KIND_LABEL as KIND_LABEL, statusColor } from './merakiHelpers';

/**
 * Findings of one Meraki compliance target. Read-only: Plexus never writes to
 * the Dashboard API, so each failed check says what to change in the
 * Meraki Dashboard instead of offering a fix.
 */
export function MerakiFindingsModal({ resultId, onClose }: { resultId: number; onClose: () => void }) {
  const result = useMerakiResult(resultId);
  const data = result.data;
  const findings: MerakiFinding[] = data?.findings || [];
  const title = data
    ? `Meraki Findings - ${data.target_name || '?'}`
    : 'Meraki Findings';

  return (
    <Modal isOpen onClose={onClose} title={title} size="large">
      {result.isLoading && <p className="text-muted">Loading findings…</p>}
      {result.isError && <div className="error">Could not load this result.</div>}
      {data && (
        <>
          <div style={{ marginBottom: '1rem', fontSize: '0.9em' }}>
            <strong>{KIND_LABEL[data.target_kind] || data.target_kind}:</strong> {data.target_name}
            {data.model ? ` (${data.model}${data.serial ? `, ${data.serial}` : ''})` : ''}
            {data.target_kind === 'device' && data.network_name ? ` in ${data.network_name}` : ''} ·{' '}
            <strong>Organization:</strong> {data.org_name || '?'} · <strong>Profile:</strong>{' '}
            {data.profile_name || '?'} · <strong>Status:</strong>{' '}
            <span style={{ color: `var(--${statusColor(data.status)})`, fontWeight: 600 }}>{data.status}</span> ·{' '}
            <strong>Score:</strong> {data.passed_rules}/{data.total_rules} passed
            {data.unreadable_rules > 0 ? ` (${data.unreadable_rules} unreadable)` : ''}
          </div>
          <p className="text-muted" style={{ fontSize: '0.85em', marginBottom: '0.75rem' }}>
            Plexus reads the Meraki Dashboard API only; failed checks are corrected in the Meraki
            Dashboard. Re-run the scan afterwards to confirm.
          </p>
          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.9em' }}>
              <thead>
                <tr style={{ borderBottom: '1px solid var(--border)' }}>
                  <th style={{ textAlign: 'left', padding: '0.5rem' }}>Result</th>
                  <th style={{ textAlign: 'left', padding: '0.5rem' }}>Check</th>
                  <th style={{ textAlign: 'left', padding: '0.5rem' }}>Detail</th>
                  <th style={{ textAlign: 'left', padding: '0.5rem' }}>IOS equivalent</th>
                </tr>
              </thead>
              <tbody>
                {findings.map((f, idx) => {
                  const label = f.unreadable ? 'UNREADABLE' : f.passed ? 'PASS' : 'FAIL';
                  const color = f.unreadable ? 'warning' : f.passed ? 'success' : 'danger';
                  return (
                    <tr key={idx} style={{ borderBottom: '1px solid var(--border)' }}>
                      <td style={{ color: `var(--${color})`, padding: '0.5rem', whiteSpace: 'nowrap', fontWeight: 600 }}>
                        {label}
                      </td>
                      <td style={{ padding: '0.5rem' }}>
                        {f.name || '-'}
                        <div style={{ fontSize: '0.8em', color: 'var(--text-muted)' }}>
                          <code>{f.check}</code>
                        </div>
                      </td>
                      <td style={{ padding: '0.5rem', fontSize: '0.9em' }}>
                        {f.detail || '-'}
                        {f.evidence && f.evidence.length > 0 && (
                          <details style={{ marginTop: '0.3rem' }}>
                            <summary style={{ cursor: 'pointer', color: 'var(--text-muted)', fontSize: '0.9em' }}>
                              {f.evidence.length} item(s)
                            </summary>
                            <ul style={{ margin: '0.3rem 0 0 1rem', padding: 0, fontSize: '0.9em' }}>
                              {f.evidence.map((e, i) => (
                                <li key={i}>{e}</li>
                              ))}
                            </ul>
                          </details>
                        )}
                      </td>
                      <td style={{ padding: '0.5rem', fontSize: '0.85em', color: 'var(--text-muted)' }}>
                        {f.ios_equivalent ? <code>{f.ios_equivalent}</code> : '-'}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </>
      )}
      <div style={{ marginTop: '1rem', textAlign: 'right' }}>
        <button type="button" className="btn btn-secondary" onClick={onClose}>
          Close
        </button>
      </div>
    </Modal>
  );
}
