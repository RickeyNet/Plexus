import { useMemo, useState } from 'react';

import { Modal } from '@/components/Modal';
import {
  ComplianceFinding,
  useComplianceScanResult,
  useCredentials,
  useRemediateFinding,
} from '@/api/compliance';

interface Props {
  resultId: number;
  onClose: () => void;
  /** Called with the new scan id after a remediation rescan replaces the result. */
  onRescan: (newId: number) => void;
}

export function FindingsModal({ resultId, onClose, onRescan }: Props) {
  const result = useComplianceScanResult(resultId);
  const credentials = useCredentials();
  const remediate = useRemediateFinding();

  const [credentialId, setCredentialId] = useState<number | null>(null);
  const [previewIndex, setPreviewIndex] = useState<number | null>(null);
  const [error, setError] = useState<string | null>(null);

  const findings = useMemo<ComplianceFinding[]>(() => {
    if (!result.data) return [];
    try {
      return JSON.parse(result.data.findings || '[]') as ComplianceFinding[];
    } catch {
      return [];
    }
  }, [result.data]);

  const credList = credentials.data || [];
  if (credentialId == null && credList.length > 0) setCredentialId(credList[0].id);

  const fixable = findings.filter(
    (f) => !f.passed && f.remediation && f.remediation.length > 0,
  );

  const remediateOne = async (rule: string) => {
    setError(null);
    if (credentialId == null) {
      setError('Select a credential before applying a fix.');
      return;
    }
    if (
      !confirm(
        `Push fix commands to the device for rule "${rule}"?\n\nThis will modify the running config and save it.`,
      )
    ) {
      return;
    }
    try {
      const res = await remediate.mutateAsync({
        result_id: resultId,
        rule_name: rule,
        credential_id: credentialId,
        dry_run: false,
      });
      if (res.rule_now_passes) {
        alert(`${res.rule} — FIXED. New score: ${res.rescan_passed}/${res.rescan_total}`);
      } else {
        alert(
          `Remediation applied but rule still failing. Review device output. New score: ${res.rescan_passed}/${res.rescan_total}`,
        );
      }
      onRescan(res.rescan_id);
    } catch (e) {
      setError(`Remediation failed: ${(e as Error).message}`);
    }
  };

  const remediateAll = async () => {
    setError(null);
    if (credentialId == null) {
      setError('Select a credential before applying fixes.');
      return;
    }
    if (fixable.length === 0) {
      setError('No auto-fixable rules found.');
      return;
    }
    if (
      !confirm(
        `Apply remediation for ${fixable.length} failed rule(s) on ${result.data?.hostname || '?'}?\n\nThis will push config changes and save.`,
      )
    ) {
      return;
    }

    let lastRescanId = resultId;
    let fixed = 0;
    let failed = 0;
    for (const f of fixable) {
      try {
        const res = await remediate.mutateAsync({
          result_id: lastRescanId,
          rule_name: f.name,
          credential_id: credentialId,
          dry_run: false,
        });
        lastRescanId = res.rescan_id;
        if (res.rule_now_passes) fixed++;
        else failed++;
      } catch {
        failed++;
      }
    }
    if (failed === 0) {
      alert(`All ${fixed} rule(s) remediated successfully.`);
    } else {
      alert(`${fixed} rule(s) fixed, ${failed} still failing — review manually.`);
    }
    onRescan(lastRescanId);
  };

  const title = result.data
    ? `Compliance Findings — ${result.data.hostname || '?'}`
    : 'Compliance Findings';

  return (
    <Modal isOpen onClose={onClose} title={title}>
      {result.isLoading && <p className="text-muted">Loading findings…</p>}
      {result.data && (
        <>
          <div style={{ marginBottom: '1rem' }}>
            <strong>Profile:</strong> {result.data.profile_name || '?'} ·{' '}
            <strong>Status:</strong> {result.data.status} · <strong>Score:</strong>{' '}
            {result.data.passed_rules}/{result.data.total_rules} passed
          </div>
          {fixable.length > 0 && (
            <div
              style={{
                marginBottom: '1rem',
                display: 'flex',
                alignItems: 'center',
                gap: '0.75rem',
                flexWrap: 'wrap',
              }}
            >
              <label style={{ fontWeight: 600, fontSize: '0.9em' }}>
                Credential for remediation:
              </label>
              <select
                className="form-select"
                style={{ maxWidth: 300 }}
                value={credentialId ?? ''}
                onChange={(e) =>
                  setCredentialId(e.target.value ? parseInt(e.target.value, 10) : null)
                }
              >
                <option value="">Select credential…</option>
                {credList.map((c) => (
                  <option key={c.id} value={c.id}>
                    {c.name}
                  </option>
                ))}
              </select>
              <button
                className="btn btn-sm btn-primary"
                onClick={remediateAll}
                disabled={remediate.isPending}
              >
                Fix All
              </button>
            </div>
          )}
          {error && <div className="error">{error}</div>}
          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.9em' }}>
              <thead>
                <tr style={{ borderBottom: '1px solid var(--border)' }}>
                  <th style={{ textAlign: 'left', padding: '0.5rem' }}>Result</th>
                  <th style={{ textAlign: 'left', padding: '0.5rem' }}>Rule</th>
                  <th style={{ textAlign: 'left', padding: '0.5rem' }}>Type</th>
                  <th style={{ textAlign: 'left', padding: '0.5rem' }}>Detail</th>
                  <th style={{ textAlign: 'left', padding: '0.5rem' }}>Action</th>
                </tr>
              </thead>
              <tbody>
                {findings.map((f, idx) => {
                  const color = f.passed ? 'success' : 'danger';
                  const hasFix = !f.passed && f.remediation && f.remediation.length > 0;
                  return (
                    <tr key={idx}>
                      <td style={{ color: `var(--${color})`, padding: '0.5rem' }}>
                        {f.passed ? 'PASS' : 'FAIL'}
                      </td>
                      <td style={{ padding: '0.5rem' }}>{f.name || '-'}</td>
                      <td style={{ padding: '0.5rem' }}>
                        <code>{f.type || '-'}</code>
                      </td>
                      <td style={{ padding: '0.5rem', fontSize: '0.85em' }}>
                        {f.detail || '-'}
                      </td>
                      <td style={{ padding: '0.5rem', whiteSpace: 'nowrap' }}>
                        {hasFix ? (
                          <>
                            <button
                              className="btn btn-sm btn-primary"
                              onClick={() => remediateOne(f.name)}
                              disabled={remediate.isPending}
                            >
                              Fix
                            </button>{' '}
                            <button
                              className="btn btn-sm btn-secondary"
                              onClick={() => setPreviewIndex(idx)}
                            >
                              Preview
                            </button>
                          </>
                        ) : !f.passed ? (
                          <span style={{ fontSize: '0.8em', color: 'var(--text-muted)' }}>
                            Manual fix required
                          </span>
                        ) : null}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </>
      )}

      {previewIndex != null && findings[previewIndex] && (
        <Modal
          isOpen
          onClose={() => setPreviewIndex(null)}
          title={`Remediation Preview — ${findings[previewIndex].name}`}
        >
          <p style={{ marginBottom: '0.75rem' }}>
            The following commands will be pushed in config mode:
          </p>
          <pre
            style={{
              background: 'var(--bg-secondary)',
              padding: '1rem',
              borderRadius: '0.5rem',
              overflowX: 'auto',
              fontSize: '0.9em',
            }}
          >
            {(findings[previewIndex].remediation || []).join('\n')}
          </pre>
          <div style={{ marginTop: '1rem', textAlign: 'right' }}>
            <button className="btn btn-secondary" onClick={() => setPreviewIndex(null)}>
              Close
            </button>
          </div>
        </Modal>
      )}
    </Modal>
  );
}
