import { useEffect, useId, useMemo, useRef, useState } from 'react';

import { BusyButton } from '@/components/BusyButton';
import { Callout } from '@/components/Callout';
import { DataTable } from '@/components/DataTable';
import { LoadingState } from '@/components/LoadingState';
import { Modal } from '@/components/Modal';
import { ProgressBar } from '@/components/ProgressBar';
import { QueryError } from '@/components/QueryError';
import { useDialogs } from '@/components/DialogProvider-context';
import {
  ComplianceFinding,
  useComplianceScanResult,
  useCredentials,
  useRemediateFinding,
} from '@/api/compliance';
import { usePendingKeys } from '@/lib/usePendingKeys';

import { FindingResultCell } from './FindingResultCell';

/** Where a running Fix All is: the rule being fixed (index of total) and the tally so far. */
interface FixAllProgress {
  index: number;
  total: number;
  rule: string;
  fixed: number;
  failed: number;
}

interface Props {
  resultId: number;
  onClose: () => void;
  /** Called with the new scan id after a remediation rescan replaces the result. */
  onRescan: (newId: number) => void;
}

export function FindingsModal({ resultId, onClose, onRescan }: Props) {
  const { confirm, alert } = useDialogs();
  const result = useComplianceScanResult(resultId);
  const credentials = useCredentials();
  const remediate = useRemediateFinding();
  const fid = useId();

  const [credentialId, setCredentialId] = useState<number | null>(null);
  const [previewIndex, setPreviewIndex] = useState<number | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [fixAll, setFixAll] = useState<FixAllProgress | null>(null);
  // Single Fix buttons are busy per rule; Fix All has its own progress.
  const fixing = usePendingKeys<string>();
  const busy = fixAll != null || fixing.anyPending;

  // A fix keeps running if the modal is closed, but must not reopen it with
  // its rescan id or pop result dialogs over another page afterwards.
  const mounted = useRef(true);
  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
    };
  }, []);

  const findings = useMemo<ComplianceFinding[]>(() => {
    if (!result.data) return [];
    try {
      return JSON.parse(result.data.findings || '[]') as ComplianceFinding[];
    } catch {
      return [];
    }
  }, [result.data]);

  const credList = useMemo(() => credentials.data || [], [credentials.data]);
  const [prevCredList, setPrevCredList] = useState(credList);
  const [prevCredentialId, setPrevCredentialId] = useState(credentialId);
  // Default to the first credential whenever the selection is cleared or the
  // list loads/changes (mirrors the original credentialId/credList effect).
  if (credList !== prevCredList || credentialId !== prevCredentialId) {
    setPrevCredList(credList);
    setPrevCredentialId(credentialId);
    if (credentialId == null && credList.length > 0) setCredentialId(credList[0].id);
  }

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
      !(await confirm({
        title: 'Apply remediation fix',
        message: `Push fix commands to the device for rule “${rule}”?\n\nThis will modify the running config and save it.`,
        confirmLabel: 'Apply fix',
      }))
    ) {
      return;
    }
    await fixing.run(rule, async () => {
      try {
        const res = await remediate.mutateAsync({
          result_id: resultId,
          rule_name: rule,
          credential_id: credentialId,
          dry_run: false,
        });
        if (!mounted.current) return;
        if (res.rule_now_passes) {
          void alert({
            title: 'Remediation applied',
            message: `${res.rule} - FIXED. New score: ${res.rescan_passed}/${res.rescan_total}`,
          });
        } else {
          void alert({
            title: 'Remediation applied',
            message: `Rule still failing. Review device output. New score: ${res.rescan_passed}/${res.rescan_total}`,
            variant: 'error',
          });
        }
        onRescan(res.rescan_id);
      } catch (e) {
        setError(`Remediation failed: ${(e as Error).message}`);
      }
    });
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
      !(await confirm({
        title: 'Apply all remediation fixes',
        message: `Apply remediation for ${fixable.length} failed rule(s) on ${result.data?.hostname || '?'}?\n\nThis will push config changes and save.`,
        confirmLabel: 'Apply fixes',
      }))
    ) {
      return;
    }

    let lastRescanId = resultId;
    let fixed = 0;
    let failed = 0;
    const total = fixable.length;
    for (const [index, f] of fixable.entries()) {
      setFixAll({ index, total, rule: f.name, fixed, failed });
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
    setFixAll(null);
    if (!mounted.current) return;
    if (failed === 0) {
      void alert({
        title: 'Remediation complete',
        message: `All ${fixed} rule(s) remediated successfully.`,
      });
    } else {
      void alert({
        title: 'Remediation complete',
        message: `${fixed} rule(s) fixed, ${failed} still failing - review manually.`,
        variant: 'error',
      });
    }
    onRescan(lastRescanId);
  };

  const title = result.data
    ? `Compliance Findings - ${result.data.hostname || '?'}`
    : 'Compliance Findings';

  return (
    <Modal
      isOpen
      onClose={onClose}
      title={title}
      size="medium"
      footer={
        <button type="button" className="btn btn-secondary" onClick={onClose}>
          Close
        </button>
      }
    >
      {result.isError && !result.data && (
        <QueryError what="scan findings" query={result} />
      )}
      {result.isLoading && <LoadingState text="Loading findings…" />}
      {result.data && (
        <>
          <div style={{ marginBottom: '1rem', fontSize: '0.9em' }}>
            <strong>Profile:</strong> {result.data.profile_name || '?'} ·{' '}
            <strong>Status:</strong> {result.data.status} · <strong>Score:</strong>{' '}
            {result.data.passed_rules}/{result.data.total_rules} passed
          </div>
          {fixable.length > 0 && credentials.isError && !credentials.data && (
            <QueryError what="credentials" query={credentials} />
          )}
          {fixable.length > 0 && (
            <div className="toolbar">
              <label htmlFor={`${fid}-credential`} style={{ fontWeight: 600, fontSize: '0.9em' }}>
                Credential for remediation:
              </label>
              <select
                id={`${fid}-credential`}
                className="form-select form-select-sm"
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
              <BusyButton
                className="btn btn-sm btn-primary"
                onClick={() => void remediateAll()}
                busy={fixAll != null}
                busyLabel="Fixing…"
                disabled={busy}
              >
                Fix All
              </BusyButton>
            </div>
          )}
          {fixAll && (
            <Callout tone="info">
              <div>
                Fixing {fixAll.index + 1} of {fixAll.total}: <strong>{fixAll.rule}</strong>
              </div>
              <ProgressBar
                value={(fixAll.index / fixAll.total) * 100}
                label="Remediation progress"
                style={{ margin: '0.4rem 0' }}
              />
              <div style={{ fontSize: '0.85em', color: 'var(--text-muted)' }}>
                {fixAll.fixed} fixed, {fixAll.failed} still failing so far
              </div>
            </Callout>
          )}
          {error && <Callout tone="danger">{error}</Callout>}
          <DataTable compact aria-label="Findings">
            <thead>
              <tr>
                <th>Result</th>
                <th>Rule</th>
                <th>Detail</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
              {findings.map((f, idx) => {
                const hasFix = !f.passed && f.remediation && f.remediation.length > 0;
                return (
                  <tr key={idx}>
                    <FindingResultCell passed={f.passed} />
                    <td>
                      {f.name || '-'}
                      {f.type && (
                        <div style={{ fontSize: '0.8em', color: 'var(--text-muted)' }}>
                          <code>{f.type}</code>
                        </div>
                      )}
                    </td>
                    <td style={{ fontSize: '0.9em' }}>{f.detail || '-'}</td>
                    <td style={{ whiteSpace: 'nowrap' }}>
                      {hasFix ? (
                        <>
                          <BusyButton
                            className="btn btn-sm btn-primary"
                            onClick={() => void remediateOne(f.name)}
                            busy={fixing.isPending(f.name) || fixAll?.rule === f.name}
                            busyLabel="Fixing…"
                            disabled={busy}
                          >
                            Fix
                          </BusyButton>{' '}
                          <button
                            className="btn btn-sm btn-secondary"
                            onClick={() => setPreviewIndex(idx)}
                          >
                            Preview
                          </button>
                        </>
                      ) : !f.passed ? (
                        <span style={{ fontSize: '0.85em', color: 'var(--text-muted)' }}>
                          Manual fix required
                        </span>
                      ) : null}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </DataTable>
        </>
      )}

      {previewIndex != null && findings[previewIndex] && (
        <Modal
          isOpen
          onClose={() => setPreviewIndex(null)}
          title={`Remediation Preview - ${findings[previewIndex].name}`}
          footer={
            <button type="button" className="btn btn-secondary" onClick={() => setPreviewIndex(null)}>
              Close
            </button>
          }
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
        </Modal>
      )}
    </Modal>
  );
}
