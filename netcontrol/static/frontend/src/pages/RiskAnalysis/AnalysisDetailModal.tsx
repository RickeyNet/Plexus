import {
  type RiskAnalysis,
  useApproveRiskAnalysis,
  useRiskAnalysis,
} from '@/api/riskAnalysis';
import { BusyButton } from '@/components/BusyButton';
import { LoadingState } from '@/components/LoadingState';
import { Modal } from '@/components/Modal';
import { QueryError } from '@/components/QueryError';
import { useDialogs } from '@/components/DialogProvider-context';
import { changeTypeLabel } from '@/lib/changeTypes';
import { formatBackendDateTime } from '@/lib/datetime';
import { severityTone, toneColor } from '@/lib/severity';
import { UnifiedDiff } from '@/pages/Configuration/UnifiedDiff';

import {
  parseJsonArray,
  parseJsonObject,
  scorePercent,
  targetLabel,
} from './helpers';

interface ChangeVolume {
  total_commands?: number;
  diff_lines_added?: number;
  diff_lines_removed?: number;
}

interface AnalysisJson {
  risk_factors?: string[];
  change_volume?: ChangeVolume;
}

interface ChangedRule {
  name: string;
  before: string;
  after: string;
  impact: 'regression' | 'improvement' | string;
}

interface ComplianceImpactItem {
  profile_name?: string;
  new_violations?: number;
  improvements?: number;
  changed_rules?: ChangedRule[];
}

interface Props {
  isOpen: boolean;
  onClose: () => void;
  analysisId: number | null;
}

export function AnalysisDetailModal({ isOpen, onClose, analysisId }: Props) {
  const { confirm, alert } = useDialogs();
  const query = useRiskAnalysis(isOpen ? analysisId : null);
  const approve = useApproveRiskAnalysis();

  const handleApprove = async (analysis: RiskAnalysis) => {
    const ok = await confirm({
      title: 'Approve risk analysis',
      message: `Approve risk analysis #${analysis.id} (${String(analysis.risk_level).toUpperCase()} risk) for ${targetLabel(analysis)}? You are recorded as the approver, and the analysis can then be linked to a new deployment of this change.`,
      confirmLabel: 'Approve',
      confirmVariant: 'primary',
    });
    if (!ok) return;
    approve.mutate(analysis.id, {
      onSuccess: () => onClose(),
      onError: (e) => {
        void alert({ message: (e as Error).message, variant: 'error' });
      },
    });
  };

  return (
    <Modal
      isOpen={isOpen}
      onClose={onClose}
      title="Risk Analysis Details"
      size="medium"
      footer={
        <>
          <button type="button" className="btn btn-secondary" onClick={onClose}>
            Close
          </button>
          {query.data && !query.data.approved && (
            <BusyButton
              className="btn btn-primary"
              busy={approve.isPending}
              busyLabel="Approving…"
              onClick={() => {
                if (query.data) void handleApprove(query.data);
              }}
            >
              Approve Change
            </BusyButton>
          )}
        </>
      }
    >
      {query.isError && !query.data && (
        <QueryError what="the risk analysis" query={query} />
      )}
      {query.isPending && <LoadingState />}
      {query.data && <DetailBody analysis={query.data} />}
    </Modal>
  );
}

function DetailBody({ analysis }: { analysis: RiskAnalysis }) {
  const color = toneColor(severityTone(analysis.risk_level));
  const percent = scorePercent(analysis.risk_score);
  const analysisObj = parseJsonObject<AnalysisJson>(analysis.analysis);
  const compliance = parseJsonArray<ComplianceImpactItem>(analysis.compliance_impact);
  const areas = parseJsonArray<string>(analysis.affected_areas);
  const factors = analysisObj.risk_factors || [];
  const volume = analysisObj.change_volume || {};
  const isApproved = !!analysis.approved;

  return (
    <>
      <div style={{ display: 'flex', gap: '1.5rem', flexWrap: 'wrap', marginBottom: '1rem' }}>
        <div style={{ textAlign: 'center' }}>
          <div
            style={{
              fontSize: '2em',
              fontWeight: 700,
              color: color,
              textTransform: 'uppercase',
            }}
          >
            {analysis.risk_level}
          </div>
          <div style={{ fontSize: '1.1em', color: 'var(--text-muted)' }}>
            Risk Score: {percent}%
          </div>
          <div
            style={{
              marginTop: '0.5rem',
              width: 120,
              background: 'var(--bg-secondary)',
              borderRadius: 4,
              height: 8,
              overflow: 'hidden',
            }}
          >
            <div
              style={{
                width: `${percent}%`,
                height: '100%',
                background: color,
                borderRadius: 4,
              }}
            />
          </div>
        </div>
        <div style={{ flex: 1, minWidth: 200 }}>
          <div>
            <strong>Target:</strong> {targetLabel(analysis)}
          </div>
          <div>
            <strong>Change type:</strong> {changeTypeLabel(analysis.change_type)}
          </div>
          <div>
            <strong>Status:</strong>{' '}
            {isApproved ? (
              <>
                <span style={{ color: 'var(--success)' }}>Approved</span>
                {analysis.approved_by ? ` by ${analysis.approved_by}` : ''}
              </>
            ) : (
              <span style={{ color: 'var(--text-muted)' }}>Pending approval</span>
            )}
          </div>
          <div>
            <strong>Created:</strong> {formatBackendDateTime(analysis.created_at)}
            {analysis.created_by ? ` by ${analysis.created_by}` : ''}
          </div>
        </div>
      </div>

      {areas.length > 0 && (
        <div style={{ marginBottom: '1rem' }}>
          <strong>Affected Areas:</strong>{' '}
          {areas.map((a) => (
            <span
              key={a}
              className="badge"
              style={{
                background: 'var(--bg-secondary)',
                padding: '2px 8px',
                borderRadius: 4,
                marginRight: '0.25rem',
                fontSize: '0.85em',
              }}
            >
              {a}
            </span>
          ))}
        </div>
      )}

      {factors.length > 0 && (
        <div style={{ marginBottom: '1rem' }}>
          <strong>Risk Factors:</strong>
          <ul style={{ margin: '0.25rem 0 0 1.5rem' }}>
            {factors.map((f, i) => (
              <li key={i} style={{ marginBottom: '0.25rem' }}>
                {f}
              </li>
            ))}
          </ul>
        </div>
      )}

      {volume.total_commands ? (
        <div style={{ marginBottom: '1rem' }}>
          <strong>Change Volume:</strong> {volume.total_commands} commands, +
          {volume.diff_lines_added || 0} / -{volume.diff_lines_removed || 0} lines
        </div>
      ) : null}

      {compliance.length > 0 && (
        <div style={{ marginBottom: '1rem' }}>
          <strong>Compliance Impact:</strong>
          {compliance.map((ci, i) => (
            <div
              key={i}
              style={{
                marginTop: '0.5rem',
                padding: '0.5rem',
                background: 'var(--bg-secondary)',
                borderRadius: 6,
              }}
            >
              <strong>{ci.profile_name || '?'}</strong>
              <span style={{ marginLeft: '0.5rem', fontSize: '0.85em' }}>
                {ci.new_violations && ci.new_violations > 0 ? (
                  <span style={{ color: 'var(--danger)' }}>
                    +{ci.new_violations} violation(s)
                  </span>
                ) : null}
                {ci.improvements && ci.improvements > 0 ? (
                  <span style={{ color: 'var(--success)', marginLeft: '0.5rem' }}>
                    +{ci.improvements} improvement(s)
                  </span>
                ) : null}
              </span>
              {ci.changed_rules && ci.changed_rules.length > 0 && (
                <div style={{ marginTop: '0.25rem', fontSize: '0.8em' }}>
                  {ci.changed_rules.map((r, j) => (
                    <div key={j} style={{ marginLeft: '1rem' }}>
                      <span
                        style={{
                          color: `var(--${r.impact === 'regression' ? 'danger' : 'success'})`,
                        }}
                      >
                        {r.impact === 'regression' ? 'REGRESS' : 'IMPROVE'}
                      </span>{' '}
                      {r.name}: {r.before} → {r.after}
                    </div>
                  ))}
                </div>
              )}
            </div>
          ))}
        </div>
      )}

      {analysis.proposed_commands && (
        <details open style={{ marginBottom: '1rem' }}>
          <summary style={{ cursor: 'pointer', fontWeight: 600 }}>Proposed Commands</summary>
          <pre
            style={{
              marginTop: '0.5rem',
              background: 'var(--bg-secondary)',
              padding: '0.75rem',
              borderRadius: 6,
              fontSize: '0.8em',
              maxHeight: 200,
              overflow: 'auto',
              whiteSpace: 'pre-wrap',
            }}
          >
            {analysis.proposed_commands}
          </pre>
        </details>
      )}

      {analysis.proposed_diff && (
        <details open style={{ marginBottom: '1rem' }}>
          <summary style={{ cursor: 'pointer', fontWeight: 600 }}>
            Predicted Config Diff
          </summary>
          <UnifiedDiff
            diffText={analysis.proposed_diff}
            style={{ marginTop: '0.5rem', maxHeight: 300 }}
          />
        </details>
      )}
    </>
  );
}
