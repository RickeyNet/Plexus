import { useMemo, useState } from 'react';

import {
  type RiskAnalysis as RiskAnalysisRow,
  type RiskAnalysisRunResult,
  type RiskAnalysisSummary,
  useDeleteRiskAnalysis,
  useRiskAnalyses,
  useRiskAnalysisSummary,
} from '@/api/riskAnalysis';
import { SeverityBadge } from '@/components/Badge';
import { DeleteButton } from '@/components/DeleteButton';
import { type DialogApi, useDialogs } from '@/components/DialogProvider-context';
import { LoadingState } from '@/components/LoadingState';
import { QueryError } from '@/components/QueryError';
import { SummaryStrip, type SummaryStripItem } from '@/components/SummaryStrip';
import { changeTypeLabel } from '@/lib/changeTypes';
import { formatBackendDateTime } from '@/lib/datetime';
import { severityTone, toneColor } from '@/lib/severity';

import { AnalysisDetailModal } from './AnalysisDetailModal';
import { NewAnalysisModal } from './NewAnalysisModal';
import { OfflineAnalysisModal } from './OfflineAnalysisModal';
import {
  filterAnalyses,
  parseJsonArray,
  scorePercent,
  targetLabel,
} from './helpers';

const LEVEL_FILTERS = [
  { value: '', label: 'All risk levels' },
  { value: 'critical', label: 'Critical' },
  { value: 'high', label: 'High' },
  { value: 'medium', label: 'Medium' },
  { value: 'low', label: 'Low' },
  { value: 'unknown', label: 'Unknown' },
];

export function RiskAnalysis() {
  const { confirm } = useDialogs();
  const summary = useRiskAnalysisSummary();
  const analyses = useRiskAnalyses(200);

  const [query, setQuery] = useState('');
  const [level, setLevel] = useState('');
  const [showNew, setShowNew] = useState(false);
  const [showOffline, setShowOffline] = useState(false);
  const [detailId, setDetailId] = useState<number | null>(null);

  const filtered = useMemo(
    () => filterAnalyses(analyses.data || [], { query, level }),
    [analyses.data, query, level],
  );

  return (
    <div className="stack stack-sm">
      <div className="toolbar">
        <h3 style={{ margin: 0 }}>Risk Analysis</h3>
        <span className="toolbar-spacer" />
        <button className="btn btn-sm btn-primary" onClick={() => setShowNew(true)}>
          New Analysis
        </button>
        <button className="btn btn-sm btn-secondary" onClick={() => setShowOffline(true)}>
          Offline Analysis
        </button>
        <button
          className="btn btn-sm btn-secondary"
          onClick={() => {
            summary.refetch();
            analyses.refetch();
          }}
        >
          Refresh
        </button>
      </div>

      <RiskSummary summary={summary.data} />

      <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
        <div
          className="toolbar"
          style={{
            padding: 'var(--space-2) var(--space-3)',
            borderBottom: '1px solid var(--border)',
            marginBottom: 0,
          }}
        >
          <select
            aria-label="Filter by risk level"
            className="form-select form-select-sm"
            value={level}
            onChange={(e) => setLevel(e.target.value)}
            style={{ maxWidth: 200 }}
          >
            {LEVEL_FILTERS.map((f) => (
              <option key={f.value} value={f.value}>
                {f.label}
              </option>
            ))}
          </select>
          <input
            aria-label="Search analyses"
            className="form-input form-input-sm"
            placeholder="Search hostname, group, or change type…"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            style={{ marginLeft: 'auto', maxWidth: 320 }}
          />
        </div>
        <div style={{ padding: 'var(--space-3)' }}>
          <AnalysisList
            items={filtered}
            loading={analyses.isLoading}
            error={analyses.isError && !analyses.data ? analyses.error : null}
            onRetry={() => void analyses.refetch()}
            isRetrying={analyses.isFetching}
            onView={(id) => setDetailId(id)}
            onNew={() => setShowNew(true)}
          />
        </div>
      </div>

      <NewAnalysisModal
        isOpen={showNew}
        onClose={() => setShowNew(false)}
        onAnalyzed={(result) => showRunResult(result, setDetailId, confirm)}
      />
      <OfflineAnalysisModal
        isOpen={showOffline}
        onClose={() => setShowOffline(false)}
        onAnalyzed={(result) => setDetailId(result.id)}
      />
      <AnalysisDetailModal
        isOpen={detailId != null}
        onClose={() => setDetailId(null)}
        analysisId={detailId}
      />
    </div>
  );
}

async function showRunResult(
  result: RiskAnalysisRunResult,
  setDetailId: (id: number) => void,
  confirm: DialogApi['confirm'],
) {
  const percent = scorePercent(result.risk_score);
  const areas = result.affected_areas?.length ? result.affected_areas.join(', ') : 'None';
  const open = await confirm({
    title: 'Risk analysis complete',
    message: (
      <div className="stack stack-sm" style={{ whiteSpace: 'normal' }}>
        <div>
          <SeverityBadge severity={result.risk_level} />
          <span style={{ marginLeft: '0.5rem', color: 'var(--text-muted)' }}>Score: {percent}%</span>
        </div>
        <div>Hosts analyzed: {result.hosts_analyzed}</div>
        <div>Compliance violations: {result.total_compliance_violations}</div>
        <div>Affected areas: {areas}</div>
        <div>Open the full details?</div>
      </div>
    ),
    confirmLabel: 'Open details',
    cancelLabel: 'Close',
    confirmVariant: 'primary',
  });
  if (open) setDetailId(result.id);
}

function RiskSummary({ summary }: { summary?: RiskAnalysisSummary }) {
  const items: SummaryStripItem[] = [
    { label: 'Total', value: String(summary?.total ?? '-') },
    { label: 'High risk', value: String(summary?.high_risk ?? '-') },
    { label: 'Approved', value: String(summary?.approved ?? '-') },
    { label: 'Pending', value: String(summary?.pending ?? '-') },
    { label: 'Last analysis', value: formatBackendDateTime(summary?.last_analysis_at) || 'Never' },
  ];
  return <SummaryStrip items={items} />;
}

function AnalysisList({
  items,
  loading,
  error,
  onRetry,
  isRetrying,
  onView,
  onNew,
}: {
  items: RiskAnalysisRow[];
  loading: boolean;
  /** Set only when the list failed and there is no data to show. */
  error: unknown;
  onRetry: () => void;
  isRetrying: boolean;
  onView: (id: number) => void;
  onNew: () => void;
}) {
  if (error) {
    return <QueryError what="risk analyses" error={error} onRetry={onRetry} isRetrying={isRetrying} />;
  }
  if (loading) return <LoadingState text="Loading risk analyses…" />;
  if (!items.length) {
    return (
      <div className="empty-state" style={{ padding: '2rem 1rem', textAlign: 'center' }}>
        <p style={{ color: 'var(--text-muted)', marginBottom: '1rem' }}>
          No risk analyses yet.
        </p>
        <button className="btn btn-primary btn-sm" onClick={onNew}>
          Run an Analysis
        </button>
      </div>
    );
  }

  return (
    <div className="stack stack-sm">
      {items.map((a) => (
        <AnalysisRow key={a.id} analysis={a} onView={() => onView(a.id)} />
      ))}
    </div>
  );
}

function AnalysisRow({ analysis, onView }: { analysis: RiskAnalysisRow; onView: () => void }) {
  const { confirm, alert } = useDialogs();
  const remove = useDeleteRiskAnalysis();
  const color = toneColor(severityTone(analysis.risk_level));
  const percent = scorePercent(analysis.risk_score);
  const areas = parseJsonArray<string>(analysis.affected_areas);
  const isApproved = !!analysis.approved;

  return (
    <div className="card-inset">
      <div
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          flexWrap: 'wrap',
          gap: '0.5rem',
        }}
      >
        <div>
          <SeverityBadge severity={analysis.risk_level} />
          <span
            style={{
              marginLeft: '0.5rem',
              fontSize: '0.9em',
              color: 'var(--text-muted)',
            }}
          >
            Score: {percent}%
          </span>
          <strong style={{ marginLeft: '0.75rem' }}>{targetLabel(analysis)}</strong>
          <span
            style={{
              marginLeft: '0.5rem',
              fontSize: '0.85em',
              color: 'var(--text-muted)',
            }}
          >
            Type: {changeTypeLabel(analysis.change_type)}
          </span>
        </div>
        <div style={{ display: 'flex', gap: '0.4rem', alignItems: 'center' }}>
          {isApproved ? (
            <span style={{ color: 'var(--success)', fontSize: '0.85em' }}>Approved</span>
          ) : (
            <span style={{ color: 'var(--text-muted)', fontSize: '0.85em' }}>Pending</span>
          )}
          <button className="btn btn-sm btn-secondary" onClick={onView}>
            Details
          </button>
          <DeleteButton
            busy={remove.isPending}
            onClick={async () => {
              const ok = await confirm({
                title: 'Delete risk analysis',
                message: `Delete risk analysis #${analysis.id} · ${targetLabel(analysis)}?`,
                confirmLabel: 'Delete',
              });
              if (!ok) return;
              remove.mutate(analysis.id, {
                onError: (e) => {
                  void alert({ message: (e as Error).message, variant: 'error' });
                },
              });
            }}
          />
        </div>
      </div>
      <div style={{ marginTop: '0.5rem', fontSize: '0.85em', color: 'var(--text-muted)' }}>
        {areas.length > 0 ? `Areas: ${areas.join(', ')} · ` : ''}
        {formatBackendDateTime(analysis.created_at)}
        {analysis.created_by ? ` by ${analysis.created_by}` : ''}
      </div>
      <div
        style={{
          marginTop: '0.5rem',
          background: 'var(--bg-secondary)',
          borderRadius: 4,
          height: 6,
          overflow: 'hidden',
        }}
      >
        <div
          style={{
            width: `${percent}%`,
            height: '100%',
            background: color,
            borderRadius: 4,
            transition: 'width 0.3s',
          }}
        />
      </div>
    </div>
  );
}
