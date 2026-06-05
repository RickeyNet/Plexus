import { useMemo, useState } from 'react';

import {
  type RiskAnalysis as RiskAnalysisRow,
  type RiskAnalysisRunResult,
  type RiskAnalysisSummary,
  useDeleteRiskAnalysis,
  useRiskAnalyses,
  useRiskAnalysisSummary,
} from '@/api/riskAnalysis';
import { type DialogApi, useDialogs } from '@/components/DialogProvider-context';

import { AnalysisDetailModal } from './AnalysisDetailModal';
import { NewAnalysisModal } from './NewAnalysisModal';
import { OfflineAnalysisModal } from './OfflineAnalysisModal';
import {
  filterAnalyses,
  formatStamp,
  levelColor,
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
    <>
      <div
        className="page-header"
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          flexWrap: 'wrap',
          gap: '0.5rem',
          marginBottom: '0.75rem',
        }}
      >
        <h2 style={{ margin: 0 }}>Risk Analysis</h2>
        <div style={{ display: 'flex', gap: '0.4rem' }}>
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
      </div>

      <SummaryStrip summary={summary.data} />

      <div className="card" style={{ marginTop: '0.75rem', padding: 0, overflow: 'hidden' }}>
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: '0.5rem',
            padding: '0.5rem 0.75rem',
            borderBottom: '1px solid var(--border)',
            flexWrap: 'wrap',
          }}
        >
          <select
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
            className="form-input"
            placeholder="Search hostname, group, or change type…"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            style={{ marginLeft: 'auto', maxWidth: 320 }}
          />
        </div>
        <div style={{ padding: '0.75rem' }}>
          <AnalysisList
            items={filtered}
            loading={analyses.isLoading}
            error={analyses.error}
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
    </>
  );
}

async function showRunResult(
  result: RiskAnalysisRunResult,
  setDetailId: (id: number) => void,
  confirm: DialogApi['confirm'],
) {
  const percent = scorePercent(result.risk_score);
  const areas = result.affected_areas?.length ? result.affected_areas.join(', ') : 'None';
  const msg = `Risk: ${String(result.risk_level).toUpperCase()} (${percent}%)\n` +
    `Hosts analyzed: ${result.hosts_analyzed}\n` +
    `Compliance violations: ${result.total_compliance_violations}\n` +
    `Affected areas: ${areas}\n\nOpen full details?`;
  if (await confirm(msg)) setDetailId(result.id);
}

function SummaryStrip({ summary }: { summary?: RiskAnalysisSummary }) {
  const items: { label: string; value: string }[] = [
    { label: 'Total', value: String(summary?.total ?? '-') },
    { label: 'High risk', value: String(summary?.high_risk ?? '-') },
    { label: 'Approved', value: String(summary?.approved ?? '-') },
    { label: 'Pending', value: String(summary?.pending ?? '-') },
    { label: 'Last analysis', value: formatStamp(summary?.last_analysis_at) || 'Never' },
  ];
  return (
    <div className="card">
      <div
        className="card-body"
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(140px, 1fr))',
          gap: '0.5rem',
          padding: '0.75rem',
        }}
      >
        {items.map((it) => (
          <div key={it.label} style={{ display: 'flex', flexDirection: 'column' }}>
            <span style={{ color: 'var(--text-muted)', fontSize: '0.75rem' }}>{it.label}</span>
            <span style={{ fontWeight: 600 }}>{it.value}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

function AnalysisList({
  items,
  loading,
  error,
  onView,
  onNew,
}: {
  items: RiskAnalysisRow[];
  loading: boolean;
  error: unknown;
  onView: (id: number) => void;
  onNew: () => void;
}) {
  if (loading) return <p className="text-muted">Loading risk analyses…</p>;
  if (error) {
    return (
      <p style={{ color: 'var(--danger)' }}>
        Failed to load risk analyses: {(error as Error).message}
      </p>
    );
  }
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
    <>
      {items.map((a) => (
        <AnalysisRow key={a.id} analysis={a} onView={() => onView(a.id)} />
      ))}
    </>
  );
}

function AnalysisRow({ analysis, onView }: { analysis: RiskAnalysisRow; onView: () => void }) {
  const { confirm, alert } = useDialogs();
  const remove = useDeleteRiskAnalysis();
  const color = levelColor(analysis.risk_level);
  const percent = scorePercent(analysis.risk_score);
  const areas = parseJsonArray<string>(analysis.affected_areas);
  const isApproved = !!analysis.approved;

  return (
    <div className="card" style={{ marginBottom: '0.75rem', padding: '1rem' }}>
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
          <span
            className="badge"
            style={{
              background: `var(--${color})`,
              color: 'white',
              fontSize: '0.8em',
              padding: '3px 10px',
              borderRadius: 4,
              textTransform: 'uppercase',
              fontWeight: 600,
            }}
          >
            {analysis.risk_level}
          </span>
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
            Type: {analysis.change_type || '?'}
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
          <button
            className="btn btn-sm"
            style={{ color: 'var(--danger)' }}
            onClick={async () => {
              if (!(await confirm('Delete this risk analysis?'))) return;
              remove.mutate(analysis.id, {
                onError: (e) => {
                  void alert({ message: (e as Error).message, variant: 'error' });
                },
              });
            }}
          >
            Delete
          </button>
        </div>
      </div>
      <div style={{ marginTop: '0.5rem', fontSize: '0.85em', color: 'var(--text-muted)' }}>
        {areas.length > 0 ? `Areas: ${areas.join(', ')} · ` : ''}
        {formatStamp(analysis.created_at)}
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
            background: `var(--${color})`,
            borderRadius: 4,
            transition: 'width 0.3s',
          }}
        />
      </div>
    </div>
  );
}
