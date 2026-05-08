import { useState, type FormEvent } from 'react';

import { useInventoryGroups } from '@/api/compliance';
import {
  reportArtifactUrl,
  useGenerateReport,
  type ReportGenerateResult,
} from '@/api/reports';

import { downloadReportExport } from './helpers';

type ReportType = 'availability' | 'compliance' | 'interface' | 'network_documentation';

const REPORT_TYPES: { value: ReportType; label: string }[] = [
  { value: 'availability', label: 'Availability' },
  { value: 'compliance', label: 'Compliance' },
  { value: 'interface', label: 'Interface Utilization' },
  { value: 'network_documentation', label: 'Network Documentation' },
];

const NO_DAYS = new Set<ReportType>(['compliance', 'network_documentation']);

export function GenerateReportTab() {
  const groupsQuery = useInventoryGroups(false);
  const generate = useGenerateReport();

  const [reportType, setReportType] = useState<ReportType>('availability');
  const [groupId, setGroupId] = useState('');
  const [days, setDays] = useState(30);
  const [result, setResult] = useState<ReportGenerateResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  const showDays = !NO_DAYS.has(reportType);

  function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    setResult(null);
    const params: Record<string, unknown> = {};
    if (groupId) params.group_id = parseInt(groupId, 10);
    if (showDays) params.days = days;
    generate.mutate(
      {
        report_type: reportType,
        parameters: params,
        persist_artifacts: reportType === 'network_documentation',
      },
      {
        onSuccess: (r) => setResult(r),
        onError: (e) => setError((e as Error).message),
      },
    );
  }

  return (
    <div>
      <form onSubmit={handleSubmit} style={{ display: 'flex', flexWrap: 'wrap', gap: '0.75rem', alignItems: 'flex-end' }}>
        <div className="form-group" style={{ marginBottom: 0 }}>
          <label className="form-label">Report Type</label>
          <select className="form-select" value={reportType} onChange={(e) => setReportType(e.target.value as ReportType)}>
            {REPORT_TYPES.map((t) => (
              <option key={t.value} value={t.value}>{t.label}</option>
            ))}
          </select>
        </div>
        <div className="form-group" style={{ marginBottom: 0 }}>
          <label className="form-label">Group</label>
          <select className="form-select" value={groupId} onChange={(e) => setGroupId(e.target.value)}>
            <option value="">All Groups</option>
            {(groupsQuery.data ?? []).map((g) => (
              <option key={g.id} value={g.id}>{g.name}</option>
            ))}
          </select>
        </div>
        {showDays && (
          <div className="form-group" style={{ marginBottom: 0 }}>
            <label className="form-label">Days</label>
            <input
              type="number"
              className="form-input"
              min={1}
              value={days}
              onChange={(e) => setDays(parseInt(e.target.value || '30', 10))}
              style={{ width: 120 }}
            />
          </div>
        )}
        <button type="submit" className="btn btn-primary" disabled={generate.isPending}>
          {generate.isPending ? 'Generating…' : 'Generate'}
        </button>
      </form>

      <div style={{ marginTop: '1rem' }}>
        {error && <div className="card" style={{ color: 'var(--danger)', padding: '1rem' }}>Error: {error}</div>}
        {generate.isPending && <div className="card" style={{ padding: '1.5rem' }}>Generating report…</div>}
        {result && <ResultBlock reportType={reportType} groupId={groupId} result={result} />}
      </div>
    </div>
  );
}

interface ResultBlockProps {
  reportType: ReportType;
  groupId: string;
  result: ReportGenerateResult;
}

function ResultBlock({ reportType, groupId, result }: ResultBlockProps) {
  const rows = result.rows ?? [];
  if (!rows.length) {
    return (
      <div className="card" style={{ padding: '1.5rem' }}>
        <p className="text-muted">Report generated with 0 rows. No data found for the selected criteria.</p>
      </div>
    );
  }

  const cols = Object.keys(rows[0]);
  const artifacts = result.artifacts ?? [];
  const artifactByType: Record<string, number> = {};
  for (const a of artifacts) {
    if (a.artifact_type && a.id) artifactByType[a.artifact_type] = a.id;
  }

  const fallbackSuffix = groupId ? `?group_id=${encodeURIComponent(groupId)}` : '';
  const isNetDoc = reportType === 'network_documentation';
  const svgUrl = isNetDoc
    ? (artifactByType.svg ? reportArtifactUrl(artifactByType.svg) : `/api/reports/export/network_documentation.svg${fallbackSuffix}`)
    : '';
  const drawioUrl = isNetDoc
    ? (artifactByType.drawio ? reportArtifactUrl(artifactByType.drawio) : `/api/reports/export/network_documentation.drawio${fallbackSuffix}`)
    : '';
  const pdfUrl = isNetDoc
    ? (artifactByType.pdf ? reportArtifactUrl(artifactByType.pdf) : `/api/reports/export/network_documentation.pdf${fallbackSuffix}`)
    : '';
  const csvUrl = result.run_id ? `/api/reports/runs/${result.run_id}/csv` : '';

  function tryDownload(url: string, name: string) {
    downloadReportExport(url, name).catch((err) => alert((err as Error).message));
  }

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.5rem' }}>
        <span>{rows.length} row{rows.length !== 1 ? 's' : ''} · Run #{result.run_id ?? '-'}</span>
        <div style={{ display: 'flex', gap: '0.4rem' }}>
          {svgUrl && <button className="btn btn-sm btn-secondary" onClick={() => tryDownload(svgUrl, 'network_documentation_topology.svg')}>Export SVG</button>}
          {drawioUrl && <button className="btn btn-sm btn-secondary" onClick={() => tryDownload(drawioUrl, 'network_documentation_topology.drawio')}>Export draw.io</button>}
          {pdfUrl && <button className="btn btn-sm btn-secondary" onClick={() => tryDownload(pdfUrl, 'network_documentation_report.pdf')}>Export PDF</button>}
          {csvUrl && <button className="btn btn-sm btn-secondary" onClick={() => tryDownload(csvUrl, `report_${result.run_id}.csv`)}>Export CSV</button>}
        </div>
      </div>
      <div style={{ overflowX: 'auto' }}>
        <table className="data-table">
          <thead>
            <tr>{cols.map((c) => <th key={c}>{c}</th>)}</tr>
          </thead>
          <tbody>
            {rows.slice(0, 200).map((r, i) => (
              <tr key={i}>
                {cols.map((c) => <td key={c}>{String(r[c] ?? '')}</td>)}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {rows.length > 200 && <p className="text-muted">Showing first 200 of {rows.length} rows. Export CSV for full data.</p>}
    </div>
  );
}
