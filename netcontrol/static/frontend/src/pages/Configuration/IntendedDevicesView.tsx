import { useState } from 'react';

import { useInventoryGroups } from '@/api/compliance';
import {
  type IntendedCompliance,
  type IntendedCounts,
  type IntendedHostFilter,
  type IntendedRow,
  type IntendedStatus,
  useGenerateIntended,
  useIntendedHosts,
} from '@/api/intendedConfig';
import { groupLabel } from '@/api/inventory';
import { StatusBadge } from '@/components/Badge';
import { BusyButton } from '@/components/BusyButton';
import { Dash } from '@/components/CatalogueParts';
import { DataTable } from '@/components/DataTable';
import { useDialogs } from '@/components/DialogProvider-context';
import { EmptyState } from '@/components/EmptyState';
import { LoadingState } from '@/components/LoadingState';
import { QueryError } from '@/components/QueryError';
import { SortableTh } from '@/components/SortableTh';
import { SummaryStrip } from '@/components/SummaryStrip';
import { clickableProps } from '@/lib/clickable';
import { formatBackendDateTime } from '@/lib/datetime';
import { idToSelect, selectToId } from '@/lib/deviceModel';
import { useObjectScope } from '@/lib/objectScope';
import { complianceStatusRank } from '@/lib/severity';
import {
  type Comparator,
  compareDate,
  compareNumber,
  compareText,
  type SortState,
  type TableSortOptions,
  useTableSort,
} from '@/lib/useTableSort';

import { IntendedDetailModal } from './IntendedDetailModal';
import { generateSummary } from './intendedHelpers';

const RIGHT = { textAlign: 'right' } as const;
const NO_FILTER: IntendedHostFilter = { group_id: null, compliance: '', status: '' };

type SortKey = 'host' | 'group' | 'template' | 'status' | 'compliance' | 'missing' | 'extra' | 'generated';
const COMPARATORS: Record<SortKey, Comparator<IntendedRow>> = {
  host: (a, b) => compareText(a.hostname, b.hostname),
  group: (a, b) => compareText(a.group_name, b.group_name),
  template: (a, b) => compareText(a.template_name, b.template_name),
  status: (a, b) => compareText(a.status, b.status),
  compliance: (a, b) => complianceStatusRank(a.compliance) - complianceStatusRank(b.compliance),
  missing: (a, b) => compareNumber(a.missing_count, b.missing_count),
  extra: (a, b) => compareNumber(a.extra_count, b.extra_count),
  generated: (a, b) => compareDate(a.generated_at, b.generated_at),
};
const TIE_BREAK: Comparator<IntendedRow> = (a, b) => compareText(a.hostname, b.hostname);
const SORT_OPTIONS: TableSortOptions<IntendedRow, SortKey> = { tieBreak: TIE_BREAK, firstDir: { missing: 'desc', extra: 'desc', generated: 'desc' } };
const INITIAL_SORT: SortState<SortKey> = { key: 'host', dir: 'asc' };

function countItems(c: IntendedCounts | undefined) {
  const v = (n: number | undefined) => (n === undefined ? '-' : n.toLocaleString());
  return [
    { label: 'Hosts', value: v(c?.hosts) },
    { label: 'Generated', value: v(c?.generated) },
    { label: 'Compliant', value: v(c?.compliant), tone: 'success' as const },
    { label: 'Non-compliant', value: v(c?.non_compliant), tone: c?.non_compliant ? ('danger' as const) : undefined },
    { label: 'Unknown', value: v(c?.unknown) },
    { label: 'Errors', value: v(c?.errors), tone: c?.errors ? ('danger' as const) : undefined },
    { label: 'No template', value: v(c?.no_template) },
  ];
}

/** The Intended tab's Devices view: counts, Generate all, filters and the rows. */
export function IntendedDevicesView({ isAdmin, onShowTemplates }: { isAdmin: boolean; onShowTemplates: () => void }) {
  const [filter, setFilter] = useState<IntendedHostFilter>(NO_FILTER);
  const [openHostId, setOpenHostId] = useState<number | null>(null);
  const [result, setResult] = useState<string | null>(null);
  const q = useIntendedHosts(filter);
  const groupsQ = useInventoryGroups(true);
  const generate = useGenerateIntended();
  const { restricted } = useObjectScope();
  const { confirm, alert } = useDialogs();
  const rows = q.data?.rows ?? [];
  const sorted = useTableSort(rows, COMPARATORS, INITIAL_SORT, SORT_OPTIONS);
  const filtered = filter.group_id !== null || filter.compliance !== '' || filter.status !== '';

  const handleGenerateAll = async () => {
    const hosts = q.data?.counts.hosts;
    const agreed = await confirm({
      title: 'Generate intended configurations',
      // A limited account generates for the hosts of the groups it may change.
      message: restricted
        ? 'Render the intended configuration of every host in the inventory groups you can change and compare each with its newest backup? Nothing is sent to the devices.'
        : `Render the intended configuration of every host${hosts !== undefined ? ` (${hosts.toLocaleString()})` : ''} and compare each with its newest backup? Nothing is sent to the devices.`,
      confirmLabel: 'Generate all',
      confirmVariant: 'primary',
    });
    if (!agreed) return;
    setResult(null);
    try {
      setResult(generateSummary(await generate.mutateAsync({})));
    } catch (err) {
      await alert({ message: `The intended configurations were not generated: ${(err as Error).message} Try again.`, variant: 'error' });
    }
  };

  const th = (key: SortKey, label: string, right = false) => (
    <SortableTh sortKey={key} sort={sorted.sort} onSort={sorted.toggle} style={right ? RIGHT : undefined}>
      {label}
    </SortableTh>
  );

  let body;
  if (q.isError && !q.data) body = <QueryError what="intended configurations" query={q} />;
  else if (q.isPending) body = <LoadingState text="Loading intended configurations…" />;
  else if (rows.length === 0 && !filtered && q.data.counts.generated === 0)
    body = (
      <EmptyState
        message="No intended configurations yet."
        description={
          isAdmin
            ? 'Add a device template on the Templates view and scope it to your devices; Plexus renders it for every matching host.'
            : 'An administrator adds device templates; Plexus then renders one intended configuration per matching host.'
        }
        action={
          isAdmin && (
            <button type="button" className="btn btn-sm btn-primary" onClick={onShowTemplates}>
              Open Templates
            </button>
          )
        }
      />
    );
  else if (rows.length === 0)
    body = (
      <EmptyState
        compact
        message="No devices match these filters."
        action={
          <button type="button" className="btn btn-sm btn-secondary" onClick={() => setFilter(NO_FILTER)}>
            Clear filters
          </button>
        }
      />
    );
  else
    body = (
      <DataTable compact aria-label="Intended configurations">
        <thead>
          <tr>
            {th('host', 'Device')}
            {th('group', 'Group')}
            {th('template', 'Template')}
            {th('status', 'Status')}
            {th('compliance', 'Compliance')}
            {th('missing', 'Missing', true)}
            {th('extra', 'Extra', true)}
            {th('generated', 'Generated')}
          </tr>
        </thead>
        <tbody>
          {sorted.rows.map((r) => (
            <tr
              key={r.host_id}
              className="row-clickable"
              title="Show the intended configuration"
              {...clickableProps(() => setOpenHostId(r.host_id), { role: null })}
            >
              <td>
                <div style={{ fontWeight: 600 }}>{r.hostname}</div>
                <div className="text-muted" style={{ fontSize: 'var(--text-xs)' }}>
                  {r.ip_address}
                </div>
              </td>
              <td>{r.group_name || <Dash />}</td>
              <td>{r.template_name || <Dash />}</td>
              <td>
                <StatusBadge status={r.status} size="sm" />
                {r.status === 'error' && r.error && (
                  <div style={{ color: 'var(--danger)', fontSize: 'var(--text-xs)', marginTop: 'var(--space-1)', maxWidth: 360 }}>
                    {r.error}
                  </div>
                )}
              </td>
              <td>
                <StatusBadge status={r.compliance} kind="compliance" size="sm" />
              </td>
              <td style={RIGHT}>{r.missing_count.toLocaleString()}</td>
              <td style={RIGHT}>{r.extra_count.toLocaleString()}</td>
              <td>{formatBackendDateTime(r.generated_at)}</td>
            </tr>
          ))}
        </tbody>
      </DataTable>
    );

  return (
    <>
      <SummaryStrip items={countItems(q.data?.counts)} />
      <div className="toolbar">
        <select
          className="form-select form-select-sm"
          aria-label="Filter by group"
          value={idToSelect(filter.group_id)}
          onChange={(e) => setFilter({ ...filter, group_id: selectToId(e.target.value) })}
        >
          <option value="">All groups</option>
          {(groupsQ.data ?? []).map((g) => (
            <option key={g.id} value={g.id}>
              {groupLabel(g)}
            </option>
          ))}
        </select>
        <select
          className="form-select form-select-sm"
          aria-label="Filter by compliance"
          value={filter.compliance}
          onChange={(e) => setFilter({ ...filter, compliance: e.target.value as IntendedCompliance | '' })}
        >
          <option value="">All compliance</option>
          <option value="compliant">Compliant</option>
          <option value="non_compliant">Non-compliant</option>
          <option value="unknown">Unknown</option>
        </select>
        <select
          className="form-select form-select-sm"
          aria-label="Filter by status"
          value={filter.status}
          onChange={(e) => setFilter({ ...filter, status: e.target.value as IntendedStatus | '' })}
        >
          <option value="">All statuses</option>
          <option value="ok">Rendered</option>
          <option value="error">Error</option>
        </select>
        <div style={{ marginLeft: 'auto', display: 'flex', gap: 'var(--space-2)', alignItems: 'center', flexWrap: 'wrap' }}>
          {result && (
            <span role="status" className="text-muted" style={{ fontSize: 'var(--text-sm)' }}>
              {result}
            </span>
          )}
          <BusyButton className="btn btn-sm btn-primary" busy={generate.isPending} busyLabel="Generating…" onClick={() => void handleGenerateAll()}>
            Generate all
          </BusyButton>
        </div>
      </div>
      {body}
      {openHostId !== null && <IntendedDetailModal hostId={openHostId} onClose={() => setOpenHostId(null)} />}
    </>
  );
}
