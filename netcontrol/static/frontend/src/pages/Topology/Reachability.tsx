import { Fragment, useMemo, useState } from 'react';

import { ApiError } from '@/api/client';
import {
  reachabilityCsvUrl,
  useMerakiSubnets,
  useReachability,
  useTopologySources,
  type MerakiSubnet,
  type PathVerdict,
  type ReachabilityQuery,
  type ReachabilityReport,
  type ReachabilityRow,
} from '@/api/meraki';
import { PageHelp } from '@/components/PageHelp';

import { DETAIL_CELL_STYLE, providerLabel, SCROLL_X_STYLE } from './helpers';
import { PathTrace } from './PathTracePanel';
import { findSubnets, subnetOptionLabel } from './paths';
import { reverseTraceQuery, verdictLabel } from './pathTrace';
import {
  buildReachabilityQuery,
  csvFileName,
  emptyForm,
  rowsToCsv,
  rowsWithVerdict,
  rowTraceQuery,
  siteRollup,
  SWEEP_KINDS,
  SWEEP_PROVIDERS,
  VERDICT_ORDER,
  vlanTextError,
  type ReachabilityForm,
} from './sweep';

const FIELD_STYLE = { display: 'flex', flexDirection: 'column', gap: '0.2rem', minWidth: 160 } as const;
const HEAD_STYLE = { ...DETAIL_CELL_STYLE, textAlign: 'left', whiteSpace: 'nowrap' } as const;
// Long names and sentences wrap anywhere, so the table never widens the page.
const TEXT_CELL_STYLE = { ...DETAIL_CELL_STYLE, overflowWrap: 'anywhere' } as const;

function rowKey(row: ReachabilityRow): string {
  return `${row.org_ref}|${row.node_id}|${row.cidr}`;
}

function subnetKey(subnet: MerakiSubnet): string {
  return `${subnet.org_ref}|${subnet.node_id}|${subnet.cidr}`;
}

function downloadText(text: string, fileName: string): void {
  const blob = new Blob([text], { type: 'text/csv;charset=utf-8' });
  const link = document.createElement('a');
  link.download = fileName;
  link.href = URL.createObjectURL(blob);
  link.click();
  URL.revokeObjectURL(link.href);
}

function toggle<T>(list: T[], value: T): T[] {
  return list.includes(value) ? list.filter((v) => v !== value) : [...list, value];
}

/**
 * The Reachability view of the Topology page: one destination and traffic,
 * traced by the server from every source network the filters keep. The
 * results come as verdict chips, a table (or a per-site rollup) and CSV; a
 * row opens its full hop-by-hop trace in place.
 */
export function Reachability() {
  const [form, setForm] = useState<ReachabilityForm>(emptyForm);
  const [query, setQuery] = useState<ReachabilityQuery | null>(null);
  const [formError, setFormError] = useState<string | null>(null);
  const [owner, setOwner] = useState('');
  const [verdict, setVerdict] = useState<PathVerdict | null>(null);
  const [bySite, setBySite] = useState(false);
  const [open, setOpen] = useState<string | null>(null);

  const subnetsQuery = useMerakiSubnets(true);
  const sourcesQuery = useTopologySources();
  const sweep = useReachability(query);

  const subnets = useMemo(() => subnetsQuery.data?.subnets ?? [], [subnetsQuery.data]);
  // Snapshot sources (an organization, account, FMC...) are filtered by id;
  // the clouds by provider, since their accounts are not map sources.
  const sources = useMemo(
    () =>
      (sourcesQuery.data?.sources ?? []).filter(
        (s) => s.id !== null && ['meraki', 'cato', 'fmc', 'panorama', 'appgate'].includes(s.type),
      ),
    [sourcesQuery.data],
  );
  const owners = useMemo(() => findSubnets(form.destination, subnets), [form.destination, subnets]);

  function update(patch: Partial<ReachabilityForm>) {
    setForm((f) => ({ ...f, ...patch }));
  }

  function setDestination(value: string) {
    // A picked suggestion stands for its whole subnet, at its owner.
    const exact = subnets.find((s) => subnetOptionLabel(s) === value.trim());
    if (exact) {
      update({ destination: exact.cidr, destinationOrgRef: exact.org_ref, destinationNodeId: exact.node_id });
      setOwner(subnetKey(exact));
      return;
    }
    update({ destination: value, destinationOrgRef: undefined, destinationNodeId: undefined });
    setOwner('');
  }

  function pickOwner(key: string) {
    setOwner(key);
    const subnet = owners.find((s) => subnetKey(s) === key);
    update({ destinationOrgRef: subnet?.org_ref, destinationNodeId: subnet?.node_id });
  }

  function run() {
    let wanted = form;
    // A typed address one subnet holds starts at that subnet's owner, as in Path Mode.
    if (wanted.destinationOrgRef === undefined && owners.length === 1) {
      wanted = { ...wanted, destinationOrgRef: owners[0].org_ref, destinationNodeId: owners[0].node_id };
    }
    const built = buildReachabilityQuery(wanted);
    if ('error' in built) {
      setFormError(built.error);
      return;
    }
    setFormError(null);
    setVerdict(null);
    setOpen(null);
    setQuery(built.query);
  }

  const report = sweep.data;
  const shown = useMemo(() => rowsWithVerdict(report?.rows ?? [], verdict), [report, verdict]);
  const rollup = useMemo(() => siteRollup(shown), [shown]);
  const vlanError = vlanTextError(form.vlans);

  return (
    <div>
      <PageHelp
        pageKey="topology.reachability"
        title="Reachability sweep"
        text="Check which networks can reach one destination with the same traffic, for example which user VLANs cannot reach a file server on tcp/445. Every network the filters keep is traced hop by hop like a Path Mode trace. Narrow the sources with kinds, VLAN ids, names (a term in /slashes/ is a regular expression), exclusions such as voice or guest, sites and address ranges. Click a verdict to show only those networks, group the results by site, open any row's full trace, and download the list as CSV."
      />

      <div className="card" style={{ padding: '0.75rem', marginBottom: '0.75rem' }}>
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.75rem', alignItems: 'flex-end' }}>
          <label style={{ ...FIELD_STYLE, minWidth: 280 }}>
            <span className="form-label">Destination</span>
            <input
              className="form-input"
              list="reachability-destinations"
              placeholder="IP address, network or subnet"
              value={form.destination}
              onChange={(e) => setDestination(e.target.value)}
              onKeyDown={(e) => { if (e.key === 'Enter') run(); }}
            />
            <datalist id="reachability-destinations">
              {subnets.map((s) => (
                <option key={subnetKey(s)} value={subnetOptionLabel(s)} />
              ))}
            </datalist>
          </label>
          {owners.length > 1 && (
            <label style={FIELD_STYLE}>
              <span className="form-label">Destination is at</span>
              <select className="form-select" value={owner} onChange={(e) => pickOwner(e.target.value)}>
                <option value="">Pick the subnet you mean</option>
                {owners.map((s) => (
                  <option key={subnetKey(s)} value={subnetKey(s)}>{subnetOptionLabel(s)}</option>
                ))}
              </select>
            </label>
          )}
          <label style={FIELD_STYLE}>
            <span className="form-label">Traffic</span>
            <input
              className="form-input"
              placeholder="tcp/445, udp 53, icmp; empty: any"
              value={form.traffic}
              onChange={(e) => update({ traffic: e.target.value })}
              onKeyDown={(e) => { if (e.key === 'Enter') run(); }}
            />
          </label>
          <button type="button" className="btn btn-sm btn-primary" onClick={run} disabled={sweep.isFetching}>
            {sweep.isFetching ? 'Running…' : 'Run'}
          </button>
          <button
            type="button"
            className="btn btn-sm btn-secondary"
            onClick={() => { setForm(emptyForm()); setOwner(''); setFormError(null); }}
          >
            Reset
          </button>
        </div>

        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.75rem', marginTop: '0.75rem', alignItems: 'flex-start' }}>
          <label style={FIELD_STYLE}>
            <span className="form-label">Sources</span>
            <select
              className="form-select"
              multiple
              size={Math.min(5, Math.max(2, sources.length))}
              value={form.sources.map(String)}
              onChange={(e) => update({ sources: [...e.target.selectedOptions].map((o) => Number(o.value)) })}
              title="None selected: all sources. Ctrl+click to pick several."
            >
              {sources.map((s) => (
                <option key={s.key} value={s.id ?? ''}>{s.name} ({providerLabel(s.type)})</option>
              ))}
            </select>
            <span className="text-muted" style={{ fontSize: '0.8rem' }}>
              {form.sources.length ? `${form.sources.length} selected` : 'All sources'}
            </span>
          </label>
          <fieldset style={{ ...FIELD_STYLE, border: 'none', padding: 0, margin: 0 }}>
            <span className="form-label">Providers</span>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, auto)', gap: '0.1rem 0.75rem' }}>
              {SWEEP_PROVIDERS.map((p) => (
                <label key={p} style={{ display: 'flex', gap: '0.3rem', alignItems: 'center' }}>
                  <input
                    type="checkbox"
                    checked={form.providers.includes(p)}
                    onChange={() => update({ providers: toggle(form.providers, p) })}
                  />
                  {providerLabel(p)}
                </label>
              ))}
            </div>
            <span className="text-muted" style={{ fontSize: '0.8rem' }}>None checked: every provider</span>
          </fieldset>
          <fieldset style={{ ...FIELD_STYLE, border: 'none', padding: 0, margin: 0 }}>
            <span className="form-label">Kinds of network</span>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, auto)', gap: '0.1rem 0.75rem' }}>
              {SWEEP_KINDS.map((k) => (
                <label key={k.key} style={{ display: 'flex', gap: '0.3rem', alignItems: 'center' }}>
                  <input
                    type="checkbox"
                    checked={form.kinds.includes(k.key)}
                    onChange={() => update({ kinds: toggle(form.kinds, k.key) })}
                  />
                  {k.label}
                </label>
              ))}
            </div>
          </fieldset>
        </div>

        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.75rem', marginTop: '0.75rem', alignItems: 'flex-end' }}>
          <label style={FIELD_STYLE}>
            <span className="form-label">VLANs</span>
            <input
              className="form-input"
              placeholder="100, 110-120"
              value={form.vlans}
              onChange={(e) => update({ vlans: e.target.value })}
              style={vlanError ? { borderColor: 'var(--danger)' } : undefined}
              title={vlanError ?? 'VLAN ids and ranges'}
            />
          </label>
          <label style={FIELD_STYLE}>
            <span className="form-label">Name contains</span>
            <input
              className="form-input"
              placeholder="user, data or /^VLAN 1\d\d /"
              value={form.name}
              onChange={(e) => update({ name: e.target.value })}
            />
          </label>
          <label style={FIELD_STYLE}>
            <span className="form-label">Exclude</span>
            <input
              className="form-input"
              placeholder="voice, guest, printer"
              value={form.exclude}
              onChange={(e) => update({ exclude: e.target.value })}
            />
          </label>
          <label style={FIELD_STYLE}>
            <span className="form-label">Sites</span>
            <input
              className="form-input"
              placeholder="branch, /^store \d+$/"
              value={form.sites}
              onChange={(e) => update({ sites: e.target.value })}
            />
          </label>
          <label style={FIELD_STYLE}>
            <span className="form-label">Within</span>
            <input
              className="form-input"
              placeholder="10.0.0.0/8, 172.16.0.0/12"
              value={form.within}
              onChange={(e) => update({ within: e.target.value })}
            />
          </label>
          <label style={{ ...FIELD_STYLE, minWidth: 120 }}>
            <span className="form-label">In VPN</span>
            <select
              className="form-select"
              value={form.inVpn}
              onChange={(e) => update({ inVpn: e.target.value as ReachabilityForm['inVpn'] })}
            >
              <option value="">Any</option>
              <option value="1">Advertised</option>
              <option value="0">Not advertised</option>
            </select>
          </label>
        </div>
        <div className="text-muted" style={{ fontSize: '0.8rem', marginTop: '0.5rem' }}>
          Lists are comma-separated and any term matches; a term in /slashes/ is a regular expression. Names and sites
          match without regard to case. The destination's own network is never swept.
        </div>
        {(formError || vlanError) && (
          <div style={{ color: 'var(--danger)', marginTop: '0.5rem' }}>{formError ?? vlanError}</div>
        )}
      </div>

      {query && sweep.isPending && (
        <div className="text-muted">Tracing every source network… a few hundred take seconds, a few thousand about a minute.</div>
      )}
      {query && sweep.error && <SweepError error={sweep.error} />}
      {report && query && (
        <Results
          report={report}
          query={query}
          rows={shown}
          rollup={rollup}
          verdict={verdict}
          onVerdict={(v) => { setVerdict((current) => (current === v ? null : v)); setOpen(null); }}
          bySite={bySite}
          onBySite={setBySite}
          open={open}
          onOpen={(key) => setOpen((current) => (current === key ? null : key))}
        />
      )}
    </div>
  );
}

function SweepError({ error }: { error: Error }) {
  const body = error instanceof ApiError ? (error.body as { count?: number; limit?: number } | null) : null;
  const tooMany = body && typeof body === 'object' && typeof body.count === 'number';
  return (
    <div className="card" style={{ padding: '0.6rem 0.85rem', borderLeft: '3px solid var(--danger)' }}>
      {tooMany ? (
        <>
          <strong>{body.count} source networks match</strong>; at most {body.limit} are swept at once. Narrow the
          filters (kinds, VLANs, names, sources or Within) and run again.
        </>
      ) : (
        <>Sweep failed: {error.message.replace(/^\d{3} /, '')}</>
      )}
    </div>
  );
}

interface ResultsProps {
  report: ReachabilityReport;
  query: ReachabilityQuery;
  rows: ReachabilityRow[];
  rollup: ReturnType<typeof siteRollup>;
  verdict: PathVerdict | null;
  onVerdict: (verdict: PathVerdict) => void;
  bySite: boolean;
  onBySite: (value: boolean) => void;
  open: string | null;
  onOpen: (key: string) => void;
}

function Results({ report, query, rows, rollup, verdict, onVerdict, bySite, onBySite, open, onOpen }: ResultsProps) {
  const destination = report.destination;
  const where = [destination.label, destination.site].filter(Boolean).join(' · ');
  return (
    <div className="card" style={{ padding: '0.75rem' }}>
      <div style={{ marginBottom: '0.5rem' }}>
        <strong>{report.candidates}</strong> network{report.candidates === 1 ? '' : 's'} traced to{' '}
        <strong>{destination.address}</strong>
        {where ? <span className="text-muted"> ({where})</span> : null} with <strong>{report.traffic}</strong>
        <span className="text-muted"> · {new Date(report.generated_at).toLocaleString()}</span>
      </div>

      <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.4rem', alignItems: 'center', marginBottom: '0.6rem' }}>
        {VERDICT_ORDER.map((v) => {
          const label = verdictLabel(v);
          const active = verdict === v;
          return (
            <button
              key={v}
              type="button"
              className={`btn btn-sm btn-secondary${active ? ' active' : ''}`}
              aria-pressed={active}
              title={active ? 'Show every verdict' : `Show only ${label.label}`}
              onClick={() => onVerdict(v)}
              style={{ borderColor: label.color }}
            >
              <span style={{ color: label.color, fontWeight: 600 }}>{label.label}</span> {report.counts[v] ?? 0}
            </button>
          );
        })}
        <label style={{ display: 'flex', gap: '0.3rem', alignItems: 'center', marginLeft: '0.5rem' }}>
          <input type="checkbox" checked={bySite} onChange={(e) => onBySite(e.target.checked)} />
          Group by site
        </label>
        <span style={{ flex: 1 }} />
        <a
          className="btn btn-sm btn-secondary"
          href={reachabilityCsvUrl(query)}
          download
          title="Every network of this sweep, whatever verdict is shown"
        >
          Download CSV
        </a>
        <button
          type="button"
          className="btn btn-sm btn-secondary"
          disabled={!rows.length}
          onClick={() => downloadText(rowsToCsv(rows), csvFileName(report, verdict ? `-${verdict}` : '-shown'))}
          title="Only the rows shown below"
        >
          Download shown rows
        </button>
      </div>

      {!report.rows.length ? (
        <div className="text-muted">No source network matches the filters.</div>
      ) : bySite ? (
        <SiteTable rollup={rollup} />
      ) : (
        <RowTable report={report} query={query} rows={rows} open={open} onOpen={onOpen} />
      )}
    </div>
  );
}

function SiteTable({ rollup }: { rollup: ReturnType<typeof siteRollup> }) {
  return (
    <div style={SCROLL_X_STYLE}>
      <table className="data-table" style={{ width: '100%' }}>
        <thead>
          <tr>
            <th style={HEAD_STYLE}>Site</th>
            <th style={HEAD_STYLE}>Networks checked</th>
            {VERDICT_ORDER.map((v) => (
              <th key={v} style={HEAD_STYLE}>{verdictLabel(v).label}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rollup.map((site) => (
            <tr key={site.site}>
              <td style={DETAIL_CELL_STYLE}>{site.site}</td>
              <td style={DETAIL_CELL_STYLE}>{site.checked}</td>
              {VERDICT_ORDER.map((v) => (
                <td key={v} style={{ ...DETAIL_CELL_STYLE, color: site.counts[v] ? verdictLabel(v).color : undefined }}>
                  {site.counts[v]}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function RowTable({
  report,
  query,
  rows,
  open,
  onOpen,
}: {
  report: ReachabilityReport;
  query: ReachabilityQuery;
  rows: ReachabilityRow[];
  open: string | null;
  onOpen: (key: string) => void;
}) {
  return (
    <div style={SCROLL_X_STYLE}>
      <table className="data-table" style={{ width: '100%' }}>
        <thead>
          <tr>
            <th style={HEAD_STYLE}>Site</th>
            <th style={HEAD_STYLE}>Network</th>
            <th style={HEAD_STYLE}>VLAN</th>
            <th style={HEAD_STYLE}>CIDR</th>
            <th style={HEAD_STYLE}>Verdict</th>
            <th style={HEAD_STYLE}>Decided at</th>
            <th style={HEAD_STYLE}>Decided by</th>
            <th style={HEAD_STYLE}>Summary</th>
            <th style={HEAD_STYLE} aria-label="Trace" />
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => {
            const key = rowKey(row);
            const label = verdictLabel(row.verdict);
            const trace = open === key ? rowTraceQuery(row, report, query) : null;
            return (
              <Fragment key={key}>
                <tr>
                  <td style={TEXT_CELL_STYLE}>
                    {row.site_name || <span className="text-muted">{row.org_name || '-'}</span>}
                  </td>
                  <td style={TEXT_CELL_STYLE} title={`${row.kind} · ${row.node_label || row.node_id}`}>{row.name}</td>
                  <td style={DETAIL_CELL_STYLE}>{row.vlan ?? ''}</td>
                  <td style={{ ...DETAIL_CELL_STYLE, whiteSpace: 'nowrap' }}>{row.cidr}</td>
                  <td style={{ ...DETAIL_CELL_STYLE, color: label.color, fontWeight: 600, whiteSpace: 'nowrap' }}>
                    {label.label}
                  </td>
                  <td style={TEXT_CELL_STYLE}>{row.decided_at}</td>
                  <td style={TEXT_CELL_STYLE}>{row.decided_by}</td>
                  <td style={{ ...TEXT_CELL_STYLE, maxWidth: 420 }} className="text-muted">{row.summary}</td>
                  <td style={DETAIL_CELL_STYLE}>
                    <button
                      type="button"
                      className="btn btn-sm btn-secondary"
                      aria-expanded={open === key}
                      onClick={() => onOpen(key)}
                      title="The full hop-by-hop trace of this network, as in Path Mode"
                    >
                      {open === key ? 'Hide' : 'Trace'}
                    </button>
                  </td>
                </tr>
                {trace && (
                  <tr>
                    <td colSpan={9} style={{ ...TEXT_CELL_STYLE, paddingLeft: '1rem' }}>
                      <PathTrace forward={trace} backward={reverseTraceQuery(trace)} />
                    </td>
                  </tr>
                )}
              </Fragment>
            );
          })}
        </tbody>
      </table>
      {!rows.length && <div className="text-muted">No network has this verdict.</div>}
    </div>
  );
}
