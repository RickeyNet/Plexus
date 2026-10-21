import { Fragment, useMemo, useState } from 'react';

import { ApiError } from '@/api/client';
import {
  reachabilityFileUrl,
  useMerakiSubnets,
  useReachability,
  useTopologySources,
  type MerakiSubnet,
  type NetworkRow,
  type PathEnd,
  type PathVerdict,
  type ReachabilityQuery,
  type ReachabilityReport,
} from '@/api/meraki';
import { PageHelp } from '@/components/PageHelp';

import { DETAIL_CELL_STYLE, providerLabel, SCROLL_X_STYLE } from './helpers';
import { PathTrace } from './PathTracePanel';
import { findSubnets, subnetOptionLabel } from './paths';
import { portsText, reverseTraceQuery, verdictLabel } from './pathTrace';
import {
  buildListQuery,
  buildReachabilityQuery,
  cloudsToMerakiForm,
  emptyForm,
  endOwnerPatch,
  endPatch,
  isListQuery,
  isTraceRow,
  isTypedSource,
  LIST_TYPED_SOURCE_ERROR,
  pairRollup,
  rowsWithVerdict,
  rowTraceQuery,
  siteRollup,
  SWEEP_KINDS,
  sweepProviders,
  sweepSources,
  VERDICT_ORDER,
  vlanTextError,
  withSingleOwners,
  type PairRollup,
  type ReachabilityForm,
  type SiteRollup,
  type SweepEnd,
  type SweepFilters,
  type SweepSourceOption,
} from './sweep';

const FIELD_STYLE = { display: 'flex', flexDirection: 'column', gap: '0.2rem', minWidth: 160 } as const;
const HEAD_STYLE = { ...DETAIL_CELL_STYLE, textAlign: 'left', whiteSpace: 'nowrap' } as const;
// Long names and sentences wrap anywhere, so the table never widens the page.
const TEXT_CELL_STYLE = { ...DETAIL_CELL_STYLE, overflowWrap: 'anywhere' } as const;
const BLOCK_STYLE = { border: 'none', padding: 0, margin: '0.75rem 0 0', minWidth: 0 } as const;
const BLOCK_TITLE_STYLE = { fontWeight: 600, padding: 0 } as const;
const NOTE_STYLE = { fontSize: '0.8rem' } as const;

const SUBNETS_LIST_ID = 'reachability-subnets';
const NO_OWNERS: Record<SweepEnd, string> = { source: '', destination: '' };

function rowKey(row: NetworkRow): string {
  // A typed source's row has no org_ref; a listed row has no destination.
  const traced = isTraceRow(row) ? row : null;
  return [row.org_ref ?? '', row.node_id, row.cidr, traced?.dst_cidr ?? '', traced?.dst_node_id ?? ''].join('|');
}

/** The label and site of a placed end, for "(where)" after its address. */
function endWhere(end: Partial<PathEnd>): string {
  return [end.label, end.site].filter(Boolean).join(' · ');
}

function subnetKey(subnet: MerakiSubnet): string {
  return `${subnet.org_ref}|${subnet.node_id}|${subnet.cidr}`;
}

function toggle<T>(list: T[], value: T): T[] {
  return list.includes(value) ? list.filter((v) => v !== value) : [...list, value];
}

/**
 * The Reachability view of the Topology page: one destination and traffic,
 * traced by the server from every source network the filters keep, or, with
 * no destination, every kept source traced to every destination network the
 * destination filters keep. The results come as verdict chips, a table (or a
 * per-site rollup) and a spreadsheet or CSV download; a row opens its full
 * hop-by-hop trace in place.
 */
export function Reachability() {
  const [form, setForm] = useState<ReachabilityForm>(emptyForm);
  const [query, setQuery] = useState<ReachabilityQuery | null>(null);
  const [formError, setFormError] = useState<string | null>(null);
  // The owner picked for each typed end (a subnet key), when several subnets hold it.
  const [picked, setPicked] = useState<Record<SweepEnd, string>>(NO_OWNERS);
  const [verdict, setVerdict] = useState<PathVerdict | null>(null);
  const [bySite, setBySite] = useState(false);
  const [open, setOpen] = useState<string | null>(null);

  const subnetsQuery = useMerakiSubnets(true);
  const sourcesQuery = useTopologySources();
  const sweep = useReachability(query);

  const subnets = useMemo(() => subnetsQuery.data?.subnets ?? [], [subnetsQuery.data]);
  const sources = useMemo(() => sweepSources(sourcesQuery.data?.sources ?? [], subnets), [sourcesQuery.data, subnets]);
  const providers = useMemo(() => sweepProviders(subnets), [subnets]);
  const owners = useMemo<Record<SweepEnd, MerakiSubnet[]>>(
    () => ({ source: findSubnets(form.source, subnets), destination: findSubnets(form.destination, subnets) }),
    [form.source, form.destination, subnets],
  );
  const matrixForm = !form.destination.trim();
  const typedSource = isTypedSource(form);

  function update(patch: Partial<ReachabilityForm>) {
    setForm((f) => ({ ...f, ...patch }));
  }

  function updateTo(patch: Partial<SweepFilters>) {
    setForm((f) => ({ ...f, to: { ...f.to, ...patch } }));
  }

  function resetTo(next: ReachabilityForm) {
    setForm(next);
    setPicked(NO_OWNERS);
    setFormError(null);
  }

  function setEnd(side: SweepEnd, value: string) {
    // A picked suggestion stands for its whole subnet, at its owner.
    const exact = subnets.find((s) => subnetOptionLabel(s) === value.trim());
    update(endPatch(side, exact ? exact.cidr : value, exact));
    setPicked((p) => ({ ...p, [side]: exact ? subnetKey(exact) : '' }));
  }

  function pickOwner(side: SweepEnd, key: string) {
    setPicked((p) => ({ ...p, [side]: key }));
    update(endOwnerPatch(side, owners[side].find((s) => subnetKey(s) === key)));
  }

  function run() {
    // A typed address one subnet holds is placed at that subnet's owner, as in Path Mode.
    submit(buildReachabilityQuery(withSingleOwners(form, subnets)));
  }

  function listNetworks() {
    submit(buildListQuery(form));
  }

  function submit(built: { query: ReachabilityQuery } | { error: string }) {
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
  const matrix = report?.mode === 'matrix';
  const traced = useMemo(
    () => (report && report.mode !== 'list' ? rowsWithVerdict(report.rows, verdict) : []),
    [report, verdict],
  );
  // A list has no verdicts: every listed network is shown.
  const shown = useMemo<NetworkRow[]>(() => (report?.mode === 'list' ? report.rows : traced), [report, traced]);
  const rollup = useMemo(() => (matrix ? [] : siteRollup(shown)), [matrix, shown]);
  const pairs = useMemo(() => (matrix ? pairRollup(traced) : []), [matrix, traced]);
  // A block that is ignored (the source block with a typed source, the
  // destination block with a typed destination) does not have its VLAN text checked.
  const vlanError =
    (typedSource ? null : vlanTextError(form.vlans)) ?? (matrixForm ? vlanTextError(form.to.vlans) : null);

  return (
    <div>
      <PageHelp
        pageKey="topology.reachability"
        title="Reachability sweep"
        text="Check which networks can reach one destination with the same traffic, for example which user VLANs cannot reach a file server on tcp/445. Every network the filters keep is traced hop by hop like a Path Mode trace. Narrow the sources with kinds, VLAN ids, names (a term in /slashes/ is a regular expression), exclusions such as voice or guest, sites and address ranges. A typed Source (an IP address, network or subnet) replaces the source filters and is traced alone. List networks shows the networks the Source networks filters keep, without tracing them, as a table and a spreadsheet. To trace many destinations at once, leave Destination empty and narrow the Destination networks: every source network is then traced to every destination network, for example every cloud subnet to every Meraki network. With the Traffic box empty each row lists the ports allowed end to end. Click a verdict to show only those networks, group the results by site, open any row's full trace, and download the list as a spreadsheet or CSV."
      />

      <div className="card" style={{ padding: '0.75rem', marginBottom: '0.75rem' }}>
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.75rem', alignItems: 'flex-end' }}>
          <datalist id={SUBNETS_LIST_ID}>
            {subnets.map((s) => (
              <option key={subnetKey(s)} value={subnetOptionLabel(s)} />
            ))}
          </datalist>
          {(['source', 'destination'] as const).map((side) => (
            <EndField
              key={side}
              label={side === 'source' ? 'Source' : 'Destination'}
              placeholder={
                side === 'source'
                  ? 'IP address, network or subnet; empty: use the filters'
                  : 'IP address, network or subnet; empty: many'
              }
              value={form[side]}
              onChange={(value) => setEnd(side, value)}
              onEnter={run}
              owners={owners[side]}
              picked={picked[side]}
              onPick={(key) => pickOwner(side, key)}
            />
          ))}
          <label style={FIELD_STYLE}>
            <span className="form-label">Traffic</span>
            <input
              className="form-input"
              placeholder="tcp/445, udp 53, icmp; empty: any"
              value={form.traffic}
              onChange={(e) => update({ traffic: e.target.value })}
              onKeyDown={(e) => { if (e.key === 'Enter') run(); }}
              title="Empty: any traffic, and each row lists the ports allowed end to end"
            />
          </label>
          <button type="button" className="btn btn-sm btn-primary" onClick={run} disabled={sweep.isFetching}>
            {sweep.isFetching ? 'Running…' : 'Run'}
          </button>
          <button
            type="button"
            className="btn btn-sm btn-secondary"
            onClick={listNetworks}
            disabled={sweep.isFetching || typedSource}
            title={
              typedSource
                ? LIST_TYPED_SOURCE_ERROR
                : 'List the networks the Source networks filters keep, without tracing them'
            }
          >
            List networks
          </button>
          <button type="button" className="btn btn-sm btn-secondary" onClick={() => resetTo(emptyForm())}>
            Reset
          </button>
          <button
            type="button"
            className="btn btn-sm btn-secondary"
            onClick={() => resetTo(cloudsToMerakiForm())}
            title="Every AWS, Azure and GCP subnet and Cato site range to every Meraki network, any traffic (lists the ports allowed). Press Run to start."
          >
            Clouds &amp; Cato → Meraki
          </button>
        </div>

        <FilterFields
          title="Source networks"
          idPrefix="reachability-from"
          filters={form}
          onChange={update}
          sources={sources}
          providers={providers}
          disabled={typedSource}
          note={typedSource ? 'Used when Source is empty.' : 'Every network these filters keep is traced.'}
        />
        <FilterFields
          title="Destination networks"
          idPrefix="reachability-to"
          filters={form.to}
          onChange={updateTo}
          sources={sources}
          providers={providers}
          disabled={!matrixForm}
          note={
            matrixForm
              ? 'Every source network is traced to every network these filters keep.'
              : 'Used when Destination is empty.'
          }
        />

        <div className="text-muted" style={{ ...NOTE_STYLE, marginTop: '0.5rem' }}>
          Lists are comma-separated and any term matches; a term in /slashes/ is a regular expression. Names and sites
          match without regard to case. The destination's own network is never swept.
        </div>
        {(formError || vlanError) && (
          <div style={{ color: 'var(--danger)', marginTop: '0.5rem' }}>{formError ?? vlanError}</div>
        )}
      </div>

      {query && sweep.isPending && (
        <div className="text-muted">
          {isListQuery(query)
            ? 'Listing the networks…'
            : 'Tracing every network… a few hundred traces take seconds, a few thousand about a minute; a matrix runs at most 20,000.'}
        </div>
      )}
      {query && sweep.error && <SweepError error={sweep.error} />}
      {report && query && (
        <Results
          report={report}
          query={query}
          rows={shown}
          rollup={rollup}
          pairs={pairs}
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

interface EndFieldProps {
  label: string;
  placeholder: string;
  value: string;
  onChange: (value: string) => void;
  onEnter: () => void;
  /** The subnets that hold the typed text; a picker is shown when there are several. */
  owners: MerakiSubnet[];
  /** Key of the owner picked among several. */
  picked: string;
  onPick: (key: string) => void;
}

/** One typed end of a sweep (Source or Destination), with the subnet suggestions and its "is at" owner picker. */
function EndField({ label, placeholder, value, onChange, onEnter, owners, picked, onPick }: EndFieldProps) {
  return (
    <>
      <label style={{ ...FIELD_STYLE, minWidth: 280 }}>
        <span className="form-label">{label}</span>
        <input
          className="form-input"
          list={SUBNETS_LIST_ID}
          placeholder={placeholder}
          value={value}
          onChange={(e) => onChange(e.target.value)}
          onKeyDown={(e) => { if (e.key === 'Enter') onEnter(); }}
        />
      </label>
      {owners.length > 1 && (
        <label style={FIELD_STYLE}>
          <span className="form-label">{label} is at</span>
          <select className="form-select" value={picked} onChange={(e) => onPick(e.target.value)}>
            <option value="">Pick the subnet you mean</option>
            {owners.map((s) => (
              <option key={subnetKey(s)} value={subnetKey(s)}>{subnetOptionLabel(s)}</option>
            ))}
          </select>
        </label>
      )}
    </>
  );
}

interface FilterFieldsProps {
  title: string;
  /** Prefix of the element ids, unique per block. */
  idPrefix: string;
  filters: SweepFilters;
  onChange: (patch: Partial<SweepFilters>) => void;
  sources: SweepSourceOption[];
  providers: string[];
  /** Dimmed and not editable (a side's block while that side's end is typed). */
  disabled?: boolean;
  note?: string;
}

/** The filters of one side of a sweep: which source (or destination) networks are kept. */
function FilterFields({ title, idPrefix, filters, onChange, sources, providers, disabled, note }: FilterFieldsProps) {
  const vlanError = vlanTextError(filters.vlans);
  const titleId = `${idPrefix}-title`;
  return (
    <fieldset
      disabled={disabled}
      aria-labelledby={titleId}
      style={{ ...BLOCK_STYLE, opacity: disabled ? 0.55 : undefined }}
    >
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.5rem', alignItems: 'baseline' }}>
        <span id={titleId} style={BLOCK_TITLE_STYLE}>{title}</span>
        {note && <span className="text-muted" style={NOTE_STYLE}>{note}</span>}
      </div>

      <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.75rem', marginTop: '0.4rem', alignItems: 'flex-start' }}>
        <label style={FIELD_STYLE}>
          <span className="form-label">Sources</span>
          <select
            className="form-select"
            multiple
            size={Math.min(5, Math.max(2, sources.length))}
            value={filters.sources.map(String)}
            onChange={(e) => onChange({ sources: [...e.target.selectedOptions].map((o) => Number(o.value)) })}
            title="None selected: all sources. Ctrl+click to pick several."
          >
            {sources.map((s) => (
              <option key={s.key} value={s.id}>{s.label}</option>
            ))}
          </select>
          <span className="text-muted" style={NOTE_STYLE}>
            {filters.sources.length ? `${filters.sources.length} selected` : 'All sources'}
          </span>
        </label>
        <fieldset style={{ ...FIELD_STYLE, border: 'none', padding: 0, margin: 0 }}>
          <span className="form-label">Providers</span>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, auto)', gap: '0.1rem 0.75rem' }}>
            {providers.map((p) => (
              <label key={p} style={{ display: 'flex', gap: '0.3rem', alignItems: 'center' }}>
                <input
                  type="checkbox"
                  checked={filters.providers.includes(p)}
                  onChange={() => onChange({ providers: toggle(filters.providers, p) })}
                />
                {providerLabel(p)}
              </label>
            ))}
          </div>
          <span className="text-muted" style={NOTE_STYLE}>None checked: every provider</span>
        </fieldset>
        <fieldset style={{ ...FIELD_STYLE, border: 'none', padding: 0, margin: 0 }}>
          <span className="form-label">Kinds of network</span>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, auto)', gap: '0.1rem 0.75rem' }}>
            {SWEEP_KINDS.map((k) => (
              <label key={k.key} style={{ display: 'flex', gap: '0.3rem', alignItems: 'center' }}>
                <input
                  type="checkbox"
                  checked={filters.kinds.includes(k.key)}
                  onChange={() => onChange({ kinds: toggle(filters.kinds, k.key) })}
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
            value={filters.vlans}
            onChange={(e) => onChange({ vlans: e.target.value })}
            style={vlanError ? { borderColor: 'var(--danger)' } : undefined}
            title={vlanError ?? 'VLAN ids and ranges'}
          />
        </label>
        <label style={FIELD_STYLE}>
          <span className="form-label">Name contains</span>
          <input
            className="form-input"
            placeholder="user, data or /^VLAN 1\d\d /"
            value={filters.name}
            onChange={(e) => onChange({ name: e.target.value })}
          />
        </label>
        <label style={FIELD_STYLE}>
          <span className="form-label">Exclude</span>
          <input
            className="form-input"
            placeholder="voice, guest, printer"
            value={filters.exclude}
            onChange={(e) => onChange({ exclude: e.target.value })}
          />
        </label>
        <label style={FIELD_STYLE}>
          <span className="form-label">Sites</span>
          <input
            className="form-input"
            placeholder="branch, /^store \d+$/"
            value={filters.sites}
            onChange={(e) => onChange({ sites: e.target.value })}
          />
        </label>
        <label style={FIELD_STYLE}>
          <span className="form-label">Within</span>
          <input
            className="form-input"
            placeholder="10.0.0.0/8, 172.16.0.0/12"
            value={filters.within}
            onChange={(e) => onChange({ within: e.target.value })}
          />
        </label>
        <label style={{ ...FIELD_STYLE, minWidth: 120 }}>
          <span className="form-label">In VPN</span>
          <select
            className="form-select"
            value={filters.inVpn}
            onChange={(e) => onChange({ inVpn: e.target.value as SweepFilters['inVpn'] })}
          >
            <option value="">Any</option>
            <option value="1">Advertised</option>
            <option value="0">Not advertised</option>
          </select>
        </label>
      </div>
    </fieldset>
  );
}

function SweepError({ error }: { error: Error }) {
  const body =
    error instanceof ApiError
      ? (error.body as { count?: number; limit?: number; error?: { message?: string } } | null)
      : null;
  const tooMany = body && typeof body === 'object' && typeof body.count === 'number';
  const serverMessage = body && typeof body === 'object' ? body.error?.message : undefined;
  return (
    <div className="card" style={{ padding: '0.6rem 0.85rem', borderLeft: '3px solid var(--danger)' }}>
      {tooMany && serverMessage ? (
        <>{serverMessage}</>
      ) : tooMany ? (
        <>
          <strong>{body.count} traces match</strong>; at most {body.limit} are traced at once. Narrow the filters
          (kinds, VLANs, names, sources or Within) and run again.
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
  rows: NetworkRow[];
  rollup: SiteRollup[];
  pairs: PairRollup[];
  verdict: PathVerdict | null;
  onVerdict: (verdict: PathVerdict) => void;
  bySite: boolean;
  onBySite: (value: boolean) => void;
  open: string | null;
  onOpen: (key: string) => void;
}

/** An end's address, then its label and site in parentheses when known. */
function EndText({ end }: { end: Partial<PathEnd> & { address: string } }) {
  const where = endWhere(end);
  return (
    <>
      <strong>{end.address}</strong>
      {where ? <span className="text-muted"> ({where})</span> : null}
    </>
  );
}

function ResultsHeading({ report }: { report: ReachabilityReport }) {
  if (report.mode === 'list') {
    return (
      <>
        <strong>{report.rows.length}</strong> network{report.rows.length === 1 ? '' : 's'}{' '}
        {report.rows.length === 1 ? 'matches' : 'match'} the filters
      </>
    );
  }
  const { source, destination } = report;
  const from = source ? <>from <EndText end={source} /></> : null;
  if (report.mode === 'matrix' || !destination) {
    return (
      <>
        <strong>{report.candidates}</strong> trace{report.candidates === 1 ? '' : 's'}:{' '}
        {from ?? (
          <>
            <strong>{report.source_count}</strong> source network{report.source_count === 1 ? '' : 's'}
          </>
        )}{' '}
        → <strong>{report.destination_count}</strong> destination network
        {report.destination_count === 1 ? '' : 's'} with <strong>{report.traffic}</strong>
      </>
    );
  }
  return (
    <>
      {from ? (
        <>
          <strong>{report.candidates}</strong> trace{report.candidates === 1 ? '' : 's'} {from}
        </>
      ) : (
        <>
          <strong>{report.candidates}</strong> network{report.candidates === 1 ? '' : 's'} traced
        </>
      )}{' '}
      to <EndText end={destination} /> with <strong>{report.traffic}</strong>
    </>
  );
}

function Results({
  report,
  query,
  rows,
  rollup,
  pairs,
  verdict,
  onVerdict,
  bySite,
  onBySite,
  open,
  onOpen,
}: ResultsProps) {
  const matrix = report.mode === 'matrix';
  const listed = report.mode === 'list';
  return (
    <div className="card" style={{ padding: '0.75rem' }}>
      <div style={{ marginBottom: '0.5rem' }}>
        <ResultsHeading report={report} />
        <span className="text-muted"> · {new Date(report.generated_at).toLocaleString()}</span>
      </div>

      <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.4rem', alignItems: 'center', marginBottom: '0.6rem' }}>
        {!listed && VERDICT_ORDER.map((v) => {
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
        <label style={{ display: 'flex', gap: '0.3rem', alignItems: 'center', marginLeft: listed ? 0 : '0.5rem' }}>
          <input type="checkbox" checked={bySite} onChange={(e) => onBySite(e.target.checked)} />
          {matrix ? 'Group by site pair' : 'Group by site'}
        </label>
        <span style={{ flex: 1 }} />
        <a
          className="btn btn-sm btn-secondary"
          href={reachabilityFileUrl(query)}
          download
          title={
            listed
              ? 'Every listed network as a spreadsheet'
              : 'Every network of this sweep as a spreadsheet, whatever verdict is shown: a summary of the counts, a tab of all rows and one per verdict'
          }
        >
          Download Excel
        </a>
        {!listed && (
          <a
            className="btn btn-sm btn-secondary"
            href={reachabilityFileUrl(query, 'xlsx', verdict)}
            download
            aria-disabled={!rows.length}
            style={rows.length ? undefined : { pointerEvents: 'none', opacity: 0.6 }}
            title="Only the rows shown below, as a spreadsheet, with the summary of the whole sweep"
          >
            Download shown rows
          </a>
        )}
        <a
          className="btn btn-sm btn-secondary"
          href={reachabilityFileUrl(query, 'csv')}
          download
          title={
            listed
              ? 'Every listed network as CSV'
              : 'Every network of this sweep as CSV, with the counts by verdict after the rows'
          }
        >
          CSV
        </a>
      </div>

      {!report.rows.length ? (
        <div className="text-muted">
          {matrix
            ? 'No source and destination networks match the filters.'
            : listed
              ? 'No network matches the filters.'
              : 'No source network matches the filters.'}
        </div>
      ) : bySite && matrix ? (
        <PairTable pairs={pairs} />
      ) : bySite ? (
        <SiteTable rollup={rollup} withVerdicts={!listed} />
      ) : (
        <RowTable report={report} query={query} rows={rows} open={open} onOpen={onOpen} />
      )}
    </div>
  );
}

function CountCells({ counts }: { counts: Record<PathVerdict, number> }) {
  return (
    <>
      {VERDICT_ORDER.map((v) => (
        <td key={v} style={{ ...DETAIL_CELL_STYLE, color: counts[v] ? verdictLabel(v).color : undefined }}>
          {counts[v]}
        </td>
      ))}
    </>
  );
}

function CountHeads() {
  return (
    <>
      {VERDICT_ORDER.map((v) => (
        <th key={v} style={HEAD_STYLE}>{verdictLabel(v).label}</th>
      ))}
    </>
  );
}

/** The rollup per site; the verdict columns only for traced rows (not for a list). */
function SiteTable({ rollup, withVerdicts }: { rollup: SiteRollup[]; withVerdicts: boolean }) {
  return (
    <div style={SCROLL_X_STYLE}>
      <table className="data-table" style={{ width: '100%' }}>
        <thead>
          <tr>
            <th style={HEAD_STYLE}>Site</th>
            <th style={HEAD_STYLE}>Networks checked</th>
            {withVerdicts && <CountHeads />}
          </tr>
        </thead>
        <tbody>
          {rollup.map((site) => (
            <tr key={site.site}>
              <td style={DETAIL_CELL_STYLE}>{site.site}</td>
              <td style={DETAIL_CELL_STYLE}>{site.checked}</td>
              {withVerdicts && <CountCells counts={site.counts} />}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function PairTable({ pairs }: { pairs: PairRollup[] }) {
  return (
    <div style={SCROLL_X_STYLE}>
      <table className="data-table" style={{ width: '100%' }}>
        <thead>
          <tr>
            <th style={HEAD_STYLE}>Source site</th>
            <th style={HEAD_STYLE}>Destination site</th>
            <th style={HEAD_STYLE}>Networks checked</th>
            <CountHeads />
          </tr>
        </thead>
        <tbody>
          {pairs.map((pair) => (
            <tr key={JSON.stringify([pair.source, pair.destination])}>
              <td style={TEXT_CELL_STYLE}>{pair.source}</td>
              <td style={TEXT_CELL_STYLE}>{pair.destination}</td>
              <td style={DETAIL_CELL_STYLE}>{pair.checked}</td>
              <CountCells counts={pair.counts} />
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
  rows: NetworkRow[];
  open: string | null;
  onOpen: (key: string) => void;
}) {
  const matrix = report.mode === 'matrix';
  const listed = report.mode === 'list';
  const columns = matrix ? 12 : 10;
  return (
    <div style={SCROLL_X_STYLE}>
      <table className="data-table" style={{ width: '100%' }}>
        <thead>
          <tr>
            <th style={HEAD_STYLE}>Site</th>
            <th style={HEAD_STYLE}>Network</th>
            <th style={HEAD_STYLE}>VLAN</th>
            <th style={HEAD_STYLE}>CIDR</th>
            {listed ? (
              <>
                <th style={HEAD_STYLE}>Provider</th>
                <th style={HEAD_STYLE}>Kind</th>
                <th style={HEAD_STYLE}>In VPN</th>
              </>
            ) : (
              <>
                {matrix && <th style={HEAD_STYLE}>Destination site</th>}
                {matrix && <th style={HEAD_STYLE}>Destination</th>}
                <th style={HEAD_STYLE}>Verdict</th>
                <th style={HEAD_STYLE}>Decided at</th>
                <th style={HEAD_STYLE}>Decided by</th>
                <th style={HEAD_STYLE}>Ports</th>
                <th style={HEAD_STYLE}>Summary</th>
                <th style={HEAD_STYLE} aria-label="Trace" />
              </>
            )}
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => {
            const key = rowKey(row);
            const networkCells = (
              <>
                <td style={TEXT_CELL_STYLE}>
                  {/* A typed source has no site or source of its own: the node its trace starts at. */}
                  {row.site_name || <span className="text-muted">{row.org_name || row.node_label || '-'}</span>}
                </td>
                <td style={TEXT_CELL_STYLE} title={[row.kind, row.node_label || row.node_id].filter(Boolean).join(' · ')}>
                  {row.name}
                </td>
                <td style={DETAIL_CELL_STYLE}>{row.vlan ?? ''}</td>
                <td style={{ ...DETAIL_CELL_STYLE, whiteSpace: 'nowrap' }}>{row.cidr}</td>
              </>
            );
            if (listed || !isTraceRow(row)) {
              return (
                <tr key={key}>
                  {networkCells}
                  <td style={DETAIL_CELL_STYLE}>{row.provider ? providerLabel(row.provider) : ''}</td>
                  <td style={DETAIL_CELL_STYLE}>{row.kind}</td>
                  <td style={DETAIL_CELL_STYLE}>{row.in_vpn === null ? '' : row.in_vpn ? 'Yes' : 'No'}</td>
                </tr>
              );
            }
            const label = verdictLabel(row.verdict);
            const trace = open === key ? rowTraceQuery(row, report, query) : null;
            return (
              <Fragment key={key}>
                <tr>
                  {networkCells}
                  {matrix && (
                    <td style={TEXT_CELL_STYLE}>
                      {row.dst_site_name || <span className="text-muted">{row.dst_org_name || '-'}</span>}
                    </td>
                  )}
                  {matrix && (
                    <td style={TEXT_CELL_STYLE} title={`${row.dst_kind} · ${row.dst_node_label || row.dst_node_id}`}>
                      {row.dst_name}
                      {row.dst_name ? ' ' : ''}
                      <span className="text-muted" style={{ whiteSpace: 'nowrap' }}>{row.dst_cidr}</span>
                    </td>
                  )}
                  <td style={{ ...DETAIL_CELL_STYLE, color: label.color, fontWeight: 600, whiteSpace: 'nowrap' }}>
                    {label.label}
                  </td>
                  <td style={TEXT_CELL_STYLE}>{row.decided_at}</td>
                  <td style={TEXT_CELL_STYLE}>{row.decided_by}</td>
                  <td style={{ ...TEXT_CELL_STYLE, maxWidth: 320 }} className="text-muted">{portsText(row.ports) ?? ''}</td>
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
                    <td colSpan={columns} style={{ ...TEXT_CELL_STYLE, paddingLeft: '1rem' }}>
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
