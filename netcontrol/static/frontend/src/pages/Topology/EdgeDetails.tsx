import { type TopologyEdge, type TopologyNode } from '@/api/topology';
import {
  type InterfaceInventoryRow,
  useHostInterfaceInventory,
} from '@/api/host-details';
import { abbreviateInterface, formatBps } from './helpers';

interface Props {
  edge: TopologyEdge;
  fromNode: TopologyNode | undefined;
  toNode: TopologyNode | undefined;
  onClose: () => void;
}

export function EdgeDetails({ edge, fromNode, toNode, onClose }: Props) {
  // Resolve numeric host ids: prefer the dedicated *_host_id columns the
  // backend joins onto edges; fall back to the node id, which is the host
  // id for inventory devices and a string sentinel for external nodes.
  const fromHostId =
    edge.from_host_id ?? (fromNode?.in_inventory ? Number(edge.from) : null);
  const toHostId =
    edge.to_host_id ?? (toNode?.in_inventory ? Number(edge.to) : null);

  const fromQ = useHostInterfaceInventory(fromHostId, true);
  const toQ = useHostInterfaceInventory(toHostId, true);

  const fromPort = pickPort(fromQ.data?.interfaces, edge.source_interface);
  const toPort = pickPort(toQ.data?.interfaces, edge.target_interface);

  const protoLabel = (edge.protocol ?? 'L2').toUpperCase();
  const util = edge.utilization;

  return (
    <aside
      style={{
        position: 'absolute',
        top: '0.75rem',
        right: '0.75rem',
        width: 480,
        maxHeight: 'calc(100% - 1.5rem)',
        background: 'var(--card-bg)',
        border: '1px solid var(--border)',
        borderRadius: '0.5rem',
        padding: '0.85rem',
        overflowY: 'auto',
        zIndex: 5,
        boxShadow: '0 4px 16px rgba(0,0,0,0.25)',
      }}
    >
      <div
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          marginBottom: '0.5rem',
        }}
      >
        <h4 style={{ margin: 0 }}>Link details</h4>
        <button
          type="button"
          className="modal-close"
          onClick={onClose}
          style={{ fontSize: '1.2rem' }}
        >
          ×
        </button>
      </div>

      <div
        style={{
          fontSize: '0.8rem',
          marginBottom: '0.65rem',
          display: 'flex',
          alignItems: 'center',
          gap: '0.5rem',
          flexWrap: 'wrap',
        }}
      >
        <strong>{fromNode?.label || edge.from}</strong>
        <span className="text-muted">
          {abbreviateInterface(edge.source_interface) || '?'}
        </span>
        <span>↔</span>
        <span className="text-muted">
          {abbreviateInterface(edge.target_interface) || '?'}
        </span>
        <strong>{toNode?.label || edge.to}</strong>
        <span className="badge badge-muted" style={{ marginLeft: 'auto' }}>
          {protoLabel}
        </span>
      </div>

      {util && (
        <div
          style={{
            fontSize: '0.75rem',
            marginBottom: '0.7rem',
            padding: '0.35rem 0.55rem',
            borderRadius: '0.3rem',
            background:
              util.utilization_pct > 75
                ? 'rgba(244,67,54,0.15)'
                : util.utilization_pct > 50
                ? 'rgba(255,235,59,0.12)'
                : 'rgba(76,175,80,0.12)',
          }}
        >
          Utilization {util.utilization_pct}% - {formatBps(util.in_bps)} in /{' '}
          {formatBps(util.out_bps)} out
        </div>
      )}

      <div
        style={{
          display: 'grid',
          gridTemplateColumns: '1fr 1fr',
          gap: '0.75rem',
        }}
      >
        <PortColumn
          heading={fromNode?.label || String(edge.from)}
          ifName={edge.source_interface}
          row={fromPort}
          loading={fromQ.isPending}
          error={fromQ.error}
          hasHost={fromHostId != null}
        />
        <PortColumn
          heading={toNode?.label || String(edge.to)}
          ifName={edge.target_interface}
          row={toPort}
          loading={toQ.isPending}
          error={toQ.error}
          hasHost={toHostId != null}
        />
      </div>

      {fromPort && toPort && (
        <MismatchSummary fromPort={fromPort} toPort={toPort} />
      )}
    </aside>
  );
}

// ── Per-endpoint port column ───────────────────────────────────────────────

function PortColumn(props: {
  heading: string;
  ifName: string | null | undefined;
  row: InterfaceInventoryRow | null;
  loading: boolean;
  error: unknown;
  hasHost: boolean;
}) {
  const { heading, ifName, row, loading, error, hasHost } = props;

  return (
    <div
      style={{
        border: '1px solid var(--border)',
        borderRadius: '0.3rem',
        padding: '0.5rem 0.6rem',
        fontSize: '0.78rem',
      }}
    >
      <div style={{ fontWeight: 500, marginBottom: '0.3rem' }}>{heading}</div>
      <div
        className="text-muted"
        style={{ fontSize: '0.7rem', marginBottom: '0.5rem' }}
      >
        {abbreviateInterface(ifName) || '(no port)'}
      </div>

      {!hasHost ? (
        <p className="text-muted" style={{ fontSize: '0.72rem' }}>
          External node - no inventory data.
        </p>
      ) : loading ? (
        <p className="text-muted" style={{ fontSize: '0.72rem' }}>
          Loading…
        </p>
      ) : error ? (
        <p style={{ color: 'var(--danger)', fontSize: '0.72rem' }}>
          {(error as Error).message}
        </p>
      ) : !row ? (
        <p className="text-muted" style={{ fontSize: '0.72rem' }}>
          Port not found in inventory.
        </p>
      ) : (
        <Field rows={describePort(row)} />
      )}
    </div>
  );
}

function Field({ rows }: { rows: [string, React.ReactNode][] }) {
  return (
    <div
      style={{
        display: 'grid',
        gridTemplateColumns: 'auto 1fr',
        gap: '0.25rem 0.6rem',
        alignItems: 'center',
      }}
    >
      {rows.flatMap(([label, value]) => [
        <span key={`l-${label}`} className="text-muted">
          {label}
        </span>,
        <span key={`v-${label}`}>{value}</span>,
      ])}
    </div>
  );
}

function describePort(r: InterfaceInventoryRow): [string, React.ReactNode][] {
  const out: [string, React.ReactNode][] = [];
  out.push(['Admin', <StateBadge value={r.admin_state} />]);
  out.push(['Oper', <StateBadge value={r.oper_state} />]);
  out.push(['Speed', r.speed_mbps ? `${r.speed_mbps} Mbps` : '-']);
  out.push(['Duplex', r.duplex || '-']);
  if (r.access_vlan) {
    out.push(['Access VLAN', String(r.access_vlan)]);
  } else if (r.trunk_vlans) {
    out.push(['Trunk', truncateList(r.trunk_vlans)]);
  } else {
    out.push(['VLAN', '-']);
  }
  const ageDays = ticksToDays(r.last_change);
  if (ageDays != null) {
    out.push(['Last change', `${ageDays.toFixed(1)} days ago`]);
  }
  if (r.description) out.push(['Desc', r.description]);
  return out;
}

// ── Cross-endpoint mismatch summary ────────────────────────────────────────

function MismatchSummary({
  fromPort,
  toPort,
}: {
  fromPort: InterfaceInventoryRow;
  toPort: InterfaceInventoryRow;
}) {
  const issues: string[] = [];

  if (
    fromPort.speed_mbps &&
    toPort.speed_mbps &&
    fromPort.speed_mbps !== toPort.speed_mbps
  ) {
    issues.push(
      `Speed mismatch: ${fromPort.speed_mbps} Mbps vs ${toPort.speed_mbps} Mbps`,
    );
  }

  const fromDup = (fromPort.duplex || '').toLowerCase();
  const toDup = (toPort.duplex || '').toLowerCase();
  if (
    fromDup &&
    toDup &&
    fromDup !== 'unknown' &&
    toDup !== 'unknown' &&
    fromDup !== toDup
  ) {
    issues.push(`Duplex mismatch: ${fromPort.duplex} vs ${toPort.duplex}`);
  }

  const fromTrunks = parseVlanCsv(fromPort.trunk_vlans);
  const toTrunks = parseVlanCsv(toPort.trunk_vlans);
  if (fromTrunks.size && toTrunks.size) {
    const onlyFrom = [...fromTrunks].filter((v) => !toTrunks.has(v));
    const onlyTo = [...toTrunks].filter((v) => !fromTrunks.has(v));
    if (onlyFrom.length) {
      issues.push(
        `Trunk VLANs only on left: ${onlyFrom.slice(0, 12).join(',')}${onlyFrom.length > 12 ? '…' : ''}`,
      );
    }
    if (onlyTo.length) {
      issues.push(
        `Trunk VLANs only on right: ${onlyTo.slice(0, 12).join(',')}${onlyTo.length > 12 ? '…' : ''}`,
      );
    }
  }

  if (issues.length === 0) return null;

  return (
    <div
      style={{
        marginTop: '0.7rem',
        padding: '0.45rem 0.6rem',
        background: 'rgba(255,193,7,0.1)',
        border: '1px solid rgba(255,193,7,0.35)',
        borderRadius: '0.3rem',
        fontSize: '0.72rem',
      }}
    >
      <div style={{ fontWeight: 500, marginBottom: '0.2rem' }}>
        Mismatches detected
      </div>
      <ul style={{ margin: 0, paddingLeft: '1rem' }}>
        {issues.map((m) => (
          <li key={m}>{m}</li>
        ))}
      </ul>
    </div>
  );
}

// ── Utilities ──────────────────────────────────────────────────────────────

function pickPort(
  rows: InterfaceInventoryRow[] | undefined,
  ifName: string | null | undefined,
): InterfaceInventoryRow | null {
  if (!rows || !ifName) return null;
  // Exact name match wins; fall back to case-insensitive then abbreviation
  // match so "Gi1/0/1" matches a stored "GigabitEthernet1/0/1" and vice
  // versa.
  const lower = ifName.toLowerCase();
  const abbr = abbreviateInterface(ifName)?.toLowerCase();
  let exact: InterfaceInventoryRow | null = null;
  let ci: InterfaceInventoryRow | null = null;
  let byAbbr: InterfaceInventoryRow | null = null;
  for (const r of rows) {
    if (r.name === ifName) {
      exact = r;
      break;
    }
    const rl = r.name.toLowerCase();
    if (!ci && rl === lower) ci = r;
    if (!byAbbr && abbr && abbreviateInterface(r.name)?.toLowerCase() === abbr) {
      byAbbr = r;
    }
  }
  return exact ?? ci ?? byAbbr;
}

function parseVlanCsv(csv: string | undefined | null): Set<number> {
  const out = new Set<number>();
  if (!csv) return out;
  for (const part of csv.split(',')) {
    const n = parseInt(part.trim(), 10);
    if (!Number.isNaN(n)) out.add(n);
  }
  return out;
}

function ticksToDays(value: string | null | undefined): number | null {
  if (!value) return null;
  const ticks = parseInt(value, 10);
  if (!Number.isFinite(ticks) || ticks <= 0) return null;
  // ifLastChange is in 1/100s units; 8_640_000 ticks = 1 day.
  return ticks / 8_640_000;
}

function truncateList(csv: string, max = 12): string {
  const parts = csv.split(',').map((s) => s.trim()).filter(Boolean);
  if (parts.length <= max) return parts.join(',');
  return `${parts.slice(0, max).join(',')}… (+${parts.length - max})`;
}

function StateBadge({ value }: { value: string }) {
  const v = (value || '').toLowerCase();
  let cls = 'badge-muted';
  if (v === 'up' || v === 'active' || v === 'operational') cls = 'badge-success';
  else if (v === 'down' || v === 'shutdown' || v === 'suspended') cls = 'badge-danger';
  else if (v === 'testing' || v === 'unknown') cls = 'badge-warning';
  return <span className={`badge ${cls}`}>{value || '-'}</span>;
}
