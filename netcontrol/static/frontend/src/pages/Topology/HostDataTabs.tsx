import { useMemo, useState } from 'react';

import { useConfigBackupDetail } from '@/api/configuration';
import {
  type ArpRow,
  type HostAuditFinding,
  type InterfaceErrorRow,
  type InterfaceInventoryRow,
  type MacAddressRow,
  type VlanDefinitionRow,
  useHostAuditFindings,
  useHostConfigBackups,
  useHostInterfaceErrors,
  useHostInterfaceInventory,
  useHostMacArp,
  useHostVlans,
} from '@/api/host-details';
import { SeverityBadge } from '@/components/Badge';
import { InterfaceAddressesTable } from '@/components/InterfaceAddressesTable';
import { Modal } from '@/components/Modal';

import { abbreviateInterface, DETAIL_CELL_STYLE, SCROLL_X_STYLE } from './helpers';

/**
 * What Plexus collected from one inventory host (SNMP/SSH): interfaces,
 * VLANs, MAC/ARP, the newest config backup, interface errors and audit
 * findings. Shared by the map's device pane and the Inventory host panel.
 */

// ── Tab content: Interfaces ────────────────────────────────────────────────

export function HostInterfacesTab({ hostId }: { hostId: number }) {
  return (
    <>
      <InterfaceInventoryTable hostId={hostId} />
      <div style={{ marginTop: '0.75rem' }}>
        <InterfaceAddressesTable hostId={hostId} dense />
      </div>
    </>
  );
}

function InterfaceInventoryTable({ hostId }: { hostId: number }) {
  const q = useHostInterfaceInventory(hostId);
  if (q.isPending) return <Loading />;
  if (q.error) return <ErrorRow error={q.error} />;
  const rows = q.data?.interfaces ?? [];
  if (rows.length === 0) return <Empty msg="No interface inventory collected yet." />;

  return (
    <CompactTable
      columns={['Port', 'Admin', 'Oper', 'Speed', 'Duplex', 'VLAN', 'Description']}
      rows={rows.map((r: InterfaceInventoryRow) => [
        abbreviateInterface(r.name) || `if${r.if_index}`,
        <StateBadge value={r.admin_state} />,
        <StateBadge value={r.oper_state} />,
        r.speed_mbps ? `${r.speed_mbps} Mbps` : '-',
        r.duplex || '-',
        r.access_vlan
          ? String(r.access_vlan)
          : r.trunk_vlans
          ? `trunk (${truncateList(r.trunk_vlans)})`
          : '-',
        r.description || '-',
      ])}
    />
  );
}

// ── Tab content: VLANs ─────────────────────────────────────────────────────

export function HostVlansTab({ hostId }: { hostId: number }) {
  const q = useHostVlans(hostId);
  if (q.isPending) return <Loading />;
  if (q.error) return <ErrorRow error={q.error} />;
  const rows = q.data?.vlans ?? [];
  if (rows.length === 0) return <Empty msg="No VLAN definitions collected yet." />;

  return (
    <CompactTable
      columns={['VLAN', 'Name', 'State']}
      rows={rows.map((r: VlanDefinitionRow) => [
        String(r.vlan_id),
        r.name || '-',
        <StateBadge value={r.state} />,
      ])}
    />
  );
}

// ── Tab content: MAC / ARP ─────────────────────────────────────────────────

export function HostMacArpTab({ hostId }: { hostId: number }) {
  const q = useHostMacArp(hostId);
  if (q.isPending) return <Loading />;
  if (q.error) return <ErrorRow error={q.error} />;
  const macs = q.data?.mac_table ?? [];
  const arps = q.data?.arp_table ?? [];
  if (macs.length === 0 && arps.length === 0) {
    return <Empty msg="No MAC or ARP entries collected yet." />;
  }

  return (
    <>
      {macs.length > 0 && (
        <>
          <SubHeading label={`MAC table (${macs.length})`} />
          <CompactTable
            columns={['MAC', 'VLAN', 'Port', 'Type']}
            rows={macs.slice(0, 200).map((m: MacAddressRow) => [
              m.mac_address,
              m.vlan ? String(m.vlan) : '-',
              abbreviateInterface(m.port_name) || '-',
              m.entry_type || '-',
            ])}
            footer={macs.length > 200 ? `Showing first 200 of ${macs.length}` : undefined}
          />
        </>
      )}
      {arps.length > 0 && (
        <>
          <SubHeading label={`ARP cache (${arps.length})`} />
          <CompactTable
            columns={['IP', 'MAC', 'Interface']}
            rows={arps.slice(0, 200).map((a: ArpRow) => [
              a.ip_address,
              a.mac_address,
              abbreviateInterface(a.interface_name) || '-',
            ])}
            footer={arps.length > 200 ? `Showing first 200 of ${arps.length}` : undefined}
          />
        </>
      )}
    </>
  );
}

// ── Tab content: Config backups ────────────────────────────────────────────

export function HostConfigTab({ hostId }: { hostId: number }) {
  // The newest successful capture: a failed attempt holds no config and can
  // be newer than the config the device still has.
  const list = useHostConfigBackups(hostId, 1, true, 'success');
  const latest = list.data?.[0];
  const detail = useConfigBackupDetail(latest?.id ?? null);
  const [expanded, setExpanded] = useState(false);

  if (list.isPending) return <Loading />;
  if (list.error) return <ErrorRow error={list.error} />;
  if (!latest) return <Empty msg="No successful config backup for this device." />;

  const configText = detail.data?.config_text ?? '';
  const capturedLabel = latest.captured_at
    ? new Date(latest.captured_at).toLocaleString()
    : '-';

  return (
    <>
      <div
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          gap: '0.5rem',
          marginBottom: '0.4rem',
          fontSize: '0.72rem',
          color: 'var(--text-muted)',
        }}
      >
        <span>
          Captured {capturedLabel}
          {latest.config_length != null ? ` · ${latest.config_length} B` : ''}
          {latest.capture_method ? ` · ${latest.capture_method}` : ''}
        </span>
        <button
          type="button"
          className="btn btn-secondary btn-sm"
          onClick={() => setExpanded(true)}
          disabled={!configText}
        >
          Expand
        </button>
      </div>

      {detail.isPending ? (
        <Loading />
      ) : detail.error ? (
        <ErrorRow error={detail.error} />
      ) : !configText ? (
        <Empty msg="Backup has no config text." />
      ) : (
        <pre
          style={{
            background: 'var(--bg)',
            border: '1px solid var(--border)',
            borderRadius: '0.35rem',
            padding: '0.5rem',
            fontFamily:
              'ui-monospace, SFMono-Regular, Menlo, Consolas, monospace',
            fontSize: '0.72rem',
            lineHeight: 1.4,
            maxHeight: 280,
            overflow: 'auto',
            whiteSpace: 'pre',
            margin: 0,
          }}
        >
          {configText}
        </pre>
      )}

      <Modal
        isOpen={expanded}
        onClose={() => setExpanded(false)}
        title={`Running config — captured ${capturedLabel}`}
        size="large"
      >
        <pre
          style={{
            background: 'var(--bg)',
            border: '1px solid var(--border)',
            borderRadius: '0.35rem',
            padding: '0.75rem',
            fontFamily:
              'ui-monospace, SFMono-Regular, Menlo, Consolas, monospace',
            fontSize: '0.8rem',
            lineHeight: 1.45,
            maxHeight: '75vh',
            overflow: 'auto',
            whiteSpace: 'pre',
            margin: 0,
          }}
        >
          {configText}
        </pre>
      </Modal>
    </>
  );
}

// ── Tab content: Interface errors ──────────────────────────────────────────

export function HostErrorsTab({ hostId }: { hostId: number }) {
  const q = useHostInterfaceErrors(hostId, 1);
  if (q.isPending) return <Loading />;
  if (q.error) return <ErrorRow error={q.error} />;
  const ifaces = q.data?.interfaces ?? [];
  // Only show interfaces that actually saw errors in the window
  const errored = ifaces.filter((row: InterfaceErrorRow) =>
    Object.values(row.metrics).some((m) => (m.max_value ?? 0) > 0),
  );
  if (errored.length === 0) {
    return <Empty msg="No interface errors in the last 24h." />;
  }

  return (
    <CompactTable
      columns={['Port', 'Metric', 'Avg', 'Peak']}
      rows={errored.flatMap((row: InterfaceErrorRow) =>
        Object.entries(row.metrics)
          .filter(([, m]) => (m.max_value ?? 0) > 0)
          .map(([metric, m]) => [
            abbreviateInterface(row.if_name) || `if${row.if_index ?? '?'}`,
            metric,
            m.avg_value != null ? String(m.avg_value) : '-',
            m.max_value != null ? String(m.max_value) : '-',
          ]),
      )}
      footer={
        q.data && q.data.active_events > 0
          ? `${q.data.active_events} active event(s)`
          : undefined
      }
    />
  );
}

// ── Tab content: Audit findings ────────────────────────────────────────────

export function HostAuditTab({ hostId }: { hostId: number }) {
  const q = useHostAuditFindings(hostId, 50);
  // Only show the latest run's findings (rows are returned id-DESC, so the
  // top run_id is the most recent). Older findings would clutter the pane.
  const { latestRunId, latest } = useMemo(() => {
    const rows = q.data?.findings ?? [];
    const runId = rows[0]?.run_id;
    return { latestRunId: runId, latest: rows.filter((r) => r.run_id === runId) };
  }, [q.data]);

  if (q.isPending) return <Loading />;
  if (q.error) return <ErrorRow error={q.error} />;
  if (latest.length === 0) return <Empty msg="No audit findings for this device." />;

  return (
    <>
      <div className="text-muted" style={{ fontSize: '0.75rem', marginBottom: '0.4rem' }}>
        Latest run #{latestRunId} · {latest.length} finding{latest.length === 1 ? '' : 's'}
      </div>
      <CompactTable
        columns={['Severity', 'Rule', 'Title']}
        rows={latest.map((f: HostAuditFinding) => [
          <SeverityBadge severity={f.severity} />,
          <code style={{ fontSize: '0.7rem' }}>{f.rule_id}</code>,
          f.title,
        ])}
      />
    </>
  );
}

// ── Shared atoms ───────────────────────────────────────────────────────────

function Loading() {
  return (
    <p className="text-muted" style={{ fontSize: '0.78rem' }}>
      Loading…
    </p>
  );
}

function ErrorRow({ error }: { error: unknown }) {
  return (
    <p style={{ color: 'var(--danger)', fontSize: '0.78rem' }}>
      {(error as Error).message}
    </p>
  );
}

function Empty({ msg }: { msg: string }) {
  return (
    <p className="text-muted" style={{ fontSize: '0.78rem' }}>
      {msg}
    </p>
  );
}

export function SubHeading({ label }: { label: string }) {
  return (
    <h6
      style={{
        margin: '0.6rem 0 0.3rem',
        fontSize: '0.72rem',
        textTransform: 'uppercase',
        letterSpacing: '0.05em',
        color: 'var(--text-muted)',
      }}
    >
      {label}
    </h6>
  );
}

function StateBadge({ value }: { value: string }) {
  const v = (value || '').toLowerCase();
  let cls = 'badge-secondary';
  if (v === 'up' || v === 'active' || v === 'operational') cls = 'badge-success';
  else if (v === 'down' || v === 'shutdown' || v === 'suspended') cls = 'badge-danger';
  else if (v === 'testing' || v === 'unknown') cls = 'badge-warning';
  return <span className={`badge ${cls}`}>{value || '-'}</span>;
}

function CompactTable(props: {
  columns: string[];
  rows: React.ReactNode[][];
  footer?: string;
}) {
  return (
    <>
      {/* Wider than the panel when a table has many columns; scroll, don't squeeze. */}
      <div style={SCROLL_X_STYLE}>
        <table
          className="data-table"
          style={{ fontSize: '0.75rem' }}
        >
          <thead>
            <tr>
              {props.columns.map((c) => (
                <th key={c} style={{ ...DETAIL_CELL_STYLE, whiteSpace: 'nowrap' }}>
                  {c}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {props.rows.map((cells, i) => (
              <tr key={i}>
                {cells.map((cell, j) => (
                  <td key={j} style={DETAIL_CELL_STYLE}>{cell}</td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {props.footer && (
        <div
          className="text-muted"
          style={{ fontSize: '0.7rem', marginTop: '0.3rem' }}
        >
          {props.footer}
        </div>
      )}
    </>
  );
}

function truncateList(csv: string, max = 8): string {
  const parts = csv.split(',').map((s) => s.trim()).filter(Boolean);
  if (parts.length <= max) return parts.join(',');
  return `${parts.slice(0, max).join(',')}…`;
}
