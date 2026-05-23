/**
 * Phase C - search-from-the-map panel.
 *
 * Lets an operator type a MAC, IP, or VLAN id and highlights every host
 * (and, for MAC/IP results, the specific port) on the topology graph.
 * Auto-detects the kind from the query string but the user can override
 * via the kind selector to disambiguate cases like "10" (VLAN vs IP).
 */
import { useEffect, useMemo, useState } from 'react';

import { useMacSearch, type MacEntry } from '@/api/networkTools';
import { useHostsByVlan, type VlanHostRole } from '@/api/host-details';

export type SearchKind = 'auto' | 'mac' | 'ip' | 'vlan';

export interface HighlightTarget {
  nodeIds: (number | string)[];
  // Per-host port hints, used so the parent can also light up matching edges
  // when a port name resolves to a known link.
  ports: { hostId: number; portName: string }[];
}

interface Props {
  onHighlight: (target: HighlightTarget | null) => void;
  onClose: () => void;
}

const MAC_RE = /^[0-9a-f]{2}([:.\-]?[0-9a-f]{2}){5}$/i;
const IPV4_RE = /^(\d{1,3}\.){1,3}\d{0,3}$/;

function detectKind(q: string): Exclude<SearchKind, 'auto'> {
  const t = q.trim();
  if (!t) return 'mac';
  if (MAC_RE.test(t)) return 'mac';
  if (IPV4_RE.test(t)) return 'ip';
  if (/^\d{1,4}$/.test(t)) return 'vlan';
  // Partial MAC fragments (hex with separators) lean MAC; everything else
  // falls through to MAC LIKE search since the backend already supports it.
  return 'mac';
}

export function TopologySearchPanel({ onHighlight, onClose }: Props) {
  const [query, setQuery] = useState('');
  const [kind, setKind] = useState<SearchKind>('auto');
  const [debounced, setDebounced] = useState('');

  // Debounce so we don't hammer the backend on every keystroke.
  useEffect(() => {
    const t = setTimeout(() => setDebounced(query.trim()), 250);
    return () => clearTimeout(t);
  }, [query]);

  const effectiveKind = kind === 'auto' ? detectKind(debounced) : kind;
  const vlanId =
    effectiveKind === 'vlan' && /^\d+$/.test(debounced)
      ? parseInt(debounced, 10)
      : null;

  // MAC / IP / partial-MAC all go through the same LIKE search endpoint --
  // the backend matches against mac_address, ip_address, and port_name.
  const macQ = useMacSearch(debounced);
  const macEnabled =
    effectiveKind === 'mac' || effectiveKind === 'ip';
  const vlanQ = useHostsByVlan(vlanId, effectiveKind === 'vlan');

  const loading =
    (macEnabled && macQ.isPending && !!debounced) ||
    (effectiveKind === 'vlan' && vlanQ.isPending && vlanId != null);

  const error = macEnabled ? macQ.error : effectiveKind === 'vlan' ? vlanQ.error : null;

  const macRows = useMemo(() => {
    if (!macEnabled || !macQ.data) return [];
    return macQ.data.slice(0, 80);
  }, [macEnabled, macQ.data]);

  const vlanRows = useMemo(() => {
    if (effectiveKind !== 'vlan') return [];
    return vlanQ.data?.hosts ?? [];
  }, [effectiveKind, vlanQ.data]);

  // ── Highlight emission ──────────────────────────────────────────────────
  // Collapse results to one highlight target whenever we have rows back.
  useEffect(() => {
    if (!debounced) {
      onHighlight(null);
      return;
    }
    if (macEnabled && macQ.data) {
      const hostIds = new Set<number>();
      const ports: { hostId: number; portName: string }[] = [];
      for (const r of macQ.data) {
        if (r.host_id != null) hostIds.add(r.host_id);
        if (r.host_id != null && r.port_name) {
          ports.push({ hostId: r.host_id, portName: r.port_name });
        }
      }
      onHighlight({ nodeIds: [...hostIds], ports });
      return;
    }
    if (effectiveKind === 'vlan' && vlanQ.data) {
      const ports: { hostId: number; portName: string }[] = [];
      for (const h of vlanQ.data.hosts) {
        for (const p of h.ports) {
          ports.push({ hostId: h.host_id, portName: p.name });
        }
      }
      onHighlight({
        nodeIds: vlanQ.data.hosts.map((h) => h.host_id),
        ports,
      });
      return;
    }
  }, [debounced, macEnabled, macQ.data, effectiveKind, vlanQ.data, onHighlight]);

  // Clear highlight when the panel unmounts so the graph isn't stuck dimmed.
  useEffect(() => {
    return () => onHighlight(null);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return (
    <aside
      style={{
        position: 'absolute',
        top: '0.75rem',
        left: '0.75rem',
        width: 380,
        maxHeight: 'calc(100% - 1.5rem)',
        background: 'var(--card-bg)',
        border: '1px solid var(--border)',
        borderRadius: '0.5rem',
        padding: '0.75rem',
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
        <h4 style={{ margin: 0 }}>Search MAC / IP / VLAN</h4>
        <button
          type="button"
          className="modal-close"
          onClick={onClose}
          style={{ fontSize: '1.2rem' }}
        >
          ×
        </button>
      </div>

      <div style={{ display: 'flex', gap: '0.4rem', marginBottom: '0.5rem' }}>
        <input
          type="text"
          className="form-input"
          autoFocus
          placeholder="aa:bb:cc:.. | 10.0.0.5 | 100"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === 'Escape') onClose();
          }}
          style={{ flex: 1 }}
        />
        <select
          className="form-select"
          value={kind}
          onChange={(e) => setKind(e.target.value as SearchKind)}
          style={{ width: 92 }}
        >
          <option value="auto">Auto</option>
          <option value="mac">MAC</option>
          <option value="ip">IP</option>
          <option value="vlan">VLAN</option>
        </select>
      </div>

      <div
        className="text-muted"
        style={{ fontSize: '0.72rem', marginBottom: '0.4rem' }}
      >
        Detected as: <strong>{debounced ? effectiveKind : '-'}</strong>
        {effectiveKind === 'vlan' && vlanId == null && debounced && (
          <> · enter a numeric VLAN id (1-4094)</>
        )}
      </div>

      {loading && (
        <p className="text-muted" style={{ fontSize: '0.8rem' }}>Searching…</p>
      )}
      {error && (
        <p style={{ color: 'var(--danger)', fontSize: '0.8rem' }}>
          {(error as Error).message}
        </p>
      )}

      {!loading && !error && debounced && (
        <ResultList
          kind={effectiveKind}
          macRows={macRows}
          vlanRows={vlanRows}
        />
      )}

      {!debounced && (
        <p className="text-muted" style={{ fontSize: '0.78rem', margin: '0.4rem 0' }}>
          Type a MAC address, IP, or VLAN id to highlight matching devices on
          the map. Press Esc to close.
        </p>
      )}
    </aside>
  );
}

// ── Result lists ───────────────────────────────────────────────────────────

function ResultList({
  kind,
  macRows,
  vlanRows,
}: {
  kind: Exclude<SearchKind, 'auto'>;
  macRows: MacEntry[];
  vlanRows: VlanHostRole[];
}) {
  if (kind === 'vlan') {
    if (vlanRows.length === 0) {
      return <Empty msg="No devices carry this VLAN." />;
    }
    return (
      <div>
        <Heading>{vlanRows.length} device(s)</Heading>
        <table className="table table-sm" style={{ fontSize: '0.78rem' }}>
          <thead>
            <tr>
              <th>Host</th>
              <th>Role</th>
              <th>Ports</th>
            </tr>
          </thead>
          <tbody>
            {vlanRows.map((h) => (
              <tr key={h.host_id}>
                <td>{h.hostname || `#${h.host_id}`}</td>
                <td>{h.roles.join(', ')}</td>
                <td>
                  {h.ports.length
                    ? h.ports
                        .slice(0, 4)
                        .map((p) => p.name)
                        .join(', ') +
                      (h.ports.length > 4 ? `… (+${h.ports.length - 4})` : '')
                    : '-'}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    );
  }

  if (macRows.length === 0) {
    return <Empty msg="No matches in current MAC/ARP tables." />;
  }
  return (
    <div>
      <Heading>{macRows.length} entry(s)</Heading>
      <table className="table table-sm" style={{ fontSize: '0.78rem' }}>
        <thead>
          <tr>
            <th>MAC</th>
            <th>IP</th>
            <th>Host</th>
            <th>Port</th>
            <th>VLAN</th>
          </tr>
        </thead>
        <tbody>
          {macRows.map((r) => (
            <tr key={`${r.host_id}-${r.mac_address}-${r.port_name}`}>
              <td style={{ fontFamily: 'monospace', fontSize: '0.72rem' }}>
                {r.mac_address}
              </td>
              <td>{r.ip_address || '-'}</td>
              <td>{r.hostname || `#${r.host_id}`}</td>
              <td>{r.port_name || '-'}</td>
              <td>{r.vlan ?? '-'}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function Heading({ children }: { children: React.ReactNode }) {
  return (
    <div
      style={{
        fontSize: '0.72rem',
        marginBottom: '0.3rem',
        color: 'var(--text-muted)',
      }}
    >
      {children}
    </div>
  );
}

function Empty({ msg }: { msg: string }) {
  return <p className="text-muted" style={{ fontSize: '0.78rem' }}>{msg}</p>;
}
