import { useMemo } from 'react';

import { TimeSeriesChart, BarChart } from '@/lib/echart';
import {
  InterfaceTimeSeriesEntry,
  InterfaceTimeSeriesResult,
  MonitoringPoll,
  PollIfDetail,
} from '@/api/deviceDetail';

import {
  formatRate,
  formatSpeed,
  isLoopback,
  isMgmt,
  isPortChannel,
  isTunnel,
  isVlan,
} from './format';

interface MergedInterface {
  if_index: number;
  name: string;
  status: string;
  speed_mbps: number;
  in_octets?: number;
  out_octets?: number;
  in_rate_bps: number | null;
  out_rate_bps: number | null;
  utilization_pct: number | null;
}

interface Props {
  ifData: InterfaceTimeSeriesResult | undefined;
  latestPoll: MonitoringPoll | null;
}

export function InterfaceTab({ ifData, latestPoll }: Props) {
  const merged = useMemo(() => mergeInterfaces(ifData, latestPoll), [ifData, latestPoll]);
  const tsInterfaces = ifData?.data || ifData?.interfaces || [];

  if (!merged.length && !tsInterfaces.length) {
    return (
      <p className="text-muted">
        No interface data available. Ensure SNMP is configured and at least one poll has
        completed.
      </p>
    );
  }

  const physicals: MergedInterface[] = [];
  const vlans: MergedInterface[] = [];
  const portChannels: MergedInterface[] = [];
  const tunnels: MergedInterface[] = [];
  const other: MergedInterface[] = [];

  merged.forEach((i) => {
    if (isVlan(i.name)) vlans.push(i);
    else if (isPortChannel(i.name)) portChannels.push(i);
    else if (isTunnel(i.name)) tunnels.push(i);
    else if (isLoopback(i.name) || isMgmt(i.name)) other.push(i);
    else physicals.push(i);
  });

  const upCount = merged.filter((i) => i.status === 'up').length;
  const downCount = merged.filter((i) => i.status === 'down').length;
  const adminDownCount = merged.filter((i) => i.status === 'admin_down').length;

  // Summary bar chart of top 20 interfaces by utilization
  const summaryData = useMemo(() => {
    const ifMap = new Map<string, InterfaceTimeSeriesEntry>();
    tsInterfaces.forEach((d) => {
      const key = d.if_name || `idx-${d.if_index}`;
      const existing = ifMap.get(key);
      if (!existing || new Date(d.sampled_at) > new Date(existing.sampled_at)) {
        ifMap.set(key, d);
      }
    });
    return [...ifMap.values()]
      .sort((a, b) => (b.utilization_pct || 0) - (a.utilization_pct || 0))
      .slice(0, 20);
  }, [tsInterfaces]);

  // Per-interface time-series data, top 12 by activity
  const trafficCharts = useMemo(() => {
    const grouped: Record<string, InterfaceTimeSeriesEntry[]> = {};
    tsInterfaces.forEach((d) => {
      const key = d.if_name || `idx-${d.if_index}`;
      (grouped[key] ||= []).push(d);
    });
    const names = Object.keys(grouped)
      .sort((a, b) => {
        const aMax = Math.max(...grouped[a].map((d) => (d.in_rate_bps || 0) + (d.out_rate_bps || 0)));
        const bMax = Math.max(...grouped[b].map((d) => (d.in_rate_bps || 0) + (d.out_rate_bps || 0)));
        return bMax - aMax;
      })
      .slice(0, 12);
    return names.map((name) => {
      const sorted = [...grouped[name]].sort(
        (a, b) => new Date(a.sampled_at).getTime() - new Date(b.sampled_at).getTime(),
      );
      return { name, data: sorted };
    });
  }, [tsInterfaces]);

  return (
    <div>
      <div
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          marginBottom: '0.75rem',
          flexWrap: 'wrap',
          gap: '0.5rem',
        }}
      >
        <h4 style={{ margin: 0 }}>{merged.length} Interfaces</h4>
        <div style={{ display: 'flex', gap: '0.5rem', fontSize: '0.85rem', flexWrap: 'wrap' }}>
          <span className="badge badge-success">{upCount} Up</span>
          {downCount > 0 && <span className="badge badge-danger">{downCount} Down</span>}
          {adminDownCount > 0 && (
            <span className="badge badge-secondary">{adminDownCount} Admin Down</span>
          )}
          <span style={{ color: 'var(--text-secondary)' }}>|</span>
          <span style={{ color: 'var(--text-secondary)' }}>{physicals.length} Physical</span>
          {portChannels.length > 0 && (
            <span style={{ color: 'var(--text-secondary)' }}>
              {portChannels.length} Port-Channel
            </span>
          )}
          <span style={{ color: 'var(--text-secondary)' }}>{vlans.length} VLAN</span>
          {tunnels.length > 0 && (
            <span style={{ color: 'var(--text-secondary)' }}>{tunnels.length} Tunnel</span>
          )}
          {other.length > 0 && (
            <span style={{ color: 'var(--text-secondary)' }}>{other.length} Other</span>
          )}
        </div>
      </div>

      {summaryData.length > 0 && (
        <div className="card" style={{ marginBottom: '1rem' }}>
          <div className="card-body" style={{ padding: '0.75rem' }}>
            <h4 style={{ margin: '0 0 0.5rem', fontSize: '0.95rem' }}>
              Top Interfaces by Utilization (%)
            </h4>
            <BarChart
              categories={summaryData.map((d) => d.if_name || `idx-${d.if_index}`)}
              values={summaryData.map((d) => Math.round((d.utilization_pct || 0) * 10) / 10)}
              rotateLabels={45}
              height={240}
            />
          </div>
        </div>
      )}

      <div
        style={{
          display: 'grid',
          gridTemplateColumns: '1fr 1fr',
          gap: '1rem',
          marginBottom: '1rem',
        }}
      >
        <SectionCard title={`Physical Interfaces (${physicals.length})`}>
          <FullInterfaceTable interfaces={physicals} />
        </SectionCard>
        <SectionCard title={`VLANs (${vlans.length})`}>
          <VlanTable interfaces={vlans} />
        </SectionCard>
      </div>

      {(portChannels.length || tunnels.length || other.length) > 0 && (
        <div
          style={{
            display: 'grid',
            gridTemplateColumns: `repeat(${[
              portChannels.length,
              tunnels.length,
              other.length,
            ].filter((n) => n > 0).length}, 1fr)`,
            gap: '1rem',
            marginBottom: '1rem',
          }}
        >
          {portChannels.length > 0 && (
            <SectionCard title={`Port-Channels (${portChannels.length})`}>
              <CompactInterfaceTable interfaces={portChannels} />
            </SectionCard>
          )}
          {tunnels.length > 0 && (
            <SectionCard title={`Tunnels (${tunnels.length})`}>
              <CompactInterfaceTable interfaces={tunnels} />
            </SectionCard>
          )}
          {other.length > 0 && (
            <SectionCard title={`Loopback / Management / Other (${other.length})`}>
              <CompactInterfaceTable interfaces={other} />
            </SectionCard>
          )}
        </div>
      )}

      {trafficCharts.length > 0 ? (
        <>
          <h4 style={{ margin: '1.25rem 0 0.5rem' }}>Traffic Charts (Top 12 by Activity)</h4>
          <div
            style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fill, minmax(360px, 1fr))',
              gap: '0.75rem',
            }}
          >
            {trafficCharts.map(({ name, data }) => (
              <div key={name} className="card" style={{ marginBottom: 0 }}>
                <div
                  className="card-title"
                  style={{ fontSize: '0.85rem', padding: '0.5rem 0.75rem' }}
                >
                  {name}
                </div>
                <TimeSeriesChart
                  height={180}
                  area
                  yAxisName="bps"
                  series={[
                    {
                      name: 'In (bps)',
                      data: data.map((d) => ({ time: d.sampled_at, value: d.in_rate_bps || 0 })),
                      color: '#3b82f6',
                    },
                    {
                      name: 'Out (bps)',
                      data: data.map((d) => ({ time: d.sampled_at, value: d.out_rate_bps || 0 })),
                      color: '#f59e0b',
                    },
                  ]}
                />
              </div>
            ))}
          </div>
        </>
      ) : (
        <p className="text-muted" style={{ marginTop: '1rem' }}>
          Traffic charts will appear after two or more polling cycles collect rate data.
        </p>
      )}
    </div>
  );
}

function StatusBadge({ status }: { status: string }) {
  if (status === 'up') return <span className="badge badge-success">Up</span>;
  if (status === 'admin_down')
    return <span className="badge badge-secondary">Admin Down</span>;
  return <span className="badge badge-danger">Down</span>;
}

function UtilBar({ pct }: { pct: number | null }) {
  if (pct == null) return <span className="text-muted">-</span>;
  const color =
    pct > 80 ? 'var(--danger)' : pct > 50 ? 'var(--warning)' : 'var(--success)';
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
      <div
        style={{
          flex: 1,
          maxWidth: 80,
          height: 6,
          background: 'var(--border)',
          borderRadius: 3,
          overflow: 'hidden',
        }}
      >
        <div
          style={{
            width: `${Math.min(pct, 100)}%`,
            height: '100%',
            background: color,
            borderRadius: 3,
          }}
        />
      </div>
      <span>{pct.toFixed(1)}%</span>
    </div>
  );
}

function SectionCard({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="card">
      <div className="card-body" style={{ padding: '0.75rem' }}>
        <h4 style={{ margin: '0 0 0.5rem', fontSize: '0.95rem' }}>{title}</h4>
        {children}
      </div>
    </div>
  );
}

function FullInterfaceTable({ interfaces }: { interfaces: MergedInterface[] }) {
  if (!interfaces.length)
    return (
      <p className="text-muted" style={{ padding: '0.5rem' }}>
        None
      </p>
    );
  return (
    <div style={{ overflowX: 'auto' }}>
      <table className="chart-table" style={{ width: '100%', fontSize: '0.82rem' }}>
        <thead>
          <tr>
            <th>Name</th>
            <th>Status</th>
            <th>Speed</th>
            <th>In</th>
            <th>Out</th>
            <th>Util</th>
          </tr>
        </thead>
        <tbody>
          {interfaces.map((i) => (
            <tr key={i.if_index}>
              <td>
                <strong>{i.name}</strong>
              </td>
              <td>
                <StatusBadge status={i.status} />
              </td>
              <td>{formatSpeed(i.speed_mbps)}</td>
              <td>{formatRate(i.in_rate_bps)}</td>
              <td>{formatRate(i.out_rate_bps)}</td>
              <td>
                <UtilBar pct={i.utilization_pct} />
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function VlanTable({ interfaces }: { interfaces: MergedInterface[] }) {
  if (!interfaces.length)
    return (
      <p className="text-muted" style={{ padding: '0.5rem' }}>
        No VLANs detected
      </p>
    );
  const vlanUp = interfaces.filter((i) => i.status === 'up').length;
  const vlanDown = interfaces.length - vlanUp;
  return (
    <>
      <div
        style={{
          marginBottom: '0.5rem',
          fontSize: '0.8rem',
          display: 'flex',
          gap: '0.5rem',
        }}
      >
        <span className="badge badge-success">{vlanUp} up</span>
        {vlanDown > 0 && <span className="badge badge-danger">{vlanDown} down</span>}
      </div>
      <div style={{ overflowY: 'auto', maxHeight: 400 }}>
        <table className="chart-table" style={{ width: '100%', fontSize: '0.82rem' }}>
          <thead>
            <tr>
              <th>VLAN</th>
              <th>Status</th>
              <th>In</th>
              <th>Out</th>
            </tr>
          </thead>
          <tbody>
            {interfaces.map((i) => (
              <tr key={i.if_index}>
                <td>
                  <strong>{i.name}</strong>
                </td>
                <td>
                  <StatusBadge status={i.status} />
                </td>
                <td style={{ fontSize: '0.78rem' }}>{formatRate(i.in_rate_bps)}</td>
                <td style={{ fontSize: '0.78rem' }}>{formatRate(i.out_rate_bps)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </>
  );
}

function CompactInterfaceTable({ interfaces }: { interfaces: MergedInterface[] }) {
  if (!interfaces.length) return null;
  return (
    <div style={{ overflowX: 'auto' }}>
      <table className="chart-table" style={{ width: '100%', fontSize: '0.82rem' }}>
        <thead>
          <tr>
            <th>Name</th>
            <th>Status</th>
            <th>Speed</th>
            <th>In</th>
            <th>Out</th>
          </tr>
        </thead>
        <tbody>
          {interfaces.map((i) => (
            <tr key={i.if_index}>
              <td>
                <strong>{i.name}</strong>
              </td>
              <td>
                <StatusBadge status={i.status} />
              </td>
              <td>{formatSpeed(i.speed_mbps)}</td>
              <td>{formatRate(i.in_rate_bps)}</td>
              <td>{formatRate(i.out_rate_bps)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function mergeInterfaces(
  ifData: InterfaceTimeSeriesResult | undefined,
  latestPoll: MonitoringPoll | null,
): MergedInterface[] {
  let pollInterfaces: PollIfDetail[] = [];
  if (latestPoll) {
    try {
      const raw =
        typeof latestPoll.if_details === 'string'
          ? JSON.parse(latestPoll.if_details || '[]')
          : latestPoll.if_details || [];
      pollInterfaces = raw as PollIfDetail[];
    } catch {
      pollInterfaces = [];
    }
  }

  const tsInterfaces = ifData?.data || ifData?.interfaces || [];

  const ifMap = new Map<string, MergedInterface>();
  pollInterfaces.forEach((iface) => {
    const idx = String(iface.if_index);
    ifMap.set(idx, {
      if_index: iface.if_index,
      name: iface.name || `ifIndex-${iface.if_index}`,
      status: iface.status || 'unknown',
      speed_mbps: iface.speed_mbps || 0,
      in_octets: iface.in_octets || 0,
      out_octets: iface.out_octets || 0,
      in_rate_bps: null,
      out_rate_bps: null,
      utilization_pct: null,
    });
  });

  const latestByIf: Record<string, InterfaceTimeSeriesEntry> = {};
  tsInterfaces.forEach((d) => {
    const idx = String(d.if_index);
    if (
      !latestByIf[idx] ||
      new Date(d.sampled_at) > new Date(latestByIf[idx].sampled_at)
    ) {
      latestByIf[idx] = d;
    }
  });
  Object.entries(latestByIf).forEach(([idx, d]) => {
    const existing =
      ifMap.get(idx) ||
      ({
        if_index: parseInt(idx, 10),
        name: d.if_name || `ifIndex-${idx}`,
        status: 'unknown',
        speed_mbps: d.if_speed_mbps || 0,
        in_rate_bps: null,
        out_rate_bps: null,
        utilization_pct: null,
      } as MergedInterface);
    existing.in_rate_bps = d.in_rate_bps ?? null;
    existing.out_rate_bps = d.out_rate_bps ?? null;
    existing.utilization_pct = d.utilization_pct ?? null;
    if (d.if_name) existing.name = d.if_name;
    ifMap.set(idx, existing);
  });

  return [...ifMap.values()].sort((a, b) => a.if_index - b.if_index);
}
