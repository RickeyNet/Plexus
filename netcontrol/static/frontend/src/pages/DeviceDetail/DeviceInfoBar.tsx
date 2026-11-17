import type { ReactNode } from 'react';

import type { MonitoringPoll } from '@/api/deviceDetail';
import { formatBackendDateTime } from '@/lib/datetime';

import { formatUptime } from './format';

/**
 * A device's newest poll at a glance: address, type, liveness, CPU, memory,
 * interface counts, uptime. On the device page and the Inventory host panel.
 */
export function DeviceInfoBar({ poll, hostId }: { poll: MonitoringPoll | null; hostId: number }) {
  if (!poll) {
    return (
      <div className="card">
        <div className="card-body">
          <span className="text-muted">No poll data available for device #{hostId}</span>
        </div>
      </div>
    );
  }
  const ifTotal =
    (poll.if_up_count || 0) + (poll.if_down_count || 0) + (poll.if_admin_down || 0);
  return (
    <div className="card card-sm">
      <div
        className="card-body"
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(140px, 1fr))',
          gap: 'var(--space-2)',
        }}
      >
        <Item label="Hostname" value={poll.hostname || 'Unknown'} />
        <Item label="IP" value={poll.ip_address || 'N/A'} />
        <Item label="Type" value={poll.device_type || 'N/A'} />
        <ItemNode label="Liveness" node={<LivenessPill poll={poll} />} />
        <Item
          label="CPU"
          value={poll.cpu_percent != null ? poll.cpu_percent.toFixed(1) + '%' : 'N/A'}
        />
        <Item
          label="Memory"
          value={
            poll.memory_percent != null ? poll.memory_percent.toFixed(1) + '%' : 'N/A'
          }
        />
        <ItemNode
          label="Interfaces"
          node={
            ifTotal > 0 ? (
              <span>
                <span className="badge badge-success">{poll.if_up_count || 0}</span>/
                <span className="badge badge-danger">{poll.if_down_count || 0}</span>/
                <span className="badge badge-secondary">{poll.if_admin_down || 0}</span>
              </span>
            ) : (
              <span>N/A</span>
            )
          }
        />
        <Item label="Uptime" value={formatUptime(poll.uptime_seconds)} />
        <Item
          label="Last Poll"
          value={formatBackendDateTime(poll.polled_at, 'N/A')}
        />
      </div>
    </div>
  );
}

function LivenessPill({ poll }: { poll: MonitoringPoll }) {
  // icmp_alive may arrive as 0/1 (older rows) or true/false - normalise
  // both. `null/undefined` means ICMP didn't run
  // (icmplib missing, or icmp_enabled=false), so we say nothing rather
  // than imply the host is down.
  const icmpRan = poll.icmp_alive !== undefined && poll.icmp_alive !== null;
  const icmpUp = icmpRan && Boolean(poll.icmp_alive);
  const snmpOk = poll.poll_status === 'ok' && poll.cpu_percent != null;
  if (!icmpRan) {
    return <span className="text-muted">ICMP disabled</span>;
  }
  if (icmpUp && snmpOk) {
    return (
      <span className="badge badge-success">
        Healthy{poll.icmp_rtt_ms != null ? ` (${poll.icmp_rtt_ms.toFixed(1)}ms)` : ''}
      </span>
    );
  }
  if (icmpUp && !snmpOk) {
    return (
      <span
        className="badge badge-warning"
        title="Host responds to ICMP but the SNMP/SSH poll did not return data - credentials, ACL, or engine-ID problem."
      >
        ICMP up, SNMP/SSH not responding
      </span>
    );
  }
  return <span className="badge badge-danger">Unreachable (no ICMP reply)</span>;
}

function Item({ label, value }: { label: string; value: string }) {
  return (
    <div style={{ display: 'flex', flexDirection: 'column' }}>
      <span style={{ color: 'var(--text-muted)', fontSize: '0.75rem' }}>{label}</span>
      <span>{value}</span>
    </div>
  );
}

function ItemNode({ label, node }: { label: string; node: ReactNode }) {
  return (
    <div style={{ display: 'flex', flexDirection: 'column' }}>
      <span style={{ color: 'var(--text-muted)', fontSize: '0.75rem' }}>{label}</span>
      {node}
    </div>
  );
}
