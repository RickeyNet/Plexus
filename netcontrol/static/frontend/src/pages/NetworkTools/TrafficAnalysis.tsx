import { useState } from 'react';

import {
  FlowApplication,
  FlowConversation,
  FlowTalker,
  FlowTimelinePoint,
  useFlowStatus,
  useFlowTopApplications,
  useFlowTopConversations,
  useFlowTopTalkers,
  useFlowTimeline,
} from '@/api/networkTools';

import { formatBytes } from './formatting';

const TIME_RANGES = [
  { value: 1, label: 'Last 1 Hour' },
  { value: 6, label: 'Last 6 Hours' },
  { value: 24, label: 'Last 24 Hours' },
  { value: 168, label: 'Last 7 Days' },
];

interface QueryShape<T> {
  data?: T[];
  error: Error | null;
  isPending: boolean;
}

export function TrafficAnalysis() {
  const [hours, setHours] = useState<number>(6);

  const status = useFlowStatus();
  const topSrc = useFlowTopTalkers({ hours, direction: 'src' });
  const topDst = useFlowTopTalkers({ hours, direction: 'dst' });
  const topApps = useFlowTopApplications({ hours });
  const topConvos = useFlowTopConversations({ hours });
  const timeline = useFlowTimeline({ hours });

  // Match the legacy "is there any data?" check: any of the four panels has rows.
  const hasData =
    (topSrc.data?.length ?? 0) > 0 ||
    (topDst.data?.length ?? 0) > 0 ||
    (topApps.data?.length ?? 0) > 0 ||
    (topConvos.data?.length ?? 0) > 0;

  const anyLoading =
    topSrc.isPending ||
    topDst.isPending ||
    topApps.isPending ||
    topConvos.isPending ||
    timeline.isPending;

  return (
    <>
      <div className="page-header">
        <h2>Traffic Analysis</h2>
        <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
          <select
            id="traffic-time-range"
            className="form-select list-control-select"
            value={hours}
            onChange={(e) => setHours(Number(e.target.value))}
          >
            {TIME_RANGES.map((r) => (
              <option key={r.value} value={r.value}>
                {r.label}
              </option>
            ))}
          </select>
          <CollectorBadge running={status.data?.running} />
        </div>
      </div>

      {anyLoading && <div className="skeleton-loader" style={{ height: '300px' }} />}

      {!anyLoading && !hasData && (
        <div className="empty-state">
          <p>No flow data available. Configure devices to send NetFlow/sFlow/IPFIX to Plexus.</p>
          <p style={{ fontSize: '0.85em', opacity: 0.7 }}>
            Collector ports: UDP 2055 (NetFlow), 6343 (sFlow).
          </p>
        </div>
      )}

      {!anyLoading && hasData && (
        <>
          <div className="chart-grid-2col" style={{ marginBottom: '1rem' }}>
            <div className="glass-card card">
              <h4 style={{ margin: '0 0 0.5rem' }}>Top Sources</h4>
              <TalkerTable query={topSrc} />
            </div>
            <div className="glass-card card">
              <h4 style={{ margin: '0 0 0.5rem' }}>Top Destinations</h4>
              <TalkerTable query={topDst} />
            </div>
          </div>

          <div className="chart-grid-2col" style={{ marginBottom: '1rem' }}>
            <div className="glass-card card">
              <h4 style={{ margin: '0 0 0.5rem' }}>Top Applications</h4>
              <ApplicationsTable query={topApps} />
            </div>
            <div className="glass-card card">
              <h4 style={{ margin: '0 0 0.5rem' }}>Top Conversations</h4>
              <ConversationsTable query={topConvos} />
            </div>
          </div>

          <div className="glass-card card">
            <h4 style={{ margin: '0 0 0.5rem' }}>Traffic Timeline</h4>
            <TimelineTable query={timeline} />
            <div style={{ marginTop: '0.5rem', fontSize: '0.85em', opacity: 0.6 }}>
              Chart visualization deferred to a follow-up PR.
            </div>
          </div>
        </>
      )}

      {status.error && (
        <div className="glass-card card" style={{ color: 'var(--warning)', marginTop: '1rem' }}>
          Could not read collector status: {status.error.message}
        </div>
      )}
    </>
  );
}

function CollectorBadge({ running }: { running: boolean | undefined }) {
  if (running === undefined) return null;
  return (
    <span
      id="flow-collector-status"
      className={`badge ${running ? 'badge-success' : 'badge-warning'}`}
    >
      {running ? 'Collector Running' : 'Collector Stopped'}
    </span>
  );
}

function TalkerTable({ query }: { query: QueryShape<FlowTalker> }) {
  if (query.error) return <ErrorRow message={query.error.message} />;
  if (!query.data || query.data.length === 0) return <NoData />;
  return (
    <table className="data-table" style={{ width: '100%', fontSize: '0.85em' }}>
      <thead>
        <tr>
          <th>IP</th>
          <th>Traffic</th>
          <th>Flows</th>
        </tr>
      </thead>
      <tbody>
        {query.data.slice(0, 10).map((r) => (
          <tr key={r.ip}>
            <td><code>{r.ip}</code></td>
            <td>{formatBytes(r.total_bytes)}</td>
            <td>{r.flow_count}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function ApplicationsTable({ query }: { query: QueryShape<FlowApplication> }) {
  if (query.error) return <ErrorRow message={query.error.message} />;
  if (!query.data || query.data.length === 0) return <NoData />;
  return (
    <table className="data-table" style={{ width: '100%', fontSize: '0.85em' }}>
      <thead>
        <tr>
          <th>Service</th>
          <th>Port</th>
          <th>Proto</th>
          <th>Traffic</th>
        </tr>
      </thead>
      <tbody>
        {query.data.slice(0, 10).map((r, i) => (
          <tr key={`${r.port}-${r.protocol}-${i}`}>
            <td>{r.service_name || '—'}</td>
            <td>{r.port}</td>
            <td>{r.protocol_name || String(r.protocol)}</td>
            <td>{formatBytes(r.total_bytes)}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function ConversationsTable({ query }: { query: QueryShape<FlowConversation> }) {
  if (query.error) return <ErrorRow message={query.error.message} />;
  if (!query.data || query.data.length === 0) return <NoData />;
  return (
    <table className="data-table" style={{ width: '100%', fontSize: '0.85em' }}>
      <thead>
        <tr>
          <th>Source</th>
          <th>Destination</th>
          <th>Traffic</th>
          <th>Flows</th>
        </tr>
      </thead>
      <tbody>
        {query.data.slice(0, 10).map((r, i) => (
          <tr key={`${r.src_ip}-${r.dst_ip}-${i}`}>
            <td><code>{r.src_ip}</code></td>
            <td><code>{r.dst_ip}</code></td>
            <td>{formatBytes(r.total_bytes)}</td>
            <td>{r.flow_count}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function TimelineTable({ query }: { query: QueryShape<FlowTimelinePoint> }) {
  if (query.error) return <ErrorRow message={query.error.message} />;
  if (!query.data || query.data.length === 0) return <NoData />;
  return (
    <table className="data-table" style={{ width: '100%', fontSize: '0.85em' }}>
      <thead>
        <tr>
          <th>Bucket</th>
          <th>Traffic</th>
        </tr>
      </thead>
      <tbody>
        {query.data.map((p, i) => (
          <tr key={`${p.bucket}-${i}`}>
            <td>{p.bucket?.replace('T', ' ').slice(0, 16) ?? '—'}</td>
            <td>{formatBytes(p.total_bytes)}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function NoData() {
  return (
    <div style={{ opacity: 0.5, textAlign: 'center', padding: '1rem' }}>No data</div>
  );
}

function ErrorRow({ message }: { message: string }) {
  return <div style={{ color: 'var(--danger)', padding: '0.5rem' }}>Failed to load: {message}</div>;
}
