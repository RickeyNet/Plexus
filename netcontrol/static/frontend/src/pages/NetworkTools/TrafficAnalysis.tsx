import { useMemo, useState } from 'react';
import { Link } from 'react-router-dom';

import { PageHelp } from '@/components/PageHelp';
import { BarChart, TimeSeriesChart } from '@/lib/echart';
import { useInventoryGroupsFull } from '@/api/inventory';
import {
  FlowApplication,
  FlowConversation,
  FlowExporter,
  FlowStatus,
  FlowTalker,
  FlowTimelinePoint,
  useFlowExporters,
  useFlowStatus,
  useFlowTopApplications,
  useFlowTopConversations,
  useFlowTopTalkers,
  useFlowTimeline,
} from '@/api/networkTools';

import { formatBytes, formatTimestamp } from './formatting';

const TIME_RANGES = [
  { value: 1, label: 'Last 1 Hour' },
  { value: 6, label: 'Last 6 Hours' },
  { value: 24, label: 'Last 24 Hours' },
  { value: 168, label: 'Last 7 Days' },
];

type Tab = 'talkers' | 'applications' | 'conversations' | 'timeline' | 'exporters';

const TABS: { id: Tab; label: string }[] = [
  { id: 'talkers', label: 'Top Talkers' },
  { id: 'applications', label: 'Top Applications' },
  { id: 'conversations', label: 'Conversations' },
  { id: 'timeline', label: 'Timeline' },
  { id: 'exporters', label: 'Exporters' },
];

const TAB_HELP: Record<Tab, { title: string; text: string }> = {
  talkers: {
    title: 'Top Talkers',
    text: 'Devices generating or receiving the most traffic in the selected window. Use the direction toggle to view sources vs destinations.',
  },
  applications: {
    title: 'Top Applications',
    text: 'Traffic broken down by destination port + IP protocol. Well-known ports are mapped to service names (HTTP, SSH, etc.).',
  },
  conversations: {
    title: 'Top Conversations',
    text: 'IP-to-IP flow pairs with the highest byte counts. Useful for spotting heavy backups, replication, or unexpected east-west traffic.',
  },
  timeline: {
    title: 'Traffic Timeline',
    text: 'Total bytes per time bucket across the selected window. Bucket size auto-scales: 1m for 1h, 5m for 6h, 15m for 24h+.',
  },
  exporters: {
    title: 'Flow Exporters',
    text: 'Devices that have sent flow records to the collector. Shows protocol (NetFlow / sFlow), packet count, sampling rate, and last-seen time.',
  },
};

export function TrafficAnalysis() {
  const [hours, setHours] = useState<number>(6);
  const [hostId, setHostId] = useState<number | null>(null);
  const [tab, setTab] = useState<Tab>('talkers');

  const status = useFlowStatus();

  // Single host list for the filter dropdown - flatten groups → hosts.
  const groups = useInventoryGroupsFull(true);
  const hostOptions = useMemo(() => {
    const list: { id: number; label: string }[] = [];
    for (const group of groups.data ?? []) {
      for (const h of group.hosts ?? []) {
        list.push({ id: h.id, label: h.hostname ?? `host-${h.id}` });
      }
    }
    list.sort((a, b) => a.label.localeCompare(b.label));
    return list;
  }, [groups.data]);

  return (
    <>
      <div className="page-header">
        <h2>Traffic Analysis</h2>
        <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center', flexWrap: 'wrap' }}>
          <select
            className="form-select list-control-select"
            value={hostId ?? ''}
            onChange={(e) => setHostId(e.target.value ? Number(e.target.value) : null)}
            aria-label="Filter by host"
          >
            <option value="">All hosts</option>
            {hostOptions.map((h) => (
              <option key={h.id} value={h.id}>
                {h.label}
              </option>
            ))}
          </select>
          <select
            className="form-select list-control-select"
            value={hours}
            onChange={(e) => setHours(Number(e.target.value))}
            aria-label="Time range"
          >
            {TIME_RANGES.map((r) => (
              <option key={r.value} value={r.value}>
                {r.label}
              </option>
            ))}
          </select>
          <CollectorBadges status={status.data} />
        </div>
      </div>

      <PageHelp
        pageKey="traffic-analysis"
        title="Traffic Analysis"
        text="Analyze NetFlow/sFlow/IPFIX traffic patterns by talker, application, conversation, or over time. Filter by host to scope to a single exporter, or view all collected flows."
      />

      <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: '0.5rem',
            padding: '0.5rem 0.75rem',
            borderBottom: '1px solid var(--border)',
            flexWrap: 'wrap',
          }}
        >
          {TABS.map((t) => (
            <button
              key={t.id}
              className={`btn btn-sm ${tab === t.id ? 'btn-primary' : 'btn-ghost'}`}
              onClick={() => setTab(t.id)}
            >
              {t.label}
            </button>
          ))}
        </div>
        <div style={{ padding: '0.75rem' }}>
          <PageHelp
            pageKey={`traffic-analysis.${tab}`}
            title={TAB_HELP[tab].title}
            text={TAB_HELP[tab].text}
          />
          {tab === 'talkers' && <TopTalkersView hours={hours} hostId={hostId} />}
          {tab === 'applications' && <ApplicationsView hours={hours} hostId={hostId} />}
          {tab === 'conversations' && <ConversationsView hours={hours} hostId={hostId} />}
          {tab === 'timeline' && <TimelineView hours={hours} hostId={hostId} />}
          {tab === 'exporters' && <ExportersView />}
        </div>
      </div>

      {status.error && (
        <div className="glass-card card" style={{ color: 'var(--warning)', marginTop: '1rem' }}>
          Could not read collector status: {status.error.message}
        </div>
      )}
    </>
  );
}

function CollectorBadges({ status }: { status: FlowStatus | undefined }) {
  if (!status) return null;
  return (
    <div style={{ display: 'flex', gap: '0.35rem', flexWrap: 'wrap' }}>
      <span className={`badge ${status.running ? 'badge-success' : 'badge-warning'}`}>
        NetFlow {status.running ? 'running' : 'stopped'}
      </span>
      <span className={`badge ${status.sflow_running ? 'badge-success' : 'badge-warning'}`}>
        sFlow {status.sflow_running ? 'running' : 'stopped'}
      </span>
    </div>
  );
}

// ── Top Talkers tab ─────────────────────────────────────────────────────────

function TopTalkersView({ hours, hostId }: { hours: number; hostId: number | null }) {
  const src = useFlowTopTalkers({ hours, direction: 'src', hostId });
  const dst = useFlowTopTalkers({ hours, direction: 'dst', hostId });

  return (
    <div className="chart-grid-2col">
      <div className="glass-card card">
        <h4 style={{ margin: '0 0 0.5rem' }}>Top Sources</h4>
        <TalkerSection query={src} />
      </div>
      <div className="glass-card card">
        <h4 style={{ margin: '0 0 0.5rem' }}>Top Destinations</h4>
        <TalkerSection query={dst} />
      </div>
    </div>
  );
}

interface QueryShape<T> {
  data?: T[];
  error: Error | null;
  isPending: boolean;
}

function TalkerSection({ query }: { query: QueryShape<FlowTalker> }) {
  if (query.isPending) return <Skeleton />;
  if (query.error) return <ErrorRow message={query.error.message} />;
  const rows = (query.data ?? []).slice(0, 10);
  if (rows.length === 0) return <NoData />;

  const categories = rows.map((r) => r.ip);
  const values = rows.map((r) => r.total_bytes);

  return (
    <>
      <BarChart categories={categories} values={values} rotateLabels={45} height={220} />
      <table className="data-table" style={{ width: '100%', fontSize: '0.85em', marginTop: '0.5rem' }}>
        <thead>
          <tr>
            <th>IP</th>
            <th style={{ textAlign: 'right' }}>Traffic</th>
            <th style={{ textAlign: 'right' }}>Flows</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((r) => (
            <tr key={r.ip}>
              <td>
                <code>{r.ip}</code>
              </td>
              <td style={{ textAlign: 'right' }}>{formatBytes(r.total_bytes)}</td>
              <td style={{ textAlign: 'right' }}>{r.flow_count}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </>
  );
}

// ── Top Applications tab ────────────────────────────────────────────────────

function ApplicationsView({ hours, hostId }: { hours: number; hostId: number | null }) {
  const apps = useFlowTopApplications({ hours, hostId });

  if (apps.isPending) return <Skeleton />;
  if (apps.error) return <ErrorRow message={apps.error.message} />;
  const rows = (apps.data ?? []).slice(0, 15);
  if (rows.length === 0) return <NoData />;

  const labelFor = (r: FlowApplication) =>
    `${r.service_name || `port-${r.port}`} (${r.protocol_name || r.protocol})`;
  const categories = rows.map(labelFor);
  const values = rows.map((r) => r.total_bytes);

  return (
    <div className="glass-card card">
      <h4 style={{ margin: '0 0 0.5rem' }}>Top Applications by Traffic</h4>
      <BarChart categories={categories} values={values} rotateLabels={45} height={260} />
      <table className="data-table" style={{ width: '100%', fontSize: '0.85em', marginTop: '0.5rem' }}>
        <thead>
          <tr>
            <th>Service</th>
            <th style={{ textAlign: 'right' }}>Port</th>
            <th>Proto</th>
            <th style={{ textAlign: 'right' }}>Traffic</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((r, i) => (
            <tr key={`${r.port}-${r.protocol}-${i}`}>
              <td>{r.service_name || '-'}</td>
              <td style={{ textAlign: 'right' }}>{r.port}</td>
              <td>{r.protocol_name || String(r.protocol)}</td>
              <td style={{ textAlign: 'right' }}>{formatBytes(r.total_bytes)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

// ── Conversations tab ───────────────────────────────────────────────────────

function ConversationsView({ hours, hostId }: { hours: number; hostId: number | null }) {
  const convos = useFlowTopConversations({ hours, hostId });

  if (convos.isPending) return <Skeleton />;
  if (convos.error) return <ErrorRow message={convos.error.message} />;
  const rows = (convos.data ?? []).slice(0, 20);
  if (rows.length === 0) return <NoData />;

  return (
    <div className="glass-card card">
      <h4 style={{ margin: '0 0 0.5rem' }}>Top Conversations</h4>
      <table className="data-table" style={{ width: '100%', fontSize: '0.85em' }}>
        <thead>
          <tr>
            <th>Source</th>
            <th>Destination</th>
            <th style={{ textAlign: 'right' }}>Traffic</th>
            <th style={{ textAlign: 'right' }}>Flows</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((r: FlowConversation, i: number) => (
            <tr key={`${r.src_ip}-${r.dst_ip}-${i}`}>
              <td>
                <code>{r.src_ip}</code>
              </td>
              <td>
                <code>{r.dst_ip}</code>
              </td>
              <td style={{ textAlign: 'right' }}>{formatBytes(r.total_bytes)}</td>
              <td style={{ textAlign: 'right' }}>{r.flow_count}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

// ── Timeline tab ────────────────────────────────────────────────────────────

function TimelineView({ hours, hostId }: { hours: number; hostId: number | null }) {
  const timeline = useFlowTimeline({ hours, hostId });

  if (timeline.isPending) return <Skeleton />;
  if (timeline.error) return <ErrorRow message={timeline.error.message} />;
  const points = timeline.data ?? [];
  if (points.length === 0) return <NoData />;

  // The chart wants bytes-per-second so the y-axis bps formatter renders right.
  // We don't know the exact bucket width from the response, but it's
  // deterministic - match the same logic the hook uses.
  const bucketMinutes = hours <= 1 ? 1 : hours <= 6 ? 5 : 15;
  const bucketSeconds = bucketMinutes * 60;

  const series = [
    {
      name: 'Traffic',
      color: '#3b82f6',
      data: points
        .filter((p: FlowTimelinePoint) => p.bucket)
        .map((p: FlowTimelinePoint) => ({
          time: p.bucket as string,
          value: (p.total_bytes * 8) / bucketSeconds,
        })),
    },
  ];

  return (
    <div className="glass-card card">
      <h4 style={{ margin: '0 0 0.5rem' }}>Traffic over time</h4>
      <TimeSeriesChart series={series} area yAxisName="bps" height={320} />
      <div className="text-muted" style={{ fontSize: '0.78rem', marginTop: '0.25rem' }}>
        Bucket size: {bucketMinutes} min. Bytes are normalised to bps assuming a full bucket
        - the last bucket may underestimate if it hasn't closed yet.
      </div>
    </div>
  );
}

// ── Exporters tab ───────────────────────────────────────────────────────────

function ExportersView() {
  const exporters = useFlowExporters();

  if (exporters.isPending) return <Skeleton />;
  if (exporters.error) return <ErrorRow message={exporters.error.message} />;
  const rows = exporters.data?.exporters ?? [];
  const cacheSize = exporters.data?.cache_size ?? 0;

  if (rows.length === 0) {
    return (
      <div className="empty-state">
        <p>No flow exporters seen yet.</p>
        <p style={{ fontSize: '0.85em', opacity: 0.7 }}>
          Configure devices to export NetFlow v5/v9/IPFIX to UDP/2055 or sFlow v5 to UDP/6343.
        </p>
      </div>
    );
  }

  return (
    <div className="glass-card card">
      <div
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          flexWrap: 'wrap',
          gap: '0.5rem',
          marginBottom: '0.5rem',
        }}
      >
        <h4 style={{ margin: 0 }}>Flow Exporters</h4>
        <span className="badge">Resolution cache: {cacheSize}</span>
      </div>
      <table className="data-table" style={{ width: '100%', fontSize: '0.85em' }}>
        <thead>
          <tr>
            <th>Exporter IP</th>
            <th>Host</th>
            <th>Type</th>
            <th style={{ textAlign: 'right' }}>Packets</th>
            <th style={{ textAlign: 'right' }}>Sampling</th>
            <th>First Seen</th>
            <th>Last Seen</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((r: FlowExporter) => (
            <tr key={r.id}>
              <td>
                <code>{r.exporter_ip}</code>
              </td>
              <td>
                {r.hostname ? (
                  r.host_id ? (
                    <Link to={`/devices/${r.host_id}`}>{r.hostname}</Link>
                  ) : (
                    r.hostname
                  )
                ) : (
                  <span className="text-muted">(unresolved)</span>
                )}
              </td>
              <td>{r.flow_type}</td>
              <td style={{ textAlign: 'right' }}>{r.packets_received.toLocaleString()}</td>
              <td style={{ textAlign: 'right' }}>
                {r.sampling_rate ? `1:${r.sampling_rate}` : '-'}
              </td>
              <td>{formatTimestamp(r.first_seen)}</td>
              <td>{formatTimestamp(r.last_seen)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

// ── Shared helpers ──────────────────────────────────────────────────────────

function NoData() {
  return (
    <div className="empty-state">
      <p>No flow data in this window.</p>
      <p style={{ fontSize: '0.85em', opacity: 0.7 }}>
        Configure devices to export NetFlow/sFlow/IPFIX to the collector, or widen the time range.
      </p>
    </div>
  );
}

function ErrorRow({ message }: { message: string }) {
  return (
    <div style={{ color: 'var(--danger)', padding: '0.5rem' }}>Failed to load: {message}</div>
  );
}

function Skeleton() {
  return <div className="skeleton-loader" style={{ height: '260px' }} />;
}
