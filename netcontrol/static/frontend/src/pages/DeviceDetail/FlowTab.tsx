import { useMemo, useState } from 'react';

import { formatBackendDateTime } from '@/lib/datetime';
import { BarChart, TimeSeriesChart } from '@/lib/echart';
import {
  FlowApplication,
  FlowConversation,
  FlowDirection,
  FlowExporter,
  FlowTalker,
  FlowTimelinePoint,
  useFlowExporters,
  useFlowTimeline,
  useFlowTopApplications,
  useFlowTopConversations,
  useFlowTopTalkers,
} from '@/api/networkTools';

interface Props {
  hostId: number;
  /** Range string from DeviceDetail (e.g. '1h', '6h', '24h', '7d', '30d'). */
  range: string;
}

const RANGE_HOURS: Record<string, number> = {
  '1h': 1,
  '6h': 6,
  '24h': 24,
  '7d': 168,
  '30d': 720,
};

type SubTab = 'talkers' | 'applications' | 'conversations' | 'timeline';

const SUB_TABS: { id: SubTab; label: string }[] = [
  { id: 'talkers', label: 'Top Talkers' },
  { id: 'applications', label: 'Applications' },
  { id: 'conversations', label: 'Conversations' },
  { id: 'timeline', label: 'Timeline' },
];

export function FlowTab({ hostId, range }: Props) {
  const hours = RANGE_HOURS[range] ?? 24;
  const [sub, setSub] = useState<SubTab>('talkers');

  return (
    <div>
      <ExporterStatus hostId={hostId} />

      <div
        style={{
          display: 'flex',
          gap: '0.25rem',
          marginTop: '0.75rem',
          marginBottom: '0.5rem',
          flexWrap: 'wrap',
        }}
      >
        {SUB_TABS.map((t) => (
          <button
            key={t.id}
            className={`btn btn-sm ${sub === t.id ? 'btn-primary' : 'btn-ghost'}`}
            onClick={() => setSub(t.id)}
          >
            {t.label}
          </button>
        ))}
      </div>

      {sub === 'talkers' && <TalkersView hostId={hostId} hours={hours} />}
      {sub === 'applications' && <ApplicationsView hostId={hostId} hours={hours} />}
      {sub === 'conversations' && <ConversationsView hostId={hostId} hours={hours} />}
      {sub === 'timeline' && <TimelineView hostId={hostId} hours={hours} />}
    </div>
  );
}

// ── Exporter status ─────────────────────────────────────────────────────────

function ExporterStatus({ hostId }: { hostId: number }) {
  const exporters = useFlowExporters();
  const rows = useMemo<FlowExporter[]>(
    () => (exporters.data?.exporters ?? []).filter((e) => e.host_id === hostId),
    [exporters.data, hostId],
  );

  if (exporters.isPending) {
    return <p className="text-muted">Loading exporter status…</p>;
  }
  if (exporters.error) {
    return (
      <div className="error">
        Failed to load exporter status: {(exporters.error as Error).message}
      </div>
    );
  }
  if (rows.length === 0) {
    return (
      <div className="card" style={{ marginBottom: 0 }}>
        <div className="card-body" style={{ padding: '0.5rem 0.75rem' }}>
          <span className="text-muted" style={{ fontSize: '0.85rem' }}>
            This device has not been seen as a flow exporter. Configure NetFlow v5/v9/IPFIX
            export to UDP/2055 or sFlow v5 to UDP/6343 on the device.
          </span>
        </div>
      </div>
    );
  }

  return (
    <div className="card" style={{ marginBottom: 0 }}>
      <div
        className="card-body"
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))',
          gap: '0.5rem',
          padding: '0.75rem',
        }}
      >
        {rows.map((r) => (
          <Item key={r.id} label={`${r.flow_type} from ${r.exporter_ip}`}>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.1rem' }}>
              <span>
                <strong>{r.packets_received.toLocaleString()}</strong> packets
              </span>
              <span style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>
                Sampling: {r.sampling_rate ? `1:${r.sampling_rate}` : '-'}
              </span>
              <span style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>
                Last record: {formatTimestamp(r.last_record_at ?? r.last_seen)}
              </span>
            </div>
          </Item>
        ))}
      </div>
    </div>
  );
}

function Item({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div style={{ display: 'flex', flexDirection: 'column' }}>
      <span style={{ color: 'var(--text-muted)', fontSize: '0.75rem' }}>{label}</span>
      {children}
    </div>
  );
}

// ── Top talkers ─────────────────────────────────────────────────────────────

function TalkersView({ hostId, hours }: { hostId: number; hours: number }) {
  const [direction, setDirection] = useState<FlowDirection>('src');
  const q = useFlowTopTalkers({ hours, direction, hostId });

  return (
    <div className="card" style={{ marginBottom: 0 }}>
      <div
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          padding: '0.5rem 0.75rem',
          flexWrap: 'wrap',
          gap: '0.5rem',
        }}
      >
        <h4 style={{ margin: 0, fontSize: '0.95rem' }}>
          Top {direction === 'src' ? 'Sources' : 'Destinations'}
        </h4>
        <div style={{ display: 'flex', gap: '0.25rem' }}>
          <button
            className={`btn btn-sm ${direction === 'src' ? 'btn-primary' : 'btn-ghost'}`}
            onClick={() => setDirection('src')}
          >
            Sources
          </button>
          <button
            className={`btn btn-sm ${direction === 'dst' ? 'btn-primary' : 'btn-ghost'}`}
            onClick={() => setDirection('dst')}
          >
            Destinations
          </button>
        </div>
      </div>
      <div style={{ padding: '0.5rem 0.75rem' }}>
        <TalkersBody query={q} />
      </div>
    </div>
  );
}

interface QueryShape<T> {
  data?: T[];
  error: Error | null;
  isPending: boolean;
}

function TalkersBody({ query }: { query: QueryShape<FlowTalker> }) {
  if (query.isPending) return <Skeleton />;
  if (query.error) return <ErrorRow message={query.error.message} />;
  const rows = (query.data ?? []).slice(0, 15);
  if (rows.length === 0) return <NoData />;

  return (
    <>
      <BarChart
        categories={rows.map((r) => r.ip)}
        values={rows.map((r) => r.total_bytes)}
        rotateLabels={45}
        height={220}
      />
      <table
        className="data-table"
        style={{ width: '100%', fontSize: '0.85em', marginTop: '0.5rem' }}
      >
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

// ── Applications ────────────────────────────────────────────────────────────

function ApplicationsView({ hostId, hours }: { hostId: number; hours: number }) {
  const apps = useFlowTopApplications({ hours, hostId });

  if (apps.isPending) return <Skeleton />;
  if (apps.error) return <ErrorRow message={apps.error.message} />;
  const rows = (apps.data ?? []).slice(0, 15);
  if (rows.length === 0) return <NoData />;

  const labelFor = (r: FlowApplication) =>
    `${r.service_name || `port-${r.port}`} (${r.protocol_name || r.protocol})`;

  return (
    <div className="card" style={{ marginBottom: 0 }}>
      <div style={{ padding: '0.5rem 0.75rem' }}>
        <h4 style={{ margin: '0 0 0.5rem', fontSize: '0.95rem' }}>
          Top Applications
        </h4>
        <BarChart
          categories={rows.map(labelFor)}
          values={rows.map((r) => r.total_bytes)}
          rotateLabels={45}
          height={240}
        />
        <table
          className="data-table"
          style={{ width: '100%', fontSize: '0.85em', marginTop: '0.5rem' }}
        >
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
    </div>
  );
}

// ── Conversations ───────────────────────────────────────────────────────────

function ConversationsView({ hostId, hours }: { hostId: number; hours: number }) {
  const convos = useFlowTopConversations({ hours, hostId });

  if (convos.isPending) return <Skeleton />;
  if (convos.error) return <ErrorRow message={convos.error.message} />;
  const rows = (convos.data ?? []).slice(0, 20);
  if (rows.length === 0) return <NoData />;

  return (
    <div className="card" style={{ marginBottom: 0 }}>
      <div style={{ padding: '0.5rem 0.75rem' }}>
        <h4 style={{ margin: '0 0 0.5rem', fontSize: '0.95rem' }}>Top Conversations</h4>
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
            {rows.map((r: FlowConversation, i) => (
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
    </div>
  );
}

// ── Timeline ────────────────────────────────────────────────────────────────

function TimelineView({ hostId, hours }: { hostId: number; hours: number }) {
  const timeline = useFlowTimeline({ hours, hostId });

  if (timeline.isPending) return <Skeleton />;
  if (timeline.error) return <ErrorRow message={timeline.error.message} />;
  const points = timeline.data ?? [];
  if (points.length === 0) return <NoData />;

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
    <div className="card" style={{ marginBottom: 0 }}>
      <div style={{ padding: '0.5rem 0.75rem' }}>
        <h4 style={{ margin: '0 0 0.5rem', fontSize: '0.95rem' }}>Traffic over time</h4>
        <TimeSeriesChart series={series} area yAxisName="bps" height={300} />
        <div className="text-muted" style={{ fontSize: '0.78rem', marginTop: '0.25rem' }}>
          Bucket size: {bucketMinutes} min. Bytes are normalised to bps assuming a full bucket
          - the last bucket may underestimate if it hasn't closed yet.
        </div>
      </div>
    </div>
  );
}

// ── Shared helpers ──────────────────────────────────────────────────────────

function NoData() {
  return (
    <p className="text-muted" style={{ padding: '0.5rem' }}>
      No flow data for this device in this window.
    </p>
  );
}

function ErrorRow({ message }: { message: string }) {
  return (
    <div style={{ color: 'var(--danger)', padding: '0.5rem' }}>
      Failed to load: {message}
    </div>
  );
}

function Skeleton() {
  return <div className="skeleton-loader" style={{ height: '240px' }} />;
}

function formatBytes(bytes: number | null | undefined): string {
  if (!bytes || bytes <= 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(1024));
  const idx = Math.min(i, units.length - 1);
  return `${(bytes / Math.pow(1024, idx)).toFixed(1)} ${units[idx]}`;
}

function formatTimestamp(value: string | null | undefined): string {
  return formatBackendDateTime(value);
}
