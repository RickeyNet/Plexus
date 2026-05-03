import { useMemo, useState } from 'react';
import { useNavigate, useParams } from 'react-router-dom';

import { TimeSeriesChart, TimeSeries } from '@/lib/echart';
import {
  MetricQueryResult,
  MonitoringPoll,
  useComplianceResults,
  useInterfaceTimeSeries,
  useIpamAddressContext,
  useMetricQuery,
  useMonitoringAlerts,
  useMonitoringPollHistory,
  useSyslogEvents,
} from '@/api/deviceDetail';

import { ErrorTrendingTab } from './ErrorTrendingTab';
import { InterfaceTab } from './InterfaceTab';
import { formatUptime } from './format';

const TABS = [
  { id: 'overview', label: 'Overview' },
  { id: 'interfaces', label: 'Interfaces' },
  { id: 'errors', label: 'Interface Errors' },
  { id: 'alerts', label: 'Alerts' },
  { id: 'compliance', label: 'Compliance' },
  { id: 'syslog', label: 'Syslog' },
] as const;
type TabId = (typeof TABS)[number]['id'];

const RANGES = ['1h', '6h', '24h', '7d', '30d'];

export function DeviceDetail() {
  const { hostId: hostIdParam } = useParams<{ hostId: string }>();
  const navigate = useNavigate();
  const hostId = hostIdParam ? parseInt(hostIdParam, 10) : null;
  const [tab, setTab] = useState<TabId>('overview');
  const [range, setRange] = useState('24h');

  const polls = useMonitoringPollHistory(hostId, 1);
  const cpu = useMetricQuery('cpu_percent', hostId, range);
  const mem = useMetricQuery('memory_percent', hostId, range);
  const rt = useMetricQuery('response_time_ms', hostId, range);
  const pl = useMetricQuery('packet_loss_pct', hostId, range);
  const ifData = useInterfaceTimeSeries(hostId, range);
  const alerts = useMonitoringAlerts(hostId, 50);
  const compliance = useComplianceResults(hostId, 20);
  const syslog = useSyslogEvents(hostId, 100);

  const latestPoll: MonitoringPoll | null =
    (polls.data?.polls && polls.data.polls[0]) || null;
  const ip = latestPoll?.ip_address || null;
  const vrf = latestPoll?.vrf_name || null;
  const ipamCtx = useIpamAddressContext(ip, vrf);

  if (hostId == null || Number.isNaN(hostId)) {
    return (
      <div>
        <p className="error">Invalid host id.</p>
        <button className="btn btn-secondary" onClick={() => navigate('/devices')}>
          Back to device list
        </button>
      </div>
    );
  }

  const title = latestPoll?.hostname || `Device #${hostId}`;

  return (
    <div>
      <div
        className="page-header"
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          flexWrap: 'wrap',
          gap: '0.5rem',
          marginBottom: '0.75rem',
        }}
      >
        <div>
          <button
            className="btn btn-sm btn-ghost"
            onClick={() => navigate('/devices')}
            style={{ marginRight: '0.5rem' }}
          >
            ← Devices
          </button>
          <span style={{ fontSize: '1.25rem', fontWeight: 600 }}>{title}</span>
        </div>
        <div style={{ display: 'flex', gap: '0.25rem', alignItems: 'center' }}>
          <span className="text-muted" style={{ fontSize: '0.85rem' }}>
            Range:
          </span>
          {RANGES.map((r) => (
            <button
              key={r}
              className={`btn btn-sm ${r === range ? 'btn-primary' : 'btn-ghost'}`}
              onClick={() => setRange(r)}
            >
              {r}
            </button>
          ))}
        </div>
      </div>

      <DeviceInfoBar poll={latestPoll} hostId={hostId} />
      {ipamCtx.data && <IpamContext ctx={ipamCtx.data} vrf={vrf} />}

      <div
        className="card"
        style={{ marginTop: '0.75rem', padding: 0, overflow: 'hidden' }}
      >
        <div
          style={{
            display: 'flex',
            gap: '0.25rem',
            padding: '0.5rem 0.75rem',
            borderBottom: '1px solid var(--border)',
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
          {tab === 'overview' && (
            <OverviewTab cpu={cpu.data} mem={mem.data} rt={rt.data} pl={pl.data} />
          )}
          {tab === 'interfaces' && (
            <InterfaceTab ifData={ifData.data} latestPoll={latestPoll} />
          )}
          {tab === 'errors' && <ErrorTrendingTab hostId={hostId} />}
          {tab === 'alerts' && (
            <AlertsTab alerts={alerts.data?.alerts || []} loading={alerts.isLoading} />
          )}
          {tab === 'compliance' && (
            <ComplianceTab
              results={compliance.data?.results || []}
              loading={compliance.isLoading}
            />
          )}
          {tab === 'syslog' && (
            <SyslogTab events={syslog.data?.events || []} loading={syslog.isLoading} />
          )}
        </div>
      </div>
    </div>
  );
}

function DeviceInfoBar({ poll, hostId }: { poll: MonitoringPoll | null; hostId: number }) {
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
    <div className="card">
      <div
        className="card-body"
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(140px, 1fr))',
          gap: '0.5rem',
          padding: '0.75rem',
        }}
      >
        <Item label="Hostname" value={poll.hostname || 'Unknown'} />
        <Item label="IP" value={poll.ip_address || 'N/A'} />
        <Item label="Type" value={poll.device_type || 'N/A'} />
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
          value={poll.polled_at ? new Date(poll.polled_at).toLocaleString() : 'N/A'}
        />
      </div>
    </div>
  );
}

function Item({ label, value }: { label: string; value: string }) {
  return (
    <div style={{ display: 'flex', flexDirection: 'column' }}>
      <span style={{ color: 'var(--text-muted)', fontSize: '0.75rem' }}>{label}</span>
      <span>{value}</span>
    </div>
  );
}

function ItemNode({ label, node }: { label: string; node: React.ReactNode }) {
  return (
    <div style={{ display: 'flex', flexDirection: 'column' }}>
      <span style={{ color: 'var(--text-muted)', fontSize: '0.75rem' }}>{label}</span>
      {node}
    </div>
  );
}

function IpamContext({
  ctx,
  vrf,
}: {
  ctx: NonNullable<ReturnType<typeof useIpamAddressContext>['data']>;
  vrf: string | null;
}) {
  const s = ctx.matched_subnet;
  if (!s) {
    return (
      <div className="card" style={{ marginTop: '0.5rem' }}>
        <div className="card-body" style={{ padding: '0.5rem 0.75rem' }}>
          <span className="text-muted" style={{ fontSize: '0.82rem' }}>
            No IPAM subnet match
          </span>
        </div>
      </div>
    );
  }
  const pct = s.utilization_pct != null ? Math.round(s.utilization_pct) : null;
  const barColor =
    pct != null
      ? pct >= 90
        ? 'var(--danger)'
        : pct >= 75
          ? 'var(--warning)'
          : 'var(--success)'
      : 'var(--success)';
  return (
    <div className="card" style={{ marginTop: '0.5rem' }}>
      <div
        className="card-body"
        style={{
          padding: '0.5rem 0.75rem',
          display: 'flex',
          alignItems: 'center',
          gap: '0.75rem',
          flexWrap: 'wrap',
        }}
      >
        <span style={{ fontSize: '0.82rem' }}>
          <strong>Subnet:</strong>{' '}
          <code style={{ fontFamily: 'monospace' }}>{s.subnet}</code>
        </span>
        {(s.vrf_name || vrf) && (
          <span
            className="badge"
            style={{ background: 'rgba(99,102,241,0.18)', color: '#a5b4fc' }}
          >
            VRF: {s.vrf_name || vrf}
          </span>
        )}
        {pct != null && (
          <span style={{ fontSize: '0.82rem' }}>
            <strong>Utilization:</strong>{' '}
            <span
              style={{
                display: 'inline-block',
                verticalAlign: 'middle',
                width: 80,
                height: 8,
                background: 'var(--border)',
                borderRadius: 4,
                overflow: 'hidden',
                margin: '0 4px',
              }}
            >
              <span
                style={{
                  display: 'block',
                  height: '100%',
                  width: `${pct}%`,
                  background: barColor,
                  borderRadius: 4,
                }}
              />
            </span>
            {pct}% ({s.used_count ?? '?'}/{s.total_count ?? '?'})
          </span>
        )}
        {ctx.is_conflict && (
          <span
            className="badge badge-danger"
            title={`IP appears in: ${(ctx.conflict_groups || []).join(', ')}`}
          >
            IP Conflict
          </span>
        )}
      </div>
    </div>
  );
}

function OverviewTab({
  cpu,
  mem,
  rt,
  pl,
}: {
  cpu?: MetricQueryResult;
  mem?: MetricQueryResult;
  rt?: MetricQueryResult;
  pl?: MetricQueryResult;
}) {
  const cpuSeries = useMemo(() => extractSeries(cpu, 'CPU %'), [cpu]);
  const memSeries = useMemo(() => extractSeries(mem, 'Memory %'), [mem]);
  const rtSeries = useMemo(() => extractSeries(rt, 'Response Time'), [rt]);
  const plSeries = useMemo(() => extractSeries(pl, 'Packet Loss'), [pl]);

  return (
    <div
      style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fit, minmax(360px, 1fr))',
        gap: '0.75rem',
      }}
    >
      <ChartCard title="CPU %">
        <TimeSeriesChart series={cpuSeries} area yAxisName="%" yMin={0} yMax={100} />
      </ChartCard>
      <ChartCard title="Memory %">
        <TimeSeriesChart series={memSeries} area yAxisName="%" yMin={0} yMax={100} />
      </ChartCard>
      <ChartCard title="Response Time (ms)">
        <TimeSeriesChart series={rtSeries} area yAxisName="ms" />
      </ChartCard>
      <ChartCard title="Packet Loss (%)">
        <TimeSeriesChart series={plSeries} area yAxisName="%" yMin={0} />
      </ChartCard>
    </div>
  );
}

function ChartCard({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="card" style={{ marginBottom: 0 }}>
      <div className="card-title" style={{ fontSize: '0.85rem', padding: '0.5rem 0.75rem' }}>
        {title}
      </div>
      <div style={{ padding: '0.5rem' }}>{children}</div>
    </div>
  );
}

function extractSeries(result: MetricQueryResult | undefined, name: string): TimeSeries[] {
  if (!result) return [{ name, data: [] }];
  const raw = result.data || [];
  return [
    {
      name,
      data: raw.map((d) => ({
        time: d.sampled_at || d.period_start || d.timestamp || '',
        value: d.val_avg ?? d.value ?? 0,
      })),
    },
  ];
}

// ── Tab content ────────────────────────────────────────────────────────────

interface MonitoringAlert {
  id: number;
  created_at: string;
  severity: string;
  metric?: string;
  message?: string;
  acknowledged?: boolean;
}

function AlertsTab({ alerts, loading }: { alerts: MonitoringAlert[]; loading: boolean }) {
  if (loading) return <p className="text-muted">Loading alerts…</p>;
  if (!alerts.length) return <p className="text-muted">No alerts for this device</p>;
  const sevClass = (s: string) =>
    s === 'critical' ? 'danger' : s === 'warning' ? 'warning' : 'info';
  return (
    <table className="chart-table">
      <thead>
        <tr>
          <th>Time</th>
          <th>Severity</th>
          <th>Metric</th>
          <th>Message</th>
          <th>Status</th>
        </tr>
      </thead>
      <tbody>
        {alerts.map((a) => (
          <tr key={a.id}>
            <td>{new Date(a.created_at).toLocaleString()}</td>
            <td>
              <span className={`badge badge-${sevClass(a.severity)}`}>{a.severity}</span>
            </td>
            <td>{a.metric || ''}</td>
            <td>{a.message || ''}</td>
            <td>{a.acknowledged ? 'Ack' : 'Open'}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

interface ComplianceResult {
  profile_name?: string;
  status?: string;
  score?: number | null;
  scanned_at?: string;
}

function ComplianceTab({
  results,
  loading,
}: {
  results: ComplianceResult[];
  loading: boolean;
}) {
  if (loading) return <p className="text-muted">Loading compliance…</p>;
  if (!results.length) return <p className="text-muted">No compliance data for this device</p>;
  return (
    <table className="chart-table">
      <thead>
        <tr>
          <th>Profile</th>
          <th>Status</th>
          <th>Score</th>
          <th>Scanned</th>
        </tr>
      </thead>
      <tbody>
        {results.map((r, i) => {
          const cls =
            r.status === 'pass' ? 'success' : r.status === 'fail' ? 'danger' : 'warning';
          return (
            <tr key={i}>
              <td>{r.profile_name || ''}</td>
              <td>
                <span className={`badge badge-${cls}`}>{r.status || ''}</span>
              </td>
              <td>{r.score != null ? r.score + '%' : 'N/A'}</td>
              <td>{r.scanned_at ? new Date(r.scanned_at).toLocaleString() : 'N/A'}</td>
            </tr>
          );
        })}
      </tbody>
    </table>
  );
}

interface SyslogEvent {
  timestamp?: string;
  severity?: string;
  message?: string;
  event_data?: string;
}

function SyslogTab({ events, loading }: { events: SyslogEvent[]; loading: boolean }) {
  if (loading) return <p className="text-muted">Loading syslog…</p>;
  if (!events.length) return <p className="text-muted">No syslog events for this device</p>;
  return (
    <table className="chart-table">
      <thead>
        <tr>
          <th>Time</th>
          <th>Severity</th>
          <th>Message</th>
        </tr>
      </thead>
      <tbody>
        {events.map((e, i) => {
          const sev = e.severity || '';
          const sevClass = ['emergency', 'alert', 'critical', 'error'].includes(sev)
            ? 'danger'
            : sev === 'warning'
              ? 'warning'
              : 'info';
          return (
            <tr key={i}>
              <td style={{ whiteSpace: 'nowrap' }}>
                {e.timestamp ? new Date(e.timestamp).toLocaleString() : '-'}
              </td>
              <td>
                <span className={`badge badge-${sevClass}`}>{sev || '-'}</span>
              </td>
              <td>{e.message || e.event_data || '-'}</td>
            </tr>
          );
        })}
      </tbody>
    </table>
  );
}
