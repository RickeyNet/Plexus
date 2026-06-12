import { Fragment, FormEvent, useEffect, useState } from 'react';
import { useQueryClient } from '@tanstack/react-query';

import { Modal } from '@/components/Modal';
import { PageHelp } from '@/components/PageHelp';
import {
  MacEntry,
  MacHostRollup,
  MacMoveEvent,
  useAcknowledgeAllMacMoves,
  useAcknowledgeMacMove,
  useMacCollectionJob,
  useMacHistory,
  useMacMoveEventHistory,
  useMacMoveEvents,
  useMacMoveSummary,
  useMacSearch,
  useMacTrackingByHost,
  useMacTrackingStats,
  useStartFleetMacCollection,
  useTriggerMacCollection,
} from '@/api/networkTools';

import { useShowMore } from '@/lib/useShowMore';

import { formatTimestamp } from './formatting';

type Tab = 'search' | 'moves' | 'hosts';

export function MacTracking() {
  const [tab, setTab] = useState<Tab>('search');
  const [fleetJobId, setFleetJobId] = useState<string | null>(null);
  const startFleet = useStartFleetMacCollection();
  const fleetJob = useMacCollectionJob(fleetJobId);
  const qc = useQueryClient();

  const jobStatus = fleetJob.data?.status;
  const isCollecting = startFleet.isPending || jobStatus === 'running';
  const result = jobStatus && jobStatus !== 'running' ? fleetJob.data?.result : null;

  // Newly-collected entries should appear on the next search once the
  // background job finishes.
  useEffect(() => {
    if (jobStatus && jobStatus !== 'running') {
      qc.invalidateQueries({ queryKey: ['mac-tracking'] });
    }
  }, [jobStatus, qc]);

  return (
    <>
      <div className="page-header">
        <h2>MAC / ARP Tracking</h2>
        <div style={{ display: 'flex', gap: '0.5rem' }}>
          <button
            type="button"
            className="btn btn-primary"
            onClick={() =>
              startFleet.mutate(undefined, {
                onSuccess: (d) => setFleetJobId(d.job_id),
              })
            }
            disabled={isCollecting}
          >
            {isCollecting ? 'Collecting…' : 'Collect Now'}
          </button>
        </div>
      </div>

      <PageHelp
        pageKey="mac-tracking"
        title="MAC & ARP Table Tracking"
        text="Search and browse MAC address and ARP tables collected from network devices. Track where hosts are connected and trace MAC-to-IP mappings across the network. The Moves tab records every time a MAC relocates (switch, port, VLAN or IP binding change) so you can review and acknowledge them like config drift."
      />

      {jobStatus === 'running' && (
        <div className="glass-card card" style={{ marginBottom: '1rem' }}>
          <span className="badge">
            Collecting… {fleetJob.data?.progress.hosts_done ?? 0}/
            {fleetJob.data?.progress.hosts_total ?? '?'} hosts walked
            {' · '}
            {fleetJob.data?.progress.macs_found ?? 0} MACs,{' '}
            {fleetJob.data?.progress.arps_found ?? 0} ARPs so far
          </span>
        </div>
      )}
      {result && (
        <div
          className="glass-card card"
          style={{
            borderColor: result.errors?.length
              ? 'var(--warning)'
              : 'var(--success)',
            marginBottom: '1rem',
          }}
        >
          <span
            className={`badge ${
              result.errors?.length ? 'badge-warning' : 'badge-success'
            }`}
          >
            Collected {result.macs_found} MACs, {result.arps_found} ARPs from{' '}
            {result.hosts_collected} host(s)
          </span>
          {!!result.errors?.length && (
            <details style={{ marginTop: '0.5rem' }}>
              <summary style={{ cursor: 'pointer', fontSize: '0.85em' }}>
                {result.errors.length} diagnostic
                {result.errors.length === 1 ? '' : 's'} — some hosts
                returned partial or no data
              </summary>
              <ul
                style={{
                  margin: '0.35rem 0 0',
                  paddingLeft: '1.25rem',
                  fontSize: '0.85em',
                }}
              >
                {result.errors.map((err, idx) => (
                  <li key={idx} style={{ color: 'var(--warning)' }}>
                    {err}
                  </li>
                ))}
              </ul>
            </details>
          )}
        </div>
      )}
      {(startFleet.isError || jobStatus === 'failed' || fleetJob.isError) && (
        <div
          className="glass-card card"
          style={{ borderColor: 'var(--danger)', marginBottom: '1rem' }}
        >
          <strong>MAC collection failed:</strong>{' '}
          {startFleet.error?.message ??
            fleetJob.data?.error ??
            fleetJob.error?.message ??
            'Unknown error'}
        </div>
      )}

      <div className="tab-controls" style={{ marginBottom: '1rem' }}>
        <button
          type="button"
          className={`btn btn-sm btn-secondary upgrade-tab-btn${tab === 'search' ? ' active' : ''}`}
          onClick={() => setTab('search')}
        >
          Search
        </button>
        <button
          type="button"
          className={`btn btn-sm btn-secondary upgrade-tab-btn${tab === 'moves' ? ' active' : ''}`}
          onClick={() => setTab('moves')}
        >
          Moves
        </button>
        <button
          type="button"
          className={`btn btn-sm btn-secondary upgrade-tab-btn${tab === 'hosts' ? ' active' : ''}`}
          onClick={() => setTab('hosts')}
        >
          By Host
        </button>
      </div>

      {tab === 'search' && <SearchTab />}
      {tab === 'moves' && <MovesTab />}
      {tab === 'hosts' && <HostsTab />}
    </>
  );
}

function SearchTab() {
  // Two pieces of state: the live input value, and the value that's been
  // submitted for search. Only the submitted value drives the network
  // request, so partial typing doesn't spam the backend.
  const [draft, setDraft] = useState('');
  const [submitted, setSubmitted] = useState('');
  const [historyMac, setHistoryMac] = useState<string | null>(null);

  const search = useMacSearch(submitted);
  const stats = useMacTrackingStats();

  const submit = (e?: FormEvent) => {
    e?.preventDefault();
    const trimmed = draft.trim();
    if (!trimmed) return;
    setSubmitted(trimmed);
  };

  const clear = () => {
    setDraft('');
    setSubmitted('');
  };

  return (
    <>
      <div
        style={{
          display: 'flex',
          gap: '0.75rem',
          flexWrap: 'wrap',
          marginBottom: '1rem',
        }}
      >
        <SummaryCard label="Total Entries" value={stats.data?.total_entries} />
        <SummaryCard
          label="Unique MACs"
          value={stats.data?.unique_macs}
          accent="success"
        />
        <SummaryCard
          label="Switches Reporting"
          value={stats.data?.switches_reporting}
        />
        <SummaryCard
          label="Last Collected"
          textValue={formatTimestamp(stats.data?.last_collected_at ?? null) || '-'}
        />
      </div>

      <form
        onSubmit={submit}
        className="page-header"
        style={{
          marginTop: 0,
          alignItems: 'center',
          gap: '0.5rem',
          flexWrap: 'wrap',
        }}
      >
        <input
          id="mac-tracking-search"
          className="form-input list-control-search"
          type="search"
          placeholder="Search by MAC (any format), IP, or port name…"
          value={draft}
          onChange={(e) => setDraft(e.target.value)}
          style={{ flex: '1 1 22rem' }}
        />
        <button type="submit" className="btn btn-sm btn-primary">
          Search
        </button>
        {submitted && (
          <button
            type="button"
            className="btn btn-sm btn-secondary"
            onClick={clear}
          >
            Clear
          </button>
        )}
        <span
          className="badge badge-sm"
          title="Unique MAC addresses tracked across all switches"
          style={{ marginLeft: 'auto' }}
        >
          {stats.data
            ? `${stats.data.unique_macs.toLocaleString()} unique MAC${stats.data.unique_macs === 1 ? '' : 's'} tracked`
            : '…'}
        </span>
      </form>

      {submitted && (
        <div
          style={{
            fontSize: '0.8em',
            opacity: 0.65,
            margin: '-0.5rem 0 0.75rem',
          }}
        >
          Showing matches for &ldquo;{submitted}&rdquo;. MAC formats (with or
          without <code>:</code> <code>-</code> <code>.</code>) all match.
          A missing MAC usually means the host&apos;s switch hasn&apos;t been
          polled yet — try &ldquo;Collect Now&rdquo;.
        </div>
      )}

      {search.isPending && (
        <div className="skeleton-loader" style={{ height: '200px' }} />
      )}

      {search.error && (
        <div className="glass-card card" style={{ color: 'var(--danger)' }}>
          Search error: {search.error.message}
        </div>
      )}

      {search.data && search.data.length === 0 && (
        <div
          className="glass-card card"
          style={{ textAlign: 'center', padding: '2rem', opacity: 0.7 }}
        >
          {submitted ? (
            <>No results found for &ldquo;{submitted}&rdquo;</>
          ) : (
            <>
              No MAC/ARP entries collected yet. Click &ldquo;Collect Now&rdquo;
              to gather them from your SNMP-enabled devices.
            </>
          )}
        </div>
      )}

      {search.data && search.data.length > 0 && (
        <div className="glass-card card" style={{ overflowX: 'auto' }}>
          <ResultsTable rows={search.data} onShowHistory={setHistoryMac} />
          <div style={{ marginTop: '0.5rem', fontSize: '0.85em', opacity: 0.6 }}>
            {search.data.length} result{search.data.length === 1 ? '' : 's'}
            {!submitted && ' (most recently seen)'}
          </div>
        </div>
      )}

      <Modal
        isOpen={historyMac !== null}
        onClose={() => setHistoryMac(null)}
        title={historyMac ? `MAC History - ${historyMac}` : 'MAC History'}
      >
        <MacHistoryBody macAddress={historyMac} />
      </Modal>
    </>
  );
}

function MovesTab() {
  const [statusFilter, setStatusFilter] = useState('open');
  const [hostFilter, setHostFilter] = useState<number | null>(null);
  const [logEvent, setLogEvent] = useState<number | null>(null);

  const summary = useMacMoveSummary();
  // Two queries: `events` is what we display (status + switch filtered).
  // `allForOptions` is status-filtered only - it feeds the switch dropdown so
  // the available switches don't disappear when one is selected.
  const events = useMacMoveEvents(statusFilter, 500, hostFilter);
  const allForOptions = useMacMoveEvents(statusFilter, 500);
  const ack = useAcknowledgeMacMove();
  const ackAll = useAcknowledgeAllMacMoves();

  // Build a stable, de-duplicated switch list from every host that appears on
  // either side of a move. A move is between two switches, so both count.
  const switchOptions = (() => {
    const byId = new Map<number, string>();
    for (const e of allForOptions.data ?? []) {
      if (e.from_host_id != null)
        byId.set(e.from_host_id, e.from_hostname || `host-${e.from_host_id}`);
      if (e.to_host_id != null)
        byId.set(e.to_host_id, e.to_hostname || `host-${e.to_host_id}`);
    }
    return [...byId.entries()].sort((a, b) => a[1].localeCompare(b[1]));
  })();

  return (
    <>
      <div
        style={{
          display: 'flex',
          gap: '0.75rem',
          flexWrap: 'wrap',
          marginBottom: '1rem',
        }}
      >
        <SummaryCard label="Open" value={summary.data?.open} accent="warning" />
        <SummaryCard
          label="Acknowledged"
          value={summary.data?.acknowledged}
          accent="success"
        />
        <SummaryCard label="Total" value={summary.data?.total} />
      </div>

      <div
        className="page-header"
        style={{ marginTop: 0, alignItems: 'center', gap: '0.5rem' }}
      >
        <select
          className="form-input"
          value={statusFilter}
          onChange={(e) => setStatusFilter(e.target.value)}
          style={{ maxWidth: '12rem' }}
        >
          <option value="all">All statuses</option>
          <option value="open">Open</option>
          <option value="acknowledged">Acknowledged</option>
        </select>
        <select
          className="form-input"
          value={hostFilter ?? ''}
          onChange={(e) =>
            setHostFilter(e.target.value ? Number(e.target.value) : null)
          }
          style={{ maxWidth: '16rem' }}
          title="Show moves where this switch is the source or destination"
        >
          <option value="">All switches</option>
          {switchOptions.map(([id, name]) => (
            <option key={id} value={id}>
              {name}
            </option>
          ))}
        </select>
        <button
          type="button"
          className="btn btn-sm"
          onClick={() => ackAll.mutate()}
          disabled={ackAll.isPending || !summary.data?.open}
        >
          {ackAll.isPending ? 'Acknowledging…' : 'Acknowledge all open'}
        </button>
      </div>

      {events.isPending && (
        <div className="skeleton-loader" style={{ height: '200px' }} />
      )}

      {events.error && (
        <div className="glass-card card" style={{ color: 'var(--danger)' }}>
          Failed to load move events: {events.error.message}
        </div>
      )}

      {events.data && events.data.length === 0 && (
        <div
          className="glass-card card"
          style={{ textAlign: 'center', padding: '2rem', opacity: 0.7 }}
        >
          No MAC move events
          {statusFilter !== 'all' ? ` with status "${statusFilter}"` : ''}
          {hostFilter != null ? ' involving the selected switch' : ''}. A move
          is recorded when a MAC changes switch, port, VLAN, or IP binding.
        </div>
      )}

      {events.data && events.data.length > 0 && (
        <div className="glass-card card" style={{ overflowX: 'auto' }}>
          <MoveEventsTable
            rows={events.data}
            onAck={(id) => ack.mutate(id)}
            ackPendingId={ack.isPending ? ack.variables ?? null : null}
            onShowLog={setLogEvent}
          />
          <div style={{ marginTop: '0.5rem', fontSize: '0.85em', opacity: 0.6 }}>
            {events.data.length} event
            {events.data.length === 1 ? '' : 's'}
          </div>
        </div>
      )}

      <Modal
        isOpen={logEvent !== null}
        onClose={() => setLogEvent(null)}
        title="MAC Move Event Log"
        size="large"
      >
        <MoveEventLogBody eventId={logEvent} />
      </Modal>
    </>
  );
}

type CollectAttempt = {
  status: 'running' | 'ok' | 'error';
  macs?: number;
  arps?: number;
  errors?: string[];
  errorMessage?: string;
  ranAt: number;
};

function HostsTab() {
  // Filter state: by default show only hosts that should be returning data
  // but aren't, since that's what the diagnostic is for.
  const [filter, setFilter] = useState<'silent' | 'reporting' | 'all'>('silent');
  const [attempts, setAttempts] = useState<Record<number, CollectAttempt>>({});
  const rollup = useMacTrackingByHost();
  const collect = useTriggerMacCollection();

  const runCollect = async (hostId: number) => {
    setAttempts((prev) => ({
      ...prev,
      [hostId]: { status: 'running', ranAt: Date.now() },
    }));
    try {
      const result = await collect.mutateAsync(hostId);
      setAttempts((prev) => ({
        ...prev,
        [hostId]: {
          status: 'ok',
          macs: result.macs_found,
          arps: result.arps_found,
          errors: result.errors,
          ranAt: Date.now(),
        },
      }));
    } catch (err) {
      setAttempts((prev) => ({
        ...prev,
        [hostId]: {
          status: 'error',
          errorMessage: err instanceof Error ? err.message : String(err),
          ranAt: Date.now(),
        },
      }));
    }
  };

  const rows = rollup.data ?? [];
  const reporting = rows.filter((r) => r.mac_count > 0);
  // A "silent" host is one that *should* be returning data: SNMP is configured
  // for its group, but the FDB walk produced nothing. Hosts without SNMP
  // enabled aren't broken — they're just not in scope, so they don't count.
  const silent = rows.filter((r) => r.snmp_enabled && r.mac_count === 0);
  const noSnmp = rows.filter((r) => !r.snmp_enabled);

  const visible =
    filter === 'silent' ? silent : filter === 'reporting' ? reporting : rows;

  const filterPill = (
    id: 'silent' | 'reporting' | 'all',
    label: string,
    count: number,
    accent?: 'warning' | 'success',
  ) => {
    const isActive = filter === id;
    const tone =
      accent === 'warning'
        ? 'var(--warning)'
        : accent === 'success'
          ? 'var(--success)'
          : 'var(--text)';
    return (
      <button
        key={id}
        type="button"
        className={`btn btn-sm${isActive ? ' btn-primary' : ' btn-secondary'}`}
        onClick={() => setFilter(id)}
        style={isActive ? undefined : { color: tone }}
      >
        {label} ({count})
      </button>
    );
  };

  return (
    <>
      <div
        style={{
          display: 'flex',
          gap: '0.75rem',
          flexWrap: 'wrap',
          marginBottom: '1rem',
        }}
      >
        <SummaryCard
          label="Reporting"
          value={reporting.length}
          accent="success"
        />
        <SummaryCard
          label="Silent (SNMP on, no MACs)"
          value={silent.length}
          accent={silent.length > 0 ? 'warning' : undefined}
        />
        <SummaryCard label="SNMP disabled" value={noSnmp.length} />
        <SummaryCard label="Hosts total" value={rows.length} />
      </div>

      <div
        className="page-header"
        style={{ marginTop: 0, alignItems: 'center', gap: '0.5rem', flexWrap: 'wrap' }}
      >
        {filterPill('silent', 'Silent', silent.length, 'warning')}
        {filterPill('reporting', 'Reporting', reporting.length, 'success')}
        {filterPill('all', 'All hosts', rows.length)}
        <span style={{ marginLeft: 'auto', fontSize: '0.85em', opacity: 0.7 }}>
          {visible.length} host{visible.length === 1 ? '' : 's'} shown
        </span>
      </div>

      {rollup.isPending && (
        <div className="skeleton-loader" style={{ height: '200px' }} />
      )}

      {rollup.error && (
        <div className="glass-card card" style={{ color: 'var(--danger)' }}>
          Failed to load host rollup: {rollup.error.message}
        </div>
      )}

      {rollup.data && visible.length === 0 && (
        <div
          className="glass-card card"
          style={{ textAlign: 'center', padding: '2rem', opacity: 0.7 }}
        >
          {filter === 'silent'
            ? 'No silent hosts — every SNMP-enabled host is returning MAC entries.'
            : filter === 'reporting'
              ? 'No host has returned any MAC entries yet. Try Collect Now.'
              : 'No hosts found.'}
        </div>
      )}

      {rollup.data && visible.length > 0 && (
        <div className="glass-card card" style={{ overflowX: 'auto' }}>
          <HostRollupTable
            rows={visible}
            attempts={attempts}
            onCollect={runCollect}
          />
        </div>
      )}
    </>
  );
}

function HostRollupTable({
  rows,
  attempts,
  onCollect,
}: {
  rows: MacHostRollup[];
  attempts: Record<number, CollectAttempt>;
  onCollect: (hostId: number) => void;
}) {
  return (
    <table className="data-table" style={{ width: '100%' }}>
      <thead>
        <tr>
          <th>Host</th>
          <th>IP</th>
          <th>Group</th>
          <th>SNMP</th>
          <th>MAC rows</th>
          <th>Unique MACs</th>
          <th>ARP rows</th>
          <th>Last MAC seen</th>
          <th />
        </tr>
      </thead>
      <tbody>
        {rows.map((r) => {
          const isSilent = r.snmp_enabled && r.mac_count === 0;
          const attempt = attempts[r.host_id];
          const isRunning = attempt?.status === 'running';
          return (
            <Fragment key={r.host_id}>
              <tr>
                <td>
                  {r.hostname || `host-${r.host_id}`}
                  {isSilent && (
                    <span
                      className="badge badge-sm badge-warning"
                      style={{ marginLeft: '0.5rem' }}
                      title="SNMP is configured for this host's group but the FDB walk returned nothing. Likely causes: not an L2 bridging device, SNMP creds wrong, ACL blocking the poller, or device requires per-VLAN v3 contexts."
                    >
                      silent
                    </span>
                  )}
                </td>
                <td>{r.ip_address}</td>
                <td>{r.group_name || '-'}</td>
                <td>
                  <span
                    className={`badge badge-sm ${
                      r.snmp_enabled ? 'badge-success' : ''
                    }`}
                  >
                    {r.snmp_enabled ? 'enabled' : 'off'}
                  </span>
                </td>
                <td>{r.mac_count.toLocaleString()}</td>
                <td>{r.unique_macs.toLocaleString()}</td>
                <td>{r.arp_count.toLocaleString()}</td>
                <td style={{ fontSize: '0.85em' }}>
                  {formatTimestamp(r.last_mac_seen)}
                </td>
                <td style={{ whiteSpace: 'nowrap' }}>
                  <button
                    type="button"
                    className="btn btn-sm"
                    onClick={() => onCollect(r.host_id)}
                    disabled={!r.snmp_enabled || isRunning}
                    title={
                      r.snmp_enabled
                        ? 'Trigger an immediate MAC/ARP walk against this host'
                        : 'SNMP is not enabled for this host’s group'
                    }
                  >
                    {isRunning ? 'Walking…' : 'Collect'}
                  </button>
                </td>
              </tr>
              {attempt && (
                <tr>
                  <td colSpan={9} style={{ padding: '0.5rem 1rem' }}>
                    <CollectAttemptDetail attempt={attempt} />
                  </td>
                </tr>
              )}
            </Fragment>
          );
        })}
      </tbody>
    </table>
  );
}

function CollectAttemptDetail({ attempt }: { attempt: CollectAttempt }) {
  if (attempt.status === 'running') {
    return (
      <div style={{ fontSize: '0.85em', opacity: 0.75 }}>
        Walking SNMP… (this can take several seconds per OID on a slow device)
      </div>
    );
  }
  if (attempt.status === 'error') {
    return (
      <div
        style={{
          fontSize: '0.85em',
          color: 'var(--danger)',
          padding: '0.5rem',
          border: '1px solid var(--danger)',
          borderRadius: '4px',
        }}
      >
        <strong>Request failed:</strong> {attempt.errorMessage || 'Unknown error'}
      </div>
    );
  }
  const had = (attempt.macs ?? 0) > 0 || (attempt.arps ?? 0) > 0;
  const hasErrors = !!attempt.errors?.length;
  // Result with no rows AND no error rows is the worst-case silent failure —
  // give it a distinct treatment so the user knows the walk completed but
  // produced literally nothing actionable.
  return (
    <div
      style={{
        fontSize: '0.85em',
        padding: '0.5rem',
        border: `1px solid var(--${hasErrors ? 'warning' : had ? 'success' : 'border'})`,
        borderRadius: '4px',
      }}
    >
      <div>
        <strong>Collected:</strong> {attempt.macs ?? 0} MACs,{' '}
        {attempt.arps ?? 0} ARPs
      </div>
      {hasErrors && (
        <ul style={{ margin: '0.35rem 0 0', paddingLeft: '1.25rem' }}>
          {attempt.errors!.map((err, idx) => (
            <li key={idx} style={{ color: 'var(--warning)' }}>
              {err}
            </li>
          ))}
        </ul>
      )}
      {!had && !hasErrors && (
        <div style={{ marginTop: '0.25rem', opacity: 0.7 }}>
          Walk completed but returned nothing. Device may not bridge / may not
          expose the FDB to this credential.
        </div>
      )}
    </div>
  );
}

function SummaryCard({
  label,
  value,
  textValue,
  accent,
}: {
  label: string;
  value?: number | undefined;
  textValue?: string;
  accent?: 'warning' | 'success';
}) {
  const color =
    accent === 'warning'
      ? 'var(--warning)'
      : accent === 'success'
        ? 'var(--success)'
        : 'var(--text)';
  const display =
    textValue !== undefined
      ? textValue
      : value !== undefined
        ? value.toLocaleString()
        : '-';
  // Timestamps need a smaller font so they fit in the tile next to the
  // numeric cards without wrapping awkwardly.
  const fontSize = textValue !== undefined ? '0.95rem' : '1.75rem';
  return (
    <div
      className="glass-card card"
      style={{ minWidth: '8rem', textAlign: 'center', padding: '1rem' }}
    >
      <div style={{ fontSize, fontWeight: 600, color }}>{display}</div>
      <div style={{ fontSize: '0.85em', opacity: 0.7 }}>{label}</div>
    </div>
  );
}

function loc(
  hostname: string | null,
  hostId: number | null,
  port: string,
  vlan: number,
  ip: string,
): string {
  const sw = hostname || (hostId != null ? `host-${hostId}` : '?');
  const parts = [`${sw}:${port || '-'}`, `vlan ${vlan}`];
  if (ip) parts.push(ip);
  return parts.join(' · ');
}

function MoveEventsTable({
  rows,
  onAck,
  ackPendingId,
  onShowLog,
}: {
  rows: MacMoveEvent[];
  onAck: (id: number) => void;
  ackPendingId: number | null;
  onShowLog: (id: number) => void;
}) {
  const { visible, hiddenCount, showMore } = useShowMore(rows);
  return (
    <>
    <table className="data-table" style={{ width: '100%' }}>
      <thead>
        <tr>
          <th>MAC Address</th>
          <th>Changed</th>
          <th>From</th>
          <th>To</th>
          <th>Detected</th>
          <th>Status</th>
          <th />
        </tr>
      </thead>
      <tbody>
        {visible.map((r) => (
          <tr key={r.id}>
            <td>
              <code style={{ fontSize: '0.85em' }}>{r.mac_address}</code>
            </td>
            <td>
              <span className="badge badge-sm">{r.change_kind || '-'}</span>
            </td>
            <td style={{ fontSize: '0.85em' }}>
              {loc(
                r.from_hostname,
                r.from_host_id,
                r.from_port,
                r.from_vlan,
                r.from_ip,
              )}
            </td>
            <td style={{ fontSize: '0.85em' }}>
              {loc(r.to_hostname, r.to_host_id, r.to_port, r.to_vlan, r.to_ip)}
            </td>
            <td style={{ fontSize: '0.85em' }}>
              {formatTimestamp(r.detected_at)}
            </td>
            <td>
              <span
                className={`badge badge-sm ${
                  r.status === 'open' ? 'badge-warning' : 'badge-success'
                }`}
              >
                {r.status}
              </span>
            </td>
            <td style={{ whiteSpace: 'nowrap' }}>
              {r.status === 'open' && (
                <button
                  type="button"
                  className="btn btn-sm"
                  onClick={() => onAck(r.id)}
                  disabled={ackPendingId === r.id}
                >
                  {ackPendingId === r.id ? '…' : 'Acknowledge'}
                </button>
              )}{' '}
              <button
                type="button"
                className="btn btn-sm"
                onClick={() => onShowLog(r.id)}
              >
                Log
              </button>
            </td>
          </tr>
        ))}
      </tbody>
    </table>
    {hiddenCount > 0 && (
      <button
        type="button"
        className="btn btn-sm"
        style={{ marginTop: '0.5rem' }}
        onClick={showMore}
      >
        Show more ({hiddenCount.toLocaleString()} hidden)
      </button>
    )}
    </>
  );
}

function MoveEventLogBody({ eventId }: { eventId: number | null }) {
  const { data, isPending, error } = useMacMoveEventHistory(eventId, 500);

  if (isPending)
    return <div className="skeleton-loader" style={{ height: '120px' }} />;
  if (error)
    return (
      <div style={{ color: 'var(--danger)' }}>
        Failed to load log: {error.message}
      </div>
    );
  if (!data || data.length === 0)
    return <p style={{ opacity: 0.7 }}>No log entries recorded yet.</p>;

  return (
    <div style={{ maxHeight: '60vh', overflow: 'auto' }}>
      {data.map((item) => (
        <div
          key={item.id}
          className="card"
          style={{ marginBottom: '0.5rem', padding: '0.75rem' }}
        >
          <div
            style={{
              display: 'flex',
              justifyContent: 'space-between',
              gap: '0.5rem',
              flexWrap: 'wrap',
            }}
          >
            <strong>{item.action}</strong>
            <span style={{ fontSize: '0.85em', color: 'var(--text-muted)' }}>
              {formatTimestamp(item.created_at) || '-'}
            </span>
          </div>
          <div
            style={{
              marginTop: '0.35rem',
              fontSize: '0.85em',
              color: 'var(--text-muted)',
            }}
          >
            Actor: {item.actor || 'system'} • Status: {item.from_status || '-'}{' '}
            → {item.to_status || '-'}
          </div>
          {item.details && (
            <div style={{ marginTop: '0.35rem', fontSize: '0.85em' }}>
              {item.details}
            </div>
          )}
        </div>
      ))}
    </div>
  );
}

function ResultsTable({
  rows,
  onShowHistory,
}: {
  rows: MacEntry[];
  onShowHistory: (mac: string) => void;
}) {
  const { visible, hiddenCount, showMore } = useShowMore(rows);
  return (
    <>
    <table className="data-table" style={{ width: '100%' }}>
      <thead>
        <tr>
          <th>MAC Address</th>
          <th>IP Address</th>
          <th>Switch</th>
          <th>Port</th>
          <th>VLAN</th>
          <th>Type</th>
          <th>First Seen</th>
          <th>Last Seen</th>
          <th />
        </tr>
      </thead>
      <tbody>
        {visible.map((r, idx) => (
          <tr key={`${r.mac_address}-${idx}`}>
            <td>
              <code style={{ fontSize: '0.85em' }}>{r.mac_address || '-'}</code>
            </td>
            <td>{r.ip_address || '-'}</td>
            <td>{r.hostname || `host-${r.host_id}`}</td>
            <td>{r.port_name || '-'}</td>
            <td>{r.vlan ?? '-'}</td>
            <td>
              <span className="badge badge-sm">{r.entry_type || 'dynamic'}</span>
            </td>
            <td style={{ fontSize: '0.85em' }}>{formatTimestamp(r.first_seen)}</td>
            <td style={{ fontSize: '0.85em' }}>{formatTimestamp(r.last_seen)}</td>
            <td>
              <button
                type="button"
                className="btn btn-sm"
                onClick={() => onShowHistory(r.mac_address)}
              >
                History
              </button>
            </td>
          </tr>
        ))}
      </tbody>
    </table>
    {hiddenCount > 0 && (
      <button
        type="button"
        className="btn btn-sm"
        style={{ marginTop: '0.5rem' }}
        onClick={showMore}
      >
        Show more ({hiddenCount.toLocaleString()} hidden)
      </button>
    )}
    </>
  );
}

function MacHistoryBody({ macAddress }: { macAddress: string | null }) {
  const { data, isPending, error } = useMacHistory(macAddress);

  if (isPending) return <div className="skeleton-loader" style={{ height: '120px' }} />;
  if (error) return <div style={{ color: 'var(--danger)' }}>Failed to load history: {error.message}</div>;
  if (!data || data.length === 0) {
    return <p style={{ opacity: 0.7 }}>No movement history found for this MAC.</p>;
  }

  return (
    <div style={{ maxHeight: '400px', overflowY: 'auto' }}>
      <table className="data-table" style={{ width: '100%' }}>
        <thead>
          <tr>
            <th>Time</th>
            <th>Switch</th>
            <th>Port</th>
            <th>VLAN</th>
            <th>IP</th>
          </tr>
        </thead>
        <tbody>
          {data.map((h, idx) => (
            <tr key={`${h.seen_at}-${idx}`}>
              <td style={{ fontSize: '0.85em' }}>{formatTimestamp(h.seen_at)}</td>
              <td>{h.hostname || `host-${h.host_id}`}</td>
              <td>{h.port_name || '-'}</td>
              <td>{h.vlan ?? '-'}</td>
              <td>{h.ip_address || '-'}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
