import { FormEvent, useState } from 'react';

import { Modal } from '@/components/Modal';
import {
  MacEntry,
  useMacHistory,
  useMacSearch,
  useTriggerMacCollection,
} from '@/api/networkTools';

import { formatTimestamp } from './formatting';

export function MacTracking() {
  // Two pieces of state: the live input value, and the value that's been
  // submitted for search. Only the submitted value drives the network
  // request, so partial typing doesn't spam the backend.
  const [draft, setDraft] = useState('');
  const [submitted, setSubmitted] = useState('');
  const [historyMac, setHistoryMac] = useState<string | null>(null);

  const search = useMacSearch(submitted);
  const collect = useTriggerMacCollection();

  const submit = (e?: FormEvent) => {
    e?.preventDefault();
    const trimmed = draft.trim();
    if (!trimmed) return;
    setSubmitted(trimmed);
  };

  return (
    <>
      <div className="page-header">
        <h2>MAC / ARP Tracking</h2>
        <div style={{ display: 'flex', gap: '0.5rem' }}>
          <button
            type="button"
            className="btn btn-primary"
            onClick={() => collect.mutate(undefined)}
            disabled={collect.isPending}
          >
            {collect.isPending ? 'Collecting…' : 'Collect Now'}
          </button>
        </div>
      </div>

      {collect.isSuccess && (
        <div
          className="glass-card card"
          style={{ borderColor: 'var(--success)', marginBottom: '1rem' }}
        >
          <span className="badge badge-success">
            Collected {collect.data.macs_found} MACs, {collect.data.arps_found} ARPs from{' '}
            {collect.data.hosts_collected} host(s)
          </span>
        </div>
      )}
      {collect.isError && (
        <div
          className="glass-card card"
          style={{ borderColor: 'var(--danger)', marginBottom: '1rem' }}
        >
          <strong>MAC collection failed:</strong> {collect.error.message}
        </div>
      )}

      <form onSubmit={submit} className="page-header" style={{ marginTop: 0 }}>
        <input
          id="mac-tracking-search"
          className="form-input list-control-search"
          type="search"
          placeholder="Search by MAC, IP, or port name…"
          value={draft}
          onChange={(e) => setDraft(e.target.value)}
        />
        <button type="submit" className="btn btn-sm btn-primary">
          Search
        </button>
      </form>

      {!submitted && (
        <div className="empty-state">
          <p>
            Search for a MAC address, IP address, or port name to see endpoint
            locations.
          </p>
          <p style={{ fontSize: '0.85em', opacity: 0.7 }}>
            MAC/ARP tables are collected automatically during topology discovery.
          </p>
        </div>
      )}

      {submitted && search.isPending && (
        <div className="skeleton-loader" style={{ height: '200px' }} />
      )}

      {submitted && search.error && (
        <div className="glass-card card" style={{ color: 'var(--danger)' }}>
          Search error: {search.error.message}
        </div>
      )}

      {submitted && search.data && search.data.length === 0 && (
        <div
          className="glass-card card"
          style={{ textAlign: 'center', padding: '2rem', opacity: 0.7 }}
        >
          No results found for &ldquo;{submitted}&rdquo;
        </div>
      )}

      {submitted && search.data && search.data.length > 0 && (
        <div className="glass-card card" style={{ overflowX: 'auto' }}>
          <ResultsTable rows={search.data} onShowHistory={setHistoryMac} />
          <div style={{ marginTop: '0.5rem', fontSize: '0.85em', opacity: 0.6 }}>
            {search.data.length} result{search.data.length === 1 ? '' : 's'}
          </div>
        </div>
      )}

      <Modal
        isOpen={historyMac !== null}
        onClose={() => setHistoryMac(null)}
        title={historyMac ? `MAC History — ${historyMac}` : 'MAC History'}
      >
        <MacHistoryBody macAddress={historyMac} />
      </Modal>
    </>
  );
}

function ResultsTable({
  rows,
  onShowHistory,
}: {
  rows: MacEntry[];
  onShowHistory: (mac: string) => void;
}) {
  return (
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
        {rows.map((r, idx) => (
          <tr key={`${r.mac_address}-${idx}`}>
            <td>
              <code style={{ fontSize: '0.85em' }}>{r.mac_address || '—'}</code>
            </td>
            <td>{r.ip_address || '—'}</td>
            <td>{r.hostname || `host-${r.host_id}`}</td>
            <td>{r.port_name || '—'}</td>
            <td>{r.vlan ?? '—'}</td>
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
              <td>{h.port_name || '—'}</td>
              <td>{h.vlan ?? '—'}</td>
              <td>{h.ip_address || '—'}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
