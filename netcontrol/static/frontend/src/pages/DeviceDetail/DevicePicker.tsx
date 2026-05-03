import { useMemo, useState } from 'react';
import { Link } from 'react-router-dom';

import { useMonitoringPolls } from '@/api/deviceDetail';

/**
 * Listing of recently-polled devices. Click a row to open the device-detail
 * page. This is the React replacement entry point for the legacy "monitoring"
 * page when you're navigating directly to a single device.
 */
export function DevicePicker() {
  const { data, isLoading, isError, error } = useMonitoringPolls(200);
  const [filter, setFilter] = useState('');

  const polls = data?.polls || [];
  const filtered = useMemo(() => {
    if (!filter.trim()) return polls;
    const q = filter.toLowerCase();
    return polls.filter(
      (p) =>
        (p.hostname || '').toLowerCase().includes(q) ||
        (p.ip_address || '').toLowerCase().includes(q),
    );
  }, [polls, filter]);

  return (
    <div>
      <div className="page-header">
        <h2 style={{ margin: 0 }}>Devices</h2>
      </div>

      <div className="card" style={{ marginBottom: '0.75rem' }}>
        <div className="card-body" style={{ padding: '0.75rem' }}>
          <input
            className="form-input"
            placeholder="Filter by hostname or IP…"
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            style={{ maxWidth: 320 }}
          />
        </div>
      </div>

      {isLoading && <p className="text-muted">Loading devices…</p>}
      {isError && (
        <div className="error">
          Failed to load devices: {error instanceof Error ? error.message : String(error)}
        </div>
      )}
      {!isLoading && !isError && filtered.length === 0 && (
        <p className="text-muted">No devices match.</p>
      )}

      {filtered.length > 0 && (
        <div className="card">
          <div className="card-body" style={{ padding: 0 }}>
            <table className="chart-table" style={{ width: '100%' }}>
              <thead>
                <tr>
                  <th>Hostname</th>
                  <th>IP</th>
                  <th>Type</th>
                  <th>CPU %</th>
                  <th>Mem %</th>
                  <th>Last Poll</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((p) => {
                  const id = (p as { host_id?: number }).host_id;
                  if (id == null) return null;
                  return (
                    <tr key={id}>
                      <td>
                        <Link to={`/devices/${id}`}>{p.hostname || `Device #${id}`}</Link>
                      </td>
                      <td>{p.ip_address || '-'}</td>
                      <td>{p.device_type || '-'}</td>
                      <td>
                        {p.cpu_percent != null ? p.cpu_percent.toFixed(1) + '%' : '-'}
                      </td>
                      <td>
                        {p.memory_percent != null
                          ? p.memory_percent.toFixed(1) + '%'
                          : '-'}
                      </td>
                      <td>
                        {p.polled_at ? new Date(p.polled_at).toLocaleString() : '-'}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
