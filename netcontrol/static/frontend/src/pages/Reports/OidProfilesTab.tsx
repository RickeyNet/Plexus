import { useMemo, useState } from 'react';

import { useDeleteOidProfile, useOidProfiles, type OidProfile } from '@/api/reports';

import { OidProfileModal } from './OidProfileModal';

const VENDOR_DEFAULTS: { vendor: string; metric: string; oid: string }[] = [
  { vendor: 'Cisco IOS', metric: 'CPU 5min', oid: '1.3.6.1.4.1.9.9.109.1.1.1.1.8' },
  { vendor: 'Cisco IOS', metric: 'Memory Used', oid: '1.3.6.1.4.1.9.9.48.1.1.1.5' },
  { vendor: 'Juniper', metric: 'CPU', oid: '1.3.6.1.4.1.2636.3.1.13.1.8' },
  { vendor: 'Juniper', metric: 'Memory', oid: '1.3.6.1.4.1.2636.3.1.13.1.11' },
  { vendor: 'Arista', metric: 'CPU', oid: '1.3.6.1.2.1.25.3.3.1.2' },
  { vendor: 'Generic', metric: 'sysUpTime', oid: '1.3.6.1.2.1.1.3.0' },
  { vendor: 'Generic', metric: 'ifHCInOctets', oid: '1.3.6.1.2.1.31.1.1.1.6' },
  { vendor: 'Generic', metric: 'ifHCOutOctets', oid: '1.3.6.1.2.1.31.1.1.1.10' },
];

export function OidProfilesTab() {
  const [vendor, setVendor] = useState('');
  const query = useOidProfiles(vendor || null);
  const del = useDeleteOidProfile();

  const [modalId, setModalId] = useState<number | null | 'new'>(null);

  const data = query.data;
  const profiles: OidProfile[] = useMemo(
    () => (Array.isArray(data) ? data : (data?.profiles ?? [])),
    [data],
  );

  const allVendors = useMemo(() => {
    const set = new Set<string>();
    for (const p of profiles) if (p.vendor) set.add(p.vendor);
    return [...set];
  }, [profiles]);

  function handleDelete(id: number) {
    if (!confirm('Delete this OID profile?')) return;
    del.mutate(id, {
      onError: (e) => alert((e as Error).message),
    });
  }

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-end', gap: '0.75rem', marginBottom: '0.75rem' }}>
        <div className="form-group" style={{ marginBottom: 0 }}>
          <label className="form-label">Vendor</label>
          <select className="form-select" value={vendor} onChange={(e) => setVendor(e.target.value)}>
            <option value="">All vendors</option>
            {allVendors.map((v) => <option key={v} value={v}>{v}</option>)}
          </select>
        </div>
        <button className="btn btn-primary" onClick={() => setModalId('new')}>+ New Profile</button>
      </div>

      {query.isPending && <p className="text-muted">Loading…</p>}
      {query.error && <p style={{ color: 'var(--danger)' }}>Failed: {(query.error as Error).message}</p>}
      {query.data && (profiles.length === 0 ? (
        <div className="empty-state">No custom OID profiles. Click "+ New Profile" to create one.</div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
          {profiles.map((p) => {
            let oidCount = 0;
            try { oidCount = JSON.parse(p.oids_json || '[]').length; } catch { /* ignore */ }
            return (
              <div key={p.id} className="card" style={{ padding: '1rem' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <div>
                    <strong>{p.name}</strong>
                    {p.vendor && <span className="badge badge-info" style={{ marginLeft: '0.5rem' }}>{p.vendor}</span>}
                    {p.device_type && <span className="text-muted" style={{ marginLeft: '0.5rem' }}>{p.device_type}</span>}
                    {p.is_default && <span className="badge badge-success" style={{ marginLeft: '0.5rem' }}>Default</span>}
                  </div>
                  <div style={{ display: 'flex', gap: '0.5rem' }}>
                    <button className="btn btn-sm btn-secondary" onClick={() => setModalId(p.id)}>Edit</button>
                    <button className="btn btn-sm btn-danger" onClick={() => handleDelete(p.id)}>Delete</button>
                  </div>
                </div>
                <div className="text-muted" style={{ fontSize: '0.85em', marginTop: '0.25rem' }}>
                  {p.description || ''} · {oidCount} OID mapping{oidCount !== 1 ? 's' : ''}
                </div>
              </div>
            );
          })}
        </div>
      ))}

      <div className="card" style={{ padding: '1rem', marginTop: '1rem' }}>
        <h4 style={{ marginTop: 0 }}>Built-in Vendor OIDs</h4>
        <p className="text-muted" style={{ marginBottom: '0.75rem' }}>These OIDs are polled automatically based on device type detection.</p>
        <table className="data-table">
          <thead><tr><th>Vendor</th><th>Metric</th><th>OID</th></tr></thead>
          <tbody>
            {VENDOR_DEFAULTS.map((d, i) => (
              <tr key={i}>
                <td>{d.vendor}</td>
                <td>{d.metric}</td>
                <td><code>{d.oid}</code></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <OidProfileModal
        mode={modalId === 'new' ? 'create' : modalId != null ? 'edit' : null}
        profileId={typeof modalId === 'number' ? modalId : null}
        onClose={() => setModalId(null)}
      />
    </div>
  );
}
