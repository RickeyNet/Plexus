import { useId, useMemo, useState } from 'react';

import { DeleteButton } from '@/components/DeleteButton';
import { useDialogs } from '@/components/DialogProvider-context';
import { useDeleteOidProfile, useOidProfiles, type OidProfile } from '@/api/monitoring';
import { LoadingState } from '@/components/LoadingState';
import { QueryError } from '@/components/QueryError';
import { usePendingKeys } from '@/lib/usePendingKeys';

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
  const { confirm, alert } = useDialogs();
  const fid = useId();
  const [vendor, setVendor] = useState('');
  // One unfiltered fetch, filtered here: the vendor list must keep every
  // vendor while one of them is selected.
  const query = useOidProfiles(null);
  const del = useDeleteOidProfile();
  const deleting = usePendingKeys<number>();

  const [modalId, setModalId] = useState<number | null | 'new'>(null);

  const data = query.data;
  const allProfiles: OidProfile[] = useMemo(
    () => (Array.isArray(data) ? data : (data?.profiles ?? [])),
    [data],
  );

  const allVendors = useMemo(() => {
    const set = new Set<string>();
    for (const p of allProfiles) if (p.vendor) set.add(p.vendor);
    return [...set].sort((a, b) => a.localeCompare(b));
  }, [allProfiles]);
  // A vendor whose last profile was deleted or renamed falls back to all vendors.
  const activeVendor = allVendors.includes(vendor) ? vendor : '';
  const profiles = useMemo(
    () => (activeVendor ? allProfiles.filter((p) => p.vendor === activeVendor) : allProfiles),
    [allProfiles, activeVendor],
  );

  async function handleDelete(p: OidProfile) {
    if (!(await confirm({ title: 'Delete OID profile', message: `Delete OID profile "${p.name}"?`, confirmLabel: 'Delete' }))) return;
    await deleting.run(p.id, async () => {
      try {
        await del.mutateAsync(p.id);
      } catch (e) {
        void alert({ message: (e as Error).message, variant: 'error' });
      }
    });
  }

  return (
    <div className="stack">
      <div className="toolbar" style={{ justifyContent: 'space-between', alignItems: 'flex-end' }}>
        <div className="form-group" style={{ marginBottom: 0 }}>
          <label className="form-label" htmlFor={`${fid}-vendor`}>Vendor</label>
          <select id={`${fid}-vendor`} className="form-select" value={activeVendor} onChange={(e) => setVendor(e.target.value)}>
            <option value="">All vendors</option>
            {allVendors.map((v) => <option key={v} value={v}>{v}</option>)}
          </select>
        </div>
        <button className="btn btn-primary" onClick={() => setModalId('new')}>+ New Profile</button>
      </div>

      {query.error && !query.data ? (
        <QueryError what="OID profiles" query={query} />
      ) : (
        query.isPending && <LoadingState />
      )}
      {query.data && (profiles.length === 0 ? (
        <div className="empty-state">
          {activeVendor ? `No custom OID profiles for ${activeVendor}.` : 'No custom OID profiles. Click "+ New Profile" to create one.'}
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
          {profiles.map((p) => {
            let oidCount = 0;
            try { oidCount = JSON.parse(p.oids_json || '[]').length; } catch { /* ignore */ }
            return (
              <div key={p.id} className="card">
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <div>
                    <strong>{p.name}</strong>
                    {p.vendor && <span className="badge badge-info" style={{ marginLeft: '0.5rem' }}>{p.vendor}</span>}
                    {p.device_type && <span className="text-muted" style={{ marginLeft: '0.5rem' }}>{p.device_type}</span>}
                    {p.is_default && <span className="badge badge-success" style={{ marginLeft: '0.5rem' }}>Default</span>}
                  </div>
                  <div style={{ display: 'flex', gap: '0.5rem' }}>
                    <button className="btn btn-sm btn-secondary" onClick={() => setModalId(p.id)}>Edit</button>
                    <DeleteButton busy={deleting.isPending(p.id)} onClick={() => void handleDelete(p)} />
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

      <div className="card">
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
