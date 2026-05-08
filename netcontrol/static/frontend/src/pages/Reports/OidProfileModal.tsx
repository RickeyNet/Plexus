import { useEffect, useState, type FormEvent } from 'react';

import { Modal } from '@/components/Modal';
import {
  useCreateOidProfile,
  useOidProfile,
  useUpdateOidProfile,
} from '@/api/reports';

interface Props {
  mode: 'create' | 'edit' | null;
  profileId: number | null;
  onClose: () => void;
}

const DEFAULT_OIDS = '[\n  {"oid": "", "metric_name": "", "label": "", "type": "gauge"}\n]';

export function OidProfileModal({ mode, profileId, onClose }: Props) {
  const isOpen = mode != null;
  const profileQuery = useOidProfile(mode === 'edit' ? profileId : null);
  const createMut = useCreateOidProfile();
  const updateMut = useUpdateOidProfile();

  const [name, setName] = useState('');
  const [vendor, setVendor] = useState('');
  const [deviceType, setDeviceType] = useState('');
  const [description, setDescription] = useState('');
  const [oidsJson, setOidsJson] = useState(DEFAULT_OIDS);

  useEffect(() => {
    if (mode === 'create') {
      setName(''); setVendor(''); setDeviceType(''); setDescription(''); setOidsJson(DEFAULT_OIDS);
    } else if (mode === 'edit' && profileQuery.data) {
      const p = profileQuery.data;
      setName(p.name ?? '');
      setVendor(p.vendor ?? '');
      setDeviceType(p.device_type ?? '');
      setDescription(p.description ?? '');
      setOidsJson(p.oids_json ?? '[]');
    }
  }, [mode, profileQuery.data]);

  function handleSubmit(e: FormEvent) {
    e.preventDefault();
    if (!name.trim()) {
      alert('Profile name is required');
      return;
    }
    try {
      JSON.parse(oidsJson);
    } catch {
      alert('Invalid OID JSON');
      return;
    }
    const data = {
      name: name.trim(),
      vendor: vendor.trim(),
      device_type: deviceType.trim(),
      description: description.trim(),
      oids_json: oidsJson.trim(),
    };
    const onError = (err: unknown) => alert((err as Error).message);
    if (mode === 'edit' && profileId != null) {
      updateMut.mutate({ id: profileId, data }, { onSuccess: onClose, onError });
    } else {
      createMut.mutate(data, { onSuccess: onClose, onError });
    }
  }

  const pending = createMut.isPending || updateMut.isPending;

  return (
    <Modal isOpen={isOpen} onClose={onClose} title={mode === 'edit' ? 'Edit OID Profile' : 'New OID Profile'} size="large">
      {mode === 'edit' && profileQuery.isPending ? (
        <p className="text-muted">Loading…</p>
      ) : (
        <form onSubmit={handleSubmit}>
          <div className="form-group">
            <label className="form-label">Name</label>
            <input className="form-input" value={name} onChange={(e) => setName(e.target.value)} required />
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.75rem' }}>
            <div className="form-group">
              <label className="form-label">Vendor</label>
              <input className="form-input" value={vendor} onChange={(e) => setVendor(e.target.value)} />
            </div>
            <div className="form-group">
              <label className="form-label">Device Type</label>
              <input className="form-input" value={deviceType} onChange={(e) => setDeviceType(e.target.value)} />
            </div>
          </div>
          <div className="form-group">
            <label className="form-label">Description</label>
            <input className="form-input" value={description} onChange={(e) => setDescription(e.target.value)} />
          </div>
          <div className="form-group">
            <label className="form-label">OID Mappings (JSON)</label>
            <textarea
              className="form-textarea"
              rows={10}
              value={oidsJson}
              onChange={(e) => setOidsJson(e.target.value)}
              style={{ fontFamily: 'monospace', fontSize: '0.85rem' }}
            />
          </div>
          <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.5rem', marginTop: '0.5rem' }}>
            <button type="button" className="btn btn-secondary" onClick={onClose}>Cancel</button>
            <button type="submit" className="btn btn-primary" disabled={pending}>
              {pending ? 'Saving…' : mode === 'edit' ? 'Save' : 'Create'}
            </button>
          </div>
        </form>
      )}
    </Modal>
  );
}
