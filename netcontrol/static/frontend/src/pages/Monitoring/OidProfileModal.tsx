import { useId, useState, type FormEvent } from 'react';

import { Callout } from '@/components/Callout';
import { FieldError } from '@/components/FieldError';
import { LoadingState } from '@/components/LoadingState';
import { Modal } from '@/components/Modal';
import {
  useCreateOidProfile,
  useOidProfile,
  useUpdateOidProfile,
} from '@/api/monitoring';

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
  const [nameError, setNameError] = useState('');
  const [jsonError, setJsonError] = useState('');
  const [saveError, setSaveError] = useState('');
  const formId = useId();

  const [prevMode, setPrevMode] = useState(mode);
  const [prevData, setPrevData] = useState(profileQuery.data);
  if (mode !== prevMode || profileQuery.data !== prevData) {
    setPrevMode(mode);
    setPrevData(profileQuery.data);
    setNameError(''); setJsonError(''); setSaveError('');
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
  }

  function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setSaveError('');
    const nameErr = name.trim() ? '' : 'Profile name is required';
    let jsonErr = '';
    try {
      JSON.parse(oidsJson);
    } catch {
      jsonErr = 'Invalid OID JSON';
    }
    setNameError(nameErr);
    setJsonError(jsonErr);
    if (nameErr || jsonErr) return;
    const data = {
      name: name.trim(),
      vendor: vendor.trim(),
      device_type: deviceType.trim(),
      description: description.trim(),
      oids_json: oidsJson.trim(),
    };
    const onError = (err: unknown) => { setSaveError((err as Error).message); };
    if (mode === 'edit' && profileId != null) {
      updateMut.mutate({ id: profileId, data }, { onSuccess: onClose, onError });
    } else {
      createMut.mutate(data, { onSuccess: onClose, onError });
    }
  }

  const pending = createMut.isPending || updateMut.isPending;

  return (
    <Modal
      isOpen={isOpen}
      onClose={onClose}
      title={mode === 'edit' ? 'Edit OID Profile' : 'New OID Profile'}
      size="medium"
      footer={
        <>
          <button type="button" className="btn btn-secondary" onClick={onClose}>Cancel</button>
          <button
            type="submit"
            form={formId}
            className="btn btn-primary"
            disabled={pending || (mode === 'edit' && profileQuery.isPending)}
          >
            {pending ? 'Saving…' : mode === 'edit' ? 'Save' : 'Create'}
          </button>
        </>
      }
    >
      {mode === 'edit' && profileQuery.isPending ? (
        <LoadingState />
      ) : (
        <form id={formId} onSubmit={handleSubmit}>
          {saveError && <Callout tone="danger">{saveError}</Callout>}
          <div className="form-group">
            <label className="form-label">Name</label>
            <input
              className="form-input"
              value={name}
              onChange={(e) => { setName(e.target.value); setNameError(''); }}
              aria-invalid={!!nameError}
              required
            />
            <FieldError>{nameError}</FieldError>
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
              onChange={(e) => { setOidsJson(e.target.value); setJsonError(''); }}
              aria-invalid={!!jsonError}
              style={{ fontFamily: 'monospace', fontSize: '0.85rem' }}
            />
            <FieldError>{jsonError}</FieldError>
          </div>
        </form>
      )}
    </Modal>
  );
}
