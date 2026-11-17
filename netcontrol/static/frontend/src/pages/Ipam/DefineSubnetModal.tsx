import { FormEvent, useId, useState } from 'react';

import { Callout } from '@/components/Callout';
import { FieldError } from '@/components/FieldError';
import { Modal } from '@/components/Modal';
import { TenantSelect } from '@/components/TenantSelect';
import { useCreateIpamPrefix } from '@/api/ipam';
import { serverFieldErrors } from '@/lib/serverFieldErrors';

interface Props {
  onClose: () => void;
}

export function DefineSubnetModal({ onClose }: Props) {
  const formId = useId();
  const create = useCreateIpamPrefix();
  const [subnet, setSubnet] = useState('');
  const [description, setDescription] = useState('');
  const [vrf, setVrf] = useState('');
  const [tenantId, setTenantId] = useState<number | null>(null);
  const [subnetError, setSubnetError] = useState<string | null>(null);
  // Messages the server gave for the description and VRF (data validation rules).
  const [serverErrors, setServerErrors] = useState<Record<string, string>>({});
  const [saveError, setSaveError] = useState<string | null>(null);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setSaveError(null);
    if (!subnet.trim()) {
      setSubnetError('Subnet CIDR is required.');
      return;
    }
    try {
      await create.mutateAsync({
        subnet: subnet.trim(),
        description: description.trim(),
        vrf: vrf.trim(),
        tenant_id: tenantId,
      });
      onClose();
    } catch (err) {
      const fields = serverFieldErrors(err);
      if (fields.subnet) setSubnetError(fields.subnet);
      setServerErrors(fields);
      setSaveError((err as Error).message);
    }
  };

  return (
    <Modal
      isOpen
      onClose={onClose}
      title="Define a Subnet"
      footer={
        <>
          <button type="button" className="btn btn-secondary" onClick={onClose}>
            Cancel
          </button>
          <button type="submit" form={formId} className="btn btn-primary" disabled={create.isPending}>
            {create.isPending ? 'Saving…' : 'Add Subnet'}
          </button>
        </>
      }
    >
      <form id={formId} onSubmit={submit}>
        {saveError && <Callout tone="danger">{saveError}</Callout>}
        <div className="form-group">
          <label className="form-label" htmlFor={`${formId}-cidr`}>
            CIDR <span className="text-muted">(e.g. 192.168.10.0/24)</span>
          </label>
          <input
            id={`${formId}-cidr`}
            className="form-input"
            value={subnet}
            onChange={(e) => {
              setSubnet(e.target.value);
              setSubnetError(null);
            }}
            required
            placeholder="10.0.0.0/24"
            aria-invalid={!!subnetError}
          />
          <FieldError>{subnetError}</FieldError>
        </div>
        <div className="form-group">
          <label className="form-label" htmlFor={`${formId}-description`}>
            Description <span className="text-muted">(optional)</span>
          </label>
          <input
            id={`${formId}-description`}
            className="form-input"
            value={description}
            onChange={(e) => {
              setDescription(e.target.value);
              setServerErrors((prev) => ({ ...prev, description: '' }));
            }}
            maxLength={255}
            placeholder="e.g. Server VLAN"
            aria-invalid={!!serverErrors.description}
          />
          <FieldError>{serverErrors.description}</FieldError>
        </div>
        <div className="form-group">
          <label className="form-label" htmlFor={`${formId}-vrf`}>
            VRF <span className="text-muted">(optional)</span>
          </label>
          <input
            id={`${formId}-vrf`}
            className="form-input"
            value={vrf}
            onChange={(e) => {
              setVrf(e.target.value);
              setServerErrors((prev) => ({ ...prev, vrf: '' }));
            }}
            maxLength={120}
            placeholder="global"
            aria-invalid={!!serverErrors.vrf}
          />
          <FieldError>{serverErrors.vrf}</FieldError>
        </div>
        <TenantSelect
          id={`${formId}-tenant`}
          value={tenantId}
          error={serverErrors.tenant_id}
          onChange={(v) => {
            setTenantId(v);
            setServerErrors((prev) => ({ ...prev, tenant_id: '' }));
          }}
        />
      </form>
    </Modal>
  );
}
