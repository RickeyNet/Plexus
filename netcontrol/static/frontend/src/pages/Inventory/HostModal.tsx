import { FormEvent, useId, useState } from 'react';

import { Callout } from '@/components/Callout';
import { FieldError } from '@/components/FieldError';
import { Modal } from '@/components/Modal';
import {
  type InventoryGroupFull,
  type InventoryHost,
  useAddHost,
  useUpdateHost,
  groupLabel,
} from '@/api/inventory';
import { DEFAULT_DEVICE_TYPE, DEVICE_TYPES } from '@/lib/deviceTypes';

import { isAwsInstanceId } from './helpers';

interface Props {
  /** When set, edit mode. When null, create mode (groupId required). */
  host: (InventoryHost & { group_id: number }) | null;
  groupId: number | null;
  groups: InventoryGroupFull[];
  onClose: () => void;
}

export function HostModal({ host, groupId, groups, onClose }: Props) {
  const formId = useId();
  const isEdit = host != null;
  const add = useAddHost();
  const update = useUpdateHost();

  const [hostname, setHostname] = useState(host?.hostname ?? '');
  const [ipAddress, setIpAddress] = useState(host?.ip_address ?? '');
  const [deviceType, setDeviceType] = useState(
    host?.device_type ?? DEFAULT_DEVICE_TYPE,
  );
  const [selectedGroupId, setSelectedGroupId] = useState<number>(
    host?.group_id ?? groupId ?? groups[0]?.id ?? 0,
  );
  const [awsInstanceId, setAwsInstanceId] = useState(
    host?.aws_instance_id ?? '',
  );
  const [errors, setErrors] = useState<{
    hostname?: string;
    ip?: string;
    awsInstanceId?: string;
    save?: string;
  }>({});

  const isPending = add.isPending || update.isPending;

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    const h = hostname.trim();
    const ip = ipAddress.trim();
    const instanceId = awsInstanceId.trim();
    const next: typeof errors = {};
    if (!h) next.hostname = 'Hostname is required.';
    if (!ip) next.ip = 'IP address is required.';
    if (instanceId && !isAwsInstanceId(instanceId)) {
      next.awsInstanceId = 'AWS instance ID must look like i-0123456789abcdef0.';
    }
    setErrors(next);
    if (next.hostname || next.ip || next.awsInstanceId) return;
    try {
      if (isEdit && host) {
        await update.mutateAsync({
          hostId: host.id,
          hostname: h,
          ip_address: ip,
          device_type: deviceType,
          group_id: selectedGroupId,
          aws_instance_id: instanceId,
        });
      } else if (groupId != null) {
        await add.mutateAsync({
          groupId,
          hostname: h,
          ip_address: ip,
          device_type: deviceType,
          aws_instance_id: instanceId,
        });
      }
      onClose();
    } catch (err) {
      setErrors({ save: (err as Error).message });
    }
  };

  return (
    <Modal
      isOpen
      onClose={onClose}
      title={isEdit ? 'Edit Host' : 'Add Host'}
      footer={
        <>
          <button type="button" className="btn btn-secondary" onClick={onClose}>
            Cancel
          </button>
          <button type="submit" form={formId} className="btn btn-primary" disabled={isPending}>
            {isPending ? 'Saving…' : isEdit ? 'Save' : 'Add Host'}
          </button>
        </>
      }
    >
      <form id={formId} onSubmit={submit}>
        {errors.save && <Callout tone="danger">{errors.save}</Callout>}
        <div className="form-group">
          <label className="form-label">Hostname</label>
          <input
            className="form-input"
            value={hostname}
            onChange={(e) => {
              setHostname(e.target.value);
              setErrors((prev) => ({ ...prev, hostname: undefined }));
            }}
            required
            autoFocus
            aria-invalid={!!errors.hostname}
          />
          <FieldError>{errors.hostname}</FieldError>
        </div>
        <div className="form-group">
          <label className="form-label">IP Address</label>
          <input
            className="form-input"
            value={ipAddress}
            onChange={(e) => {
              setIpAddress(e.target.value);
              setErrors((prev) => ({ ...prev, ip: undefined }));
            }}
            required
            aria-invalid={!!errors.ip}
          />
          <FieldError>{errors.ip}</FieldError>
        </div>
        <div className="form-group">
          <label className="form-label">Device Type</label>
          <select
            className="form-select"
            value={deviceType ?? DEFAULT_DEVICE_TYPE}
            onChange={(e) => setDeviceType(e.target.value)}
          >
            {DEVICE_TYPES.map((t) => (
              <option key={t.value} value={t.value}>
                {t.label}
              </option>
            ))}
          </select>
        </div>
        <div className="form-group">
          <label className="form-label">AWS instance ID</label>
          <input
            className="form-input"
            value={awsInstanceId}
            onChange={(e) => {
              setAwsInstanceId(e.target.value);
              setErrors((prev) => ({ ...prev, awsInstanceId: undefined }));
            }}
            placeholder="i-0123456789abcdef0"
            spellCheck={false}
            autoComplete="off"
            aria-invalid={!!errors.awsInstanceId}
          />
          <FieldError>{errors.awsInstanceId}</FieldError>
          <div
            className="text-muted"
            style={{ fontSize: '0.78rem', marginTop: '0.25rem' }}
          >
            Optional. Pins this host to an EC2 instance on the Topology map
            when its IP is not one of the instance&apos;s addresses.
          </div>
        </div>
        {isEdit && (
          <div className="form-group">
            <label className="form-label">Group</label>
            <select
              className="form-select"
              value={String(selectedGroupId)}
              onChange={(e) => setSelectedGroupId(Number(e.target.value))}
            >
              {groups.map((g) => (
                <option key={g.id} value={g.id}>
                  {groupLabel(g)}
                </option>
              ))}
            </select>
          </div>
        )}
      </form>
    </Modal>
  );
}
