import { FormEvent, useId, useState } from 'react';

import { CustomDataError, toCustomDataError, useSaveObjectData } from '@/api/customData';
import { useHostStatuses } from '@/api/deviceModel';
import { useVlans, useVrfs } from '@/api/networkObjects';
import { Callout } from '@/components/Callout';
import { CustomDataSection } from '@/components/CustomDataSection';
import { FieldError } from '@/components/FieldError';
import { Modal } from '@/components/Modal';
import {
  type InventoryGroupFull,
  type InventoryHost,
  useAddHost,
  useUpdateHost,
  groupLabel,
} from '@/api/inventory';
import {
  changedHostDeviceFields,
  type DeviceIdKey,
  type HostDeviceValues,
  idToSelect,
  initialHostDeviceValues,
  selectToId,
} from '@/lib/deviceModel';
import { DEFAULT_DEVICE_TYPE, DEVICE_TYPES } from '@/lib/deviceTypes';
import { hostNetworkBody } from '@/lib/networkObjects';
import { saveCustomDataDraft, useCustomDataDraft } from '@/lib/useCustomDataDraft';

import { type DeviceFieldErrors, DeviceModelFields } from './DeviceModelFields';
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
  const saveData = useSaveObjectData();
  const draft = useCustomDataDraft('host', isEdit ? { type: 'host', id: host.id } : null);
  // Set once the host itself is saved; a retry after a failed custom-data
  // save then sends only the custom data.
  const [savedId, setSavedId] = useState<number | null>(null);

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
  // Rows of the all-groups listing do not carry the VRF / VLAN: those start
  // empty and are only sent when typed, so an edit never clears them.
  const [vrfName, setVrfName] = useState(host?.vrf_name ?? '');
  const [vlanId, setVlanId] = useState(host?.vlan_id ?? '');
  const vrfsQ = useVrfs();
  const vlansQ = useVlans();
  const [errors, setErrors] = useState<{
    hostname?: string;
    ip?: string;
    awsInstanceId?: string;
    save?: string;
  }>({});
  // Device model values: what the user changed on top of the host's own (a
  // new host starts on the default lifecycle status). Only changed keys are
  // sent, so saving does not lock a value discovery set.
  const statusesQ = useHostStatuses();
  const defaultStatusId = statusesQ.data?.find((s) => s.is_default)?.id ?? null;
  const deviceInitial = initialHostDeviceValues(host, defaultStatusId);
  const [deviceEdits, setDeviceEdits] = useState<Partial<HostDeviceValues>>({});
  const device: HostDeviceValues = { ...deviceInitial, ...deviceEdits };
  const [deviceErrors, setDeviceErrors] = useState<DeviceFieldErrors>({});
  const editDevice = (key: DeviceIdKey | 'location_detail', value: number | string | null) => {
    setDeviceEdits((prev) => ({ ...prev, [key]: value }));
    setDeviceErrors((prev) => ({ ...prev, [key]: undefined }));
  };

  const isPending = add.isPending || update.isPending || saveData.isPending;

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
    const deviceFields = changedHostDeviceFields(deviceInitial, device);
    const network = hostNetworkBody(
      isEdit && host ? { vrf_name: host.vrf_name, vlan_id: host.vlan_id } : null,
      vrfName,
      vlanId,
    );
    const withData = draft.ready && (draft.dirty || (!isEdit && draft.hasData));
    if (withData && Object.keys(draft.checkRequired()).length > 0) return;
    let hostId = savedId;
    try {
      if (hostId !== null) {
        // Saved on an earlier try; only the custom data is left.
      } else if (isEdit && host) {
        await update.mutateAsync({
          hostId: host.id,
          hostname: h,
          ip_address: ip,
          device_type: deviceType,
          group_id: selectedGroupId,
          aws_instance_id: instanceId,
          device: deviceFields,
          network,
        });
        hostId = host.id;
      } else if (groupId != null) {
        const created = await add.mutateAsync({
          groupId,
          hostname: h,
          ip_address: ip,
          device_type: deviceType,
          aws_instance_id: instanceId,
          device: deviceFields,
          network,
        });
        hostId = created.id;
      }
    } catch (err) {
      // A 400 names the device model values the server rejected (an id that no longer exists).
      const failure = toCustomDataError(err);
      if (failure instanceof CustomDataError && Object.keys(failure.fields).length > 0) {
        setDeviceErrors(failure.fields as DeviceFieldErrors);
        setErrors({ save: `The host was not saved: ${failure.message} Fix the marked fields and save again.` });
      } else {
        setErrors({ save: (err as Error).message });
      }
      return;
    }
    if (hostId === null) {
      onClose();
      return;
    }
    setSavedId(hostId);
    if (withData) {
      const failure = await saveCustomDataDraft(saveData, draft, { type: 'host', id: hostId });
      if (failure) {
        setErrors({ save: `The host was saved, but its tags and custom fields were not: ${failure} Fix them and save again.` });
        return;
      }
    }
    onClose();
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
        {/* Once the host is saved only its custom data can still change here. */}
        <fieldset disabled={savedId !== null} className="fieldset-plain">
          <div className="form-group">
            <label className="form-label" htmlFor={`${formId}-hostname`}>Hostname</label>
            <input
              id={`${formId}-hostname`}
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
            <label className="form-label" htmlFor={`${formId}-ip`}>IP Address</label>
            <input
              id={`${formId}-ip`}
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
            <label className="form-label" htmlFor={`${formId}-device-type`}>Platform</label>
            <select
              id={`${formId}-device-type`}
              className="form-select"
              value={deviceType ?? DEFAULT_DEVICE_TYPE}
              onChange={(e) => setDeviceType(e.target.value)}
              aria-describedby={`${formId}-device-type-help`}
            >
              {DEVICE_TYPES.map((t) => (
                <option key={t.value} value={t.value}>
                  {t.label}
                </option>
              ))}
            </select>
            <div className="form-help" id={`${formId}-device-type-help`}>
              The driver Plexus uses to connect to the host.
            </div>
          </div>
          <div className="form-group">
            <label className="form-label" htmlFor={`${formId}-aws-instance`}>AWS instance ID</label>
            <input
              id={`${formId}-aws-instance`}
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
          <div className="form-group">
            <label className="form-label" htmlFor={`${formId}-vrf`}>VRF</label>
            <input
              id={`${formId}-vrf`}
              className="form-input"
              value={vrfName}
              onChange={(e) => setVrfName(e.target.value)}
              list={`${formId}-vrf-options`}
              spellCheck={false}
              autoComplete="off"
              aria-describedby={`${formId}-vrf-help`}
            />
            <datalist id={`${formId}-vrf-options`}>
              {(vrfsQ.data ?? []).map((v) => (
                <option key={v.id} value={v.name} />
              ))}
            </datalist>
            <div className="form-help" id={`${formId}-vrf-help`}>
              Optional. The VRF the host&apos;s address is in; empty is the global VRF.
            </div>
          </div>
          <div className="form-group">
            <label className="form-label" htmlFor={`${formId}-vlan`}>VLAN ID</label>
            <input
              id={`${formId}-vlan`}
              className="form-input"
              value={vlanId}
              onChange={(e) => setVlanId(e.target.value)}
              list={`${formId}-vlan-options`}
              inputMode="numeric"
              autoComplete="off"
            />
            <datalist id={`${formId}-vlan-options`}>
              {(vlansQ.data ?? []).map((v) => (
                <option key={v.id} value={String(v.vid)}>
                  {[v.name, v.site?.name].filter(Boolean).join(' · ')}
                </option>
              ))}
            </datalist>
          </div>
          {isEdit && (
            <div className="form-group">
              <label className="form-label" htmlFor={`${formId}-group`}>Group</label>
              <select
                id={`${formId}-group`}
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
          <section className="custom-data-section">
            <h4 className="custom-data-section-title">Device</h4>
            <DeviceModelFields
              idPrefix={formId}
              ids={{
                device_type_id: idToSelect(device.device_type_id),
                role_id: idToSelect(device.role_id),
                lifecycle_status_id: idToSelect(device.lifecycle_status_id),
                site_id: idToSelect(device.site_id),
              }}
              onIdChange={(key, value) => editDevice(key, selectToId(value))}
              location={device.location_detail}
              onLocationChange={(value) => editDevice('location_detail', value ?? '')}
              errors={deviceErrors}
            />
          </section>
        </fieldset>
        <CustomDataSection objectType="host" draft={draft} canCreateTags />
      </form>
    </Modal>
  );
}
