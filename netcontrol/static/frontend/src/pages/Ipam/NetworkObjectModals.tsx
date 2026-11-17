import { useId, useState } from 'react';

import { CustomDataError } from '@/api/customData';
import { useGeoSites } from '@/api/floorPlan';
import { type Vlan, type Vrf, useCreateVlan, useCreateVrf, useUpdateVlan, useUpdateVrf } from '@/api/networkObjects';
import { DescriptionInput, SaveFailure } from '@/components/CatalogueParts';
import { FieldError } from '@/components/FieldError';
import { Modal } from '@/components/Modal';
import { ModalActions } from '@/components/ModalActions';
import { NameInput } from '@/components/NameInput';
import { TenantSelect } from '@/components/TenantSelect';
import { idToSelect, selectToId } from '@/lib/deviceModel';
import { parseVid, VID_MAX, VID_MIN, VLAN_NAME_MAX, VRF_NAME_MAX, VRF_RD_MAX } from '@/lib/networkObjects';
import { runSave } from '@/lib/recordSave';
import { serverFieldErrors } from '@/lib/serverFieldErrors';
import { useNameField } from '@/lib/useNameField';

// ── VRF ────────────────────────────────────────────────────────────────────

/** Creates a VRF, or edits one's route distinguisher and description (the name cannot change). */
export function VrfModal({ vrf, onClose }: { vrf: Vrf | null; onClose: () => void }) {
  const id = useId();
  const create = useCreateVrf();
  const update = useUpdateVrf();
  const name = useNameField(vrf?.name ?? '', VRF_NAME_MAX, 'Name', (n) => `A VRF named "${n}" already exists.`);
  const [rd, setRd] = useState(vrf?.rd ?? '');
  const [description, setDescription] = useState(vrf?.description ?? '');
  const [tenantId, setTenantId] = useState<number | null>(vrf?.tenant_id ?? null);
  const [failure, setFailure] = useState<string | null>(null);
  // Messages the server gave per field (data validation rules).
  const [serverErrors, setServerErrors] = useState<Record<string, string>>({});
  const rdError =
    rd.trim().length > VRF_RD_MAX ? `Route distinguisher must be ${VRF_RD_MAX} characters or fewer.` : serverErrors.rd;

  const submit = () => {
    if (!vrf) {
      name.touch();
      if (name.error) return;
    }
    if (rd.trim().length > VRF_RD_MAX) return;
    setServerErrors({});
    const data = { rd: rd.trim(), description: description.trim(), tenant_id: tenantId };
    void runSave(
      () => (vrf ? update.mutateAsync({ id: vrf.id, data }) : create.mutateAsync({ name: name.trimmed, ...data })),
      vrf ? null : name,
      setFailure,
      onClose,
      (err) => {
        setServerErrors(serverFieldErrors(err));
        return false;
      },
    );
  };

  return (
    <Modal
      isOpen
      onClose={onClose}
      size="small"
      title={vrf ? `Edit VRF ${vrf.name}` : 'Add VRF'}
      footer={
        <ModalActions
          onClose={onClose}
          primaryLabel={vrf ? 'Save VRF' : 'Add VRF'}
          primaryBusy={create.isPending || update.isPending}
          primaryBusyLabel="Saving…"
          onPrimary={submit}
        />
      }
    >
      <SaveFailure what="VRF" message={failure} />
      {vrf ? (
        <div className="form-group">
          <div className="form-label">Name</div>
          <div>{vrf.name}</div>
          <div className="form-help">The name of a VRF cannot change.</div>
        </div>
      ) : (
        <NameInput
          id={id}
          label="Name"
          field={name}
          max={VRF_NAME_MAX}
          help={`Up to ${VRF_NAME_MAX} characters, as devices name it. Names are unique, ignoring case.`}
        />
      )}
      <FieldError>{serverErrors.name}</FieldError>
      <div className="form-group">
        <label className="form-label" htmlFor={`${id}-rd`}>
          Route distinguisher (optional)
        </label>
        <input
          id={`${id}-rd`}
          className="form-input"
          value={rd}
          maxLength={VRF_RD_MAX + 1}
          placeholder="65000:100"
          spellCheck={false}
          autoFocus={vrf !== null}
          aria-invalid={!!rdError}
          aria-describedby={`${id}-rd-error`}
          onChange={(e) => {
            setRd(e.target.value);
            setServerErrors((prev) => ({ ...prev, rd: '' }));
          }}
        />
        <FieldError id={`${id}-rd-error`}>{rdError}</FieldError>
      </div>
      <DescriptionInput
        id={id}
        value={description}
        error={serverErrors.description}
        onChange={(v) => {
          setDescription(v);
          setServerErrors((prev) => ({ ...prev, description: '' }));
        }}
      />
      <TenantSelect
        id={`${id}-tenant`}
        value={tenantId}
        error={serverErrors.tenant_id}
        onChange={(v) => {
          setTenantId(v);
          setServerErrors((prev) => ({ ...prev, tenant_id: '' }));
        }}
      />
    </Modal>
  );
}

// ── VLAN ───────────────────────────────────────────────────────────────────

/** Creates a VLAN, or edits one's name, site and description (the VLAN id cannot change). */
export function VlanModal({ vlan, onClose }: { vlan: Vlan | null; onClose: () => void }) {
  const id = useId();
  const create = useCreateVlan();
  const update = useUpdateVlan();
  const sitesQ = useGeoSites();
  const [vidText, setVidText] = useState(vlan ? String(vlan.vid) : '');
  const [vidTouched, setVidTouched] = useState(false);
  const [name, setName] = useState(vlan?.name ?? '');
  const [siteId, setSiteId] = useState<number | null>(vlan?.site_id ?? null);
  const [description, setDescription] = useState(vlan?.description ?? '');
  const [tenantId, setTenantId] = useState<number | null>(vlan?.tenant_id ?? null);
  const [failure, setFailure] = useState<string | null>(null);
  const [siteError, setSiteError] = useState<string | undefined>();
  // Messages the server gave per field (data validation rules).
  const [serverErrors, setServerErrors] = useState<Record<string, string>>({});

  const vid = vlan ? vlan.vid : parseVid(vidText);
  const vidLocalError = vid === null ? `VLAN ID must be a whole number from ${VID_MIN} to ${VID_MAX}.` : undefined;
  const vidError = vidLocalError ?? serverErrors.vid;
  const nameLocalError =
    name.trim().length > VLAN_NAME_MAX ? `Name must be ${VLAN_NAME_MAX} characters or fewer.` : undefined;
  const nameError = nameLocalError ?? serverErrors.name;

  const submit = async () => {
    setVidTouched(true);
    if (vid === null || nameLocalError) return;
    setFailure(null);
    setSiteError(undefined);
    setServerErrors({});
    const data = { name: name.trim(), site_id: siteId, description: description.trim(), tenant_id: tenantId };
    try {
      if (vlan) await update.mutateAsync({ id: vlan.id, data });
      else await create.mutateAsync({ vid, ...data });
      onClose();
    } catch (err) {
      // An unknown site is a 400 naming the field; a duplicate (site, VLAN ID) a 409 whose message says so;
      // a value a data validation rule refuses a 422 naming its field.
      if (err instanceof CustomDataError && err.fields.site_id) setSiteError(err.fields.site_id);
      else {
        setServerErrors(serverFieldErrors(err));
        setFailure((err as Error).message);
      }
    }
  };

  return (
    <Modal
      isOpen
      onClose={onClose}
      size="small"
      title={vlan ? `Edit VLAN ${vlan.vid}` : 'Add VLAN'}
      footer={
        <ModalActions
          onClose={onClose}
          primaryLabel={vlan ? 'Save VLAN' : 'Add VLAN'}
          primaryBusy={create.isPending || update.isPending}
          primaryBusyLabel="Saving…"
          onPrimary={() => void submit()}
        />
      }
    >
      <SaveFailure what="VLAN" message={failure} />
      {vlan ? (
        <div className="form-group">
          <div className="form-label">VLAN ID</div>
          <div>{vlan.vid}</div>
          <div className="form-help">The VLAN ID cannot change.</div>
        </div>
      ) : (
        <div className="form-group">
          <label className="form-label" htmlFor={`${id}-vid`}>
            VLAN ID
          </label>
          <input
            id={`${id}-vid`}
            className="form-input"
            inputMode="numeric"
            value={vidText}
            autoFocus
            aria-invalid={vidTouched && !!vidError}
            aria-describedby={`${id}-vid-error`}
            onChange={(e) => {
              setVidText(e.target.value);
              setServerErrors((prev) => ({ ...prev, vid: '' }));
            }}
            onBlur={() => setVidTouched(true)}
          />
          <FieldError id={`${id}-vid-error`}>{vidTouched ? vidError : undefined}</FieldError>
        </div>
      )}
      {vlan && <FieldError>{serverErrors.vid}</FieldError>}
      <div className="form-group">
        <label className="form-label" htmlFor={`${id}-name`}>
          Name (optional)
        </label>
        <input
          id={`${id}-name`}
          className="form-input"
          value={name}
          maxLength={VLAN_NAME_MAX + 1}
          autoFocus={vlan !== null}
          aria-invalid={!!nameError}
          aria-describedby={`${id}-name-error`}
          onChange={(e) => {
            setName(e.target.value);
            setServerErrors((prev) => ({ ...prev, name: '' }));
          }}
        />
        <FieldError id={`${id}-name-error`}>{nameError}</FieldError>
      </div>
      <div className="form-group">
        <label className="form-label" htmlFor={`${id}-site`}>
          Site
        </label>
        <select
          id={`${id}-site`}
          className="form-select"
          value={idToSelect(siteId)}
          aria-invalid={!!siteError}
          aria-describedby={`${id}-site-help ${id}-site-error`}
          onChange={(e) => {
            setSiteId(selectToId(e.target.value));
            setSiteError(undefined);
          }}
        >
          <option value="">No site (global)</option>
          {(sitesQ.data ?? []).map((s) => (
            <option key={s.id} value={s.id}>
              {s.name}
            </option>
          ))}
        </select>
        <div className="form-help" id={`${id}-site-help`}>
          A device&apos;s VLAN belongs to the record of its own site when there is one, otherwise to the global one.
        </div>
        <FieldError id={`${id}-site-error`}>{siteError}</FieldError>
      </div>
      <DescriptionInput
        id={id}
        value={description}
        error={serverErrors.description}
        onChange={(v) => {
          setDescription(v);
          setServerErrors((prev) => ({ ...prev, description: '' }));
        }}
      />
      <TenantSelect
        id={`${id}-tenant`}
        value={tenantId}
        error={serverErrors.tenant_id}
        onChange={(v) => {
          setTenantId(v);
          setServerErrors((prev) => ({ ...prev, tenant_id: '' }));
        }}
      />
    </Modal>
  );
}
