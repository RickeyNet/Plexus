import { useId, useState, useRef } from 'react';

import { useAuthStatus } from '@/api/auth';
import { Callout } from '@/components/Callout';
import { FieldError } from '@/components/FieldError';
import { Modal } from '@/components/Modal';
import { ModalActions } from '@/components/ModalActions';
import { TenantSelect } from '@/components/TenantSelect';
import {
  GeoFloor,
  useCreateGeoFloor,
  useUpdateGeoFloor,
  useUploadFloorImage,
} from '@/api/floorPlan';
import { SITE_STATUSES, useRegions, useSaveSite } from '@/api/organization';
import { idToSelect, selectToId } from '@/lib/deviceModel';
import { siteStatusLabel, timeZoneOptions, treeOptions } from '@/lib/organization';
import { serverFieldErrors } from '@/lib/serverFieldErrors';
import { canUseFeature } from '@/lib/tabGating';

// ── Add / Edit Site ─────────────────────────────────────────────────────────

/** The fields of a site the dialog edits (an `OrgSite` or a `GeoSiteSummary`). */
export interface EditableSite {
  id: number;
  name: string;
  address?: string | null;
  lat?: number | null;
  lng?: number | null;
  region_id?: number | null;
  status?: string | null;
  facility?: string | null;
  time_zone?: string | null;
  tenant_id?: number | null;
}

/**
 * Creates a site (`site` null) or edits one: name, address, coordinates and
 * its place in the location hierarchy (region, status, facility, time zone)
 * and tenant. Shared by the Floor Plans page and the Organization page.
 */
export function SiteModal({ site, onClose }: { site: EditableSite | null; onClose: () => void }) {
  const id = useId();
  const [name, setName] = useState(site?.name ?? '');
  const [address, setAddress] = useState(site?.address ?? '');
  const [lat, setLat] = useState(site?.lat != null ? String(site.lat) : '');
  const [lng, setLng] = useState(site?.lng != null ? String(site.lng) : '');
  const [regionId, setRegionId] = useState<number | null>(site?.region_id ?? null);
  const [status, setStatus] = useState(site?.status || 'active');
  const [facility, setFacility] = useState(site?.facility ?? '');
  const [timeZone, setTimeZone] = useState(site?.time_zone ?? '');
  const [tenantId, setTenantId] = useState<number | null>(site?.tenant_id ?? null);
  const [err, setErr] = useState<string | null>(null);
  const [fieldErrors, setFieldErrors] = useState<Record<string, string>>({});
  const auth = useAuthStatus().data;
  const regionsQ = useRegions(auth === undefined || canUseFeature('organization', auth));
  const save = useSaveSite();
  const regionChoices = treeOptions(regionsQ.data ?? []);
  const clearError = (key: string) => setFieldErrors((prev) => ({ ...prev, [key]: '' }));

  const submit = async () => {
    setErr(null);
    setFieldErrors({});
    if (!name.trim()) {
      setFieldErrors({ name: 'Site name is required.' });
      return;
    }
    try {
      await save.mutateAsync({
        id: site?.id ?? null,
        data: {
          name: name.trim(),
          address: address.trim(),
          lat: lat ? parseFloat(lat) : null,
          lng: lng ? parseFloat(lng) : null,
          region_id: regionId,
          status,
          facility: facility.trim(),
          time_zone: timeZone.trim(),
          tenant_id: tenantId,
        },
      });
      onClose();
    } catch (e) {
      const fields = serverFieldErrors(e);
      setFieldErrors(fields);
      if (Object.keys(fields).length === 0) setErr(e instanceof Error ? e.message : String(e));
    }
  };

  return (
    <Modal
      isOpen
      onClose={onClose}
      title={site ? `Edit site ${site.name}` : 'Add Site'}
      footer={
        <ModalActions
          onClose={onClose}
          primaryLabel={site ? 'Save Site' : 'Create Site'}
          primaryDisabled={!name.trim() || save.isPending}
          onPrimary={() => void submit()}
        />
      }
    >
      <FieldRow label="Name *" htmlFor={`${id}-name`}>
        <input
          id={`${id}-name`}
          className="form-input"
          placeholder="Site name"
          value={name}
          aria-invalid={!!fieldErrors.name}
          onChange={(e) => {
            setName(e.target.value);
            clearError('name');
          }}
          autoFocus
        />
        <FieldError>{fieldErrors.name}</FieldError>
      </FieldRow>
      <FieldRow label="Address" htmlFor={`${id}-address`}>
        <input
          id={`${id}-address`}
          className="form-input"
          placeholder="Street address or description"
          value={address}
          onChange={(e) => setAddress(e.target.value)}
        />
      </FieldRow>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.5rem' }}>
        <FieldRow label="Latitude" htmlFor={`${id}-lat`}>
          <input
            id={`${id}-lat`}
            className="form-input"
            type="number"
            step="any"
            placeholder="-90 to 90"
            value={lat}
            onChange={(e) => setLat(e.target.value)}
          />
        </FieldRow>
        <FieldRow label="Longitude" htmlFor={`${id}-lng`}>
          <input
            id={`${id}-lng`}
            className="form-input"
            type="number"
            step="any"
            placeholder="-180 to 180"
            value={lng}
            onChange={(e) => setLng(e.target.value)}
          />
        </FieldRow>
      </div>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.5rem' }}>
        <FieldRow label="Region" htmlFor={`${id}-region`}>
          <select
            id={`${id}-region`}
            className="form-select"
            value={idToSelect(regionId)}
            aria-invalid={!!fieldErrors.region_id}
            onChange={(e) => {
              setRegionId(selectToId(e.target.value));
              clearError('region_id');
            }}
          >
            <option value="">No region</option>
            {regionChoices.map((o) => (
              <option key={o.value} value={o.value}>
                {o.label}
              </option>
            ))}
          </select>
          <FieldError>{fieldErrors.region_id}</FieldError>
        </FieldRow>
        <FieldRow label="Status" htmlFor={`${id}-status`}>
          <select
            id={`${id}-status`}
            className="form-select"
            value={status}
            aria-invalid={!!fieldErrors.status}
            onChange={(e) => {
              setStatus(e.target.value);
              clearError('status');
            }}
          >
            {SITE_STATUSES.map((s) => (
              <option key={s} value={s}>
                {siteStatusLabel(s)}
              </option>
            ))}
          </select>
          <FieldError>{fieldErrors.status}</FieldError>
        </FieldRow>
      </div>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.5rem' }}>
        <FieldRow label="Facility" htmlFor={`${id}-facility`}>
          <input
            id={`${id}-facility`}
            className="form-input"
            placeholder="Data center or building"
            value={facility}
            maxLength={100}
            aria-invalid={!!fieldErrors.facility}
            onChange={(e) => {
              setFacility(e.target.value);
              clearError('facility');
            }}
          />
          <FieldError>{fieldErrors.facility}</FieldError>
        </FieldRow>
        <FieldRow label="Time zone" htmlFor={`${id}-tz`}>
          <input
            id={`${id}-tz`}
            className="form-input"
            placeholder="Europe/Amsterdam"
            list={`${id}-tz-list`}
            value={timeZone}
            maxLength={64}
            spellCheck={false}
            aria-invalid={!!fieldErrors.time_zone}
            onChange={(e) => {
              setTimeZone(e.target.value);
              clearError('time_zone');
            }}
          />
          <datalist id={`${id}-tz-list`}>
            {timeZoneOptions().map((z) => (
              <option key={z} value={z} />
            ))}
          </datalist>
          <FieldError>{fieldErrors.time_zone}</FieldError>
        </FieldRow>
      </div>
      <TenantSelect
        id={`${id}-tenant`}
        value={tenantId}
        error={fieldErrors.tenant_id}
        onChange={(v) => {
          setTenantId(v);
          clearError('tenant_id');
        }}
      />
      {err && <ErrorBox message={err} />}
    </Modal>
  );
}

export function AddSiteModal({ onClose }: { onClose: () => void }) {
  return <SiteModal site={null} onClose={onClose} />;
}

// ── Add Floor ───────────────────────────────────────────────────────────────

export function AddFloorModal({
  siteId,
  onClose,
}: {
  siteId: number;
  onClose: () => void;
}) {
  const [name, setName] = useState('');
  const [floorNumber, setFloorNumber] = useState('0');
  const [err, setErr] = useState<string | null>(null);
  const create = useCreateGeoFloor(siteId);

  return (
    <Modal
      isOpen
      onClose={onClose}
      title="Add Floor"
      size="small"
      footer={
        <ModalActions
          onClose={onClose}
          primaryLabel="Add Floor"
          primaryDisabled={!name.trim() || create.isPending}
          onPrimary={async () => {
            setErr(null);
            if (!name.trim()) {
              setErr('Floor name is required');
              return;
            }
            try {
              await create.mutateAsync({
                name: name.trim(),
                floor_number: parseInt(floorNumber, 10) || 0,
              });
              onClose();
            } catch (e) {
              setErr(e instanceof Error ? e.message : String(e));
            }
          }}
        />
      }
    >
      <FieldRow label="Floor Name *" htmlFor="geo-floor-name">
        <input
          id="geo-floor-name"
          className="form-input"
          placeholder="e.g. Building A – Floor 2"
          value={name}
          onChange={(e) => setName(e.target.value)}
          autoFocus
        />
      </FieldRow>
      <FieldRow label="Floor Number" htmlFor="geo-floor-number">
        <input
          id="geo-floor-number"
          className="form-input"
          type="number"
          placeholder="0"
          value={floorNumber}
          onChange={(e) => setFloorNumber(e.target.value)}
        />
      </FieldRow>
      {err && <ErrorBox message={err} />}
    </Modal>
  );
}

// ── Edit Floor ──────────────────────────────────────────────────────────────

export function EditFloorModal({
  floor,
  onClose,
}: {
  floor: GeoFloor;
  onClose: () => void;
}) {
  const [name, setName] = useState(floor.name);
  const [floorNumber, setFloorNumber] = useState(String(floor.floor_number ?? 0));
  const [err, setErr] = useState<string | null>(null);
  const update = useUpdateGeoFloor();

  return (
    <Modal
      isOpen
      onClose={onClose}
      title="Edit Floor"
      size="small"
      footer={
        <ModalActions
          onClose={onClose}
          primaryLabel="Save"
          primaryDisabled={!name.trim() || update.isPending}
          onPrimary={async () => {
            setErr(null);
            if (!name.trim()) {
              setErr('Floor name is required');
              return;
            }
            try {
              await update.mutateAsync({
                floorId: floor.id,
                body: {
                  name: name.trim(),
                  floor_number: parseInt(floorNumber, 10) || 0,
                },
              });
              onClose();
            } catch (e) {
              setErr(e instanceof Error ? e.message : String(e));
            }
          }}
        />
      }
    >
      <FieldRow label="Floor Name *" htmlFor="geo-edit-floor-name">
        <input
          id="geo-edit-floor-name"
          className="form-input"
          value={name}
          onChange={(e) => setName(e.target.value)}
          autoFocus
        />
      </FieldRow>
      <FieldRow label="Floor Number" htmlFor="geo-edit-floor-number">
        <input
          id="geo-edit-floor-number"
          className="form-input"
          type="number"
          value={floorNumber}
          onChange={(e) => setFloorNumber(e.target.value)}
        />
      </FieldRow>
      {err && <ErrorBox message={err} />}
    </Modal>
  );
}

// ── Upload Image ────────────────────────────────────────────────────────────

export function UploadImageModal({
  floorId,
  onClose,
}: {
  floorId: number;
  onClose: () => void;
}) {
  const fileRef = useRef<HTMLInputElement>(null);
  const [err, setErr] = useState<string | null>(null);
  const upload = useUploadFloorImage();

  return (
    <Modal
      isOpen
      onClose={onClose}
      title="Upload Floor Plan Image"
      size="small"
      footer={
        <ModalActions
          onClose={onClose}
          primaryLabel="Upload"
          primaryDisabled={upload.isPending}
          onPrimary={async () => {
            setErr(null);
            const file = fileRef.current?.files?.[0];
            if (!file) {
              setErr('Please select an image file');
              return;
            }
            try {
              await upload.mutateAsync({ floorId, file });
              onClose();
            } catch (e) {
              setErr(e instanceof Error ? e.message : String(e));
            }
          }}
        />
      }
    >
      <p style={{ fontSize: '0.85rem', color: 'var(--text-muted)', marginBottom: '0.75rem' }}>
        Upload a JPEG, PNG, GIF, WebP, or SVG image of the floor plan. Max 20 MB.
      </p>
      <FieldRow label="Image file" htmlFor="geo-image-file">
        <input
          id="geo-image-file"
          ref={fileRef}
          type="file"
          className="form-input"
          accept="image/jpeg,image/png,image/gif,image/webp,image/svg+xml"
        />
      </FieldRow>
      {err && <ErrorBox message={err} />}
    </Modal>
  );
}

// ── Shared building blocks ──────────────────────────────────────────────────

function FieldRow({
  label,
  htmlFor,
  children,
}: {
  label: string;
  htmlFor: string;
  children: React.ReactNode;
}) {
  return (
    <div className="form-group">
      <label className="form-label" htmlFor={htmlFor}>{label}</label>
      {children}
    </div>
  );
}

function ErrorBox({ message }: { message: string }) {
  return <Callout tone="danger">{message}</Callout>;
}
