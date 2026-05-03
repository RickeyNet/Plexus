import { useState, useRef } from 'react';

import { Modal } from '@/components/Modal';
import {
  GeoFloor,
  useCreateGeoFloor,
  useCreateGeoSite,
  useDeleteGeoFloor,
  useUpdateGeoFloor,
  useUploadFloorImage,
} from '@/api/floorPlan';

// ── Add Site ────────────────────────────────────────────────────────────────

export function AddSiteModal({ onClose }: { onClose: () => void }) {
  const [name, setName] = useState('');
  const [address, setAddress] = useState('');
  const [lat, setLat] = useState('');
  const [lng, setLng] = useState('');
  const [err, setErr] = useState<string | null>(null);
  const create = useCreateGeoSite();

  return (
    <Modal isOpen onClose={onClose} title="Add Site">
      <FieldRow label="Name *" htmlFor="geo-site-name">
        <input
          id="geo-site-name"
          className="form-input"
          placeholder="Site name"
          value={name}
          onChange={(e) => setName(e.target.value)}
          autoFocus
        />
      </FieldRow>
      <FieldRow label="Address" htmlFor="geo-site-address">
        <input
          id="geo-site-address"
          className="form-input"
          placeholder="Street address or description"
          value={address}
          onChange={(e) => setAddress(e.target.value)}
        />
      </FieldRow>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.5rem' }}>
        <FieldRow label="Latitude" htmlFor="geo-site-lat">
          <input
            id="geo-site-lat"
            className="form-input"
            type="number"
            step="any"
            placeholder="-90 to 90"
            value={lat}
            onChange={(e) => setLat(e.target.value)}
          />
        </FieldRow>
        <FieldRow label="Longitude" htmlFor="geo-site-lng">
          <input
            id="geo-site-lng"
            className="form-input"
            type="number"
            step="any"
            placeholder="-180 to 180"
            value={lng}
            onChange={(e) => setLng(e.target.value)}
          />
        </FieldRow>
      </div>
      {err && <ErrorBox message={err} />}
      <ModalActions
        onClose={onClose}
        primaryLabel="Create Site"
        primaryDisabled={!name.trim() || create.isPending}
        onPrimary={async () => {
          setErr(null);
          if (!name.trim()) {
            setErr('Site name is required');
            return;
          }
          try {
            await create.mutateAsync({
              name: name.trim(),
              address: address.trim() || undefined,
              lat: lat ? parseFloat(lat) : null,
              lng: lng ? parseFloat(lng) : null,
            });
            onClose();
          } catch (e) {
            setErr(e instanceof Error ? e.message : String(e));
          }
        }}
      />
    </Modal>
  );
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
    <Modal isOpen onClose={onClose} title="Add Floor">
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
    <Modal isOpen onClose={onClose} title="Edit Floor">
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
    <Modal isOpen onClose={onClose} title="Upload Floor Plan Image">
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
    </Modal>
  );
}

// ── Delete Floor confirmation hook ──────────────────────────────────────────

export function useConfirmDeleteFloor() {
  const remove = useDeleteGeoFloor();
  return async (floor: GeoFloor) => {
    if (!confirm(`Delete floor "${floor.name}" and all its device pins?`)) {
      return { confirmed: false as const };
    }
    try {
      await remove.mutateAsync(floor.id);
      return { confirmed: true as const, ok: true as const };
    } catch (e) {
      return {
        confirmed: true as const,
        ok: false as const,
        error: e instanceof Error ? e.message : String(e),
      };
    }
  };
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
  return <div className="error">{message}</div>;
}

function ModalActions({
  onClose,
  primaryLabel,
  primaryDisabled,
  onPrimary,
}: {
  onClose: () => void;
  primaryLabel: string;
  primaryDisabled: boolean;
  onPrimary: () => void;
}) {
  return (
    <div
      style={{
        display: 'flex',
        gap: '0.5rem',
        justifyContent: 'flex-end',
        marginTop: '1rem',
      }}
    >
      <button type="button" className="btn btn-secondary" onClick={onClose}>
        Cancel
      </button>
      <button
        type="button"
        className="btn btn-primary"
        disabled={primaryDisabled}
        onClick={onPrimary}
      >
        {primaryLabel}
      </button>
    </div>
  );
}
