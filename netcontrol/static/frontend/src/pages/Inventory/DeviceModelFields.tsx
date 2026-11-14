import type { ReactNode } from 'react';

import { useDeviceRoles, useDeviceTypes, useHostStatuses } from '@/api/deviceModel';
import { useGeoSites } from '@/api/floorPlan';
import { FieldError } from '@/components/FieldError';
import { QueryError } from '@/components/QueryError';
import { type DeviceIdKey, deviceTypeOptionGroups, KEEP, LOCATION_DETAIL_MAX } from '@/lib/deviceModel';

export type DeviceFieldErrors = Partial<Record<DeviceIdKey | 'location_detail', string>>;

export interface DeviceModelFieldsProps {
  /** Prefix for the control ids (a `useId()` value). */
  idPrefix: string;
  /** Each select's value: '' for none, the id as text, or `KEEP` with `allowKeep`. */
  ids: Record<DeviceIdKey, string>;
  onIdChange: (key: DeviceIdKey, value: string) => void;
  /** The rack / room text; null means "leave unchanged" (only with `allowKeep`). */
  location: string | null;
  onLocationChange: (value: string | null) => void;
  /** Bulk edit: every control starts at "Leave unchanged". */
  allowKeep?: boolean;
  errors?: DeviceFieldErrors;
}

/**
 * The device type, role, lifecycle status, site and rack / room controls of
 * the host dialog and the bulk edit dialog. Device types are grouped by
 * manufacturer; each select has a "None" choice that clears the value.
 */
export function DeviceModelFields({
  idPrefix,
  ids,
  onIdChange,
  location,
  onLocationChange,
  allowKeep = false,
  errors = {},
}: DeviceModelFieldsProps) {
  const typesQ = useDeviceTypes();
  const rolesQ = useDeviceRoles();
  const statusesQ = useHostStatuses();
  const sitesQ = useGeoSites();

  const failed = [
    { what: 'device types', query: typesQ },
    { what: 'device roles', query: rolesQ },
    { what: 'lifecycle statuses', query: statusesQ },
    { what: 'sites', query: sitesQ },
  ].filter((f) => f.query.isError && !f.query.data);

  const fixedOptions = (
    <>
      {allowKeep && <option value={KEEP}>Leave unchanged</option>}
      <option value="">None</option>
    </>
  );

  const select = (key: DeviceIdKey, label: string, options: ReactNode, help?: string) => {
    const id = `${idPrefix}-${key}`;
    return (
      <div className="form-group">
        <label className="form-label" htmlFor={id}>
          {label}
        </label>
        <select
          id={id}
          className="form-select"
          value={ids[key]}
          onChange={(e) => onIdChange(key, e.target.value)}
          aria-invalid={!!errors[key]}
          aria-describedby={help ? `${id}-help` : undefined}
        >
          {fixedOptions}
          {options}
        </select>
        {help && (
          <div className="form-help" id={`${id}-help`}>
            {help}
          </div>
        )}
        <FieldError>{errors[key]}</FieldError>
      </div>
    );
  };

  const locationId = `${idPrefix}-location`;

  return (
    <>
      {failed.map((f) => (
        <QueryError key={f.what} what={f.what} query={f.query} />
      ))}
      {select(
        'device_type_id',
        'Device type',
        deviceTypeOptionGroups(typesQ.data ?? []).map((group) => (
          <optgroup key={group.label} label={group.label}>
            {group.options.map((o) => (
              <option key={o.value} value={o.value}>
                {o.label}
              </option>
            ))}
          </optgroup>
        )),
        allowKeep ? undefined : 'The hardware model. Discovery no longer changes it once you set it here.',
      )}
      {select(
        'role_id',
        'Role',
        (rolesQ.data ?? []).map((r) => (
          <option key={r.id} value={r.id}>
            {r.name}
          </option>
        )),
      )}
      {select(
        'lifecycle_status_id',
        'Lifecycle status',
        (statusesQ.data ?? []).map((s) => (
          <option key={s.id} value={s.id}>
            {s.is_default ? `${s.name} (default)` : s.name}
          </option>
        )),
      )}
      {select(
        'site_id',
        'Site',
        (sitesQ.data ?? []).map((s) => (
          <option key={s.id} value={s.id}>
            {s.name}
          </option>
        )),
        allowKeep ? undefined : 'Sites are managed on the Geolocation page.',
      )}
      <div className="form-group">
        {allowKeep && (
          <label className="form-check">
            <input
              type="checkbox"
              checked={location !== null}
              onChange={(e) => onLocationChange(e.target.checked ? '' : null)}
            />
            Change rack / room
          </label>
        )}
        <label className="form-label" htmlFor={locationId}>
          Rack / room
        </label>
        <input
          id={locationId}
          className="form-input"
          value={location ?? ''}
          maxLength={LOCATION_DETAIL_MAX}
          disabled={location === null}
          placeholder="Row 4, rack 12"
          aria-invalid={!!errors.location_detail}
          aria-describedby={`${locationId}-help`}
          onChange={(e) => onLocationChange(e.target.value)}
        />
        <div className="form-help" id={`${locationId}-help`}>
          {allowKeep
            ? 'Leave the box empty to clear it on every selected host.'
            : `Optional. Where in the site the host is, up to ${LOCATION_DETAIL_MAX} characters.`}
        </div>
        <FieldError>{errors.location_detail}</FieldError>
      </div>
    </>
  );
}
