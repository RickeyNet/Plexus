import { useAuthStatus } from '@/api/auth';
import { useTenants } from '@/api/organization';
import { idToSelect, selectToId } from '@/lib/deviceModel';
import { canUseFeature } from '@/lib/tabGating';

import { FieldError } from './FieldError';

export interface TenantSelectProps {
  /** The select's id; the error line is `${id}-error`. */
  id: string;
  value: number | null;
  onChange: (tenantId: number | null) => void;
  /** A message the server gave for `tenant_id`. */
  error?: string;
  label?: string;
  help?: string;
  disabled?: boolean;
}

/**
 * The tenant of a record (host, site, prefix, address, VLAN, VRF): every
 * tenant by name plus "No tenant". Tenants need the `organization` feature;
 * without it the field is hidden unless the record has a tenant, which then
 * shows read only so a save cannot drop it by accident.
 */
export function TenantSelect({ id, value, onChange, error, label = 'Tenant', help, disabled }: TenantSelectProps) {
  const auth = useAuthStatus().data;
  const allowed = auth === undefined || canUseFeature('organization', auth);
  const q = useTenants(allowed);
  if (!allowed && value === null) return null;
  const tenants = q.data ?? [];
  const known = value === null || tenants.some((t) => t.id === value);
  return (
    <div className="form-group">
      <label className="form-label" htmlFor={id}>
        {label}
      </label>
      <select
        id={id}
        className="form-select"
        value={idToSelect(value)}
        disabled={disabled || !allowed || q.isError}
        aria-invalid={!!error}
        aria-describedby={`${id}-help ${id}-error`}
        onChange={(e) => onChange(selectToId(e.target.value))}
      >
        <option value="">No tenant</option>
        {!known && <option value={idToSelect(value)}>{q.isLoading ? 'Loading…' : `Tenant ${value}`}</option>}
        {tenants.map((t) => (
          <option key={t.id} value={t.id}>
            {t.group_name ? `${t.name} (${t.group_name})` : t.name}
          </option>
        ))}
      </select>
      {help && (
        <div className="form-help" id={`${id}-help`}>
          {help}
        </div>
      )}
      <FieldError id={`${id}-error`}>{error}</FieldError>
    </div>
  );
}
