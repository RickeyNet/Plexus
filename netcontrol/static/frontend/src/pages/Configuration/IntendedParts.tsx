import type { IntendedScope } from '@/api/intendedConfig';
import { Badge } from '@/components/Badge';
import { QueryError } from '@/components/QueryError';
import { formatBackendDateTime } from '@/lib/datetime';
import { idToSelect, selectToId } from '@/lib/deviceModel';

import { driverOptions, type NamedRecord, scopeOptions } from './intendedHelpers';
import { useIntendedScopeLookups } from './useIntendedScopeLookups';

/**
 * Parts the template and context lists and editors share: the name, enabled
 * and updated cells, the enabled switch and the scope pickers.
 */

export function NameCell({ name, description }: { name: string; description: string }) {
  return (
    <>
      <div style={{ fontWeight: 600 }}>{name}</div>
      {description && (
        <div className="text-muted" style={{ fontSize: 'var(--text-xs)' }}>
          {description}
        </div>
      )}
    </>
  );
}

export function EnabledBadge({ enabled }: { enabled: boolean }) {
  return (
    <Badge size="sm" tone={enabled ? 'success' : 'neutral'}>
      {enabled ? 'Enabled' : 'Disabled'}
    </Badge>
  );
}

export function UpdatedCell({ at, by }: { at: string; by: string }) {
  return (
    <>
      {formatBackendDateTime(at)}
      {by && (
        <div className="text-muted" style={{ fontSize: 'var(--text-xs)' }}>
          {by}
        </div>
      )}
    </>
  );
}

export function EnabledField({ value, onChange, help, disabled }: { value: boolean; onChange: (v: boolean) => void; help: string; disabled?: boolean }) {
  return (
    <div className="form-group">
      <label className="form-check">
        <input type="checkbox" checked={value} disabled={disabled} onChange={(e) => onChange(e.target.checked)} />
        Enabled
      </label>
      <div className="form-help">{help}</div>
    </div>
  );
}

interface Props {
  /** Prefix for the control ids (a `useId()` value). */
  idPrefix: string;
  scope: IntendedScope;
  onChange: (next: IntendedScope) => void;
  /** Contexts also scope to one host. */
  host?: { value: number | null; onChange: (id: number | null) => void };
  disabled?: boolean;
}

/**
 * The scope pickers of the template and context editors: driver, role, site
 * and group (and host for a context). "Any" leaves a field unset; a stored id
 * whose record is gone shows as "(deleted)".
 */
export function IntendedScopeFields({ idPrefix, scope, onChange, host, disabled }: Props) {
  const { names, failed } = useIntendedScopeLookups();

  const idSelect = (
    key: 'role_id' | 'site_id' | 'group_id' | 'host_id',
    label: string,
    list: readonly NamedRecord[] | undefined,
    value: number | null,
    set: (id: number | null) => void,
  ) => {
    const id = `${idPrefix}-${key}`;
    return (
      <div className="form-group">
        <label className="form-label" htmlFor={id}>
          {label}
        </label>
        <select id={id} className="form-select" value={idToSelect(value)} disabled={disabled} onChange={(e) => set(selectToId(e.target.value))}>
          <option value="">Any</option>
          {scopeOptions(list, value).map((r) => (
            <option key={r.id} value={r.id}>
              {r.name}
            </option>
          ))}
        </select>
      </div>
    );
  };

  const driverId = `${idPrefix}-device_type`;
  return (
    <div role="group" aria-labelledby={`${idPrefix}-scope-label`}>
      <div className="form-label" id={`${idPrefix}-scope-label`}>
        Applies to
      </div>
      <div className="form-help" style={{ marginBottom: 'var(--space-2)' }}>
        Every field that is set must match the device. A field naming a deleted record matches no device.
      </div>
      {failed.map((f) => (
        <QueryError key={f.what} what={f.what} query={f.query} />
      ))}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', columnGap: 'var(--space-3)' }}>
        <div className="form-group">
          <label className="form-label" htmlFor={driverId}>
            Driver
          </label>
          <select
            id={driverId}
            className="form-select"
            value={scope.device_type}
            disabled={disabled}
            onChange={(e) => onChange({ ...scope, device_type: e.target.value })}
          >
            <option value="">Any</option>
            {driverOptions(scope.device_type).map((d) => (
              <option key={d.value} value={d.value}>
                {d.label}
              </option>
            ))}
          </select>
        </div>
        {idSelect('role_id', 'Role', names.roles, scope.role_id, (v) => onChange({ ...scope, role_id: v }))}
        {idSelect('site_id', 'Site', names.sites, scope.site_id, (v) => onChange({ ...scope, site_id: v }))}
        {idSelect('group_id', 'Group', names.groups, scope.group_id, (v) => onChange({ ...scope, group_id: v }))}
        {host && idSelect('host_id', 'Host', names.hosts, host.value, host.onChange)}
      </div>
    </div>
  );
}
