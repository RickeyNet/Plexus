import type { ReactNode } from 'react';

import { type ObjectType, useCustomFields, useTags } from '@/api/customData';
import { useDeviceRoles, useDeviceTypes, useHostStatuses, useManufacturers } from '@/api/deviceModel';
import { useGeoSites } from '@/api/floorPlan';
import {
  applicableFields,
  type CustomDataFilterValue,
  EMPTY_CUSTOM_DATA_FILTER,
  filterCount,
  HAS_VALUE,
  toggleTag,
} from '@/lib/customData';
import { DEVICE_FACETS, type DeviceFacet, type FacetChoice, NONE, toggleFacetChoice } from '@/lib/deviceModel';

import { Badge } from './Badge';
import { Menu, MenuCheckboxItem, MenuItem, MenuSeparator } from './Menu';
import { TagChip, TagChips } from './TagChips';

export interface CustomDataFilterProps {
  objectType: ObjectType;
  value: CustomDataFilterValue;
  onChange: (value: CustomDataFilterValue) => void;
  /** Also offer the device model facets (manufacturer, device type, role, lifecycle status, site). */
  deviceFacets?: boolean;
}

/**
 * A "Filter" menu over tags and custom fields: tags as checkboxes (every
 * checked tag must be present), choice and yes/no fields by value, the other
 * fields as "has a value". With `deviceFacets`, the device model facets
 * follow, each a multi-choice where the choices are alternatives. Without
 * device facets it is hidden until a tag or field exists.
 */
export function CustomDataFilter({ objectType, value, onChange, deviceFacets = false }: CustomDataFilterProps) {
  const tagsQ = useTags();
  const fieldsQ = useCustomFields(objectType);
  const tags = [...(tagsQ.data ?? [])].sort((a, b) => a.name.localeCompare(b.name));
  const fields = applicableFields(fieldsQ.data ?? [], objectType);
  const count = filterCount(value);
  if (!deviceFacets && tags.length === 0 && fields.length === 0 && count === 0) return null;

  const setField = (key: string, wanted: string, on: boolean) => {
    const next = { ...value.fields };
    if (on) next[key] = wanted;
    else delete next[key];
    onChange({ ...value, fields: next });
  };

  const what = deviceFacets ? 'Filter hosts' : 'Filter by tags and custom fields';
  const name = count > 0 ? `${what}, ${count} active` : what;

  return (
    <Menu
      label={what}
      align="start"
      width={260}
      trigger={
        <button type="button" className="btn btn-sm btn-secondary" aria-label={name} title={name}>
          Filter
          {count > 0 && (
            <Badge size="sm" tone="primary" className="filter-count">
              {count}
            </Badge>
          )}
        </button>
      }
    >
      {tags.length > 0 && (
        <>
          <div className="menu-group-label" role="presentation">
            Tags
          </div>
          {tags.map((tag) => (
            <MenuCheckboxItem
              key={tag.id}
              checked={value.tagIds.includes(tag.id)}
              onChange={() => onChange({ ...value, tagIds: toggleTag(value.tagIds, tag.id) })}
            >
              <TagChips tags={[tag]} />
            </MenuCheckboxItem>
          ))}
        </>
      )}
      {fields.map((field) => {
        const current = value.fields[field.key];
        const choices =
          field.field_type === 'select'
            ? field.choices.map((c) => ({ wanted: c, label: c }))
            : field.field_type === 'boolean'
              ? [
                  { wanted: 'true', label: 'Yes' },
                  { wanted: 'false', label: 'No' },
                ]
              : [{ wanted: HAS_VALUE, label: 'Has a value' }];
        return (
          <div key={field.id} role="group" aria-label={field.label}>
            <MenuSeparator />
            <div className="menu-group-label" role="presentation">
              {field.label}
            </div>
            {choices.map((choice) => (
              <MenuCheckboxItem
                key={choice.wanted}
                checked={current === choice.wanted}
                onChange={(on) => setField(field.key, choice.wanted, on)}
              >
                {choice.label}
              </MenuCheckboxItem>
            ))}
          </div>
        );
      })}
      {deviceFacets && (
        <DeviceFacetGroups
          value={value}
          onToggle={(facet, choice) => onChange({ ...value, device: toggleFacetChoice(value.device, facet, choice) })}
        />
      )}
      {count > 0 && (
        <>
          <MenuSeparator />
          <MenuItem onSelect={() => onChange(EMPTY_CUSTOM_DATA_FILTER)}>Clear filter</MenuItem>
        </>
      )}
    </Menu>
  );
}

interface FacetChoiceItem {
  choice: FacetChoice;
  label: ReactNode;
}

/** The device model facets: "None" plus each catalogue record. Loaded when the menu opens. */
function DeviceFacetGroups({
  value,
  onToggle,
}: {
  value: CustomDataFilterValue;
  onToggle: (facet: DeviceFacet, choice: FacetChoice) => void;
}) {
  const manufacturersQ = useManufacturers();
  const typesQ = useDeviceTypes();
  const rolesQ = useDeviceRoles();
  const statusesQ = useHostStatuses();
  const sitesQ = useGeoSites();

  const records: Record<DeviceFacet, FacetChoiceItem[]> = {
    manufacturer: (manufacturersQ.data ?? []).map((m) => ({ choice: m.id, label: m.name })),
    device_type: (typesQ.data ?? []).map((t) => ({ choice: t.id, label: `${t.manufacturer} ${t.model}` })),
    role: (rolesQ.data ?? []).map((r) => ({ choice: r.id, label: <TagChip color={r.color}>{r.name}</TagChip> })),
    lifecycle_status: (statusesQ.data ?? []).map((s) => ({
      choice: s.id,
      label: <TagChip color={s.color}>{s.name}</TagChip>,
    })),
    site: (sitesQ.data ?? []).map((s) => ({ choice: s.id, label: s.name })),
  };

  return (
    <>
      {DEVICE_FACETS.map(({ key, label }) => {
        const chosen = value.device?.[key] ?? [];
        const items: FacetChoiceItem[] = [{ choice: NONE, label: 'None' }, ...records[key]];
        return (
          <div key={key} role="group" aria-label={label}>
            <MenuSeparator />
            <div className="menu-group-label" role="presentation">
              {label}
            </div>
            {items.map((item) => (
              <MenuCheckboxItem
                key={String(item.choice)}
                checked={chosen.includes(item.choice)}
                onChange={() => onToggle(key, item.choice)}
              >
                {item.label}
              </MenuCheckboxItem>
            ))}
          </div>
        );
      })}
    </>
  );
}
