import { type ObjectType, useCustomFields, useTags } from '@/api/customData';
import {
  applicableFields,
  type CustomDataFilterValue,
  EMPTY_CUSTOM_DATA_FILTER,
  filterCount,
  HAS_VALUE,
  toggleTag,
} from '@/lib/customData';

import { Badge } from './Badge';
import { Menu, MenuCheckboxItem, MenuItem, MenuSeparator } from './Menu';
import { TagChips } from './TagChips';

export interface CustomDataFilterProps {
  objectType: ObjectType;
  value: CustomDataFilterValue;
  onChange: (value: CustomDataFilterValue) => void;
}

/**
 * A "Filter" menu over tags and custom fields: tags as checkboxes (every
 * checked tag must be present), choice and yes/no fields by value, the other
 * fields as "has a value". Hidden until a tag or field exists.
 */
export function CustomDataFilter({ objectType, value, onChange }: CustomDataFilterProps) {
  const tagsQ = useTags();
  const fieldsQ = useCustomFields(objectType);
  const tags = [...(tagsQ.data ?? [])].sort((a, b) => a.name.localeCompare(b.name));
  const fields = applicableFields(fieldsQ.data ?? [], objectType);
  const count = filterCount(value);
  if (tags.length === 0 && fields.length === 0 && count === 0) return null;

  const setField = (key: string, wanted: string, on: boolean) => {
    const next = { ...value.fields };
    if (on) next[key] = wanted;
    else delete next[key];
    onChange({ ...value, fields: next });
  };

  const name = count > 0 ? `Filter by tags and custom fields, ${count} active` : 'Filter by tags and custom fields';

  return (
    <Menu
      label="Filter by tags and custom fields"
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
      {count > 0 && (
        <>
          <MenuSeparator />
          <MenuItem onSelect={() => onChange(EMPTY_CUSTOM_DATA_FILTER)}>Clear filter</MenuItem>
        </>
      )}
    </Menu>
  );
}
