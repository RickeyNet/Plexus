import { useId } from 'react';

import { TAG_COLORS, tagColorLabel } from '@/lib/customData';

import { TagChip } from './TagChips';

export interface TagColorPickerProps {
  value: string;
  onChange: (color: string) => void;
  /** The group's visible label. */
  legend?: string;
}

/** The tag palette as radio chips (tags, device roles, lifecycle statuses). */
export function TagColorPicker({ value, onChange, legend = 'Color' }: TagColorPickerProps) {
  const name = useId();
  return (
    <fieldset className="form-group fieldset-plain">
      <legend className="form-label">{legend}</legend>
      <div className="tag-color-options">
        {TAG_COLORS.map((slot) => (
          <label key={slot} className="form-check">
            <input type="radio" name={name} value={slot} checked={value === slot} onChange={() => onChange(slot)} />
            <TagChip color={slot}>{tagColorLabel(slot)}</TagChip>
          </label>
        ))}
      </div>
    </fieldset>
  );
}
