import { type KeyboardEvent, useId, useState } from 'react';

import { type TagRef, useCreateTag, useTags } from '@/api/customData';
import { tagPickerOptions, TAG_NAME_MAX, toggleTag } from '@/lib/customData';

import { FieldError } from './FieldError';
import { TagChip } from './TagChips';

export interface TagPickerProps {
  /** Ids of the selected tags. */
  value: number[];
  onChange: (ids: number[]) => void;
  /** Offer "Create tag" when no tag has the typed name. */
  canCreate: boolean;
  /** The visible label; defaults to "Tags". */
  label?: string;
  /** Help text under the input. */
  help?: string;
}

/**
 * Chooses tags: the selected ones as removable chips, then a type-ahead over
 * every tag. Arrow keys move through the list, Enter picks, Escape closes it,
 * Backspace in an empty box removes the last chip. When nothing has the typed
 * name and `canCreate` is set, the list offers to create it.
 */
export function TagPicker({ value, onChange, canCreate, label = 'Tags', help }: TagPickerProps) {
  const id = useId();
  const tagsQ = useTags();
  const create = useCreateTag();
  const [query, setQuery] = useState('');
  const [open, setOpen] = useState(false);
  const [active, setActive] = useState(0);
  const [createError, setCreateError] = useState<string | null>(null);

  const tags: TagRef[] = tagsQ.data ?? [];
  const byId = new Map(tags.map((t) => [t.id, t]));
  const { matches, createName } = tagPickerOptions(tags, value, query, canCreate && !create.isPending);
  const optionCount = matches.length + (createName ? 1 : 0);
  const showList = open && optionCount > 0;
  const activeIndex = Math.min(active, Math.max(optionCount - 1, 0));
  const optionId = (i: number) => `${id}-opt-${i}`;

  const pick = (tagId: number) => {
    onChange(toggleTag(value, tagId));
    setQuery('');
    setActive(0);
  };

  const createTag = (name: string) => {
    setCreateError(null);
    create.mutate(
      { name },
      {
        onSuccess: (tag) => {
          if (!value.includes(tag.id)) onChange([...value, tag.id]);
          setQuery('');
          setActive(0);
        },
        onError: (err) => setCreateError(`The tag "${name}" was not created: ${err.message}`),
      },
    );
  };

  const choose = (index: number) => {
    if (index < matches.length) pick(matches[index].id);
    else if (createName) createTag(createName);
  };

  const onKeyDown = (e: KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
      e.preventDefault();
      setOpen(true);
      if (optionCount === 0) return;
      const step = e.key === 'ArrowDown' ? 1 : -1;
      setActive((activeIndex + step + optionCount) % optionCount);
    } else if (e.key === 'Enter') {
      // Never submit the surrounding form from the tag box.
      e.preventDefault();
      if (showList) choose(activeIndex);
    } else if (e.key === 'Escape' && showList) {
      // Close the list only, not an enclosing dialog.
      e.stopPropagation();
      setOpen(false);
    } else if (e.key === 'Backspace' && query === '' && value.length > 0) {
      onChange(value.slice(0, -1));
    }
  };

  return (
    <div className="form-group">
      <label className="form-label" htmlFor={`${id}-input`}>
        {label}
      </label>
      <div className="tag-picker">
        {value.length > 0 && (
          <ul className="tag-picker-selected" aria-label={`Selected ${label.toLowerCase()}`}>
            {value.map((tagId) => {
              const tag = byId.get(tagId);
              const name = tag?.name ?? (tagsQ.data ? `Deleted tag #${tagId}` : `Tag #${tagId}`);
              return (
                <li key={tagId}>
                  <TagChip color={tag?.color}>
                    {name}
                    <button
                      type="button"
                      className="tag-chip-remove"
                      aria-label={`Remove tag ${name}`}
                      title={`Remove tag ${name}`}
                      onClick={() => onChange(value.filter((v) => v !== tagId))}
                    >
                      ×
                    </button>
                  </TagChip>
                </li>
              );
            })}
          </ul>
        )}
        <div className="tag-picker-input">
          <input
            id={`${id}-input`}
            className="form-input"
            role="combobox"
            aria-expanded={showList}
            aria-controls={`${id}-list`}
            aria-autocomplete="list"
            aria-activedescendant={showList ? optionId(activeIndex) : undefined}
            aria-describedby={[help ? `${id}-help` : '', createError ? `${id}-error` : ''].filter(Boolean).join(' ') || undefined}
            autoComplete="off"
            maxLength={TAG_NAME_MAX + 1}
            placeholder={canCreate ? 'Find or create a tag' : 'Find a tag'}
            value={query}
            onChange={(e) => {
              setQuery(e.target.value);
              setOpen(true);
              setActive(0);
              setCreateError(null);
            }}
            onFocus={() => setOpen(true)}
            onBlur={() => setOpen(false)}
            onKeyDown={onKeyDown}
          />
          {showList && (
            <ul className="tag-picker-list" id={`${id}-list`} role="listbox" aria-label={label}>
              {matches.map((tag, i) => (
                <li
                  key={tag.id}
                  id={optionId(i)}
                  role="option"
                  aria-selected={i === activeIndex}
                  className={`tag-picker-option${i === activeIndex ? ' active' : ''}`}
                  // mousedown, not click: the input must keep focus.
                  onMouseDown={(e) => {
                    e.preventDefault();
                    pick(tag.id);
                  }}
                  onMouseEnter={() => setActive(i)}
                >
                  <TagChip color={tag.color}>{tag.name}</TagChip>
                </li>
              ))}
              {createName && (
                <li
                  id={optionId(matches.length)}
                  role="option"
                  aria-selected={activeIndex === matches.length}
                  className={`tag-picker-option${activeIndex === matches.length ? ' active' : ''}`}
                  onMouseDown={(e) => {
                    e.preventDefault();
                    createTag(createName);
                  }}
                  onMouseEnter={() => setActive(matches.length)}
                >
                  Create tag &quot;{createName}&quot;
                </li>
              )}
            </ul>
          )}
        </div>
      </div>
      {help && (
        <div className="form-help" id={`${id}-help`}>
          {help}
        </div>
      )}
      {create.isPending && <div className="form-help">Creating tag…</div>}
      <FieldError id={`${id}-error`}>{createError}</FieldError>
    </div>
  );
}
