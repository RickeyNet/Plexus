import { useId, useState } from 'react';

import { CustomDataError, type Tag, useCreateTag, useUpdateTag } from '@/api/customData';
import { Callout } from '@/components/Callout';
import { FieldError } from '@/components/FieldError';
import { Modal } from '@/components/Modal';
import { ModalActions } from '@/components/ModalActions';
import { TagChip } from '@/components/TagChips';
import { TAG_COLORS, TAG_NAME_MAX, tagColorLabel } from '@/lib/customData';

/** Creates a tag (`tag` null) or renames, recolors and redescribes one. */
export function TagModal({ tag, onClose }: { tag: Tag | null; onClose: () => void }) {
  const id = useId();
  const create = useCreateTag();
  const update = useUpdateTag();
  const [name, setName] = useState(tag?.name ?? '');
  const [color, setColor] = useState<string>(tag?.color ?? 'gray');
  const [description, setDescription] = useState(tag?.description ?? '');
  const [touched, setTouched] = useState(false);
  const [nameTaken, setNameTaken] = useState<string | null>(null);
  const [failure, setFailure] = useState<string | null>(null);

  const trimmed = name.trim();
  const nameError = !trimmed
    ? 'Name is required.'
    : trimmed.length > TAG_NAME_MAX
      ? `Name must be ${TAG_NAME_MAX} characters or fewer.`
      : nameTaken === trimmed.toLowerCase()
        ? `A tag named "${trimmed}" already exists.`
        : undefined;
  const shownNameError = touched || nameTaken ? nameError : undefined;
  const busy = create.isPending || update.isPending;

  const submit = () => {
    setTouched(true);
    if (nameError) return;
    setFailure(null);
    const data = { name: trimmed, color, description: description.trim() };
    const onError = (err: Error) => {
      if (err instanceof CustomDataError && err.status === 409) setNameTaken(trimmed.toLowerCase());
      else setFailure(err.message);
    };
    if (tag) update.mutate({ id: tag.id, data }, { onSuccess: onClose, onError });
    else create.mutate(data, { onSuccess: onClose, onError });
  };

  return (
    <Modal
      isOpen
      onClose={onClose}
      title={tag ? `Edit tag ${tag.name}` : 'New tag'}
      footer={
        <ModalActions
          onClose={onClose}
          primaryLabel={tag ? 'Save tag' : 'Create tag'}
          primaryBusy={busy}
          primaryBusyLabel="Saving…"
          onPrimary={submit}
        />
      }
    >
      {failure && (
        <Callout tone="danger" title="The tag was not saved">
          {failure} Check the fields and try again.
        </Callout>
      )}

      <div className="form-group">
        <label className="form-label" htmlFor={`${id}-name`}>
          Name
        </label>
        <input
          id={`${id}-name`}
          className="form-input"
          value={name}
          maxLength={TAG_NAME_MAX + 1}
          autoFocus
          aria-invalid={!!shownNameError}
          aria-describedby={`${id}-name-help ${id}-name-error`}
          onChange={(e) => setName(e.target.value)}
          onBlur={() => setTouched(true)}
        />
        <div className="form-help" id={`${id}-name-help`}>
          Up to {TAG_NAME_MAX} characters. Names are unique, ignoring case.
        </div>
        <FieldError id={`${id}-name-error`}>{shownNameError}</FieldError>
      </div>

      <fieldset className="form-group fieldset-plain">
        <legend className="form-label">Color</legend>
        <div className="tag-color-options">
          {TAG_COLORS.map((slot) => (
            <label key={slot} className="form-check">
              <input type="radio" name={`${id}-color`} value={slot} checked={color === slot} onChange={() => setColor(slot)} />
              <TagChip color={slot}>{tagColorLabel(slot)}</TagChip>
            </label>
          ))}
        </div>
      </fieldset>

      <div className="form-group">
        <label className="form-label" htmlFor={`${id}-description`}>
          Description (optional)
        </label>
        <input
          id={`${id}-description`}
          className="form-input"
          value={description}
          maxLength={500}
          onChange={(e) => setDescription(e.target.value)}
        />
      </div>

      <div className="form-group">
        <span className="form-label">Preview</span>
        <div>
          <TagChip color={color}>{trimmed || 'Tag name'}</TagChip>
        </div>
      </div>
    </Modal>
  );
}
