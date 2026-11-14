import { useId, useState } from 'react';

import { CustomDataError, type Tag, useCreateTag, useUpdateTag } from '@/api/customData';
import { Callout } from '@/components/Callout';
import { Modal } from '@/components/Modal';
import { ModalActions } from '@/components/ModalActions';
import { NameInput } from '@/components/NameInput';
import { TagChip } from '@/components/TagChips';
import { TagColorPicker } from '@/components/TagColorPicker';
import { TAG_NAME_MAX } from '@/lib/customData';
import { useNameField } from '@/lib/useNameField';

/** Creates a tag (`tag` null) or renames, recolors and redescribes one. */
export function TagModal({ tag, onClose }: { tag: Tag | null; onClose: () => void }) {
  const id = useId();
  const create = useCreateTag();
  const update = useUpdateTag();
  const name = useNameField(tag?.name ?? '', TAG_NAME_MAX, 'Name', (n) => `A tag named "${n}" already exists.`);
  const [color, setColor] = useState<string>(tag?.color ?? 'gray');
  const [description, setDescription] = useState(tag?.description ?? '');
  const [failure, setFailure] = useState<string | null>(null);
  const busy = create.isPending || update.isPending;

  const submit = () => {
    name.touch();
    if (name.error) return;
    setFailure(null);
    const data = { name: name.trimmed, color, description: description.trim() };
    const onError = (err: Error) => {
      if (err instanceof CustomDataError && err.status === 409) name.markTaken();
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

      <NameInput
        id={id}
        label="Name"
        field={name}
        max={TAG_NAME_MAX}
        help={`Up to ${TAG_NAME_MAX} characters. Names are unique, ignoring case.`}
      />

      <TagColorPicker value={color} onChange={setColor} />

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
          <TagChip color={color}>{name.trimmed || 'Tag name'}</TagChip>
        </div>
      </div>
    </Modal>
  );
}
