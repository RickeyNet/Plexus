import type { ObjectType } from '@/api/customData';
import type { CustomDataDraft } from '@/lib/useCustomDataDraft';

import { CustomFieldsForm } from './CustomFieldsForm';
import { LoadingState } from './LoadingState';
import { QueryError } from './QueryError';
import { TagPicker } from './TagPicker';

export interface CustomDataSectionProps {
  objectType: ObjectType;
  draft: CustomDataDraft;
  /** Offer "Create tag" in the tag picker. */
  canCreateTags: boolean;
  /** Section heading; null for none. */
  title?: string | null;
  disabled?: boolean;
}

/**
 * The "Tags and custom fields" part of an object's form: a tag picker and an
 * input per applicable field, bound to a `useCustomDataDraft` draft.
 */
export function CustomDataSection({
  objectType,
  draft,
  canCreateTags,
  title = 'Tags and custom fields',
  disabled,
}: CustomDataSectionProps) {
  let body;
  if (draft.loadError) {
    body = <QueryError what="tags and custom fields" query={draft.loadError} />;
  } else if (!draft.ready) {
    body = <LoadingState text="Loading tags and custom fields…" />;
  } else {
    body = (
      <fieldset disabled={disabled} className="fieldset-plain">
        <TagPicker value={draft.tagIds} onChange={draft.setTagIds} canCreate={canCreateTags} />
        <CustomFieldsForm
          objectType={objectType}
          values={draft.values}
          onChange={draft.setValues}
          errors={draft.errors}
        />
      </fieldset>
    );
  }
  return (
    <section className={title ? 'custom-data-section' : undefined}>
      {title && <h4 className="custom-data-section-title">{title}</h4>}
      {body}
    </section>
  );
}
