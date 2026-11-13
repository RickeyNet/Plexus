import { useMemo, useState } from 'react';

import {
  CustomDataError,
  type ObjectDataPut,
  type ObjectRef,
  type ObjectType,
  useCustomFields,
  useObjectData,
  type useSaveObjectData,
} from '@/api/customData';

import { applicableFields, type FormValues, initialFieldValues, missingRequired, toPutFields } from './customData';

/**
 * The edit state of one object's tags and custom field values, for a form
 * that saves them: starts from the stored data (or, for a new object with
 * `ref` null, from the field defaults) and keeps only what the user changed,
 * so data that loads late fills in every untouched field.
 */
export function useCustomDataDraft(objectType: ObjectType, ref: ObjectRef | null) {
  const fieldsQ = useCustomFields(objectType);
  const dataQ = useObjectData(ref);
  const fields = useMemo(() => applicableFields(fieldsQ.data ?? [], objectType), [fieldsQ.data, objectType]);
  const stored = dataQ.data;

  const [tagEdits, setTagEdits] = useState<number[] | null>(null);
  const [valueEdits, setValueEdits] = useState<FormValues>({});
  const [errors, setErrors] = useState<Record<string, string>>({});

  const values = useMemo(
    () => ({ ...initialFieldValues(fields, stored?.fields ?? {}), ...valueEdits }),
    [fields, stored, valueEdits],
  );
  const tagIds = tagEdits ?? stored?.tags.map((t) => t.id) ?? [];
  const dirty = tagEdits !== null || Object.keys(valueEdits).length > 0;
  const hasData = tagIds.length > 0 || Object.values(values).some((v) => v !== '');
  /** Definitions (and the stored data, for an existing object) have loaded, so a full replace is safe. */
  const ready = fieldsQ.isSuccess && (ref === null || dataQ.isSuccess);

  const setValues = (next: FormValues) => {
    const changed = Object.keys(next).filter((key) => next[key] !== values[key]);
    if (changed.length === 0) return;
    setValueEdits((prev) => {
      const out = { ...prev };
      for (const key of changed) out[key] = next[key];
      return out;
    });
    // A field's error clears as soon as it is edited.
    setErrors((prev) => {
      const out = { ...prev };
      for (const key of changed) delete out[key];
      return out;
    });
  };

  return {
    fields,
    tagIds,
    setTagIds: (ids: number[]) => setTagEdits(ids),
    values,
    setValues,
    errors,
    setErrors,
    dirty,
    hasData,
    ready,
    /** The stored data or definitions failed to load. */
    loadError: (ref !== null && dataQ.isError ? dataQ : null) ?? (fieldsQ.isError ? fieldsQ : null),
    /** Sets and returns the errors for required fields with no value; empty when none. */
    checkRequired: (): Record<string, string> => {
      const missing = missingRequired(fields, values);
      setErrors(missing);
      return missing;
    },
    toPut: (): ObjectDataPut => ({ tag_ids: tagIds, fields: toPutFields(fields, values) }),
    /** Drops every edit and error. */
    reset: () => {
      setTagEdits(null);
      setValueEdits({});
      setErrors({});
    },
  };
}

export type CustomDataDraft = ReturnType<typeof useCustomDataDraft>;

/**
 * Saves a draft to `ref`. Returns null on success, else the reason; a
 * rejected field's message is set on the draft under that field.
 */
export async function saveCustomDataDraft(
  save: ReturnType<typeof useSaveObjectData>,
  draft: CustomDataDraft,
  ref: ObjectRef,
): Promise<string | null> {
  try {
    await save.mutateAsync({ ref, data: draft.toPut() });
    return null;
  } catch (err) {
    if (err instanceof CustomDataError) {
      draft.setErrors(err.fields);
      return err.message;
    }
    return (err as Error).message;
  }
}
