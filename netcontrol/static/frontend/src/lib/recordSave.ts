import { CustomDataError } from '@/api/customData';

import type { NameField } from './useNameField';

/**
 * Runs a catalogue dialog's save: a 409 marks the name as taken (or, with
 * no name field, shows the server's message), any other failure shows in
 * the dialog's callout; success closes the dialog.
 */
export async function runSave(
  save: () => Promise<unknown>,
  name: NameField | null,
  setFailure: (message: string | null) => void,
  onClose: () => void,
) {
  setFailure(null);
  try {
    await save();
    onClose();
  } catch (err) {
    if (name && err instanceof CustomDataError && err.status === 409) name.markTaken();
    else setFailure((err as Error).message);
  }
}
