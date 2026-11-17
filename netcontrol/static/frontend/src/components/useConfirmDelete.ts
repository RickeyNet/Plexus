import { CustomDataError } from '@/api/customData';

import { useDialogs } from './DialogProvider-context';

function capitalised(text: string): string {
  return text ? `${text[0].toUpperCase()}${text.slice(1)}` : text;
}

/**
 * Asks to delete a record (naming it), deletes it, and explains a refusal:
 * a 409 says what still uses the record. `note` is added to the question.
 * Resolves to whether it was deleted.
 */
export function useConfirmDelete() {
  const { confirm, alert } = useDialogs();
  return async (what: string, name: string, remove: () => Promise<unknown>, note = ''): Promise<boolean> => {
    const agreed = await confirm({
      title: `Delete ${what}`,
      message: `Delete ${what} "${name}"?${note ? ` ${note}` : ''} This cannot be undone.`,
      confirmLabel: `Delete ${what}`,
    });
    if (!agreed) return false;
    try {
      await remove();
      return true;
    } catch (err) {
      const inUse = err instanceof CustomDataError && err.status === 409;
      await alert({
        title: inUse ? `${capitalised(what)} in use` : `${capitalised(what)} not deleted`,
        message: inUse ? (err as Error).message : `The ${what} "${name}" was not deleted: ${(err as Error).message} Try again.`,
        variant: 'error',
      });
      return false;
    }
  };
}
