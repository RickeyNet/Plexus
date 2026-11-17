/**
 * Bulk import API: preview and commit an import (multipart form), and the
 * template download URL. Types and request building live in lib/bulkImport.
 */
import { useMutation, useQueryClient } from '@tanstack/react-query';

import {
  buildImportForm,
  IMPORT_TYPES,
  type ImportInput,
  importPath,
  type ImportReport,
  type ImportType,
} from '@/lib/bulkImport';

import { apiRequest } from './client';
import { invalidateInventory } from './inventory';
import { invalidateOverview } from './ipam';
import { NETWORK_OBJECTS_QUERY_ROOT } from './networkObjects';

export interface ImportRequest extends ImportInput {
  type: ImportType;
}

/** The URL of an empty CSV with the columns a type's import expects. */
export function importTemplateUrl(type: ImportType): string {
  return `/api${importPath(type, 'template')}`;
}

/** What an import would do; nothing is written. */
export function usePreviewImport() {
  return useMutation<ImportReport, Error, ImportRequest>({
    mutationFn: ({ type, ...input }) =>
      apiRequest<ImportReport>(importPath(type, 'preview'), {
        method: 'POST',
        body: buildImportForm({ ...input, atomic: undefined }),
      }),
  });
}

/**
 * Write the import. The server plans it again; a refused import (row errors,
 * or a write that failed and was rolled back) is a 422 whose body is the
 * report (read it with `reportFromErrorBody`).
 */
export function useCommitImport() {
  const qc = useQueryClient();
  return useMutation<ImportReport, Error, ImportRequest>({
    mutationFn: ({ type, ...input }) =>
      apiRequest<ImportReport>(importPath(type, 'commit'), { method: 'POST', body: buildImportForm(input) }),
    onSettled: (_data, _err, vars) => {
      qc.invalidateQueries({ queryKey: ['custom-data'] });
      if (IMPORT_TYPES[vars.type].family === 'inventory') {
        invalidateInventory(qc);
      } else {
        invalidateOverview(qc);
        qc.invalidateQueries({ queryKey: NETWORK_OBJECTS_QUERY_ROOT });
      }
    },
  });
}
