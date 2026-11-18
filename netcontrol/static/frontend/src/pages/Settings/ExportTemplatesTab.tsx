import { useState } from 'react';

import {
  type ExportTemplate,
  exportTemplateRenderUrl,
  useDeleteExportTemplate,
  useExportObjectTypes,
  useExportTemplates,
} from '@/api/exportTemplates';
import { Badge } from '@/components/Badge';
import { DataTable } from '@/components/DataTable';
import { DeleteButton } from '@/components/DeleteButton';
import { useDialogs } from '@/components/DialogProvider-context';
import { EmptyState } from '@/components/EmptyState';
import { LoadingState } from '@/components/LoadingState';
import { QueryError } from '@/components/QueryError';
import { usePendingKeys } from '@/lib/usePendingKeys';

import { ExportTemplateModal } from './ExportTemplateModal';

const RIGHT = { textAlign: 'right' } as const;

/** Settings tab: Jinja2 templates that export the objects of one type as a file. */
export function ExportTemplatesTab() {
  const templatesQ = useExportTemplates();
  const typesQ = useExportObjectTypes();
  const remove = useDeleteExportTemplate();
  const deleting = usePendingKeys<number>();
  const { confirm, alert } = useDialogs();
  const [editing, setEditing] = useState<ExportTemplate | 'new' | null>(null);

  const templates = templatesQ.data?.templates ?? [];
  const objectTypes = typesQ.data?.object_types ?? [];
  const labelOf = (key: string) => objectTypes.find((t) => t.key === key)?.label ?? key;
  const addButton = (
    <button type="button" className="btn btn-sm btn-primary" onClick={() => setEditing('new')} disabled={!typesQ.data}>
      Add export template
    </button>
  );

  const handleDelete = (t: ExportTemplate) =>
    void deleting.run(t.id, async () => {
      const agreed = await confirm({
        title: 'Delete export template',
        message: `Delete the export template "${t.name}"? It leaves the Export menu of ${labelOf(t.object_type).toLowerCase()}.`,
        confirmLabel: 'Delete template',
      });
      if (!agreed) return;
      try {
        await remove.mutateAsync(t.id);
      } catch (err) {
        await alert({
          title: 'Template not deleted',
          message: `The export template "${t.name}" was not deleted: ${(err as Error).message} Try again.`,
          variant: 'error',
        });
      }
    });

  if (templatesQ.isError && !templatesQ.data) return <QueryError what="export templates" query={templatesQ} />;
  if (typesQ.isError && !typesQ.data) return <QueryError what="export object types" query={typesQ} />;
  if (templatesQ.isPending || typesQ.isPending) return <LoadingState />;

  return (
    <div className="stack stack-sm">
      {templates.length > 0 && <div style={{ display: 'flex', justifyContent: 'flex-end' }}>{addButton}</div>}
      {templates.length === 0 ? (
        <EmptyState
          compact
          message="No export templates yet."
          description="Add a template to export hosts, IPAM prefixes or addresses, VLANs, circuits or sites in your own format, such as a CSV for another tool or a configuration snippet. It appears in the Export menu of that list."
          action={addButton}
        />
      ) : (
        <DataTable compact aria-label="Export templates">
          <thead>
            <tr>
              <th>Name</th>
              <th>Object type</th>
              <th>File</th>
              <th style={RIGHT}>Actions</th>
            </tr>
          </thead>
          <tbody>
            {templates.map((t) => (
              <tr key={t.id}>
                <td>
                  {t.name}
                  {t.description && (
                    <div className="form-help" style={{ margin: 0 }}>
                      {t.description}
                    </div>
                  )}
                </td>
                <td>{labelOf(t.object_type)}</td>
                <td>
                  <code>{t.mime_type}</code>
                  {t.file_extension && <> .{t.file_extension}</>}{' '}
                  {!t.as_attachment && (
                    <Badge tone="neutral" size="sm">
                      Inline
                    </Badge>
                  )}
                </td>
                <td style={RIGHT}>
                  <div style={{ display: 'inline-flex', gap: 'var(--space-1)', flexWrap: 'wrap', justifyContent: 'flex-end' }}>
                    <a className="btn btn-sm btn-secondary" href={exportTemplateRenderUrl(t.id)} download={t.as_attachment || undefined}>
                      Export
                    </a>
                    <button type="button" className="btn btn-sm btn-secondary" onClick={() => setEditing(t)}>
                      Edit
                    </button>
                    <DeleteButton
                      busy={deleting.isPending(t.id)}
                      onClick={() => handleDelete(t)}
                      aria-label={`Delete export template ${t.name}`}
                    />
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </DataTable>
      )}
      {editing && (
        <ExportTemplateModal
          template={editing === 'new' ? null : editing}
          objectTypes={objectTypes}
          onClose={() => setEditing(null)}
        />
      )}
    </div>
  );
}
