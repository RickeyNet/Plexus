import { useState } from 'react';

import { type ConfigTemplate, useDeleteIntendedTemplate, useIntendedTemplates } from '@/api/intendedConfig';
import { Badge } from '@/components/Badge';
import { CardHeader, CatalogueBody, RowActions } from '@/components/CatalogueParts';
import { DataTable } from '@/components/DataTable';
import { useDialogs } from '@/components/DialogProvider-context';
import { EmptyState } from '@/components/EmptyState';
import { clickableProps } from '@/lib/clickable';
import { usePendingKeys } from '@/lib/usePendingKeys';

import { scopeSummary } from './intendedHelpers';
import { EnabledBadge, NameCell, UpdatedCell } from './IntendedParts';
import { TemplateModal } from './TemplateModal';
import { useIntendedScopeLookups } from './useIntendedScopeLookups';

const RIGHT = { textAlign: 'right' } as const;

/** The Intended tab's Templates view: admins add, edit and delete; others read. */
export function IntendedTemplatesView({ isAdmin }: { isAdmin: boolean }) {
  const q = useIntendedTemplates();
  const remove = useDeleteIntendedTemplate();
  const { names } = useIntendedScopeLookups();
  const { confirm, alert } = useDialogs();
  const deleting = usePendingKeys<number>();
  const [editing, setEditing] = useState<ConfigTemplate | 'new' | null>(null);
  const rows = q.data ?? [];

  const addButton = isAdmin && (
    <button type="button" className="btn btn-sm btn-primary" onClick={() => setEditing('new')}>
      Add template
    </button>
  );

  const handleDelete = (t: ConfigTemplate) =>
    void deleting.run(t.id, async () => {
      const uses = t.host_count
        ? ` It renders the intended configuration of ${t.host_count.toLocaleString()} host${t.host_count === 1 ? '' : 's'}; they lose it unless another template matches them.`
        : '';
      const agreed = await confirm({
        title: 'Delete template',
        message: `Delete template "${t.name}"?${uses} Templates that include it stop rendering. This cannot be undone.`,
        confirmLabel: 'Delete template',
      });
      if (!agreed) return;
      try {
        await remove.mutateAsync(t.id);
      } catch (err) {
        await alert({ title: 'Template not deleted', message: `The template "${t.name}" was not deleted: ${(err as Error).message} Try again.`, variant: 'error' });
      }
    });

  return (
    <div className="card">
      <CardHeader
        title="Templates"
        sub={q.data && `${rows.length.toLocaleString()} template${rows.length === 1 ? '' : 's'}`}
        actions={rows.length > 0 && addButton}
      />
      <CatalogueBody
        query={q}
        what="templates"
        rows={rows}
        empty={
          <EmptyState
            compact
            message="No templates yet."
            description="A device template is Jinja2 text rendered with each matching device's data into its intended configuration. A snippet is text other templates include."
            action={addButton || undefined}
          />
        }
      >
        <DataTable compact aria-label="Templates">
          <thead>
            <tr>
              <th>Name</th>
              <th>Kind</th>
              <th>Applies to</th>
              <th>Enabled</th>
              <th style={RIGHT}>Hosts</th>
              <th>Updated</th>
              {isAdmin && <th style={RIGHT}>Actions</th>}
            </tr>
          </thead>
          <tbody>
            {rows.map((t) => (
              <tr
                key={t.id}
                className="row-clickable"
                title={isAdmin ? 'Edit the template' : 'Show the template'}
                {...clickableProps(() => setEditing(t), { role: null })}
              >
                <td>
                  <NameCell name={t.name} description={t.description} />
                </td>
                <td>
                  <Badge size="sm" tone={t.kind === 'snippet' ? 'neutral' : 'primary'}>
                    {t.kind === 'snippet' ? 'Snippet' : 'Device'}
                  </Badge>
                </td>
                <td>{t.kind === 'snippet' ? <span className="text-muted">Included by other templates</span> : scopeSummary(t, names)}</td>
                <td>
                  <EnabledBadge enabled={t.enabled} />
                </td>
                <td style={RIGHT}>{t.host_count.toLocaleString()}</td>
                <td>
                  <UpdatedCell at={t.updated_at} by={t.updated_by} />
                </td>
                {isAdmin && (
                  // The row opens the editor; the buttons do their own thing.
                  <td style={RIGHT} onClick={(e) => e.stopPropagation()}>
                    <RowActions
                      label={`template ${t.name}`}
                      onEdit={() => setEditing(t)}
                      onDelete={() => handleDelete(t)}
                      deleting={deleting.isPending(t.id)}
                    />
                  </td>
                )}
              </tr>
            ))}
          </tbody>
        </DataTable>
      </CatalogueBody>
      {editing && <TemplateModal template={editing === 'new' ? null : editing} readOnly={!isAdmin} onClose={() => setEditing(null)} />}
    </div>
  );
}
