import { useState } from 'react';

import { isGitOwned } from '@/api/gitSources';
import { type ConfigContext, useDeleteIntendedContext, useIntendedContexts } from '@/api/intendedConfig';
import { CardHeader, CatalogueBody, RowActions } from '@/components/CatalogueParts';
import { DataTable } from '@/components/DataTable';
import { useDialogs } from '@/components/DialogProvider-context';
import { EmptyState } from '@/components/EmptyState';
import { GitOwnedBadge } from '@/components/GitOwnedBadge';
import { clickableProps } from '@/lib/clickable';
import { usePendingKeys } from '@/lib/usePendingKeys';

import { ContextModal } from './ContextModal';
import { scopeSummary } from './intendedHelpers';
import { EnabledBadge, NameCell, UpdatedCell } from './IntendedParts';
import { useIntendedScopeLookups } from './useIntendedScopeLookups';

const RIGHT = { textAlign: 'right' } as const;

/** The Intended tab's Contexts view: JSON data merged by weight into each device's `context`. */
export function IntendedContextsView({ isAdmin }: { isAdmin: boolean }) {
  const q = useIntendedContexts();
  const remove = useDeleteIntendedContext();
  const { names } = useIntendedScopeLookups();
  const { confirm, alert } = useDialogs();
  const deleting = usePendingKeys<number>();
  const [editing, setEditing] = useState<ConfigContext | 'new' | null>(null);
  const rows = q.data ?? [];

  const addButton = isAdmin && (
    <button type="button" className="btn btn-sm btn-primary" onClick={() => setEditing('new')}>
      Add context
    </button>
  );

  const handleDelete = (c: ConfigContext) =>
    void deleting.run(c.id, async () => {
      const agreed = await confirm({
        title: 'Delete context',
        message: `Delete context "${c.name}"? Its data leaves the context of every device it applies to at the next generation. This cannot be undone.`,
        confirmLabel: 'Delete context',
      });
      if (!agreed) return;
      try {
        await remove.mutateAsync(c.id);
      } catch (err) {
        await alert({ title: 'Context not deleted', message: `The context "${c.name}" was not deleted: ${(err as Error).message} Try again.`, variant: 'error' });
      }
    });

  return (
    <div className="card">
      <CardHeader
        title="Contexts"
        sub={q.data && `${rows.length.toLocaleString()} context${rows.length === 1 ? '' : 's'}, merged by weight (lowest first)`}
        actions={rows.length > 0 && addButton}
      />
      <CatalogueBody
        query={q}
        what="contexts"
        rows={rows}
        empty={
          <EmptyState
            compact
            message="No config contexts yet."
            description="A context is JSON data, such as NTP servers or a syslog host, that templates read as context for the devices it applies to."
            action={addButton || undefined}
          />
        }
      >
        <DataTable compact aria-label="Contexts">
          <thead>
            <tr>
              <th>Name</th>
              <th style={RIGHT}>Weight</th>
              <th>Applies to</th>
              <th>Enabled</th>
              <th>Updated</th>
              {isAdmin && <th style={RIGHT}>Actions</th>}
            </tr>
          </thead>
          <tbody>
            {rows.map((c) => (
              <tr
                key={c.id}
                className="row-clickable"
                title={isAdmin && !isGitOwned(c) ? 'Edit the context' : 'Show the context'}
                {...clickableProps(() => setEditing(c), { role: null })}
              >
                <td>
                  <NameCell name={c.name} description={c.description} />
                  <GitOwnedBadge record={c} />
                </td>
                <td style={RIGHT}>{c.weight.toLocaleString()}</td>
                <td>{scopeSummary(c, names)}</td>
                <td>
                  <EnabledBadge enabled={c.enabled} />
                </td>
                <td>
                  <UpdatedCell at={c.updated_at} by={c.updated_by} />
                </td>
                {isAdmin && (
                  // The row opens the editor; the buttons do their own thing.
                  <td style={RIGHT} onClick={(e) => e.stopPropagation()}>
                    {/* A Git source's context changes in its repository. */}
                    {!isGitOwned(c) && (
                      <RowActions
                        label={`context ${c.name}`}
                        onEdit={() => setEditing(c)}
                        onDelete={() => handleDelete(c)}
                        deleting={deleting.isPending(c.id)}
                      />
                    )}
                  </td>
                )}
              </tr>
            ))}
          </tbody>
        </DataTable>
      </CatalogueBody>
      {editing && <ContextModal context={editing === 'new' ? null : editing} readOnly={!isAdmin || (editing !== 'new' && isGitOwned(editing))} onClose={() => setEditing(null)} />}
    </div>
  );
}
