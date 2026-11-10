import { lazy, Suspense, useMemo, useState } from 'react';

import { Badge } from '@/components/Badge';
import { DeleteButton } from '@/components/DeleteButton';
import { useDialogs } from '@/components/DialogProvider-context';
import { useDeletePlaybook, usePlaybooks, type Playbook } from '@/api/jobs';
import { EmptyState } from '@/components/EmptyState';
import { LoadingState } from '@/components/LoadingState';
import { QueryError } from '@/components/QueryError';
import { usePendingKeys } from '@/lib/usePendingKeys';

import { parseTags } from './helpers';

// CodeMirror + python/yaml language grammars + dracula theme together weigh
// ~400 KB. Defer loading them until the user actually opens the editor.
const PlaybookFormModal = lazy(() =>
  import('./PlaybookFormModal').then((m) => ({ default: m.PlaybookFormModal })),
);

export function PlaybooksTab() {
  const { confirm, alert } = useDialogs();
  const query = usePlaybooks();
  const deleteMut = useDeletePlaybook();
  const deleting = usePendingKeys<number>();
  const [search, setSearch] = useState('');
  const [editing, setEditing] = useState<{ mode: 'create' } | { mode: 'edit'; id: number } | null>(null);

  const filtered = useMemo(() => {
    const items = query.data ?? [];
    const q = search.trim().toLowerCase();
    if (!q) return items;
    return items.filter((pb) => {
      const tags = parseTags(pb.tags).join(' ').toLowerCase();
      return (
        pb.name.toLowerCase().includes(q) ||
        (pb.description ?? '').toLowerCase().includes(q) ||
        pb.filename.toLowerCase().includes(q) ||
        tags.includes(q)
      );
    });
  }, [query.data, search]);

  async function handleDelete(pb: Playbook) {
    const ok = await confirm({
      title: 'Delete playbook',
      message: `Delete playbook "${pb.name}"? This cannot be undone.`,
      confirmLabel: 'Delete',
    });
    if (!ok) return;
    await deleting.run(pb.id, async () => {
      try {
        await deleteMut.mutateAsync(pb.id);
      } catch (e) {
        void alert({ message: (e as Error).message, variant: 'error' });
      }
    });
  }

  return (
    <div>
      <div className="toolbar">
        <input
          className="form-input"
          placeholder="Search playbooks…"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          style={{ width: 240 }}
        />
        <span className="toolbar-spacer" />
        <button className="btn btn-primary" onClick={() => setEditing({ mode: 'create' })}>+ New Playbook</button>
      </div>

      {query.error && !query.data ? (
        <QueryError what="playbooks" query={query} />
      ) : (
        query.isPending && <LoadingState />
      )}
      {query.data && (filtered.length === 0 ? (
        <EmptyState message="No playbooks" />
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
          {filtered.map((pb) => (
            <PlaybookRow
              key={pb.id}
              pb={pb}
              onEdit={() => setEditing({ mode: 'edit', id: pb.id })}
              isDeleting={deleting.isPending(pb.id)}
              onDelete={() => void handleDelete(pb)}
            />
          ))}
        </div>
      ))}

      {editing && (
        <Suspense fallback={null}>
          <PlaybookFormModal
            mode={editing.mode}
            playbookId={editing.mode === 'edit' ? editing.id : null}
            onClose={() => setEditing(null)}
          />
        </Suspense>
      )}
    </div>
  );
}

function PlaybookRow({
  pb,
  isDeleting,
  onEdit,
  onDelete,
}: {
  pb: Playbook;
  isDeleting: boolean;
  onEdit: () => void;
  onDelete: () => void;
}) {
  const tags = parseTags(pb.tags);
  const isAnsible = pb.type === 'ansible';
  return (
    <div className="card card-sm" style={{ display: 'flex', justifyContent: 'space-between', gap: 'var(--space-4)', alignItems: 'center' }}>
      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', flexWrap: 'wrap' }}>
          <Badge tone={isAnsible ? 'info' : 'primary'}>{isAnsible ? 'Ansible' : 'Python'}</Badge>
          <span style={{ fontWeight: 600 }}>{pb.name}</span>
          {tags.map((tag) => (
            <span key={tag} className="badge badge-secondary">{tag}</span>
          ))}
        </div>
        {pb.description && <div className="text-muted" style={{ marginTop: '0.25rem', fontSize: '0.9rem' }}>{pb.description}</div>}
        <div className="text-muted" style={{ fontSize: '0.75rem', marginTop: '0.25rem' }}>File: {pb.filename}</div>
      </div>
      <div style={{ display: 'flex', gap: '0.4rem' }}>
        <button className="btn btn-sm btn-secondary" onClick={onEdit}>Edit</button>
        <DeleteButton busy={isDeleting} onClick={onDelete} />
      </div>
    </div>
  );
}
