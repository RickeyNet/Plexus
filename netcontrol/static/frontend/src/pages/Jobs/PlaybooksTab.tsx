import { lazy, Suspense, useMemo, useState } from 'react';

import { Badge } from '@/components/Badge';
import { Callout } from '@/components/Callout';
import { DeleteButton } from '@/components/DeleteButton';
import { useDialogs } from '@/components/DialogProvider-context';
import { useDeletePlaybook, usePlaybooks, type Playbook } from '@/api/jobs';
import { EmptyState } from '@/components/EmptyState';
import { LoadingState } from '@/components/LoadingState';

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

  async function handleDelete(id: number) {
    if (!(await confirm('Delete this playbook? This cannot be undone.'))) return;
    deleteMut.mutate(id, { onError: (e) => { void alert({ message: (e as Error).message, variant: 'error' }); } });
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

      {query.isPending && <LoadingState />}
      {query.error && <Callout tone="danger">Failed: {(query.error as Error).message}</Callout>}
      {query.data && (filtered.length === 0 ? (
        <EmptyState message="No playbooks" />
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
          {filtered.map((pb) => (
            <PlaybookRow
              key={pb.id}
              pb={pb}
              onEdit={() => setEditing({ mode: 'edit', id: pb.id })}
              onDelete={() => handleDelete(pb.id)}
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

function PlaybookRow({ pb, onEdit, onDelete }: { pb: Playbook; onEdit: () => void; onDelete: () => void }) {
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
        <DeleteButton onClick={onDelete} />
      </div>
    </div>
  );
}
