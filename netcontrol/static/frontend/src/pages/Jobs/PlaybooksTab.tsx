import { useMemo, useState } from 'react';

import { useDeletePlaybook, usePlaybooks, type Playbook } from '@/api/jobs';

import { parseTags } from './helpers';
import { PlaybookFormModal } from './PlaybookFormModal';

export function PlaybooksTab() {
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

  function handleDelete(id: number) {
    if (!confirm('Delete this playbook? This cannot be undone.')) return;
    deleteMut.mutate(id, { onError: (e) => alert((e as Error).message) });
  }

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', flexWrap: 'wrap', gap: '0.5rem', marginBottom: '0.75rem' }}>
        <input
          className="form-input"
          placeholder="Search playbooks…"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          style={{ width: 240 }}
        />
        <button className="btn btn-primary" onClick={() => setEditing({ mode: 'create' })}>+ New Playbook</button>
      </div>

      {query.isPending && <p className="text-muted">Loading…</p>}
      {query.error && <p style={{ color: 'var(--danger)' }}>Failed: {(query.error as Error).message}</p>}
      {query.data && (filtered.length === 0 ? (
        <div className="empty-state">No playbooks</div>
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

      <PlaybookFormModal
        mode={editing?.mode ?? null}
        playbookId={editing?.mode === 'edit' ? editing.id : null}
        onClose={() => setEditing(null)}
      />
    </div>
  );
}

function PlaybookRow({ pb, onEdit, onDelete }: { pb: Playbook; onEdit: () => void; onDelete: () => void }) {
  const tags = parseTags(pb.tags);
  const isAnsible = pb.type === 'ansible';
  return (
    <div className="card" style={{ padding: '0.75rem 1rem', display: 'flex', justifyContent: 'space-between', gap: '1rem', alignItems: 'center' }}>
      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', flexWrap: 'wrap' }}>
          <span className="badge" style={{ background: isAnsible ? 'var(--info)' : 'var(--primary)', color: '#fff' }}>
            {isAnsible ? 'Ansible' : 'Python'}
          </span>
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
        <button className="btn btn-sm btn-danger" onClick={onDelete}>Delete</button>
      </div>
    </div>
  );
}
