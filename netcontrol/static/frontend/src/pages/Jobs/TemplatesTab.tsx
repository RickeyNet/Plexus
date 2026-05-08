import { useMemo, useState } from 'react';

import {
  useDeleteTemplate,
  useTemplates,
  type ConfigTemplate,
} from '@/api/jobs';

import { TemplateFormModal } from './TemplateFormModal';

export function TemplatesTab() {
  const query = useTemplates();
  const deleteMut = useDeleteTemplate();
  const [search, setSearch] = useState('');
  const [editing, setEditing] = useState<{ mode: 'create' } | { mode: 'edit'; id: number } | null>(null);
  const [expanded, setExpanded] = useState<Set<number>>(new Set());

  const filtered = useMemo(() => {
    const items = query.data ?? [];
    const q = search.trim().toLowerCase();
    if (!q) return items;
    return items.filter((t) =>
      t.name.toLowerCase().includes(q) ||
      (t.description ?? '').toLowerCase().includes(q) ||
      t.content.toLowerCase().includes(q),
    );
  }, [query.data, search]);

  function handleDelete(id: number) {
    if (!confirm('Delete this template?')) return;
    deleteMut.mutate(id, { onError: (e) => alert((e as Error).message) });
  }

  function copyContent(content: string) {
    navigator.clipboard.writeText(content).catch(() => alert('Copy failed'));
  }

  function toggleExpand(id: number) {
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id); else next.add(id);
      return next;
    });
  }

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', flexWrap: 'wrap', gap: '0.5rem', marginBottom: '0.75rem' }}>
        <input
          className="form-input"
          placeholder="Search templates…"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          style={{ width: 240 }}
        />
        <button className="btn btn-primary" onClick={() => setEditing({ mode: 'create' })}>+ New Template</button>
      </div>

      {query.isPending && <p className="text-muted">Loading…</p>}
      {query.error && <p style={{ color: 'var(--danger)' }}>Failed: {(query.error as Error).message}</p>}
      {query.data && (filtered.length === 0 ? (
        <div className="empty-state">No templates</div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
          {filtered.map((t) => (
            <TemplateRow
              key={t.id}
              template={t}
              expanded={expanded.has(t.id)}
              onToggle={() => toggleExpand(t.id)}
              onCopy={() => copyContent(t.content)}
              onEdit={() => setEditing({ mode: 'edit', id: t.id })}
              onDelete={() => handleDelete(t.id)}
            />
          ))}
        </div>
      ))}

      <TemplateFormModal
        mode={editing?.mode ?? null}
        templateId={editing?.mode === 'edit' ? editing.id : null}
        onClose={() => setEditing(null)}
      />
    </div>
  );
}

function TemplateRow({
  template, expanded, onToggle, onCopy, onEdit, onDelete,
}: {
  template: ConfigTemplate;
  expanded: boolean;
  onToggle: () => void;
  onCopy: () => void;
  onEdit: () => void;
  onDelete: () => void;
}) {
  const lines = template.content.split('\n');
  const isLong = lines.length > 3;
  const visible = expanded || !isLong ? template.content : lines.slice(0, 3).join('\n');
  return (
    <div className="card" style={{ padding: '0.75rem 1rem' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', gap: '1rem', alignItems: 'flex-start', flexWrap: 'wrap' }}>
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ fontWeight: 600 }}>{template.name}</div>
          {template.description && <div className="text-muted" style={{ fontSize: '0.85rem' }}>{template.description}</div>}
        </div>
        <div style={{ display: 'flex', gap: '0.4rem', flexWrap: 'wrap' }}>
          <button className="btn btn-sm btn-secondary" onClick={onCopy}>Copy</button>
          {isLong && <button className="btn btn-sm btn-secondary" onClick={onToggle}>{expanded ? 'Collapse' : 'Expand'}</button>}
          <button className="btn btn-sm btn-secondary" onClick={onEdit}>Edit</button>
          <button className="btn btn-sm btn-danger" onClick={onDelete}>Delete</button>
        </div>
      </div>
      <pre
        tabIndex={0}
        style={{
          marginTop: '0.5rem',
          background: 'var(--bg-secondary)',
          padding: '0.5rem',
          borderRadius: 4,
          fontFamily: 'monospace',
          fontSize: '0.82rem',
          maxHeight: expanded ? 'none' : '5em',
          overflow: 'auto',
          whiteSpace: 'pre',
          userSelect: 'text',
          cursor: 'text',
        }}
      >
        {visible}
      </pre>
    </div>
  );
}
