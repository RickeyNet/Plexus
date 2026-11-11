import { useMemo, useState } from 'react';

import { CopyButton } from '@/components/CopyButton';
import { DeleteButton } from '@/components/DeleteButton';
import { useDialogs } from '@/components/DialogProvider-context';
import {
  useDeleteTemplate,
  useTemplates,
  type ConfigTemplate,
} from '@/api/jobs';
import { EmptyState } from '@/components/EmptyState';
import { LoadingState } from '@/components/LoadingState';
import { QueryError } from '@/components/QueryError';
import { usePendingKeys } from '@/lib/usePendingKeys';

import { TemplateFormModal } from './TemplateFormModal';

export function TemplatesTab() {
  const { confirm, alert } = useDialogs();
  const query = useTemplates();
  const deleteMut = useDeleteTemplate();
  const deleting = usePendingKeys<number>();
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
      (t.device_type ?? '').toLowerCase().includes(q) ||
      t.content.toLowerCase().includes(q),
    );
  }, [query.data, search]);

  async function handleDelete(t: ConfigTemplate) {
    const ok = await confirm({
      title: 'Delete instruction set',
      message: `Delete instruction set "${t.name}"?`,
      confirmLabel: 'Delete',
    });
    if (!ok) return;
    await deleting.run(t.id, async () => {
      try {
        await deleteMut.mutateAsync(t.id);
      } catch (e) {
        void alert({ message: (e as Error).message, variant: 'error' });
      }
    });
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
      <div className="toolbar">
        <input
          className="form-input"
          placeholder="Search instructions…"
          aria-label="Search instructions"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          style={{ width: 240 }}
        />
        <span className="toolbar-spacer" />
        <button className="btn btn-primary" onClick={() => setEditing({ mode: 'create' })}>+ New Instruction Set</button>
      </div>

      {query.error && !query.data ? (
        <QueryError what="instructions" query={query} />
      ) : (
        query.isPending && <LoadingState />
      )}
      {query.data && (filtered.length === 0 ? (
        <EmptyState message={search.trim() ? 'No matching instructions' : 'No instructions'} />
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
          {filtered.map((t) => (
            <TemplateRow
              key={t.id}
              template={t}
              expanded={expanded.has(t.id)}
              onToggle={() => toggleExpand(t.id)}
              onEdit={() => setEditing({ mode: 'edit', id: t.id })}
              isDeleting={deleting.isPending(t.id)}
              onDelete={() => void handleDelete(t)}
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
  template, expanded, isDeleting, onToggle, onEdit, onDelete,
}: {
  template: ConfigTemplate;
  expanded: boolean;
  onToggle: () => void;
  onEdit: () => void;
  isDeleting: boolean;
  onDelete: () => void;
}) {
  const lines = template.content.split('\n');
  const isLong = lines.length > 3;
  const visible = expanded || !isLong ? template.content : lines.slice(0, 3).join('\n');
  return (
    <div className="card card-sm">
      <div style={{ display: 'flex', justifyContent: 'space-between', gap: '1rem', alignItems: 'flex-start', flexWrap: 'wrap' }}>
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ fontWeight: 600 }}>
            {template.name}
            {template.device_type ? (
              <span
                className="badge"
                style={{ marginLeft: '0.5rem', fontSize: '0.7rem', fontWeight: 500 }}
              >
                {template.device_type}
              </span>
            ) : null}
          </div>
          {template.description && <div className="text-muted" style={{ fontSize: '0.85rem' }}>{template.description}</div>}
        </div>
        <div style={{ display: 'flex', gap: '0.4rem', flexWrap: 'wrap' }}>
          <CopyButton text={template.content} />
          {isLong && <button className="btn btn-sm btn-secondary" onClick={onToggle}>{expanded ? 'Collapse' : 'Expand'}</button>}
          <button className="btn btn-sm btn-secondary" onClick={onEdit}>Edit</button>
          <DeleteButton busy={isDeleting} onClick={onDelete} />
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
