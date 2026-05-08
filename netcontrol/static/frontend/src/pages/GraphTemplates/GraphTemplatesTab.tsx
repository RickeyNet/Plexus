import { useMemo, useState } from 'react';

import { useGraphTemplates, type GraphTemplate } from '@/api/graphTemplates';

import { GraphTemplateDetailModal } from './GraphTemplateDetailModal';
import { GraphTemplateCreateModal } from './GraphTemplateCreateModal';

const CATEGORIES = [
  { value: '', label: 'All categories' },
  { value: 'system', label: 'System' },
  { value: 'traffic', label: 'Traffic' },
  { value: 'availability', label: 'Availability' },
  { value: 'custom', label: 'Custom' },
];

export function GraphTemplatesTab() {
  const query = useGraphTemplates();
  const [category, setCategory] = useState('');
  const [search, setSearch] = useState('');
  const [detailId, setDetailId] = useState<number | null>(null);
  const [creating, setCreating] = useState(false);

  const items: GraphTemplate[] = useMemo(() => {
    let list = query.data?.graph_templates ?? [];
    if (category) list = list.filter((t) => t.category === category);
    if (search) {
      const q = search.toLowerCase();
      list = list.filter(
        (t) =>
          (t.name || '').toLowerCase().includes(q) ||
          (t.category || '').toLowerCase().includes(q),
      );
    }
    return list;
  }, [query.data, category, search]);

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', flexWrap: 'wrap', gap: '0.75rem', alignItems: 'flex-end', marginBottom: '0.75rem' }}>
        <div style={{ display: 'flex', gap: '0.75rem', flexWrap: 'wrap' }}>
          <div className="form-group" style={{ marginBottom: 0 }}>
            <label className="form-label">Category</label>
            <select className="form-select" value={category} onChange={(e) => setCategory(e.target.value)}>
              {CATEGORIES.map((c) => <option key={c.value} value={c.value}>{c.label}</option>)}
            </select>
          </div>
          <div className="form-group" style={{ marginBottom: 0, minWidth: 220 }}>
            <label className="form-label">Search</label>
            <input className="form-input" value={search} onChange={(e) => setSearch(e.target.value)} placeholder="Filter…" />
          </div>
        </div>
        <button className="btn btn-primary" onClick={() => setCreating(true)}>+ New Template</button>
      </div>

      {query.isPending && <p className="text-muted">Loading…</p>}
      {query.error && <p style={{ color: 'var(--danger)' }}>Failed: {(query.error as Error).message}</p>}
      {query.data && (items.length === 0 ? (
        <div className="empty-state">No graph templates match the current filter.</div>
      ) : (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(320px, 1fr))', gap: '1rem' }}>
          {items.map((t) => (
            <button
              key={t.id}
              type="button"
              className="card"
              style={{ textAlign: 'left', padding: '1rem', cursor: 'pointer', border: 'none' }}
              onClick={() => setDetailId(t.id)}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.5rem' }}>
                <h4 style={{ margin: 0 }}>{t.name}</h4>
                {t.built_in && <span className="badge badge-info" style={{ fontSize: '0.7rem' }}>Built-in</span>}
              </div>
              <p className="text-muted" style={{ margin: '0 0 0.5rem', fontSize: '0.85rem' }}>
                {t.description || 'No description'}
              </p>
              <div style={{ display: 'flex', gap: '0.75rem', fontSize: '0.8rem' }}>
                <span>{t.scope}</span>
                <span className="badge badge-secondary">{t.category}</span>
                <span>{t.graph_type}</span>
              </div>
            </button>
          ))}
        </div>
      ))}

      <GraphTemplateDetailModal templateId={detailId} onClose={() => setDetailId(null)} />
      <GraphTemplateCreateModal isOpen={creating} onClose={() => setCreating(false)} />
    </div>
  );
}
