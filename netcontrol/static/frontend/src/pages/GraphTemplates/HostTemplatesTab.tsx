import { useState } from 'react';

import { useDialogs } from '@/components/DialogProvider-context';
import {
  useDeleteHostTemplate,
  useHostTemplates,
  type HostTemplate,
} from '@/api/graphTemplates';

import { HostTemplateModal } from './HostTemplateModal';

export function HostTemplatesTab() {
  const { confirm, alert } = useDialogs();
  const query = useHostTemplates();
  const deleteMut = useDeleteHostTemplate();
  const [modalId, setModalId] = useState<number | 'new' | null>(null);

  const items: HostTemplate[] = query.data?.host_templates ?? [];

  async function handleDelete(id: number) {
    if (!(await confirm('Delete this host template?'))) return;
    deleteMut.mutate(id, {
      onError: (e) => { void alert({ message: (e as Error).message, variant: 'error' }); },
    });
  }

  function parseDeviceTypes(raw?: string): string[] {
    try {
      return JSON.parse(raw || '[]');
    } catch {
      return [];
    }
  }

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'flex-end', marginBottom: '0.75rem' }}>
        <button className="btn btn-primary" onClick={() => setModalId('new')}>+ New Host Template</button>
      </div>

      {query.isPending && <p className="text-muted">Loading…</p>}
      {query.error && <p style={{ color: 'var(--danger)' }}>Failed: {(query.error as Error).message}</p>}
      {query.data && (items.length === 0 ? (
        <div className="empty-state">No host templates configured.</div>
      ) : (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(320px, 1fr))', gap: '1rem' }}>
          {items.map((ht) => {
            const dtypes = parseDeviceTypes(ht.device_types);
            const dtLabel = dtypes.length ? dtypes.join(', ') : 'All devices';
            const gtCount = (ht.graph_templates ?? []).length;
            return (
              <div key={ht.id} className="card" style={{ padding: '1rem' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.5rem' }}>
                  <h4 style={{ margin: 0 }}>{ht.name}</h4>
                  <span className={`badge ${ht.auto_apply ? 'badge-success' : 'badge-secondary'}`}>
                    {ht.auto_apply ? 'Auto-apply' : 'Manual'}
                  </span>
                </div>
                <p className="text-muted" style={{ margin: '0 0 0.5rem', fontSize: '0.85rem' }}>{ht.description || ''}</p>
                <div style={{ display: 'flex', gap: '0.75rem', fontSize: '0.8rem' }}>
                  <span>Devices: {dtLabel}</span>
                  <span>{gtCount} graph template{gtCount !== 1 ? 's' : ''}</span>
                </div>
                {gtCount > 0 && (
                  <div style={{ marginTop: '0.5rem', fontSize: '0.8rem' }}>
                    {(ht.graph_templates ?? []).map((g) => (
                      <span key={g.id} className="badge badge-secondary" style={{ margin: '0.1rem' }}>{g.name}</span>
                    ))}
                  </div>
                )}
                <div style={{ display: 'flex', gap: '0.5rem', marginTop: '0.75rem' }}>
                  <button className="btn btn-sm btn-secondary" onClick={() => setModalId(ht.id)}>Edit</button>
                  <button className="btn btn-sm btn-danger" onClick={() => handleDelete(ht.id)}>Delete</button>
                </div>
              </div>
            );
          })}
        </div>
      ))}

      <HostTemplateModal
        mode={modalId === 'new' ? 'create' : modalId != null ? 'edit' : null}
        templateId={typeof modalId === 'number' ? modalId : null}
        onClose={() => setModalId(null)}
      />
    </div>
  );
}
