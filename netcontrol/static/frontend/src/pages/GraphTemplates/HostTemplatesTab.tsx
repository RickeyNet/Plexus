import { useState } from 'react';

import { Callout } from '@/components/Callout';
import { DeleteButton } from '@/components/DeleteButton';
import { useDialogs } from '@/components/DialogProvider-context';
import {
  useDeleteHostTemplate,
  useHostTemplates,
  type HostTemplate,
} from '@/api/graphTemplates';
import { EmptyState } from '@/components/EmptyState';
import { LoadingState } from '@/components/LoadingState';

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
      <div className="toolbar" style={{ justifyContent: 'flex-end' }}>
        <button className="btn btn-primary" onClick={() => setModalId('new')}>+ New Host Template</button>
      </div>

      {query.isPending && <LoadingState />}
      {query.error && <Callout tone="danger">Failed: {(query.error as Error).message}</Callout>}
      {query.data && (items.length === 0 ? (
        <EmptyState message="No host templates configured." />
      ) : (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(320px, 1fr))', gap: '1rem' }}>
          {items.map((ht) => {
            const dtypes = parseDeviceTypes(ht.device_types);
            const dtLabel = dtypes.length ? dtypes.join(', ') : 'All devices';
            const gtCount = (ht.graph_templates ?? []).length;
            return (
              <div key={ht.id} className="card">
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
                  <DeleteButton onClick={() => handleDelete(ht.id)} />
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
