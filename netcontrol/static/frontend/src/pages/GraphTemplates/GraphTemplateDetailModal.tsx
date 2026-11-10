import { useState } from 'react';

import { Callout } from '@/components/Callout';
import { DeleteButton } from '@/components/DeleteButton';
import { EmptyState } from '@/components/EmptyState';
import { LoadingState } from '@/components/LoadingState';
import { Modal } from '@/components/Modal';
import { useDialogs } from '@/components/DialogProvider-context';
import {
  useDeleteGraphTemplate,
  useDeleteGraphTemplateItem,
  useGraphTemplate,
  type GraphTemplateItem,
} from '@/api/graphTemplates';

import { GraphTemplateFormModal } from './GraphTemplateFormModal';
import { GraphTemplateItemModal } from './GraphTemplateItemModal';

interface Props {
  templateId: number | null;
  onClose: () => void;
}

export function GraphTemplateDetailModal({ templateId, onClose }: Props) {
  const { confirm, alert } = useDialogs();
  const isOpen = templateId != null;
  const query = useGraphTemplate(templateId);
  const deleteMut = useDeleteGraphTemplate();
  const deleteItemMut = useDeleteGraphTemplateItem();
  const [editing, setEditing] = useState(false);
  // The series dialog: 'new' to add one, a series to edit it, null when closed.
  const [itemForm, setItemForm] = useState<GraphTemplateItem | 'new' | null>(null);

  async function handleDelete() {
    const tpl = query.data;
    if (!tpl) return;
    if (
      !(await confirm({
        title: 'Delete graph template',
        message: `Delete graph template "${tpl.name}"? This will also remove all host graph instances using it.`,
        confirmLabel: 'Delete',
      }))
    )
      return;
    deleteMut.mutate(tpl.id, {
      onSuccess: onClose,
      onError: (err) => { void alert({ message: (err as Error).message, variant: 'error' }); },
    });
  }

  async function handleDeleteItem(item: GraphTemplateItem) {
    if (templateId == null) return;
    if (
      !(await confirm({
        title: 'Delete data series',
        message: `Delete data series "${item.label || item.metric_name}"?`,
        confirmLabel: 'Delete',
      }))
    )
      return;
    deleteItemMut.mutate(
      { templateId, itemId: item.id },
      { onError: (err) => { void alert({ message: (err as Error).message, variant: 'error' }); } },
    );
  }

  const tpl = query.data;
  const editable = !!tpl && !tpl.built_in;
  const items = tpl?.items ?? [];
  const nextSortOrder = items.reduce((max, i) => Math.max(max, i.sort_order ?? 0), -1) + 1;

  return (
    <Modal
      isOpen={isOpen}
      onClose={onClose}
      title={tpl?.name ?? 'Graph Template'}
      size="medium"
      footer={
        <>
          {editable && (
            <DeleteButton
              size="md"
              className="modal-footer-start"
              onClick={handleDelete}
              disabled={deleteMut.isPending}
              busy={deleteMut.isPending}
            />
          )}
          {editable && (
            <button type="button" className="btn btn-secondary" onClick={() => setEditing(true)}>Edit</button>
          )}
          <button type="button" className="btn btn-secondary" onClick={onClose}>Close</button>
        </>
      }
    >
      {query.isPending && <LoadingState />}
      {query.error && <Callout tone="danger">Failed: {(query.error as Error).message}</Callout>}
      {tpl && (
        <>
          <p>{tpl.description || ''}</p>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.5rem', marginBottom: '1rem', fontSize: '0.85rem' }}>
            <div><strong>Type:</strong> {tpl.graph_type}</div>
            <div><strong>Scope:</strong> {tpl.scope}</div>
            <div><strong>Category:</strong> {tpl.category}</div>
            <div><strong>Y-Axis:</strong> {tpl.y_axis_label || '-'}</div>
            <div><strong>Stacked:</strong> {tpl.stacked ? 'Yes' : 'No'}</div>
            <div><strong>Area Fill:</strong> {tpl.area_fill ? 'Yes' : 'No'}</div>
            <div><strong>Grid Size:</strong> {tpl.grid_w ?? 0}x{tpl.grid_h ?? 0}</div>
            <div><strong>Built-in:</strong> {tpl.built_in ? 'Yes' : 'No'}</div>
          </div>
          {tpl.built_in && (
            <Callout tone="info">
              Built-in templates ship with Plexus and are read-only. Create a new template to plot a different set of series.
            </Callout>
          )}
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <h4>Data Series ({items.length})</h4>
            {editable && (
              <button type="button" className="btn btn-sm btn-primary" onClick={() => setItemForm('new')}>+ Add Series</button>
            )}
          </div>
          {items.length ? (
            <table className="data-table">
              <thead>
                <tr>
                  <th>Label</th><th>Metric</th><th>Type</th><th>Color</th><th>Consolidation</th><th>Sort</th>
                  {editable && <th>Actions</th>}
                </tr>
              </thead>
              <tbody>
                {items.map((i) => (
                  <tr key={i.id}>
                    <td>{i.label}</td>
                    <td><code>{i.metric_name}</code></td>
                    <td>{i.line_type}</td>
                    <td>
                      <span style={{ display: 'inline-block', width: 16, height: 16, borderRadius: 3, background: i.color, verticalAlign: 'middle' }} />{' '}
                      {i.color}
                    </td>
                    <td>{i.consolidation}</td>
                    <td>{i.sort_order}</td>
                    {editable && (
                      <td style={{ whiteSpace: 'nowrap', textAlign: 'right' }}>
                        <button
                          type="button"
                          className="btn btn-sm btn-secondary"
                          onClick={() => setItemForm(i)}
                          aria-label={`Edit data series ${i.label || i.metric_name}`}
                        >
                          Edit
                        </button>{' '}
                        <DeleteButton
                          onClick={() => handleDeleteItem(i)}
                          disabled={deleteItemMut.isPending}
                          busy={deleteItemMut.isPending && deleteItemMut.variables?.itemId === i.id}
                          aria-label={`Delete data series ${i.label || i.metric_name}`}
                        />
                      </td>
                    )}
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <EmptyState
              compact
              message={editable ? 'No data series yet. Add a series to give this template something to plot.' : 'No data series defined.'}
            />
          )}
        </>
      )}

      {templateId != null && (
        <GraphTemplateFormModal
          mode={editing ? 'edit' : null}
          templateId={templateId}
          onClose={() => setEditing(false)}
        />
      )}
      {templateId != null && itemForm != null && (
        <GraphTemplateItemModal
          key={itemForm === 'new' ? 'new' : itemForm.id}
          templateId={templateId}
          item={itemForm === 'new' ? null : itemForm}
          nextSortOrder={nextSortOrder}
          onClose={() => setItemForm(null)}
        />
      )}
    </Modal>
  );
}
