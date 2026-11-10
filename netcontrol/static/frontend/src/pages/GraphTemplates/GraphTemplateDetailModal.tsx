import { Callout } from '@/components/Callout';
import { DeleteButton } from '@/components/DeleteButton';
import { EmptyState } from '@/components/EmptyState';
import { LoadingState } from '@/components/LoadingState';
import { Modal } from '@/components/Modal';
import { useDialogs } from '@/components/DialogProvider-context';
import {
  useDeleteGraphTemplate,
  useGraphTemplate,
} from '@/api/graphTemplates';

interface Props {
  templateId: number | null;
  onClose: () => void;
}

export function GraphTemplateDetailModal({ templateId, onClose }: Props) {
  const { confirm, alert } = useDialogs();
  const isOpen = templateId != null;
  const query = useGraphTemplate(templateId);
  const deleteMut = useDeleteGraphTemplate();

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

  return (
    <Modal
      isOpen={isOpen}
      onClose={onClose}
      title={query.data?.name ?? 'Graph Template'}
      size="medium"
      footer={
        <>
          {query.data && !query.data.built_in && (
            <DeleteButton
              size="md"
              className="modal-footer-start"
              onClick={handleDelete}
              disabled={deleteMut.isPending}
              busy={deleteMut.isPending}
            />
          )}
          <button type="button" className="btn btn-secondary" onClick={onClose}>Close</button>
        </>
      }
    >
      {query.isPending && <LoadingState />}
      {query.error && <Callout tone="danger">Failed: {(query.error as Error).message}</Callout>}
      {query.data && (() => {
        const tpl = query.data;
        const items = tpl.items ?? [];
        return (
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
            <h4>Data Series ({items.length})</h4>
            {items.length ? (
              <table className="data-table">
                <thead>
                  <tr><th>Label</th><th>Metric</th><th>Type</th><th>Color</th><th>Consolidation</th></tr>
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
                    </tr>
                  ))}
                </tbody>
              </table>
            ) : <EmptyState compact message="No data series defined." />}
          </>
        );
      })()}
    </Modal>
  );
}
