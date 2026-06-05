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

  async function handleDelete(id: number) {
    if (!(await confirm('Delete this graph template? This will also remove all host graph instances using it.'))) return;
    deleteMut.mutate(id, {
      onSuccess: onClose,
      onError: (err) => { void alert({ message: (err as Error).message, variant: 'error' }); },
    });
  }

  return (
    <Modal isOpen={isOpen} onClose={onClose} title={query.data?.name ?? 'Graph Template'} size="large">
      {query.isPending && <p className="text-muted">Loading…</p>}
      {query.error && <p style={{ color: 'var(--danger)' }}>Failed: {(query.error as Error).message}</p>}
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
            ) : <p className="text-muted">No data series defined.</p>}
            <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: '1rem' }}>
              {!tpl.built_in ? (
                <button className="btn btn-danger" onClick={() => handleDelete(tpl.id)} disabled={deleteMut.isPending}>
                  {deleteMut.isPending ? 'Deleting…' : 'Delete'}
                </button>
              ) : <span />}
              <button className="btn btn-secondary" onClick={onClose}>Close</button>
            </div>
          </>
        );
      })()}
    </Modal>
  );
}
