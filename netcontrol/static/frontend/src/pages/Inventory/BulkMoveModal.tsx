import { FormEvent, useState } from 'react';

import { Modal } from '@/components/Modal';
import { useDialogs } from '@/components/DialogProvider-context';
import { type InventoryGroupFull, useMoveHosts } from '@/api/inventory';

interface Props {
  hostIds: number[];
  sourceGroupId: number;
  groups: InventoryGroupFull[];
  onClose: () => void;
}

export function BulkMoveModal({ hostIds, sourceGroupId, groups, onClose }: Props) {
  const { alert } = useDialogs();
  const move = useMoveHosts();
  const candidates = groups.filter((g) => g.id !== sourceGroupId);
  const [targetGroupId, setTargetGroupId] = useState<number>(
    candidates[0]?.id ?? 0,
  );

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (!targetGroupId) return;
    try {
      await move.mutateAsync({ hostIds, targetGroupId });
      onClose();
    } catch (err) {
      void alert({ message: (err as Error).message, variant: 'error' });
    }
  };

  return (
    <Modal
      isOpen
      onClose={onClose}
      title={`Move ${hostIds.length} Host(s)`}
    >
      {candidates.length === 0 ? (
        <>
          <p className="text-muted">
            No other groups available to move hosts to.
          </p>
          <div
            style={{
              display: 'flex',
              justifyContent: 'flex-end',
              marginTop: '1rem',
            }}
          >
            <button type="button" className="btn btn-secondary" onClick={onClose}>
              Close
            </button>
          </div>
        </>
      ) : (
        <form onSubmit={submit}>
          <div className="form-group">
            <label className="form-label">Destination Group</label>
            <select
              className="form-select"
              value={String(targetGroupId)}
              onChange={(e) => setTargetGroupId(Number(e.target.value))}
              required
            >
              {candidates.map((g) => (
                <option key={g.id} value={g.id}>
                  {g.name}
                </option>
              ))}
            </select>
          </div>
          <div
            style={{
              display: 'flex',
              gap: '0.5rem',
              justifyContent: 'flex-end',
              marginTop: '1rem',
            }}
          >
            <button type="button" className="btn btn-secondary" onClick={onClose}>
              Cancel
            </button>
            <button
              type="submit"
              className="btn btn-primary"
              disabled={move.isPending}
            >
              {move.isPending ? 'Moving…' : 'Move'}
            </button>
          </div>
        </form>
      )}
    </Modal>
  );
}
