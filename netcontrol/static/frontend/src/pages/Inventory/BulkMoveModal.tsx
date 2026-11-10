import { FormEvent, useId, useState } from 'react';

import { Callout } from '@/components/Callout';
import { EmptyState } from '@/components/EmptyState';
import { Modal } from '@/components/Modal';
import { groupLabel, type InventoryGroupFull, useMoveHosts } from '@/api/inventory';

interface Props {
  hostIds: number[];
  sourceGroupId: number;
  groups: InventoryGroupFull[];
  onClose: () => void;
}

export function BulkMoveModal({ hostIds, sourceGroupId, groups, onClose }: Props) {
  const move = useMoveHosts();
  const formId = useId();
  const candidates = groups.filter((g) => g.id !== sourceGroupId);
  const [targetGroupId, setTargetGroupId] = useState<number>(
    candidates[0]?.id ?? 0,
  );
  const [error, setError] = useState<string | null>(null);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);
    if (!targetGroupId) return;
    try {
      await move.mutateAsync({ hostIds, targetGroupId });
      onClose();
    } catch (err) {
      setError((err as Error).message);
    }
  };

  return (
    <Modal
      isOpen
      onClose={onClose}
      title={`Move ${hostIds.length} Host(s)`}
      size="small"
      footer={
        candidates.length === 0 ? (
          <button type="button" className="btn btn-secondary" onClick={onClose}>
            Close
          </button>
        ) : (
          <>
            <button type="button" className="btn btn-secondary" onClick={onClose}>
              Cancel
            </button>
            <button
              type="submit"
              form={formId}
              className="btn btn-primary"
              disabled={move.isPending}
            >
              {move.isPending ? 'Moving…' : 'Move'}
            </button>
          </>
        )
      }
    >
      {candidates.length === 0 ? (
        <EmptyState compact message="No other groups available to move hosts to." />
      ) : (
        <form id={formId} onSubmit={submit}>
          {error && <Callout tone="danger">{error}</Callout>}
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
                  {groupLabel(g)}
                </option>
              ))}
            </select>
          </div>
        </form>
      )}
    </Modal>
  );
}
