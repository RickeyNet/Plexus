import { useId, useState } from 'react';

import { type TopologyMute, type TopologyMuteTarget, useMuteTopologyEntity } from '@/api/monitoring';
import { Callout } from '@/components/Callout';
import { Modal } from '@/components/Modal';
import { ModalActions } from '@/components/ModalActions';
import { sourceTypeLabel } from '@/pages/Topology/merakiHelpers';
import {
  MUTE_REASON_MAX,
  entityTypeLabel,
  isMuteReasonValid,
  muteEntityChoiceLabel,
  muteRequestBody,
  submitMute,
} from '@/pages/Dashboard/sourceHealth';

interface MuteEntityModalProps {
  target: TopologyMuteTarget;
  onClose: () => void;
}

/**
 * Mutes an integration entity, or everything at its site, with a reason. The
 * one mute dialog, opened from the Dashboard's integration problems and from
 * Monitoring -> Availability.
 */
export function MuteEntityModal({ target, onClose }: MuteEntityModalProps) {
  const fid = useId();
  const [scope, setScope] = useState<TopologyMute['scope']>('entity');
  const [reason, setReason] = useState('');
  const [error, setError] = useState<string | null>(null);
  const mute = useMuteTopologyEntity();

  async function handleMute() {
    setError(null);
    setError(await submitMute(mute.mutateAsync, muteRequestBody(target, scope, reason), onClose));
  }

  return (
    <Modal
      isOpen
      onClose={onClose}
      title="Mute alerts"
      size="small"
      footer={
        <ModalActions
          onClose={onClose}
          primaryLabel="Mute"
          primaryDisabled={!isMuteReasonValid(reason)}
          primaryBusy={mute.isPending}
          primaryBusyLabel="Muting…"
          onPrimary={() => void handleMute()}
        />
      }
    >
      <div className="stack">
        {error && <Callout tone="danger">{error}</Callout>}
        <div>
          {entityTypeLabel(target.entity_type)} <strong>{target.name}</strong>{' '}
          <span className="text-muted">({sourceTypeLabel(target.provider)})</span>
        </div>
        <div role="radiogroup" aria-label="What to mute" style={{ display: 'grid', gap: 'var(--space-1)' }}>
          <label style={{ display: 'flex', gap: 'var(--space-2)', alignItems: 'center' }}>
            <input
              type="radio"
              name={`${fid}-scope`}
              value="entity"
              checked={scope === 'entity'}
              onChange={() => setScope('entity')}
            />
            {muteEntityChoiceLabel(target.entity_type)}
          </label>
          {target.site && (
            <label style={{ display: 'flex', gap: 'var(--space-2)', alignItems: 'center' }}>
              <input
                type="radio"
                name={`${fid}-scope`}
                value="site"
                checked={scope === 'site'}
                onChange={() => setScope('site')}
              />
              Everything at site {target.site}
            </label>
          )}
        </div>
        <div className="form-group">
          <label className="form-label" htmlFor={`${fid}-reason`}>
            Reason
          </label>
          <input
            id={`${fid}-reason`}
            className="form-input"
            required
            maxLength={MUTE_REASON_MAX}
            value={reason}
            onChange={(e) => setReason(e.target.value)}
            autoFocus
          />
        </div>
        <p className="text-muted" style={{ margin: 0, fontSize: 'var(--text-sm)' }}>
          Muted entities are left off the Dashboard and send no notifications until unmuted.
        </p>
      </div>
    </Modal>
  );
}
