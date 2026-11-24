import { useId, useState } from 'react';

import { groupLabel } from '@/api/inventory';
import { useCredentials, useInventoryGroups } from '@/api/compliance';
import {
  useStartCaptureGroupJob,
  useStartCaptureSingleJob,
} from '@/api/configuration';
import { Callout } from '@/components/Callout';
import { FieldError } from '@/components/FieldError';
import { Modal } from '@/components/Modal';
import { QueryError } from '@/components/QueryError';
import { useObjectScope } from '@/lib/objectScope';

import { NO_CREDENTIAL, type PolicyCredentialChoice, policyCredentialId } from './helpers';

interface Props {
  onClose: () => void;
  onJobStarted: (jobId: string) => void;
}

export function CaptureSnapshotModal({ onClose, onJobStarted }: Props) {
  const groups = useInventoryGroups(true);
  // Capturing writes snapshots: a limited account picks from the groups
  // (and their hosts) it may change.
  const { writableGroups } = useObjectScope();
  const groupChoices = writableGroups(groups.data || []);
  const creds = useCredentials();
  const single = useStartCaptureSingleJob();
  const group = useStartCaptureGroupJob();
  const [hostId, setHostId] = useState<number | null>(null);
  const [groupId, setGroupId] = useState<number | null>(null);
  // null: nothing chosen yet; NO_CREDENTIAL: OPNsense firewalls only (their
  // snapshot is their config.xml backup, never read over SSH).
  const [credId, setCredId] = useState<PolicyCredentialChoice>(null);
  const [targetError, setTargetError] = useState<string | null>(null);
  const [credError, setCredError] = useState<string | null>(null);
  const [saveError, setSaveError] = useState<string | null>(null);
  const formId = useId();

  const hosts = groupChoices.flatMap((g) => g.hosts || []);

  const isPending = single.isPending || group.isPending;

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setSaveError(null);
    const missingTarget = !hostId && !groupId;
    setTargetError(missingTarget ? 'Please select a host or group' : null);
    setCredError(credId == null ? 'Choose a credential, or None for OPNsense firewalls only' : null);
    if (missingTarget || credId == null) return;
    const credentialId = policyCredentialId(credId);
    const onSuccess = (res: { job_id: string }) => {
      onClose();
      onJobStarted(res.job_id);
    };
    const onError = (err: unknown) => setSaveError((err as Error).message);
    if (groupId) {
      group.mutate({ groupId, credentialId }, { onSuccess, onError });
    } else if (hostId) {
      single.mutate({ hostId, credentialId }, { onSuccess, onError });
    }
  };

  return (
    <Modal
      isOpen
      onClose={onClose}
      title="Capture Running Config"
      footer={
        <>
          <button type="button" className="btn btn-secondary" onClick={onClose}>
            Cancel
          </button>
          <button
            type="submit"
            form={formId}
            className="btn btn-primary"
            disabled={isPending}
          >
            {isPending ? 'Starting…' : 'Capture'}
          </button>
        </>
      }
    >
      <form id={formId} onSubmit={handleSubmit}>
        {saveError && <Callout tone="danger">{saveError}</Callout>}
        {groups.isError && !groups.data && (
          <QueryError what="inventory groups" query={groups} />
        )}
        {creds.isError && !creds.data && (
          <QueryError what="credentials" query={creds} />
        )}
        <div className="form-group">
          <label className="form-label" htmlFor={`${formId}-host`}>Single Host</label>
          <select
            id={`${formId}-host`}
            className="form-select"
            value={hostId ?? ''}
            onChange={(e) => {
              setHostId(e.target.value ? Number(e.target.value) : null);
              if (e.target.value) setGroupId(null);
              setTargetError(null);
            }}
            aria-invalid={!!targetError}
          >
            <option value="">Select a host…</option>
            {hosts.map((h) => (
              <option key={h.id} value={h.id}>
                {h.hostname} ({h.ip_address})
              </option>
            ))}
          </select>
        </div>
        <div className="form-group">
          <label className="form-label" htmlFor={`${formId}-group`}>Or Entire Group</label>
          <select
            id={`${formId}-group`}
            className="form-select"
            value={groupId ?? ''}
            onChange={(e) => {
              setGroupId(e.target.value ? Number(e.target.value) : null);
              if (e.target.value) setHostId(null);
              setTargetError(null);
            }}
            aria-invalid={!!targetError}
          >
            <option value="">- Or select entire group -</option>
            {groupChoices.map((g) => (
              <option key={g.id} value={g.id}>
                {groupLabel(g)} ({(g.hosts || []).length} hosts)
              </option>
            ))}
          </select>
          <FieldError>{targetError}</FieldError>
        </div>
        <div className="form-group">
          <label className="form-label" htmlFor={`${formId}-credential`}>Credentials</label>
          <select
            id={`${formId}-credential`}
            className="form-select"
            value={credId ?? ''}
            onChange={(e) => {
              const value = e.target.value;
              setCredId(value === NO_CREDENTIAL ? NO_CREDENTIAL : value ? Number(value) : null);
              setCredError(null);
            }}
            aria-invalid={!!credError}
            aria-describedby={`${formId}-credential-hint`}
            required
          >
            <option value="">Select credentials…</option>
            <option value={NO_CREDENTIAL}>None (OPNsense firewalls only)</option>
            {(creds.data || []).map((c) => (
              <option key={c.id} value={c.id}>
                {c.name}
              </option>
            ))}
          </select>
          <FieldError>{credError}</FieldError>
          <p
            id={`${formId}-credential-hint`}
            className="text-muted"
            style={{ fontSize: '0.85em', marginTop: '0.25rem' }}
          >
            Devices read over SSH use this credential. An OPNsense firewall is
            captured from its newest config.xml backup and needs none; with
            None, every SSH device of the group fails.
          </p>
        </div>
      </form>
    </Modal>
  );
}
