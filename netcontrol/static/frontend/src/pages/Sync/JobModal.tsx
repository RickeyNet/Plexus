import { useId, useState } from 'react';

import { type SyncJob, useSaveSyncJob, useSyncCatalog, useSyncConnections } from '@/api/sync';
import { SaveFailure } from '@/components/CatalogueParts';
import { Callout } from '@/components/Callout';
import { FieldError } from '@/components/FieldError';
import { Modal } from '@/components/Modal';
import { ModalActions } from '@/components/ModalActions';
import { serverFieldErrors } from '@/lib/serverFieldErrors';
import {
  DIRECTION_HELP,
  DIRECTION_LABEL,
  HOST_GROUP_MAX,
  INTERVAL_MAX,
  INTERVAL_MIN,
  type JobDraft,
  type JobErrors,
  KIND_LABEL,
  OBJECT_TYPES,
  OBJECT_TYPE_LABEL,
  POLICY_LABEL,
  SYNC_NAME_MAX,
  type SyncDirection,
  type SyncPolicy,
  emptyJobDraft,
  jobDraftOf,
  toJobInput,
  validateJob,
  writesPlexus,
} from '@/lib/sync';
import { TextField } from '@/pages/Circuits/parts';
import { CheckboxField } from '@/pages/Settings/FormFields';

interface JobModalProps {
  /** The job to edit; `null` adds one. */
  job: SyncJob | null;
  onClose: () => void;
}

/** Adds or edits a sync job. Saving does not run it. */
export function JobModal({ job, onClose }: JobModalProps) {
  const id = useId();
  const save = useSaveSyncJob();
  const connections = useSyncConnections();
  const catalog = useSyncCatalog();
  const [draft, setDraft] = useState<JobDraft>(() =>
    job ? jobDraftOf(job) : emptyJobDraft(connections.data?.[0]?.id ?? null),
  );
  const [touched, setTouched] = useState<Partial<Record<keyof JobErrors, boolean>>>({});
  const [failure, setFailure] = useState<string | null>(null);
  const [serverErrors, setServerErrors] = useState<Record<string, string>>({});

  const errors = validateJob(draft);
  const shown = (f: keyof JobErrors) => (touched[f] ? errors[f] : undefined) ?? serverErrors[f];
  const touch = (f: keyof JobErrors) => setTouched((t) => ({ ...t, [f]: true }));
  const set = (patch: Partial<JobDraft>) => {
    setDraft((d) => ({ ...d, ...patch }));
    setServerErrors({});
  };
  const connection = connections.data?.find((c) => c.id === draft.connection_id);
  const defaults = connection && catalog.data?.default_mappings[connection.kind];

  const toggleType = (type: (typeof OBJECT_TYPES)[number], on: boolean) => {
    touch('object_types');
    set({ object_types: on ? [...draft.object_types, type] : draft.object_types.filter((t) => t !== type) });
  };

  const submit = () => {
    setTouched({ name: true, connection_id: true, object_types: true, mappings: true, host_group: true, interval: true });
    if (Object.keys(errors).length > 0) return;
    setFailure(null);
    save.mutate(
      { id: job?.id ?? null, data: toJobInput(draft) },
      {
        onSuccess: onClose,
        onError: (err) => {
          const { interval_minutes, ...fields } = serverFieldErrors(err);
          if (interval_minutes) fields.interval = interval_minutes;
          setServerErrors(fields);
          if (!Object.keys(fields).length) setFailure(err.message);
        },
      },
    );
  };

  return (
    <Modal
      isOpen
      onClose={onClose}
      size="medium"
      title={job ? `Edit sync job ${job.name}` : 'Add sync job'}
      footer={
        <ModalActions
          onClose={onClose}
          primaryLabel={job ? 'Save job' : 'Add job'}
          primaryBusy={save.isPending}
          primaryBusyLabel="Saving…"
          onPrimary={submit}
        />
      }
    >
      <SaveFailure what="sync job" message={failure} />
      <div className="form-row">
        <div style={{ flex: '2 1 16rem' }} onBlur={() => touch('name')}>
          <TextField
            id={`${id}-name`}
            label="Name"
            value={draft.name}
            max={SYNC_NAME_MAX}
            autoFocus
            error={shown('name')}
            onChange={(name) => set({ name })}
          />
        </div>
        <div className="form-group" style={{ flex: '1 1 14rem' }}>
          <label className="form-label" htmlFor={`${id}-conn`}>
            Connection
          </label>
          <select
            id={`${id}-conn`}
            className="form-select"
            value={draft.connection_id ?? ''}
            aria-invalid={!!shown('connection_id')}
            aria-describedby={`${id}-conn-error`}
            onChange={(e) => set({ connection_id: e.target.value ? Number(e.target.value) : null })}
            onBlur={() => touch('connection_id')}
          >
            <option value="">Pick a connection</option>
            {(connections.data ?? []).map((c) => (
              <option key={c.id} value={c.id}>
                {c.name} ({KIND_LABEL[c.kind] ?? c.kind})
              </option>
            ))}
          </select>
          <FieldError id={`${id}-conn-error`}>{shown('connection_id')}</FieldError>
        </div>
      </div>

      <div className="form-row">
        <div className="form-group" style={{ flex: '1 1 14rem' }}>
          <label className="form-label" htmlFor={`${id}-dir`}>
            Direction
          </label>
          <select
            id={`${id}-dir`}
            className="form-select"
            value={draft.direction}
            aria-describedby={`${id}-dir-help`}
            onChange={(e) => set({ direction: e.target.value as SyncDirection })}
          >
            {(Object.keys(DIRECTION_LABEL) as SyncDirection[]).map((d) => (
              <option key={d} value={d}>
                {DIRECTION_LABEL[d]}
              </option>
            ))}
          </select>
          <div className="form-help" id={`${id}-dir-help`}>
            {DIRECTION_HELP[draft.direction]}
          </div>
        </div>
        {draft.direction === 'bidirectional' ? (
          <div className="form-group" style={{ flex: '1 1 12rem' }}>
            <label className="form-label" htmlFor={`${id}-policy`}>
              When both sides differ
            </label>
            <select
              id={`${id}-policy`}
              className="form-select"
              value={draft.conflict_policy}
              onChange={(e) => set({ conflict_policy: e.target.value as SyncPolicy })}
            >
              {(Object.keys(POLICY_LABEL) as SyncPolicy[]).map((p) => (
                <option key={p} value={p}>
                  {POLICY_LABEL[p]}
                </option>
              ))}
            </select>
          </div>
        ) : (
          <CheckboxField
            inRow
            label="Delete records missing from the source"
            checked={draft.delete_missing}
            onChange={(delete_missing) => set({ delete_missing })}
            help={`Deletes in ${draft.direction === 'import' ? 'Plexus' : 'the remote system'}; a run that would delete more than half the records holds them back.`}
          />
        )}
      </div>

      <div className="form-group" role="group" aria-labelledby={`${id}-types-label`}>
        <div className="form-label" id={`${id}-types-label`}>
          Object types
        </div>
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 'var(--space-1) var(--space-4)' }}>
          {OBJECT_TYPES.map((t) => (
            <CheckboxField
              key={t}
              label={OBJECT_TYPE_LABEL[t]}
              checked={draft.object_types.includes(t)}
              onChange={(on) => toggleType(t, on)}
            />
          ))}
        </div>
        <div className="form-help">Run in this order, so a device's site and device type exist before it.</div>
        <FieldError>{shown('object_types')}</FieldError>
      </div>

      {writesPlexus(draft.direction) && draft.object_types.includes('devices') && (
        <div onBlur={() => touch('host_group')}>
          <TextField
            id={`${id}-group`}
            label="Inventory group for new devices"
            value={draft.host_group}
            max={HOST_GROUP_MAX}
            help="A group path such as Synced / NetBox; created on the first real run."
            error={shown('host_group')}
            onChange={(host_group) => set({ host_group })}
          />
        </div>
      )}
      {writesPlexus(draft.direction) && draft.object_types.some((t) => t !== 'devices') && (
        <Callout tone="info">
          Writing sites, catalogues and IPAM records into Plexus needs admin rights; the data validation rules and the change
          log apply to every synced change.
        </Callout>
      )}

      <div className="form-row">
        <div className="form-group" style={{ flex: '0 1 12rem' }}>
          <label className="form-label" htmlFor={`${id}-interval`}>
            Run every (minutes)
          </label>
          <input
            id={`${id}-interval`}
            className="form-input"
            inputMode="numeric"
            value={draft.interval}
            aria-invalid={!!shown('interval')}
            aria-describedby={`${id}-interval-help ${id}-interval-error`}
            onChange={(e) => set({ interval: e.target.value })}
            onBlur={() => touch('interval')}
          />
          <div className="form-help" id={`${id}-interval-help`}>
            0 runs only by hand; else {INTERVAL_MIN} to {INTERVAL_MAX}.
          </div>
          <FieldError id={`${id}-interval-error`}>{shown('interval')}</FieldError>
        </div>
        <CheckboxField inRow label="Scheduled runs enabled" checked={draft.enabled} onChange={(enabled) => set({ enabled })} />
      </div>

      <TextField
        id={`${id}-desc`}
        label="Description"
        value={draft.description}
        max={1000}
        onChange={(description) => set({ description })}
      />

      <details>
        <summary>Field mappings (advanced)</summary>
        <div onBlur={() => touch('mappings')}>
          <TextField
            id={`${id}-map`}
            label="Mapping overrides (JSON)"
            value={draft.mappingsText}
            max={64 * 1024}
            multiline
            placeholder={'{"devices": {"role": true, "serial": "asset.serial"}, "vrfs": {"_endpoint": "u_cmdb_ci_vrf"}}'}
            help="Per object type: a field set to a remote path syncs at that path, true turns an optional field on at its default path, false leaves it out. _endpoint changes the API path or table, _create_defaults the values every create sends."
            error={shown('mappings')}
            onChange={(mappingsText) => set({ mappingsText })}
          />
        </div>
        {defaults && (
          <div className="card-inset" style={{ overflowX: 'auto' }}>
            <div className="text-muted" style={{ marginBottom: 'var(--space-2)' }}>
              Default mapping for {KIND_LABEL[connection.kind]}
            </div>
            <table className="data-table">
              <thead>
                <tr>
                  <th>Object type</th>
                  <th>Endpoint</th>
                  <th>Fields (field: remote path)</th>
                </tr>
              </thead>
              <tbody>
                {OBJECT_TYPES.filter((t) => draft.object_types.includes(t)).map((t) => (
                  <tr key={t}>
                    <td>{OBJECT_TYPE_LABEL[t]}</td>
                    <td>
                      <code>{defaults[t]?.endpoint || 'none: set _endpoint'}</code>
                    </td>
                    <td>
                      {Object.entries(defaults[t]?.paths ?? {}).map(([field, path]) => (
                        <div key={field}>
                          <code>
                            {field}: {path}
                          </code>
                          {defaults[t].optional.includes(field) && <span className="text-muted"> (off unless turned on)</span>}
                          {defaults[t].read_only.includes(field) && <span className="text-muted"> (read only)</span>}
                        </div>
                      ))}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </details>
    </Modal>
  );
}
