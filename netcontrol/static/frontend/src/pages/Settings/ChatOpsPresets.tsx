import { useId, useState } from 'react';

import {
  ChatJobPreset,
  useChatJobPresets,
  useCreateChatJobPreset,
  useDeleteChatJobPreset,
  useUpdateChatJobPreset,
} from '@/api/chatops';
import { Badge } from '@/components/Badge';
import { BusyButton } from '@/components/BusyButton';
import { Callout } from '@/components/Callout';
import { DataTable } from '@/components/DataTable';
import { useDialogs } from '@/components/DialogProvider-context';
import { EmptyState } from '@/components/EmptyState';
import { FieldError } from '@/components/FieldError';
import { LoadingState } from '@/components/LoadingState';
import { QueryError } from '@/components/QueryError';
import { PresetFormErrors, validatePreset } from '@/lib/chatops';
import { usePendingKeys } from '@/lib/usePendingKeys';

import { CheckboxField } from './FormFields';

function AddPresetForm() {
  const fid = useId();
  const create = useCreateChatJobPreset();
  const [name, setName] = useState('');
  const [jobId, setJobId] = useState('');
  const [description, setDescription] = useState('');
  const [commit, setCommit] = useState(false);
  const [errors, setErrors] = useState<PresetFormErrors>({});
  const [failure, setFailure] = useState<string | null>(null);

  return (
    <form
      onSubmit={(e) => {
        e.preventDefault();
        setFailure(null);
        const found = validatePreset({ name, jobId });
        setErrors(found);
        if (Object.keys(found).length) return;
        create.mutate(
          { name: name.trim(), job_id: Number(jobId), description: description.trim(), commit, enabled: true },
          {
            onSuccess: () => {
              setName('');
              setJobId('');
              setDescription('');
              setCommit(false);
            },
            onError: (err) => setFailure(`The preset was not added: ${(err as Error).message}`),
          },
        );
      }}
    >
      {failure && <Callout tone="danger">{failure}</Callout>}
      <div style={{ display: 'flex', gap: 'var(--space-3)', flexWrap: 'wrap', alignItems: 'flex-start' }}>
        <div className="form-group" style={{ flex: '1 1 180px' }}>
          <label className="form-label" htmlFor={`${fid}-name`}>Preset name</label>
          <input
            id={`${fid}-name`}
            className="form-input"
            value={name}
            aria-invalid={!!errors.name}
            aria-describedby={`${fid}-name-err`}
            onChange={(e) => {
              setErrors({ ...errors, name: undefined });
              setName(e.target.value);
            }}
          />
          <FieldError id={`${fid}-name-err`}>{errors.name}</FieldError>
        </div>
        <div className="form-group" style={{ flex: '0 1 140px' }}>
          <label className="form-label" htmlFor={`${fid}-job`}>Copy job #</label>
          <input
            id={`${fid}-job`}
            className="form-input"
            inputMode="numeric"
            value={jobId}
            aria-invalid={!!errors.jobId}
            aria-describedby={`${fid}-job-err`}
            onChange={(e) => {
              setErrors({ ...errors, jobId: undefined });
              setJobId(e.target.value);
            }}
          />
          <FieldError id={`${fid}-job-err`}>{errors.jobId}</FieldError>
        </div>
        <div className="form-group" style={{ flex: '2 1 220px' }}>
          <label className="form-label" htmlFor={`${fid}-desc`}>Description (optional)</label>
          <input
            id={`${fid}-desc`}
            className="form-input"
            value={description}
            onChange={(e) => setDescription(e.target.value)}
          />
        </div>
        <CheckboxField inRow label="Run with commit" checked={commit} onChange={setCommit} />
        <div className="form-group" style={{ alignSelf: 'flex-end' }}>
          <BusyButton type="submit" className="btn btn-primary" busy={create.isPending} busyLabel="Adding…">
            Add preset
          </BusyButton>
        </div>
      </div>
    </form>
  );
}

/** The allowlist of jobs chat may launch with /plexus run. */
export function ChatOpsPresets() {
  const { confirm, alert } = useDialogs();
  const presets = useChatJobPresets();
  const update = useUpdateChatJobPreset();
  const remove = useDeleteChatJobPreset();
  const pending = usePendingKeys<number>();
  const rows = presets.data ?? [];

  async function save(preset: ChatJobPreset, change: Partial<Pick<ChatJobPreset, 'commit' | 'enabled'>>) {
    const next = { description: preset.description, commit: preset.commit, enabled: preset.enabled, ...change };
    if (change.commit) {
      const agreed = await confirm({
        title: 'Allow commit',
        message: `Let chat users run '${preset.name}' with commit? It then changes device configuration (after a confirm in chat).`,
        confirmLabel: 'Allow commit',
      });
      if (!agreed) return;
    }
    await pending.run(preset.id, async () => {
      try {
        await update.mutateAsync({ id: preset.id, body: next });
      } catch (e) {
        void alert({ message: `The preset was not changed: ${(e as Error).message}`, variant: 'error' });
      }
    });
  }

  return (
    <div className="stack stack-sm">
      <p className="text-muted" style={{ margin: 0 }}>
        A preset copies a job&apos;s playbook, targets, credential, template and inputs. Chat users run it with{' '}
        <code>/plexus run &lt;name&gt;</code> when <code>run</code> is allowed on the bot and they may run the
        playbook (and commit, for commit presets) themselves. The credential must be one the chat user may use.
      </p>
      <AddPresetForm />
      {presets.isError && !presets.data && <QueryError what="job presets" query={presets} />}
      {presets.isPending && <LoadingState text="Loading presets…" />}
      {presets.data && rows.length === 0 && <EmptyState compact message="No job presets yet." />}
      {rows.length > 0 && (
        <DataTable compact aria-label="Job presets">
          <thead>
            <tr>
              <th>Name</th>
              <th>Playbook</th>
              <th>Targets</th>
              <th>Mode</th>
              <th>Enabled</th>
              <th style={{ textAlign: 'right' }}>Actions</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((p) => (
              <tr key={p.id}>
                <td>
                  {p.name}
                  {p.description && <div className="text-muted">{p.description}</div>}
                </td>
                <td>
                  {p.playbook_name}
                  {p.source_job_id && <div className="text-muted">from job #{p.source_job_id}</div>}
                </td>
                <td>{p.targets || '-'}</td>
                <td>
                  <Badge tone={p.commit ? 'warning' : 'info'} size="sm">
                    {p.commit ? 'Commit' : 'Dry run'}
                  </Badge>
                </td>
                <td>{p.enabled ? 'Yes' : 'No'}</td>
                <td style={{ textAlign: 'right', whiteSpace: 'nowrap' }}>
                  <BusyButton
                    className="btn btn-sm btn-secondary"
                    busy={pending.isPending(p.id)}
                    onClick={() => void save(p, { enabled: !p.enabled })}
                  >
                    {p.enabled ? 'Disable' : 'Enable'}
                  </BusyButton>{' '}
                  <BusyButton
                    className="btn btn-sm btn-secondary"
                    busy={pending.isPending(p.id)}
                    onClick={() => void save(p, { commit: !p.commit })}
                  >
                    {p.commit ? 'Make dry run' : 'Allow commit'}
                  </BusyButton>{' '}
                  <BusyButton
                    className="btn btn-sm btn-danger"
                    busy={pending.isPending(p.id)}
                    onClick={async () => {
                      const agreed = await confirm({
                        title: 'Delete preset',
                        message: `Delete the preset '${p.name}'? Chat users can no longer run it.`,
                        confirmLabel: 'Delete',
                        confirmVariant: 'danger',
                      });
                      if (!agreed) return;
                      await pending.run(p.id, async () => {
                        try {
                          await remove.mutateAsync(p.id);
                        } catch (e) {
                          void alert({ message: `The preset was not deleted: ${(e as Error).message}`, variant: 'error' });
                        }
                      });
                    }}
                  >
                    Delete
                  </BusyButton>
                </td>
              </tr>
            ))}
          </tbody>
        </DataTable>
      )}
    </div>
  );
}
