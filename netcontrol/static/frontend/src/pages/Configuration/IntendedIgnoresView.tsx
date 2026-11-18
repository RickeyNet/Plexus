import { useId, useState } from 'react';

import {
  type IgnoreKind,
  type IgnoreRule,
  type IgnoreRuleInput,
  useCreateRemediationIgnore,
  useDeleteRemediationIgnore,
  useRemediationIgnores,
  useUpdateRemediationIgnore,
} from '@/api/intendedRemediation';
import { BusyButton } from '@/components/BusyButton';
import { CardHeader, CatalogueBody } from '@/components/CatalogueParts';
import { Callout } from '@/components/Callout';
import { DataTable } from '@/components/DataTable';
import { useDialogs } from '@/components/DialogProvider-context';
import { EmptyState } from '@/components/EmptyState';
import { usePendingKeys } from '@/lib/usePendingKeys';

import { driverOptions, IGNORE_KINDS, ignoreKindLabel } from './intendedHelpers';
import { EnabledBadge, NameCell } from './IntendedParts';

const EMPTY: IgnoreRuleInput = { kind: 'exact', pattern: '', device_type: '', description: '', enabled: true };

/**
 * The Intended tab's Ignore rules view (admins): lines remediation leaves
 * alone. A matching line, with its block, is dropped from both the intended
 * and the running configuration before the commands are worked out.
 */
export function IntendedIgnoresView() {
  const q = useRemediationIgnores();
  const create = useCreateRemediationIgnore();
  const update = useUpdateRemediationIgnore();
  const remove = useDeleteRemediationIgnore();
  const { confirm, alert } = useDialogs();
  const pending = usePendingKeys<number>();
  const [draft, setDraft] = useState<IgnoreRuleInput>(EMPTY);
  const [error, setError] = useState<string | null>(null);
  const fid = useId();
  const rows = q.data ?? [];

  const add = async () => {
    setError(null);
    try {
      await create.mutateAsync({ ...draft, pattern: draft.pattern.trim() });
      setDraft(EMPTY);
    } catch (err) {
      setError(`The rule was not added: ${(err as Error).message}`);
    }
  };

  const toggle = (r: IgnoreRule) =>
    void pending.run(r.id, async () => {
      try {
        const { kind, pattern, device_type, description } = r;
        await update.mutateAsync({ id: r.id, data: { kind, pattern, device_type, description, enabled: !r.enabled } });
      } catch (err) {
        await alert({ title: 'Rule not changed', message: `The rule was not changed: ${(err as Error).message} Try again.`, variant: 'error' });
      }
    });

  const handleDelete = (r: IgnoreRule) =>
    void pending.run(r.id, async () => {
      const agreed = await confirm({
        title: 'Delete ignore rule',
        message: `Delete the rule "${r.pattern}"? Remediation stops ignoring the lines it matched. This cannot be undone.`,
        confirmLabel: 'Delete rule',
      });
      if (!agreed) return;
      try {
        await remove.mutateAsync(r.id);
      } catch (err) {
        await alert({ title: 'Rule not deleted', message: `The rule was not deleted: ${(err as Error).message} Try again.`, variant: 'error' });
      }
    });

  const help = IGNORE_KINDS.find((k) => k.value === draft.kind)?.help;

  return (
    <div className="card">
      <CardHeader
        title="Remediation ignore rules"
        sub={q.data && `${rows.length.toLocaleString()} rule${rows.length === 1 ? '' : 's'}; a matching line is left alone with its block`}
      />
      <form
        className="toolbar"
        style={{ flexWrap: 'wrap', alignItems: 'flex-end', gap: 'var(--space-2)' }}
        onSubmit={(e) => {
          e.preventDefault();
          void add();
        }}
      >
        <div className="form-group" style={{ margin: 0 }}>
          <label className="form-label" htmlFor={`${fid}-kind`}>
            Match
          </label>
          <select
            id={`${fid}-kind`}
            className="form-select"
            value={draft.kind}
            onChange={(e) => setDraft({ ...draft, kind: e.target.value as IgnoreKind })}
          >
            {IGNORE_KINDS.map((k) => (
              <option key={k.value} value={k.value}>
                {k.label}
              </option>
            ))}
          </select>
        </div>
        <div className="form-group" style={{ margin: 0, flex: '1 1 220px' }}>
          <label className="form-label" htmlFor={`${fid}-pattern`}>
            Pattern
          </label>
          <input
            id={`${fid}-pattern`}
            className="form-input"
            value={draft.pattern}
            placeholder={draft.kind === 'regex' ? '^ntp server ' : 'ntp server'}
            onChange={(e) => setDraft({ ...draft, pattern: e.target.value })}
          />
          {help && <div className="form-help">{help}</div>}
        </div>
        <div className="form-group" style={{ margin: 0 }}>
          <label className="form-label" htmlFor={`${fid}-driver`}>
            Driver
          </label>
          <select
            id={`${fid}-driver`}
            className="form-select"
            value={draft.device_type}
            onChange={(e) => setDraft({ ...draft, device_type: e.target.value })}
          >
            <option value="">Any driver</option>
            {driverOptions(draft.device_type).map((d) => (
              <option key={d.value} value={d.value}>
                {d.label}
              </option>
            ))}
          </select>
        </div>
        <div className="form-group" style={{ margin: 0, flex: '1 1 180px' }}>
          <label className="form-label" htmlFor={`${fid}-description`}>
            Description
          </label>
          <input
            id={`${fid}-description`}
            className="form-input"
            value={draft.description}
            onChange={(e) => setDraft({ ...draft, description: e.target.value })}
          />
        </div>
        <BusyButton type="submit" className="btn btn-primary" busy={create.isPending} busyLabel="Adding…" disabled={!draft.pattern.trim()}>
          Add rule
        </BusyButton>
      </form>
      {error && <Callout tone="danger">{error}</Callout>}
      <CatalogueBody
        query={q}
        what="ignore rules"
        rows={rows}
        empty={
          <EmptyState
            compact
            message="No ignore rules yet."
            description="Add one for lines the device sets itself, such as certificates or counters, so remediation never touches them."
          />
        }
      >
        <DataTable compact aria-label="Ignore rules">
          <thead>
            <tr>
              <th>Pattern</th>
              <th>Match</th>
              <th>Driver</th>
              <th>Enabled</th>
              <th style={{ textAlign: 'right' }}>Actions</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((r) => (
              <tr key={r.id}>
                <td>
                  <NameCell name={r.pattern} description={r.description} />
                </td>
                <td>{ignoreKindLabel(r.kind)}</td>
                <td>{r.device_type || 'Any'}</td>
                <td>
                  <EnabledBadge enabled={r.enabled} />
                </td>
                <td style={{ textAlign: 'right', whiteSpace: 'nowrap' }}>
                  <button type="button" className="btn btn-sm btn-secondary" disabled={pending.isPending(r.id)} onClick={() => toggle(r)}>
                    {r.enabled ? 'Disable' : 'Enable'}
                  </button>{' '}
                  <button type="button" className="btn btn-sm btn-danger" disabled={pending.isPending(r.id)} onClick={() => handleDelete(r)}>
                    Delete
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </DataTable>
      </CatalogueBody>
    </div>
  );
}
