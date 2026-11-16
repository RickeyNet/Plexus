import { useId, useMemo, useState, type FormEvent } from 'react';

import { BusyButton } from '@/components/BusyButton';
import { Callout } from '@/components/Callout';
import { useDialogs } from '@/components/DialogProvider-context';
import { FieldError } from '@/components/FieldError';
import { Modal } from '@/components/Modal';
import { useAuthStatus } from '@/api/auth';
import { CustomDataError } from '@/api/customData';
import {
  useJobCredentials,
  useLaunchJob,
  usePlaybooks,
  useSecretVariables,
  useTemplates,
  type JobInputField,
} from '@/api/jobs';
import { useInventoryGroupsFull } from '@/api/inventory';

import { countTargetHosts, filterTargetGroups } from './helpers';
import { JobInputsForm } from './JobInputsForm';
import {
  buildInputsPayload,
  seedInputValues,
  validateInputs,
  validateInputValue,
  type InputValue,
  type InputValues,
} from './jobInputs';

interface Props {
  isOpen: boolean;
  onClose: () => void;
  onLaunched?: (jobId: number) => void;
}

export function LaunchJobModal({ isOpen, onClose, onLaunched }: Props) {
  const formId = useId();
  const { confirm } = useDialogs();
  const playbooksQuery = usePlaybooks();
  const groupsQuery = useInventoryGroupsFull(true);
  const credsQuery = useJobCredentials();
  const tplQuery = useTemplates();
  const launchMut = useLaunchJob();
  const auth = useAuthStatus();
  const isAdmin = auth.data?.role === 'admin';

  const [playbookId, setPlaybookId] = useState('');
  const [credentialId, setCredentialId] = useState('');
  const [templateId, setTemplateId] = useState('');
  const [priority, setPriority] = useState('2');
  const [dependsOn, setDependsOn] = useState('');
  const [pendingCommit, setPendingCommit] = useState<boolean | null>(null);
  const [adHocIps, setAdHocIps] = useState('');
  const [hostIds, setHostIds] = useState<Set<number>>(new Set());
  const [targetQuery, setTargetQuery] = useState('');
  const [inputValues, setInputValues] = useState<InputValues>({});
  const [inputErrors, setInputErrors] = useState<Record<string, string>>({});
  const [playbookError, setPlaybookError] = useState<string | null>(null);
  const [targetsError, setTargetsError] = useState<string | null>(null);
  const [launchError, setLaunchError] = useState<string | null>(null);

  const selectedPb = useMemo(
    () => playbooksQuery.data?.find((p) => String(p.id) === playbookId),
    [playbooksQuery.data, playbookId],
  );
  const isAnsible = selectedPb?.type === 'ansible';
  const inputSchema: JobInputField[] = selectedPb?.input_schema ?? selectedPb?.parameters_schema ?? [];
  const supportsDryRun = selectedPb?.supports_dry_run !== false;
  const canRun = selectedPb?.can_run !== false;
  const canCommit = selectedPb?.can_commit !== false;
  // Secret variables are listed for admins only; others type the name.
  const wantsSecrets = isAdmin && inputSchema.some((f) => f.type === 'secret');
  const secretsQuery = useSecretVariables(wantsSecrets);
  const secretNames = wantsSecrets && secretsQuery.data ? secretsQuery.data.map((v) => v.name) : undefined;

  const groups = groupsQuery.data;
  const shownGroups = useMemo(() => filterTargetGroups(groups ?? [], targetQuery), [groups, targetQuery]);
  const totalHosts = useMemo(() => countTargetHosts(groups ?? []), [groups]);

  // Seed defaults whenever the user picks a different playbook so the form
  // shows the schema's defaults instead of stale state from a prior selection.
  const [prevPbId, setPrevPbId] = useState(selectedPb?.id);
  if (selectedPb?.id !== prevPbId) {
    setPrevPbId(selectedPb?.id);
    setInputValues(selectedPb ? seedInputValues(inputSchema) : {});
    setInputErrors({});
  }

  function reset() {
    setPlaybookId(''); setCredentialId(''); setTemplateId('');
    setPriority('2'); setDependsOn('');
    setAdHocIps(''); setHostIds(new Set()); setTargetQuery('');
    setInputValues({}); setInputErrors({});
    setPlaybookError(null); setTargetsError(null); setLaunchError(null);
  }

  function changeInput(name: string, value: InputValue) {
    setInputValues((prev) => ({ ...prev, [name]: value }));
    // A message clears as soon as the field changes; blur checks it again.
    setInputErrors((prev) => {
      if (!(name in prev)) return prev;
      const next = { ...prev };
      delete next[name];
      return next;
    });
  }

  function blurInput(name: string) {
    const field = inputSchema.find((f) => f.name === name);
    if (!field) return;
    const msg = validateInputValue(field, inputValues[name]);
    setInputErrors((prev) => {
      const next = { ...prev };
      if (msg) next[name] = msg;
      else delete next[name];
      return next;
    });
  }

  function toggleGroup(groupHostIds: number[], checked: boolean) {
    setTargetsError(null);
    setHostIds((prev) => {
      const next = new Set(prev);
      groupHostIds.forEach((id) => { if (checked) next.add(id); else next.delete(id); });
      return next;
    });
  }

  function toggleHost(id: number, checked: boolean) {
    setTargetsError(null);
    setHostIds((prev) => {
      const next = new Set(prev);
      if (checked) next.add(id); else next.delete(id);
      return next;
    });
  }

  function handleSubmit(e: FormEvent) {
    e.preventDefault();
    // Enter in the form is the safe action: a dry run when the task has one.
    if (supportsDryRun) void handleRun(false);
  }

  async function handleRun(commit: boolean) {
    setLaunchError(null);
    const adHocList = adHocIps.trim()
      ? adHocIps.split(/[\n,]+/).map((s) => s.trim()).filter(Boolean)
      : [];
    const pbErr = playbookId ? null : 'Select a task';
    const tgtErr = hostIds.size === 0 && adHocList.length === 0
      ? 'Select at least one host or enter an IP address'
      : null;
    const inErrs = validateInputs(inputSchema, inputValues);
    setPlaybookError(pbErr);
    setTargetsError(tgtErr);
    setInputErrors(inErrs);
    if (pbErr || tgtErr || Object.keys(inErrs).length > 0) return;
    const depsList = dependsOn.trim()
      ? dependsOn.split(',').map((s) => parseInt(s.trim(), 10)).filter((n) => !isNaN(n))
      : undefined;

    if (commit) {
      const groupNames = (groups ?? [])
        .filter((g) => (g.hosts ?? []).some((h) => hostIds.has(h.id)))
        .map((g) => g.name);
      const targets = [
        hostIds.size > 0 && `${hostIds.size} inventory host${hostIds.size === 1 ? '' : 's'} (${groupNames.join(', ')})`,
        adHocList.length > 0 && `${adHocList.length} ad-hoc address${adHocList.length === 1 ? '' : 'es'}`,
      ].filter(Boolean).join(' and ');
      const ok = await confirm({
        title: 'Run and commit job',
        message:
          `Run '${selectedPb?.name ?? 'the selected task'}' and commit changes on ${targets}? ` +
          (supportsDryRun
            ? 'This is not a dry run: it makes changes on the devices.'
            : 'This task has no dry-run mode, so it always makes changes on the devices.'),
        confirmLabel: 'Run and commit',
      });
      if (!ok) return;
    }

    launchMut.mutate(
      {
        playbook_id: parseInt(playbookId, 10),
        credential_id: credentialId ? parseInt(credentialId, 10) : undefined,
        template_id: !isAnsible && templateId ? parseInt(templateId, 10) : undefined,
        commit,
        priority: parseInt(priority, 10) || 2,
        host_ids: hostIds.size > 0 ? Array.from(hostIds) : undefined,
        depends_on: depsList && depsList.length > 0 ? depsList : undefined,
        ad_hoc_ips: adHocList.length > 0 ? adHocList : undefined,
        inputs: inputSchema.length > 0 ? buildInputsPayload(inputSchema, inputValues) : undefined,
      },
      {
        onSuccess: (r) => {
          reset();
          onClose();
          onLaunched?.(r.job_id);
        },
        onError: (err) => {
          // A 422 names the bad inputs; show each under its field.
          if (err instanceof CustomDataError && Object.keys(err.fields).length > 0) {
            const known = new Set(inputSchema.map((f) => f.name));
            const fieldErrs = Object.fromEntries(Object.entries(err.fields).filter(([k]) => known.has(k)));
            setInputErrors(fieldErrs);
            const other = Object.entries(err.fields).filter(([k]) => !known.has(k)).map(([, m]) => m);
            setLaunchError(other.length > 0 ? other.join(' ') : err.message);
          } else {
            setLaunchError((err as Error).message);
          }
        },
        onSettled: () => setPendingCommit(null),
      },
    );
    setPendingCommit(commit);
  }

  const runBlocked = !selectedPb || !canRun;

  return (
    <Modal
      isOpen={isOpen}
      onClose={onClose}
      title="Launch Job"
      footer={
        <>
          <button type="button" className="btn btn-secondary" onClick={onClose}>Cancel</button>
          {supportsDryRun && (
            <BusyButton
              type="submit"
              form={formId}
              className="btn btn-primary"
              busy={launchMut.isPending && pendingCommit === false}
              busyLabel="Starting…"
              disabled={launchMut.isPending || runBlocked}
            >
              Run dry-run
            </BusyButton>
          )}
          <BusyButton
            type="button"
            className="btn btn-danger"
            busy={launchMut.isPending && pendingCommit === true}
            busyLabel="Starting…"
            disabled={launchMut.isPending || runBlocked || !canCommit}
            onClick={() => void handleRun(true)}
          >
            Run and commit
          </BusyButton>
        </>
      }
    >
      <form id={formId} onSubmit={handleSubmit}>
        {launchError && <Callout tone="danger">{launchError}</Callout>}
        {selectedPb && !canRun && (
          <Callout tone="warning">You are not allowed to run this task. Ask an admin to add you to its run permissions.</Callout>
        )}
        {selectedPb && canRun && !canCommit && (
          <Callout tone="info">You can run this task as a dry run only. Committing changes needs commit permission.</Callout>
        )}
        {selectedPb && !supportsDryRun && (
          <Callout tone="warning">This task has no dry-run mode. Every run makes changes on the devices.</Callout>
        )}
        <div className="form-group">
          <label className="form-label" htmlFor={`${formId}-playbook`}>Task</label>
          <select
            id={`${formId}-playbook`}
            className="form-select"
            value={playbookId}
            onChange={(e) => { setPlaybookId(e.target.value); setPlaybookError(null); }}
            aria-invalid={!!playbookError}
            required
            disabled={playbooksQuery.isError}
          >
            <option value="">Select a task…</option>
            {(playbooksQuery.data ?? []).map((pb) => (
              <option key={pb.id} value={pb.id}>
                {pb.name}{pb.type === 'ansible' ? ' [Ansible]' : ''}
              </option>
            ))}
          </select>
          {playbooksQuery.isError && (
            <small className="text-muted">Tasks could not be loaded. You may not have access to Tasks.</small>
          )}
          <FieldError>{playbookError}</FieldError>
        </div>

        <div className="form-group">
          <span className="form-label" id={`${formId}-targets`}>Select Targets</span>
          {(groups ?? []).length > 0 && (
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', flexWrap: 'wrap', marginBottom: '0.5rem' }}>
              <input
                type="search"
                className="form-input"
                placeholder="Search hosts or groups…"
                aria-label="Search targets"
                value={targetQuery}
                onChange={(e) => setTargetQuery(e.target.value)}
                // Enter in this box would otherwise submit the launch form.
                onKeyDown={(e) => { if (e.key === 'Enter') e.preventDefault(); }}
                style={{ flex: '1 1 200px', width: 'auto' }}
              />
              <span className="text-muted" aria-live="polite" style={{ fontSize: '0.85rem', whiteSpace: 'nowrap' }}>
                {hostIds.size} of {totalHosts} selected
              </span>
              <button
                type="button"
                className="btn btn-sm btn-secondary"
                disabled={hostIds.size === 0}
                onClick={() => setHostIds(new Set())}
              >
                Clear
              </button>
            </div>
          )}
          <div role="group" aria-labelledby={`${formId}-targets`} style={{ background: 'var(--bg-secondary)', padding: '1rem', borderRadius: 6, maxHeight: 320, overflowY: 'auto', border: '1px solid var(--border)' }}>
            {(groups ?? []).length === 0 ? (
              <div className="empty-state">
                {groupsQuery.isError ? 'Inventory could not be loaded. Enter ad-hoc IPs below.' : 'No inventory groups available'}
              </div>
            ) : shownGroups.length === 0 ? (
              <div className="empty-state">No hosts or groups match the search</div>
            ) : shownGroups.map((group) => {
              const hosts = group.hosts ?? [];
              const groupHostIds = hosts.map((h) => h.id);
              const allChecked = hosts.length > 0 && groupHostIds.every((id) => hostIds.has(id));
              return (
                <div key={group.id} style={{ marginBottom: '0.75rem', paddingBottom: '0.5rem', borderBottom: '1px solid var(--border)' }}>
                  <label style={{ display: 'flex', alignItems: 'center', cursor: 'pointer', fontWeight: 600 }}>
                    <input
                      type="checkbox"
                      checked={allChecked}
                      onChange={(e) => toggleGroup(groupHostIds, e.target.checked)}
                      style={{ marginRight: '0.5rem' }}
                    />
                    {group.name}
                    <span className="text-muted" style={{ fontWeight: 400, marginLeft: '0.5rem' }}>({hosts.length} hosts)</span>
                  </label>
                  <div style={{ marginLeft: '1.5rem', marginTop: '0.25rem' }}>
                    {hosts.map((h) => (
                      <label key={h.id} style={{ display: 'flex', alignItems: 'center', padding: '0.15rem 0', cursor: 'pointer' }}>
                        <input
                          type="checkbox"
                          checked={hostIds.has(h.id)}
                          onChange={(e) => toggleHost(h.id, e.target.checked)}
                          style={{ marginRight: '0.5rem' }}
                        />
                        <span>{h.hostname}</span>
                        <span className="text-muted" style={{ marginLeft: '0.5rem', fontSize: '0.85rem' }}>{h.ip_address}</span>
                        <span className="text-muted" style={{ marginLeft: '0.5rem', fontSize: '0.75rem' }}>({h.device_type || 'cisco_ios'})</span>
                      </label>
                    ))}
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        <div className="form-group">
          <label className="form-label" htmlFor={`${formId}-adhoc-ips`}>Ad-Hoc IP Addresses</label>
          <textarea
            id={`${formId}-adhoc-ips`}
            className="form-input"
            rows={3}
            value={adHocIps}
            onChange={(e) => { setAdHocIps(e.target.value); setTargetsError(null); }}
            aria-invalid={!!targetsError}
            placeholder="One IP per line or comma-separated&#10;e.g. 192.0.2.50, 198.51.100.100"
            style={{ fontFamily: 'monospace', fontSize: '0.85rem' }}
          />
          <small className="text-muted">Targets devices not in inventory. Will run as cisco_ios by default.</small>
          <FieldError>{targetsError}</FieldError>
        </div>

        <div className="form-group">
          <label className="form-label" htmlFor={`${formId}-credential`}>Credential (optional)</label>
          <select id={`${formId}-credential`} className="form-select" value={credentialId} onChange={(e) => setCredentialId(e.target.value)} disabled={credsQuery.isError}>
            <option value="">None</option>
            {(credsQuery.data ?? []).map((c) => (
              <option key={c.id} value={c.id}>{c.name}</option>
            ))}
          </select>
          {credsQuery.isError && (
            <small className="text-muted">Credentials could not be loaded. You may not have access to Credentials.</small>
          )}
        </div>

        {!isAnsible && (
          <div className="form-group">
            <label className="form-label" htmlFor={`${formId}-template`}>Instructions (optional)</label>
            <select id={`${formId}-template`} className="form-select" value={templateId} onChange={(e) => setTemplateId(e.target.value)} disabled={tplQuery.isError}>
              <option value="">None</option>
              {(tplQuery.data ?? []).map((t) => (
                <option key={t.id} value={t.id}>{t.name}</option>
              ))}
            </select>
            <small className="text-muted">
              {tplQuery.isError
                ? 'Instructions could not be loaded. You may not have access to Instructions.'
                : 'Required if the selected task expects instructions.'}
            </small>
          </div>
        )}

        {inputSchema.length > 0 && (
          <div role="group" aria-labelledby={`${formId}-inputs`} style={{ padding: '0.75rem', background: 'var(--bg-secondary)', border: '1px solid var(--border)', borderRadius: 6, marginBottom: '1rem' }}>
            <div id={`${formId}-inputs`} style={{ fontWeight: 600, marginBottom: '0.5rem' }}>Task Inputs</div>
            <JobInputsForm
              schema={inputSchema}
              values={inputValues}
              errors={inputErrors}
              onChange={changeInput}
              onBlur={blurInput}
              groups={groups}
              secretNames={secretNames}
            />
          </div>
        )}

        <div style={{ display: 'flex', gap: '0.75rem', flexWrap: 'wrap' }}>
          <div className="form-group" style={{ flex: 1, minWidth: 140 }}>
            <label className="form-label" htmlFor={`${formId}-priority`}>Priority</label>
            <select id={`${formId}-priority`} className="form-select" value={priority} onChange={(e) => setPriority(e.target.value)}>
              <option value="0">Low</option>
              <option value="1">Below Normal</option>
              <option value="2">Normal</option>
              <option value="3">High</option>
              <option value="4">Critical</option>
            </select>
          </div>
          <div className="form-group" style={{ flex: 1, minWidth: 140 }}>
            <label className="form-label" htmlFor={`${formId}-depends-on`}>Depends On (Job IDs)</label>
            <input
              id={`${formId}-depends-on`}
              className="form-input"
              value={dependsOn}
              onChange={(e) => setDependsOn(e.target.value)}
              placeholder="e.g. 12, 15"
            />
          </div>
        </div>
      </form>
    </Modal>
  );
}
