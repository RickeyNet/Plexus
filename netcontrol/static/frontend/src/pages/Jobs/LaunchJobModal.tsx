import { useId, useMemo, useState, type FormEvent } from 'react';

import { Callout } from '@/components/Callout';
import { useDialogs } from '@/components/DialogProvider-context';
import { FieldError } from '@/components/FieldError';
import { Modal } from '@/components/Modal';
import {
  useJobCredentials,
  useLaunchJob,
  usePlaybooks,
  useTemplates,
  type PlaybookParameter,
} from '@/api/jobs';
import { useInventoryGroupsFull } from '@/api/inventory';

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

  const [playbookId, setPlaybookId] = useState('');
  const [credentialId, setCredentialId] = useState('');
  const [templateId, setTemplateId] = useState('');
  const [priority, setPriority] = useState('2');
  const [dependsOn, setDependsOn] = useState('');
  const [dryRun, setDryRun] = useState(true);
  const [adHocIps, setAdHocIps] = useState('');
  const [hostIds, setHostIds] = useState<Set<number>>(new Set());
  const [paramValues, setParamValues] = useState<Record<string, string | boolean>>({});
  const [playbookError, setPlaybookError] = useState<string | null>(null);
  const [targetsError, setTargetsError] = useState<string | null>(null);
  const [launchError, setLaunchError] = useState<string | null>(null);

  const selectedPb = useMemo(
    () => playbooksQuery.data?.find((p) => String(p.id) === playbookId),
    [playbooksQuery.data, playbookId],
  );
  const isAnsible = selectedPb?.type === 'ansible';
  const paramSchema: PlaybookParameter[] = selectedPb?.parameters_schema ?? [];

  // Seed defaults whenever the user picks a different playbook so the form
  // shows the schema's defaults instead of stale state from a prior selection.
  const [prevPbId, setPrevPbId] = useState(selectedPb?.id);
  if (selectedPb?.id !== prevPbId) {
    setPrevPbId(selectedPb?.id);
    if (!selectedPb) {
      setParamValues({});
    } else {
      const seeded: Record<string, string | boolean> = {};
      for (const f of paramSchema) {
        if (f.type === 'bool') {
          seeded[f.name] = typeof f.default === 'boolean' ? f.default : false;
        } else {
          seeded[f.name] = f.default == null ? '' : String(f.default);
        }
      }
      setParamValues(seeded);
    }
  }

  function reset() {
    setPlaybookId(''); setCredentialId(''); setTemplateId('');
    setPriority('2'); setDependsOn(''); setDryRun(true);
    setAdHocIps(''); setHostIds(new Set()); setParamValues({});
    setPlaybookError(null); setTargetsError(null); setLaunchError(null);
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

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setLaunchError(null);
    const adHocList = adHocIps.trim()
      ? adHocIps.split(/[\n,]+/).map((s) => s.trim()).filter(Boolean)
      : [];
    const pbErr = playbookId ? null : 'Select a playbook';
    const tgtErr = hostIds.size === 0 && adHocList.length === 0
      ? 'Select at least one host or enter an IP address'
      : null;
    setPlaybookError(pbErr);
    setTargetsError(tgtErr);
    if (pbErr || tgtErr) return;
    const depsList = dependsOn.trim()
      ? dependsOn.split(',').map((s) => parseInt(s.trim(), 10)).filter((n) => !isNaN(n))
      : undefined;

    const parameters: Record<string, unknown> = {};
    for (const f of paramSchema) {
      const v = paramValues[f.name];
      if (v === '' || v === undefined) continue; // server fills in defaults
      parameters[f.name] = v;
    }

    if (!dryRun) {
      const groupNames = (groupsQuery.data ?? [])
        .filter((g) => (g.hosts ?? []).some((h) => hostIds.has(h.id)))
        .map((g) => g.name);
      const targets = [
        hostIds.size > 0 && `${hostIds.size} inventory host${hostIds.size === 1 ? '' : 's'} (${groupNames.join(', ')})`,
        adHocList.length > 0 && `${adHocList.length} ad-hoc address${adHocList.length === 1 ? '' : 'es'}`,
      ].filter(Boolean).join(' and ');
      const ok = await confirm({
        title: 'Launch live job',
        message: `Run '${selectedPb?.name ?? 'the selected playbook'}' live against ${targets}? This is not a dry run: it makes changes on the devices.`,
        confirmLabel: 'Launch live',
      });
      if (!ok) return;
    }

    launchMut.mutate(
      {
        playbook_id: parseInt(playbookId, 10),
        credential_id: credentialId ? parseInt(credentialId, 10) : undefined,
        template_id: !isAnsible && templateId ? parseInt(templateId, 10) : undefined,
        dry_run: dryRun,
        priority: parseInt(priority, 10) || 2,
        host_ids: hostIds.size > 0 ? Array.from(hostIds) : undefined,
        depends_on: depsList && depsList.length > 0 ? depsList : undefined,
        ad_hoc_ips: adHocList.length > 0 ? adHocList : undefined,
        parameters: paramSchema.length > 0 ? parameters : undefined,
      },
      {
        onSuccess: (r) => {
          reset();
          onClose();
          onLaunched?.(r.job_id);
        },
        onError: (err) => { setLaunchError((err as Error).message); },
      },
    );
  }

  return (
    <Modal
      isOpen={isOpen}
      onClose={onClose}
      title="Launch Job"
      footer={
        <>
          <button type="button" className="btn btn-secondary" onClick={onClose}>Cancel</button>
          <button type="submit" form={formId} className="btn btn-primary" disabled={launchMut.isPending}>
            {launchMut.isPending ? 'Launching…' : 'Launch'}
          </button>
        </>
      }
    >
      <form id={formId} onSubmit={(e) => void handleSubmit(e)}>
        {launchError && <Callout tone="danger">{launchError}</Callout>}
        <div className="form-group">
          <label className="form-label" htmlFor={`${formId}-playbook`}>Playbook</label>
          <select
            id={`${formId}-playbook`}
            className="form-select"
            value={playbookId}
            onChange={(e) => { setPlaybookId(e.target.value); setPlaybookError(null); }}
            aria-invalid={!!playbookError}
            required
            disabled={playbooksQuery.isError}
          >
            <option value="">Select a playbook…</option>
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
          <div role="group" aria-labelledby={`${formId}-targets`} style={{ background: 'var(--bg-secondary)', padding: '1rem', borderRadius: 6, maxHeight: 320, overflowY: 'auto', border: '1px solid var(--border)' }}>
            {(groupsQuery.data ?? []).length === 0 ? (
              <div className="empty-state">
                {groupsQuery.isError ? 'Inventory could not be loaded. Enter ad-hoc IPs below.' : 'No inventory groups available'}
              </div>
            ) : (groupsQuery.data ?? []).map((group) => {
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
            <label className="form-label" htmlFor={`${formId}-template`}>Template (optional)</label>
            <select id={`${formId}-template`} className="form-select" value={templateId} onChange={(e) => setTemplateId(e.target.value)} disabled={tplQuery.isError}>
              <option value="">None</option>
              {(tplQuery.data ?? []).map((t) => (
                <option key={t.id} value={t.id}>{t.name}</option>
              ))}
            </select>
            <small className="text-muted">
              {tplQuery.isError
                ? 'Instructions could not be loaded. You may not have access to Instructions.'
                : 'Required if the selected playbook expects a template.'}
            </small>
          </div>
        )}

        {paramSchema.length > 0 && (
          <div style={{ padding: '0.75rem', background: 'var(--bg-secondary)', border: '1px solid var(--border)', borderRadius: 6, marginBottom: '1rem' }}>
            <div style={{ fontWeight: 600, marginBottom: '0.5rem' }}>Playbook Parameters</div>
            {paramSchema.map((f) => {
              const val = paramValues[f.name];
              const id = `pb-param-${f.name}`;
              if (f.type === 'bool') {
                return (
                  <div className="form-group" key={f.name}>
                    <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                      <input
                        id={id}
                        type="checkbox"
                        checked={Boolean(val)}
                        onChange={(e) => setParamValues((p) => ({ ...p, [f.name]: e.target.checked }))}
                      />
                      {f.label}
                      {f.required && <span style={{ color: 'var(--danger)' }}>*</span>}
                    </label>
                    {f.help && <small className="text-muted">{f.help}</small>}
                  </div>
                );
              }
              return (
                <div className="form-group" key={f.name}>
                  <label className="form-label" htmlFor={id}>
                    {f.label}
                    {f.required && <span style={{ color: 'var(--danger)', marginLeft: '0.25rem' }}>*</span>}
                  </label>
                  <input
                    id={id}
                    className="form-input"
                    type={f.type === 'int' ? 'number' : 'text'}
                    value={typeof val === 'string' ? val : ''}
                    required={f.required}
                    onChange={(e) => setParamValues((p) => ({ ...p, [f.name]: e.target.value }))}
                  />
                  {f.help && <small className="text-muted">{f.help}</small>}
                </div>
              );
            })}
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

        <div className="form-group">
          <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <input type="checkbox" checked={dryRun} onChange={(e) => setDryRun(e.target.checked)} />
            Dry Run (simulation)
          </label>
        </div>
      </form>
    </Modal>
  );
}
