import { useEffect, useMemo, useState, type FormEvent } from 'react';

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

  const selectedPb = useMemo(
    () => playbooksQuery.data?.find((p) => String(p.id) === playbookId),
    [playbooksQuery.data, playbookId],
  );
  const isAnsible = selectedPb?.type === 'ansible';
  const paramSchema: PlaybookParameter[] = selectedPb?.parameters_schema ?? [];

  // Seed defaults whenever the user picks a different playbook so the form
  // shows the schema's defaults instead of stale state from a prior selection.
  useEffect(() => {
    if (!selectedPb) {
      setParamValues({});
      return;
    }
    const seeded: Record<string, string | boolean> = {};
    for (const f of paramSchema) {
      if (f.type === 'bool') {
        seeded[f.name] = typeof f.default === 'boolean' ? f.default : false;
      } else {
        seeded[f.name] = f.default == null ? '' : String(f.default);
      }
    }
    setParamValues(seeded);
  }, [selectedPb?.id]); // eslint-disable-line react-hooks/exhaustive-deps

  function reset() {
    setPlaybookId(''); setCredentialId(''); setTemplateId('');
    setPriority('2'); setDependsOn(''); setDryRun(true);
    setAdHocIps(''); setHostIds(new Set()); setParamValues({});
  }

  function toggleGroup(groupHostIds: number[], checked: boolean) {
    setHostIds((prev) => {
      const next = new Set(prev);
      groupHostIds.forEach((id) => { if (checked) next.add(id); else next.delete(id); });
      return next;
    });
  }

  function toggleHost(id: number, checked: boolean) {
    setHostIds((prev) => {
      const next = new Set(prev);
      if (checked) next.add(id); else next.delete(id);
      return next;
    });
  }

  function handleSubmit(e: FormEvent) {
    e.preventDefault();
    if (!playbookId) {
      alert('Select a playbook');
      return;
    }
    const adHocList = adHocIps.trim()
      ? adHocIps.split(/[\n,]+/).map((s) => s.trim()).filter(Boolean)
      : [];
    if (hostIds.size === 0 && adHocList.length === 0) {
      alert('Select at least one host or enter an IP address');
      return;
    }
    const depsList = dependsOn.trim()
      ? dependsOn.split(',').map((s) => parseInt(s.trim(), 10)).filter((n) => !isNaN(n))
      : undefined;

    const parameters: Record<string, unknown> = {};
    for (const f of paramSchema) {
      const v = paramValues[f.name];
      if (v === '' || v === undefined) continue; // server fills in defaults
      parameters[f.name] = v;
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
        onError: (err) => alert((err as Error).message),
      },
    );
  }

  return (
    <Modal isOpen={isOpen} onClose={onClose} title="Launch Job" size="large">
      <form onSubmit={handleSubmit}>
        <div className="form-group">
          <label className="form-label">Playbook</label>
          <select className="form-select" value={playbookId} onChange={(e) => setPlaybookId(e.target.value)} required>
            <option value="">Select a playbook…</option>
            {(playbooksQuery.data ?? []).map((pb) => (
              <option key={pb.id} value={pb.id}>
                {pb.name}{pb.type === 'ansible' ? ' [Ansible]' : ''}
              </option>
            ))}
          </select>
        </div>

        <div className="form-group">
          <label className="form-label">Select Targets</label>
          <div style={{ background: 'var(--bg-secondary)', padding: '1rem', borderRadius: 6, maxHeight: 320, overflowY: 'auto', border: '1px solid var(--border)' }}>
            {(groupsQuery.data ?? []).length === 0 ? (
              <div className="empty-state">No inventory groups available</div>
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
          <label className="form-label">Ad-Hoc IP Addresses</label>
          <textarea
            className="form-input"
            rows={3}
            value={adHocIps}
            onChange={(e) => setAdHocIps(e.target.value)}
            placeholder="One IP per line or comma-separated&#10;e.g. 10.0.1.50, 192.168.1.100"
            style={{ fontFamily: 'monospace', fontSize: '0.85rem' }}
          />
          <small className="text-muted">Targets devices not in inventory. Will run as cisco_ios by default.</small>
        </div>

        <div className="form-group">
          <label className="form-label">Credential (optional)</label>
          <select className="form-select" value={credentialId} onChange={(e) => setCredentialId(e.target.value)}>
            <option value="">None</option>
            {(credsQuery.data ?? []).map((c) => (
              <option key={c.id} value={c.id}>{c.name}</option>
            ))}
          </select>
        </div>

        {!isAnsible && (
          <div className="form-group">
            <label className="form-label">Template (optional)</label>
            <select className="form-select" value={templateId} onChange={(e) => setTemplateId(e.target.value)}>
              <option value="">None</option>
              {(tplQuery.data ?? []).map((t) => (
                <option key={t.id} value={t.id}>{t.name}</option>
              ))}
            </select>
            <small className="text-muted">Required if the selected playbook expects a template.</small>
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
            <label className="form-label">Priority</label>
            <select className="form-select" value={priority} onChange={(e) => setPriority(e.target.value)}>
              <option value="0">Low</option>
              <option value="1">Below Normal</option>
              <option value="2">Normal</option>
              <option value="3">High</option>
              <option value="4">Critical</option>
            </select>
          </div>
          <div className="form-group" style={{ flex: 1, minWidth: 140 }}>
            <label className="form-label">Depends On (Job IDs)</label>
            <input
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

        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.5rem', marginTop: '1rem' }}>
          <button type="button" className="btn btn-secondary" onClick={onClose}>Cancel</button>
          <button type="submit" className="btn btn-primary" disabled={launchMut.isPending}>
            {launchMut.isPending ? 'Launching…' : 'Launch'}
          </button>
        </div>
      </form>
    </Modal>
  );
}
