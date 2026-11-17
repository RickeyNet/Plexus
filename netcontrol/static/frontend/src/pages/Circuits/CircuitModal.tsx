import { useId, useMemo, useState } from 'react';

import { useAuthStatus } from '@/api/auth';
import {
  type Circuit,
  type CircuitChoices,
  type CircuitStatus,
  type ProviderNetwork,
  type TermSide,
  useCircuitChoices,
  useCircuitProviders,
  useCircuitTypes,
  useHostInterfaceNames,
  useProviderNetworks,
  useSaveCircuit,
} from '@/api/circuits';
import { CustomDataError } from '@/api/customData';
import { useBillingCircuits } from '@/api/reports';
import { SaveFailure } from '@/components/CatalogueParts';
import { FieldError } from '@/components/FieldError';
import { Modal } from '@/components/Modal';
import { ModalActions } from '@/components/ModalActions';
import {
  CIRCUIT_CID_MAX,
  CIRCUIT_COMMENTS_MAX,
  CIRCUIT_DESCRIPTION_MAX,
  CIRCUIT_STATUSES,
  CIRCUIT_TEXT_MAX,
  isValidDate,
  parseKbps,
  TERM_SIDES,
  type TerminationDraft,
  terminationDraft,
  terminationErrors,
  terminationInput,
  terminationOf,
} from '@/lib/circuits';
import { serverFieldErrors } from '@/lib/serverFieldErrors';
import { canUseFeature } from '@/lib/tabGating';

import { IdSelect, TextField } from './parts';

/** Creates a circuit or edits one, with its A and Z terminations. */
export function CircuitModal({ circuit, onClose }: { circuit: Circuit | null; onClose: () => void }) {
  const id = useId();
  const save = useSaveCircuit();
  const providers = useCircuitProviders();
  const types = useCircuitTypes();
  const networks = useProviderNetworks();
  const choices = useCircuitChoices();
  const auth = useAuthStatus().data;
  const [form, setForm] = useState({
    cid: circuit?.cid ?? '',
    provider_id: circuit?.provider_id ?? null,
    circuit_type_id: circuit?.circuit_type_id ?? null,
    status: (circuit?.status ?? 'active') as CircuitStatus,
    tenant_id: circuit?.tenant_id ?? null,
    install_date: circuit?.install_date ?? '',
    termination_date: circuit?.termination_date ?? '',
    commit_rate: circuit?.commit_rate_kbps == null ? '' : String(circuit.commit_rate_kbps),
    description: circuit?.description ?? '',
    comments: circuit?.comments ?? '',
    billing_circuit_id: circuit?.billing_circuit_id ?? null,
  });
  const [terms, setTerms] = useState<Record<TermSide, TerminationDraft>>({
    A: terminationDraft(circuit ? terminationOf(circuit, 'A') : undefined),
    Z: terminationDraft(circuit ? terminationOf(circuit, 'Z') : undefined),
  });
  const [tried, setTried] = useState(false);
  const [failure, setFailure] = useState<string | null>(null);
  const [serverErrors, setServerErrors] = useState<Record<string, string>>({});

  const localErrors = useMemo(() => {
    const e: Record<string, string> = {};
    const cid = form.cid.trim();
    if (!cid) e.cid = 'Circuit ID is required.';
    else if (cid.length > CIRCUIT_CID_MAX) e.cid = `Circuit ID must be ${CIRCUIT_CID_MAX} characters or fewer.`;
    if (form.provider_id === null) e.provider_id = 'Choose a provider.';
    if (form.circuit_type_id === null) e.circuit_type_id = 'Choose a circuit type.';
    if (!isValidDate(form.install_date)) e.install_date = 'Install date must be a date as YYYY-MM-DD.';
    if (!isValidDate(form.termination_date)) e.termination_date = 'Termination date must be a date as YYYY-MM-DD.';
    else if (form.install_date && form.termination_date && form.termination_date < form.install_date)
      e.termination_date = 'Termination date must not be before the install date.';
    if (parseKbps(form.commit_rate) === undefined) e.commit_rate_kbps = 'Commit rate must be a whole number of kbps.';
    for (const side of TERM_SIDES) Object.assign(e, terminationErrors(side, terms[side]));
    return e;
  }, [form, terms]);
  // Local errors show once a save was tried; server errors until the field changes.
  const errors: Record<string, string> = { ...serverErrors, ...(tried ? localErrors : {}) };

  const set = <K extends keyof typeof form>(key: K, apiKey: string = key) => (value: (typeof form)[K]) => {
    setForm((prev) => ({ ...prev, [key]: value }));
    setServerErrors((prev) => ({ ...prev, [apiKey]: '' }));
  };
  const setTerm = (side: TermSide) => (patch: Partial<TerminationDraft>) => {
    setTerms((prev) => ({ ...prev, [side]: { ...prev[side], ...patch } }));
    setServerErrors((prev) =>
      Object.fromEntries(Object.entries(prev).filter(([k]) => !k.startsWith(`terminations.${side}.`))),
    );
  };

  const submit = async () => {
    setTried(true);
    if (Object.keys(localErrors).length > 0) return;
    setFailure(null);
    setServerErrors({});
    const data = {
      cid: form.cid.trim(),
      provider_id: form.provider_id,
      circuit_type_id: form.circuit_type_id,
      status: form.status,
      tenant_id: form.tenant_id,
      install_date: form.install_date.trim(),
      termination_date: form.termination_date.trim(),
      commit_rate_kbps: parseKbps(form.commit_rate) ?? null,
      description: form.description.trim(),
      comments: form.comments.trim(),
      billing_circuit_id: form.billing_circuit_id,
      terminations: TERM_SIDES.filter((s) => terms[s].enabled).map((s) => terminationInput(s, terms[s])),
    };
    try {
      await save.mutateAsync({ id: circuit?.id ?? null, data });
      onClose();
    } catch (err) {
      const fields = serverFieldErrors(err);
      if (Object.keys(fields).length > 0) {
        setServerErrors(fields);
        return;
      }
      if (err instanceof CustomDataError && err.status === 409) {
        setServerErrors({ cid: err.message });
        return;
      }
      setFailure((err as Error).message);
    }
  };

  const providerOptions = (providers.data ?? []).map((p) => ({ id: p.id, label: p.name }));
  const typeOptions = (types.data ?? []).map((t) => ({ id: t.id, label: t.name }));
  const tenantOptions = (choices.data?.tenants ?? []).map((t) => ({ id: t.id, label: t.name }));

  return (
    <Modal
      isOpen
      onClose={onClose}
      size="large"
      title={circuit ? `Edit circuit ${circuit.cid}` : 'Add circuit'}
      footer={
        <ModalActions
          onClose={onClose}
          primaryLabel={circuit ? 'Save circuit' : 'Add circuit'}
          primaryBusy={save.isPending}
          primaryBusyLabel="Saving…"
          onPrimary={() => void submit()}
        />
      }
    >
      <SaveFailure what="circuit" message={failure} />
      <div className="form-row" style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(14rem, 1fr))', gap: '0 1rem' }}>
        <TextField
          id={`${id}-cid`}
          label="Circuit ID"
          value={form.cid}
          onChange={set('cid')}
          error={errors.cid}
          max={CIRCUIT_CID_MAX + 1}
          help="The provider's ID for the circuit; unique per provider."
          autoFocus
        />
        <IdSelect id={`${id}-provider`} label="Provider" value={form.provider_id} onChange={set('provider_id')} options={providerOptions} none="Choose a provider" error={errors.provider_id} />
        <IdSelect id={`${id}-type`} label="Circuit type" value={form.circuit_type_id} onChange={set('circuit_type_id')} options={typeOptions} none="Choose a type" error={errors.circuit_type_id} />
        <div className="form-group">
          <label className="form-label" htmlFor={`${id}-status`}>
            Status
          </label>
          <select id={`${id}-status`} className="form-select" value={form.status} onChange={(e) => set('status')(e.target.value as CircuitStatus)}>
            {CIRCUIT_STATUSES.map((s) => (
              <option key={s.value} value={s.value}>
                {s.label}
              </option>
            ))}
          </select>
          <FieldError>{errors.status}</FieldError>
        </div>
        <IdSelect id={`${id}-tenant`} label="Tenant (optional)" value={form.tenant_id} onChange={set('tenant_id')} options={tenantOptions} none="No tenant" error={errors.tenant_id} />
        <TextField
          id={`${id}-commit`}
          label="Commit rate, kbps (optional)"
          value={form.commit_rate}
          onChange={set('commit_rate', 'commit_rate_kbps')}
          error={errors.commit_rate_kbps}
          max={14}
          placeholder="100000"
        />
        <TextField id={`${id}-install`} label="Install date (optional)" value={form.install_date} onChange={set('install_date')} error={errors.install_date} max={10} placeholder="YYYY-MM-DD" />
        <TextField id={`${id}-term`} label="Termination date (optional)" value={form.termination_date} onChange={set('termination_date')} error={errors.termination_date} max={10} placeholder="YYYY-MM-DD" />
        {canUseFeature('reports', auth) ? (
          <BillingPicker id={`${id}-billing`} value={form.billing_circuit_id} onChange={set('billing_circuit_id')} error={errors.billing_circuit_id} />
        ) : (
          circuit?.billing_circuit_name && (
            <div className="form-group">
              <div className="form-label">Billing circuit</div>
              <div>{circuit.billing_circuit_name}</div>
            </div>
          )
        )}
      </div>
      <TextField id={`${id}-description`} label="Description (optional)" value={form.description} onChange={set('description')} error={errors.description} max={CIRCUIT_DESCRIPTION_MAX} />
      <TextField id={`${id}-comments`} label="Comments (optional)" value={form.comments} onChange={set('comments')} error={errors.comments} max={CIRCUIT_COMMENTS_MAX} multiline />
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(18rem, 1fr))', gap: '1rem' }}>
        {TERM_SIDES.map((side) => (
          <TerminationEditor
            key={side}
            id={`${id}-${side}`}
            side={side}
            draft={terms[side]}
            onChange={setTerm(side)}
            errors={errors}
            choices={choices.data}
            networks={networks.data ?? []}
          />
        ))}
      </div>
    </Modal>
  );
}

function BillingPicker({
  id,
  value,
  onChange,
  error,
}: {
  id: string;
  value: number | null;
  onChange: (v: number | null) => void;
  error?: string;
}) {
  const q = useBillingCircuits();
  const options = (q.data?.circuits ?? []).map((b) => ({
    id: b.id,
    label: b.customer ? `${b.name} (${b.customer})` : b.name,
  }));
  return <IdSelect id={id} label="Billing circuit (optional)" value={value} onChange={onChange} options={options} none="Not billed" error={error} />;
}

function TerminationEditor({
  id,
  side,
  draft,
  onChange,
  errors,
  choices,
  networks,
}: {
  id: string;
  side: TermSide;
  draft: TerminationDraft;
  onChange: (patch: Partial<TerminationDraft>) => void;
  errors: Record<string, string>;
  choices: CircuitChoices | undefined;
  networks: ProviderNetwork[];
}) {
  const p = `terminations.${side}.`;
  const interfaces = useHostInterfaceNames(draft.enabled ? draft.host_id : null);
  const listId = `${id}-interfaces`;
  return (
    <fieldset className="card-inset" style={{ minWidth: 0, margin: 0 }}>
      <legend style={{ fontWeight: 600 }}>
        <label className="form-check" style={{ display: 'inline-flex', gap: '0.4rem', alignItems: 'center' }}>
          <input type="checkbox" checked={draft.enabled} onChange={(e) => onChange({ enabled: e.target.checked })} />
          {side} termination
        </label>
      </legend>
      <FieldError>{errors[`${p}term_side`]}</FieldError>
      {draft.enabled && (
        <>
          <div className="form-group">
            <div className="form-label">Ends at</div>
            <div style={{ display: 'flex', gap: '1rem' }}>
              {(['site', 'network'] as const).map((kind) => (
                <label key={kind} className="form-check" style={{ display: 'inline-flex', gap: '0.35rem', alignItems: 'center' }}>
                  <input type="radio" name={`${id}-kind`} checked={draft.kind === kind} onChange={() => onChange({ kind })} />
                  {kind === 'site' ? 'A site' : 'A provider network'}
                </label>
              ))}
            </div>
          </div>
          {draft.kind === 'site' ? (
            <IdSelect
              id={`${id}-site`}
              label="Site"
              value={draft.site_id}
              onChange={(v) => onChange({ site_id: v })}
              options={(choices?.sites ?? []).map((s) => ({ id: s.id, label: s.name }))}
              none="Choose a site"
              error={errors[`${p}site_id`]}
            />
          ) : (
            <>
              <IdSelect
                id={`${id}-network`}
                label="Provider network"
                value={draft.provider_network_id}
                onChange={(v) => onChange({ provider_network_id: v })}
                options={networks.map((n) => ({ id: n.id, label: `${n.provider_name} · ${n.name}` }))}
                none="Choose a provider network"
                error={errors[`${p}provider_network_id`]}
              />
              <FieldError>{errors[`${p}site_id`]}</FieldError>
            </>
          )}
          <IdSelect
            id={`${id}-host`}
            label="Device (optional)"
            value={draft.host_id}
            onChange={(v) => onChange({ host_id: v, interface_name: v === null ? '' : draft.interface_name })}
            options={(choices?.hosts ?? []).map((h) => ({ id: h.id, label: h.hostname || h.ip_address }))}
            none="No device"
            error={errors[`${p}host_id`]}
          />
          <div className="form-group">
            <label className="form-label" htmlFor={`${id}-iface`}>
              Interface (optional)
            </label>
            <input
              id={`${id}-iface`}
              className="form-input"
              list={listId}
              value={draft.interface_name}
              maxLength={CIRCUIT_TEXT_MAX}
              disabled={draft.host_id === null}
              placeholder={draft.host_id === null ? 'Choose a device first' : 'GigabitEthernet0/1'}
              aria-invalid={!!errors[`${p}interface_name`]}
              onChange={(e) => onChange({ interface_name: e.target.value })}
            />
            <datalist id={listId}>
              {(interfaces.data ?? []).map((name) => (
                <option key={name} value={name} />
              ))}
            </datalist>
            <div className="form-help">The names Plexus collected for the device are offered.</div>
            <FieldError>{errors[`${p}interface_name`]}</FieldError>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0 0.75rem' }}>
            <TextField id={`${id}-port`} label="Port speed, kbps" value={draft.port_speed} onChange={(v) => onChange({ port_speed: v })} error={errors[`${p}port_speed_kbps`]} max={14} />
            <TextField id={`${id}-up`} label="Upstream speed, kbps" value={draft.upstream_speed} onChange={(v) => onChange({ upstream_speed: v })} error={errors[`${p}upstream_speed_kbps`]} max={14} />
            <TextField id={`${id}-xc`} label="Cross-connect ID" value={draft.xconnect_id} onChange={(v) => onChange({ xconnect_id: v })} error={errors[`${p}xconnect_id`]} max={CIRCUIT_TEXT_MAX} />
            <TextField id={`${id}-pp`} label="Patch panel / port" value={draft.pp_info} onChange={(v) => onChange({ pp_info: v })} error={errors[`${p}pp_info`]} max={CIRCUIT_TEXT_MAX} />
          </div>
          <TextField id={`${id}-desc`} label="Description (optional)" value={draft.description} onChange={(v) => onChange({ description: v })} error={errors[`${p}description`]} max={CIRCUIT_DESCRIPTION_MAX} />
        </>
      )}
    </fieldset>
  );
}
