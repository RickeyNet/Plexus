import { useId, useMemo, useState } from 'react';

import {
  type HardwareNotice,
  type LifecycleSettings,
  type SupportContract,
  useLifecycleChoices,
  useSaveContract,
  useSaveLifecycleSettings,
  useSaveNotice,
} from '@/api/lifecycle';
import { SaveFailure } from '@/components/CatalogueParts';
import { FieldError } from '@/components/FieldError';
import { Modal } from '@/components/Modal';
import { ModalActions } from '@/components/ModalActions';
import {
  COMMENTS_MAX,
  CONTRACT_ID_MAX,
  type ContractDraft,
  contractDraft,
  contractErrors,
  contractInput,
  DESCRIPTION_MAX,
  MILESTONES,
  type NoticeDraft,
  noticeDraft,
  noticeErrors,
  noticeInput,
  noticeTarget,
  PART_NUMBER_MAX,
  PROVIDER_MAX,
  SUPPORT_LEVEL_MAX,
  URL_MAX,
  WARN_DAYS_MAX,
} from '@/lib/lifecycle';
import { serverFieldErrors } from '@/lib/serverFieldErrors';
import { IdSelect, TextField } from '@/pages/Circuits/parts';

/** Runs a dialog's save: field errors from the server show at their inputs, anything else in the callout. */
async function saveWith(
  save: () => Promise<unknown>,
  setErrors: (e: Record<string, string>) => void,
  setFailure: (m: string | null) => void,
  onClose: () => void,
) {
  setFailure(null);
  try {
    await save();
    onClose();
  } catch (err) {
    const fields = serverFieldErrors(err);
    if (Object.keys(fields).length > 0) setErrors(fields);
    else setFailure((err as Error).message);
  }
}

// ── Notice ─────────────────────────────────────────────────────────────────

/** Adds (`notice` null) or edits an end-of-life notice. */
export function NoticeModal({ notice, onClose }: { notice: HardwareNotice | null; onClose: () => void }) {
  const id = useId();
  const save = useSaveNotice();
  const choices = useLifecycleChoices();
  const [draft, setDraft] = useState<NoticeDraft>(() => noticeDraft(notice));
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [failure, setFailure] = useState<string | null>(null);

  const set = <K extends keyof NoticeDraft>(key: K, value: NoticeDraft[K]) => {
    setDraft((prev) => ({ ...prev, [key]: value }));
    setErrors((prev) => ({ ...prev, [key]: '' }));
  };

  const typeOptions = (choices.data?.device_types ?? []).map((t) => ({
    id: t.id,
    label: `${t.manufacturer} ${t.model}${t.part_number ? ` (${t.part_number})` : ''}`,
  }));

  const submit = () => {
    const found = noticeErrors(draft);
    setErrors(found);
    if (Object.keys(found).length > 0) return;
    void saveWith(
      () => save.mutateAsync({ id: notice?.id ?? null, data: noticeInput(draft) }),
      setErrors,
      setFailure,
      onClose,
    );
  };

  return (
    <Modal
      isOpen
      onClose={onClose}
      size="medium"
      title={notice ? `Edit notice for ${noticeTarget(notice)}` : 'Add end-of-life notice'}
      footer={
        <ModalActions
          onClose={onClose}
          primaryLabel={notice ? 'Save notice' : 'Add notice'}
          primaryBusy={save.isPending}
          primaryBusyLabel="Saving…"
          onPrimary={submit}
        />
      }
    >
      <SaveFailure what="notice" message={failure} />
      <fieldset className="form-group" style={{ border: 0, padding: 0, margin: 0 }}>
        <legend className="form-label">Applies to</legend>
        <div style={{ display: 'flex', gap: 'var(--space-4)', flexWrap: 'wrap' }}>
          {(
            [
              ['device_type', 'A device type'],
              ['part_number', 'A part number'],
            ] as const
          ).map(([value, label]) => (
            <label key={value} style={{ display: 'flex', gap: 'var(--space-2)', alignItems: 'center' }}>
              <input
                type="radio"
                name={`${id}-target`}
                checked={draft.target === value}
                onChange={() => set('target', value)}
              />
              {label}
            </label>
          ))}
        </div>
      </fieldset>
      {draft.target === 'device_type' ? (
        <IdSelect
          id={`${id}-device-type`}
          label="Device type"
          value={draft.device_type_id}
          onChange={(v) => set('device_type_id', v)}
          options={typeOptions}
          none={choices.isPending ? 'Loading…' : 'Choose a device type'}
          error={errors.device_type_id}
        />
      ) : (
        <TextField
          id={`${id}-part`}
          label="Part number"
          value={draft.part_number}
          onChange={(v) => set('part_number', v)}
          max={PART_NUMBER_MAX}
          error={errors.part_number}
          help="Matches device types by part number or model, and modules by part number, ignoring case."
        />
      )}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(14rem, 1fr))', gap: '0 var(--space-4)' }}>
        {MILESTONES.map((m) => (
          <TextField
            key={m.key}
            id={`${id}-${m.key}`}
            label={`${m.label} (optional)`}
            value={draft[m.key]}
            onChange={(v) => set(m.key, v)}
            max={10}
            placeholder="YYYY-MM-DD"
            error={errors[m.key]}
          />
        ))}
      </div>
      <TextField
        id={`${id}-url`}
        label="Documentation URL (optional)"
        value={draft.documentation_url}
        onChange={(v) => set('documentation_url', v)}
        max={URL_MAX}
        placeholder="https://"
        error={errors.documentation_url}
      />
      <TextField
        id={`${id}-comments`}
        label="Comments (optional)"
        value={draft.comments}
        onChange={(v) => set('comments', v)}
        max={COMMENTS_MAX}
        multiline
        error={errors.comments}
      />
    </Modal>
  );
}

// ── Contract ───────────────────────────────────────────────────────────────

/** Ticks the devices a contract covers, with a name filter. */
function HostChecklist({
  id,
  selected,
  onChange,
  error,
}: {
  id: string;
  selected: number[];
  onChange: (ids: number[]) => void;
  error?: string;
}) {
  const choices = useLifecycleChoices();
  const [filter, setFilter] = useState('');
  const chosen = useMemo(() => new Set(selected), [selected]);
  const hosts = choices.data?.hosts ?? [];
  const needle = filter.trim().toLowerCase();
  const shown = needle
    ? hosts.filter((h) => h.hostname.toLowerCase().includes(needle) || h.ip_address.includes(needle))
    : hosts;
  const toggle = (hostId: number, on: boolean) =>
    onChange(on ? [...selected, hostId] : selected.filter((x) => x !== hostId));

  return (
    <fieldset className="form-group" style={{ border: 0, padding: 0, margin: 0 }} aria-describedby={error ? `${id}-error` : undefined}>
      <legend className="form-label">
        Covered devices ({selected.length.toLocaleString()} selected)
      </legend>
      <input
        type="search"
        className="form-input form-input-sm"
        aria-label="Filter devices"
        placeholder="Filter by name or IP"
        value={filter}
        onChange={(e) => setFilter(e.target.value)}
        style={{ marginBottom: 'var(--space-2)' }}
      />
      <div
        style={{
          maxHeight: '12rem',
          overflowY: 'auto',
          border: '1px solid var(--border)',
          borderRadius: 'var(--radius-sm, 4px)',
          padding: 'var(--space-2)',
        }}
      >
        {choices.isPending && <span className="text-muted">Loading devices…</span>}
        {!choices.isPending && shown.length === 0 && <span className="text-muted">No device matches.</span>}
        {shown.map((h) => (
          <label key={h.id} style={{ display: 'flex', gap: 'var(--space-2)', alignItems: 'center', padding: '2px 0' }}>
            <input type="checkbox" checked={chosen.has(h.id)} onChange={(e) => toggle(h.id, e.target.checked)} />
            <span>{h.hostname}</span>
            <span className="text-muted" style={{ fontSize: '0.88em' }}>
              {h.ip_address}
            </span>
          </label>
        ))}
      </div>
      <FieldError id={`${id}-error`}>{error}</FieldError>
    </fieldset>
  );
}

/** Adds (`contract` null) or edits a support contract and the devices it covers. */
export function ContractModal({ contract, onClose }: { contract: SupportContract | null; onClose: () => void }) {
  const id = useId();
  const save = useSaveContract();
  const [draft, setDraft] = useState<ContractDraft>(() => contractDraft(contract));
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [failure, setFailure] = useState<string | null>(null);

  const set = <K extends keyof ContractDraft>(key: K, value: ContractDraft[K]) => {
    setDraft((prev) => ({ ...prev, [key]: value }));
    setErrors((prev) => ({ ...prev, [key]: '' }));
  };

  const submit = () => {
    const found = contractErrors(draft);
    setErrors(found);
    if (Object.keys(found).length > 0) return;
    void saveWith(
      () => save.mutateAsync({ id: contract?.id ?? null, data: contractInput(draft) }),
      setErrors,
      setFailure,
      onClose,
    );
  };

  const text = (key: 'provider' | 'contract_id' | 'support_level' | 'description', label: string, max: number, help?: string) => (
    <TextField
      id={`${id}-${key}`}
      label={label}
      value={draft[key]}
      onChange={(v) => set(key, v)}
      max={max}
      error={errors[key]}
      help={help}
    />
  );

  return (
    <Modal
      isOpen
      onClose={onClose}
      size="medium"
      title={contract ? `Edit contract ${contract.contract_id}` : 'Add support contract'}
      footer={
        <ModalActions
          onClose={onClose}
          primaryLabel={contract ? 'Save contract' : 'Add contract'}
          primaryBusy={save.isPending}
          primaryBusyLabel="Saving…"
          onPrimary={submit}
        />
      }
    >
      <SaveFailure what="contract" message={failure} />
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(14rem, 1fr))', gap: '0 var(--space-4)' }}>
        {text('provider', 'Provider', PROVIDER_MAX, 'The vendor or reseller.')}
        {text('contract_id', 'Contract ID', CONTRACT_ID_MAX, 'Unique per provider, ignoring case.')}
        <TextField
          id={`${id}-start`}
          label="Start date (optional)"
          value={draft.start_date}
          onChange={(v) => set('start_date', v)}
          max={10}
          placeholder="YYYY-MM-DD"
          error={errors.start_date}
        />
        <TextField
          id={`${id}-end`}
          label="End date (optional)"
          value={draft.end_date}
          onChange={(v) => set('end_date', v)}
          max={10}
          placeholder="YYYY-MM-DD"
          error={errors.end_date}
          help="The last day covered. Without one the contract never expires."
        />
        <TextField
          id={`${id}-cost`}
          label="Cost (optional)"
          value={draft.cost}
          onChange={(v) => set('cost', v)}
          max={16}
          placeholder="1500.00"
          error={errors.cost}
        />
        <TextField
          id={`${id}-currency`}
          label="Currency (optional)"
          value={draft.currency}
          onChange={(v) => set('currency', v)}
          max={3}
          placeholder="USD"
          error={errors.currency}
        />
      </div>
      {text('support_level', 'Support level (optional)', SUPPORT_LEVEL_MAX, 'For example 24x7x4 or Next business day.')}
      {text('description', 'Description (optional)', DESCRIPTION_MAX)}
      <HostChecklist id={`${id}-hosts`} selected={draft.host_ids} onChange={(v) => set('host_ids', v)} error={errors.host_ids} />
      <TextField
        id={`${id}-comments`}
        label="Comments (optional)"
        value={draft.comments}
        onChange={(v) => set('comments', v)}
        max={COMMENTS_MAX}
        multiline
        error={errors.comments}
      />
    </Modal>
  );
}

// ── Settings ───────────────────────────────────────────────────────────────

/** The lifecycle alert check: on or off and its warning windows. */
export function LifecycleSettingsModal({ settings, onClose }: { settings: LifecycleSettings; onClose: () => void }) {
  const id = useId();
  const save = useSaveLifecycleSettings();
  const [enabled, setEnabled] = useState(settings.alerts_enabled);
  const [contractDays, setContractDays] = useState(String(settings.contract_warn_days));
  const [supportDays, setSupportDays] = useState(String(settings.support_warn_days));
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [failure, setFailure] = useState<string | null>(null);

  const days = (text: string): number | null => {
    const n = Number(text.trim());
    return Number.isInteger(n) && n >= 1 && n <= WARN_DAYS_MAX ? n : null;
  };

  const submit = () => {
    const contract = days(contractDays);
    const support = days(supportDays);
    const found: Record<string, string> = {};
    const message = `Enter a whole number of days from 1 to ${WARN_DAYS_MAX}.`;
    if (contract === null) found.contract_warn_days = message;
    if (support === null) found.support_warn_days = message;
    setErrors(found);
    if (contract === null || support === null) return;
    void saveWith(
      () => save.mutateAsync({ alerts_enabled: enabled, contract_warn_days: contract, support_warn_days: support }),
      setErrors,
      setFailure,
      onClose,
    );
  };

  return (
    <Modal
      isOpen
      onClose={onClose}
      size="small"
      title="Lifecycle alert settings"
      footer={
        <ModalActions
          onClose={onClose}
          primaryLabel="Save settings"
          primaryBusy={save.isPending}
          primaryBusyLabel="Saving…"
          onPrimary={submit}
        />
      }
    >
      <SaveFailure what="settings" message={failure} />
      <div className="form-group">
        <label style={{ display: 'flex', gap: 'var(--space-2)', alignItems: 'center' }}>
          <input type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} />
          Raise monitoring alerts for lifecycle conditions
        </label>
      </div>
      <TextField
        id={`${id}-contract`}
        label="Warn before a contract ends (days)"
        value={contractDays}
        onChange={(v) => {
          setContractDays(v);
          setErrors((prev) => ({ ...prev, contract_warn_days: '' }));
        }}
        max={4}
        error={errors.contract_warn_days}
      />
      <TextField
        id={`${id}-support`}
        label="Warn before the last date of support (days)"
        value={supportDays}
        onChange={(v) => {
          setSupportDays(v);
          setErrors((prev) => ({ ...prev, support_warn_days: '' }));
        }}
        max={4}
        error={errors.support_warn_days}
      />
    </Modal>
  );
}
