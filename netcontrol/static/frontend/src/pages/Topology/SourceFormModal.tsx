import { useState } from 'react';

import {
  type CloudProvider,
  type MerakiOrg,
  type OrgBuildOptions,
  useCreateMerakiOrg,
  useUpdateMerakiOrg,
} from '@/api/meraki';
import { Callout } from '@/components/Callout';
import { Modal } from '@/components/Modal';

import { SourceSetupModal } from './SourceSetupModal';
import { isSourceFormReady, type SourceFormValues } from './sourceForm';
import { SOURCE_FORM_CONFIGS, sourceFormFields, type SourceField } from './sourceFormConfigs';

export interface SourceFormModalProps {
  provider: CloudProvider;
  existing: MerakiOrg | null;
  defaultOptions: OrgBuildOptions;
  onClose: () => void;
}

const HELP_STYLE = { fontSize: '0.85em', marginTop: '0.25rem' } as const;

/**
 * Add or edit a topology source (Meraki, Cato, FMC, Panorama, Appgate), laid
 * out from its provider config. Adding goes on to the setup steps (check the
 * credentials, first collection, import devices); a failed check comes back
 * here to edit the source just added. Editing an existing source just saves.
 */
export function SourceFormModal({ provider, existing, defaultOptions, onClose }: SourceFormModalProps) {
  const config = SOURCE_FORM_CONFIGS[provider];
  // The source this dialog added; from then on the form edits it.
  const [created, setCreated] = useState<MerakiOrg | null>(null);
  const [setupRun, setSetupRun] = useState(0);
  const [inSetup, setInSetup] = useState(false);
  const saved = existing ?? created;
  const isEdit = saved !== null;
  const [values, setValues] = useState<SourceFormValues>(() => config.fromRecord(existing, defaultOptions));
  const [errMsg, setErrMsg] = useState<string | null>(null);

  const create = useCreateMerakiOrg();
  const update = useUpdateMerakiOrg();
  const pending = create.isPending || update.isPending;
  const ready = isSourceFormReady(sourceFormFields(config), values, isEdit);

  const setValue = (name: string, value: string | number | boolean) => setValues((prev) => ({ ...prev, [name]: value }));

  const submit = async () => {
    setErrMsg(null);
    const body = config.toPayload(values);
    try {
      if (existing) {
        await update.mutateAsync({ id: existing.id, body });
        onClose();
        return;
      }
      const result = created
        ? await update.mutateAsync({ id: created.id, body })
        : await create.mutateAsync(body);
      setCreated(result.org);
      setSetupRun((run) => run + 1);
      setInSetup(true);
    } catch (err) {
      setErrMsg(err instanceof Error ? err.message : String(err));
    }
  };

  const renderField = (field: SourceField) => {
    const id = `${config.idPrefix}-${field.name.replace(/_/g, '-')}`;
    const value = values[field.name];

    if (field.type === 'checkbox') {
      return (
        <div className="form-group" key={field.name} style={{ marginBottom: '0.4rem' }}>
          <label style={{ display: 'flex', alignItems: 'flex-start', gap: '0.5rem' }}>
            <input
              type="checkbox"
              checked={Boolean(value)}
              onChange={(e) => setValue(field.name, e.target.checked)}
              style={{ marginTop: '0.2rem' }}
            />
            <span>
              {field.label}
              {field.help && (
                <span className="text-muted" style={{ display: 'block', fontSize: '0.85em' }}>
                  {field.help}
                </span>
              )}
            </span>
          </label>
        </div>
      );
    }

    const isRequired = field.required === true || (field.required === 'create' && !isEdit);
    const isSecret = field.type === 'password';
    const placeholder = isSecret
      ? isEdit && saved?.has_api_key
        ? '(unchanged if empty)'
        : ''
      : field.placeholder;

    return (
      <div className="form-group" key={field.name}>
        <label className="form-label" htmlFor={id}>
          {field.label} {isRequired && <span style={{ color: 'var(--danger)' }}>*</span>}
        </label>
        <input
          id={id}
          className="form-input"
          type={field.type === 'url' ? 'text' : (field.type ?? 'text')}
          value={typeof value === 'boolean' ? '' : (value ?? '')}
          min={field.min}
          max={field.max}
          onChange={(e) =>
            setValue(
              field.name,
              field.type === 'number' ? Number(e.target.value) || (field.min ?? 0) : e.target.value,
            )
          }
          placeholder={placeholder}
          autoComplete={isSecret ? 'new-password' : field.autoComplete}
        />
        {field.help && (
          <div className="text-muted" style={HELP_STYLE}>
            {field.help}
          </div>
        )}
      </div>
    );
  };

  if (inSetup && created) {
    return <SourceSetupModal key={setupRun} org={created} onEdit={() => setInSetup(false)} onClose={onClose} />;
  }

  return (
    <Modal
      isOpen
      onClose={onClose}
      title={`${isEdit ? 'Edit' : 'Add'} ${config.noun}`}
      size="medium"
      footer={
        <>
          <button type="button" className="btn btn-secondary" onClick={onClose}>
            Cancel
          </button>
          <button type="button" className="btn btn-primary" disabled={!ready || pending} onClick={submit}>
            {existing ? 'Save' : created ? 'Save and check again' : config.addLabel}
          </button>
        </>
      }
    >
      {config.blocks.map((block, i) => {
        switch (block.kind) {
          case 'heading':
            return (
              <h4 key={i} style={{ margin: '0.75rem 0 0.5rem' }}>
                {block.text}
              </h4>
            );
          case 'note':
            return (
              <div key={i} className="text-muted" style={{ fontSize: '0.85em', marginBottom: '0.75rem' }}>
                {block.content}
              </div>
            );
          case 'node':
            return <div key={i}>{block.content}</div>;
          case 'fields':
            if (block.columns === 2) {
              return (
                <div key={i} style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
                  {block.fields.map(renderField)}
                </div>
              );
            }
            return (
              <div key={i} style={block.maxWidth ? { maxWidth: block.maxWidth } : undefined}>
                {block.fields.map(renderField)}
              </div>
            );
        }
      })}

      {errMsg && (
        <Callout tone="danger">
          <strong>{isEdit ? 'Update failed' : 'Create failed'}:</strong> {errMsg}
        </Callout>
      )}
    </Modal>
  );
}
