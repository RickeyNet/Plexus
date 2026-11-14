import { useId, useState } from 'react';

import { type ConfigContext, type IntendedScope, useCreateIntendedContext, useUpdateIntendedContext } from '@/api/intendedConfig';
import { DescriptionInput, SaveFailure } from '@/components/CatalogueParts';
import { FieldError } from '@/components/FieldError';
import { Modal } from '@/components/Modal';
import { ModalActions } from '@/components/ModalActions';
import { NameInput } from '@/components/NameInput';
import { runSave } from '@/lib/recordSave';
import { useNameField } from '@/lib/useNameField';

import { EnabledField, IntendedScopeFields } from './IntendedParts';
import {
  ANY_SCOPE,
  contextBody,
  DEFAULT_WEIGHT,
  INTENDED_NAME_MAX,
  parseContextData,
  parseWeight,
  WEIGHT_MAX,
  WEIGHT_MIN,
} from './intendedHelpers';

interface Props {
  context: ConfigContext | null;
  readOnly?: boolean;
  onClose: () => void;
}

const NEW_DATA = '{\n  \n}\n';

function initialScope(c: ConfigContext | null): IntendedScope {
  return c ? { device_type: c.device_type, role_id: c.role_id, site_id: c.site_id, group_id: c.group_id } : ANY_SCOPE;
}

/** Creates or edits a config context; the JSON data must be an object before it is sent. */
export function ContextModal({ context, readOnly = false, onClose }: Props) {
  const id = useId();
  const create = useCreateIntendedContext();
  const update = useUpdateIntendedContext();
  const name = useNameField(context?.name ?? '', INTENDED_NAME_MAX, 'Name', (n) => `A context named "${n}" already exists.`);
  const [weightText, setWeightText] = useState(String(context?.weight ?? DEFAULT_WEIGHT));
  const [weightTouched, setWeightTouched] = useState(false);
  const [scope, setScope] = useState<IntendedScope>(() => initialScope(context));
  const [hostId, setHostId] = useState<number | null>(context?.host_id ?? null);
  const [description, setDescription] = useState(context?.description ?? '');
  const [enabled, setEnabled] = useState(context?.enabled ?? true);
  const [dataText, setDataText] = useState(context ? `${JSON.stringify(context.data, null, 2)}\n` : NEW_DATA);
  const [dataError, setDataError] = useState<string | undefined>();
  const [failure, setFailure] = useState<string | null>(null);

  const weight = parseWeight(weightText);
  const weightError = weight === null ? `Weight must be a whole number from ${WEIGHT_MIN} to ${WEIGHT_MAX.toLocaleString()}.` : undefined;

  const submit = () => {
    name.touch();
    setWeightTouched(true);
    const parsed = parseContextData(dataText);
    setDataError('error' in parsed ? parsed.error : undefined);
    if (name.error || weight === null || 'error' in parsed) return;
    const data = contextBody({ name: name.value, weight, ...scope, host_id: hostId, description, enabled }, parsed.data);
    void runSave(
      () => (context ? update.mutateAsync({ id: context.id, data }) : create.mutateAsync(data)),
      name,
      setFailure,
      onClose,
    );
  };

  const title = readOnly ? `Context ${context?.name ?? ''}` : context ? `Edit context ${context.name}` : 'Add context';

  return (
    <Modal
      isOpen
      onClose={onClose}
      size="medium"
      title={title}
      footer={
        readOnly ? (
          <button type="button" className="btn btn-secondary" onClick={onClose}>
            Close
          </button>
        ) : (
          <ModalActions
            onClose={onClose}
            primaryLabel={context ? 'Save context' : 'Add context'}
            primaryBusy={create.isPending || update.isPending}
            primaryBusyLabel="Saving…"
            onPrimary={submit}
          />
        )
      }
    >
      <SaveFailure what="context" message={failure} />
      {readOnly ? (
        <div className="form-group">
          <div className="form-label">Name</div>
          <div>{context?.name}</div>
        </div>
      ) : (
        <NameInput id={id} label="Name" field={name} max={INTENDED_NAME_MAX} help={`Up to ${INTENDED_NAME_MAX} characters, unique ignoring case.`} />
      )}
      <div className="form-group">
        <label className="form-label" htmlFor={`${id}-weight`}>
          Weight
        </label>
        <input
          id={`${id}-weight`}
          className="form-input"
          inputMode="numeric"
          value={weightText}
          readOnly={readOnly}
          style={{ maxWidth: 160 }}
          aria-invalid={weightTouched && !!weightError}
          aria-describedby={`${id}-weight-help ${id}-weight-error`}
          onChange={(e) => setWeightText(e.target.value)}
          onBlur={() => setWeightTouched(true)}
        />
        <div className="form-help" id={`${id}-weight-help`}>
          Contexts merge in weight order, lowest first, so a higher weight overrides a lower one.
        </div>
        <FieldError id={`${id}-weight-error`}>{weightTouched ? weightError : undefined}</FieldError>
      </div>
      <IntendedScopeFields idPrefix={id} scope={scope} onChange={setScope} host={{ value: hostId, onChange: setHostId }} disabled={readOnly} />
      {readOnly ? (
        context?.description && (
          <div className="form-group">
            <div className="form-label">Description</div>
            <div>{context.description}</div>
          </div>
        )
      ) : (
        <DescriptionInput id={id} value={description} onChange={setDescription} />
      )}
      <EnabledField value={enabled} onChange={setEnabled} disabled={readOnly} help="A disabled context is left out of every merge." />
      <div className="form-group">
        <label className="form-label" htmlFor={`${id}-data`}>
          Data (JSON object)
        </label>
        <textarea
          id={`${id}-data`}
          className="form-textarea drift-baseline-textarea"
          value={dataText}
          readOnly={readOnly}
          rows={14}
          spellCheck={false}
          aria-invalid={!!dataError}
          aria-describedby={`${id}-data-help ${id}-data-error`}
          onChange={(e) => {
            setDataText(e.target.value);
            setDataError(undefined);
          }}
        />
        <div className="form-help" id={`${id}-data-help`}>
          Templates read the merged data as context. Objects merge key by key; any other value, lists included, replaces.
        </div>
        <FieldError id={`${id}-data-error`}>{dataError}</FieldError>
      </div>
    </Modal>
  );
}
