import { useId, useState } from 'react';

import {
  type ConfigTemplate,
  type IntendedScope,
  type TemplateKind,
  useCreateIntendedTemplate,
  useUpdateIntendedTemplate,
} from '@/api/intendedConfig';
import { DescriptionInput, SaveFailure } from '@/components/CatalogueParts';
import { FieldError } from '@/components/FieldError';
import { Modal } from '@/components/Modal';
import { ModalActions } from '@/components/ModalActions';
import { NameInput } from '@/components/NameInput';
import { runSave } from '@/lib/recordSave';
import { useNameField } from '@/lib/useNameField';

import { EnabledField, IntendedScopeFields } from './IntendedParts';
import { ANY_SCOPE, INTENDED_NAME_MAX, TEMPLATE_TEXT_MAX, templateBody, templateTextError } from './intendedHelpers';
import { TemplatePreviewPane } from './TemplatePreviewPane';

interface Props {
  template: ConfigTemplate | null;
  /** Non-admins see the template without editing it. */
  readOnly?: boolean;
  onClose: () => void;
}

function initialScope(t: ConfigTemplate | null): IntendedScope {
  return t ? { device_type: t.device_type, role_id: t.role_id, site_id: t.site_id, group_id: t.group_id } : ANY_SCOPE;
}

/** Creates or edits a template, with a preview against a real host; read only for non-admins. */
export function TemplateModal({ template, readOnly = false, onClose }: Props) {
  const id = useId();
  const create = useCreateIntendedTemplate();
  const update = useUpdateIntendedTemplate();
  const name = useNameField(template?.name ?? '', INTENDED_NAME_MAX, 'Name', (n) => `A template named "${n}" already exists.`);
  const [kind, setKind] = useState<TemplateKind>(template?.kind === 'snippet' ? 'snippet' : 'device');
  const [scope, setScope] = useState<IntendedScope>(() => initialScope(template));
  const [description, setDescription] = useState(template?.description ?? '');
  const [enabled, setEnabled] = useState(template?.enabled ?? true);
  const [text, setText] = useState(template?.template_text ?? '');
  const [textError, setTextError] = useState<string | undefined>();
  const [failure, setFailure] = useState<string | null>(null);
  const tooLong = text.length > TEMPLATE_TEXT_MAX ? `The template must be ${TEMPLATE_TEXT_MAX.toLocaleString()} characters or fewer.` : undefined;
  const shownTextError = tooLong ?? textError;

  const submit = () => {
    name.touch();
    if (name.error || tooLong) return;
    setTextError(undefined);
    const data = templateBody({ name: name.value, kind, ...scope, template_text: text, description, enabled });
    void runSave(
      () => (template ? update.mutateAsync({ id: template.id, data }) : create.mutateAsync(data)),
      name,
      setFailure,
      onClose,
      (err) => {
        const atLine = templateTextError(err);
        if (atLine) setTextError(atLine);
        return atLine !== null;
      },
    );
  };

  const title = readOnly ? `Template ${template?.name ?? ''}` : template ? `Edit template ${template.name}` : 'Add template';

  return (
    <Modal
      isOpen
      onClose={onClose}
      size="large"
      title={title}
      footer={
        readOnly ? (
          <button type="button" className="btn btn-secondary" onClick={onClose}>
            Close
          </button>
        ) : (
          <ModalActions
            onClose={onClose}
            primaryLabel={template ? 'Save template' : 'Add template'}
            primaryBusy={create.isPending || update.isPending}
            primaryBusyLabel="Saving…"
            onPrimary={submit}
          />
        )
      }
    >
      <SaveFailure what="template" message={failure} />
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: readOnly ? 'minmax(0, 1fr)' : 'repeat(auto-fit, minmax(min(100%, 420px), 1fr))',
          gap: 'var(--space-5)',
          alignItems: 'start',
        }}
      >
        <div>
          {readOnly ? (
            <div className="form-group">
              <div className="form-label">Name</div>
              <div>{template?.name}</div>
            </div>
          ) : (
            <NameInput id={id} label="Name" field={name} max={INTENDED_NAME_MAX} help={`Up to ${INTENDED_NAME_MAX} characters, unique ignoring case. Other templates include it by this name.`} />
          )}
          <div className="form-group">
            <label className="form-label" htmlFor={`${id}-kind`}>
              Kind
            </label>
            <select
              id={`${id}-kind`}
              className="form-select"
              value={kind}
              disabled={readOnly}
              aria-describedby={`${id}-kind-help`}
              onChange={(e) => setKind(e.target.value as TemplateKind)}
            >
              <option value="device">Device: rendered for the devices it applies to</option>
              <option value="snippet">Snippet: only included by other templates</option>
            </select>
            <div className="form-help" id={`${id}-kind-help`}>
              When several device templates match a device, the most specific wins (group, then site, role, driver).
            </div>
          </div>
          {kind === 'device' && <IntendedScopeFields idPrefix={id} scope={scope} onChange={setScope} disabled={readOnly} />}
          {readOnly ? (
            template?.description && (
              <div className="form-group">
                <div className="form-label">Description</div>
                <div>{template.description}</div>
              </div>
            )
          ) : (
            <DescriptionInput id={id} value={description} onChange={setDescription} />
          )}
          <EnabledField
            value={enabled}
            onChange={setEnabled}
            disabled={readOnly}
            help="A disabled template is not rendered for devices; other templates can still include it."
          />
          <div className="form-group">
            <label className="form-label" htmlFor={`${id}-text`}>
              Template (Jinja2)
            </label>
            <textarea
              id={`${id}-text`}
              className="form-textarea drift-baseline-textarea"
              value={text}
              readOnly={readOnly}
              rows={20}
              spellCheck={false}
              wrap="off"
              aria-invalid={!!shownTextError}
              aria-describedby={`${id}-text-help ${id}-text-error`}
              onChange={(e) => {
                setText(e.target.value);
                setTextError(undefined);
              }}
            />
            <div className="form-help" id={`${id}-text-help`}>
              Uses host, group, site, vlans, vrfs, interfaces and context. Filters: netmask, wildcard, network, prefixlen, nth_host, ip.
            </div>
            <FieldError id={`${id}-text-error`}>{shownTextError}</FieldError>
          </div>
        </div>
        {!readOnly && <TemplatePreviewPane idPrefix={id} templateId={template?.id ?? null} text={text} />}
      </div>
    </Modal>
  );
}
