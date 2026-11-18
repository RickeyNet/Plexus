import { useId, useState } from 'react';

import {
  type ExportObjectType,
  type ExportObjectTypeInfo,
  type ExportTemplate,
  useCreateExportTemplate,
  usePreviewExportTemplate,
  useUpdateExportTemplate,
} from '@/api/exportTemplates';
import { BusyButton } from '@/components/BusyButton';
import { Callout } from '@/components/Callout';
import { DescriptionInput, SaveFailure } from '@/components/CatalogueParts';
import { EmptyState } from '@/components/EmptyState';
import { FieldError } from '@/components/FieldError';
import { LoadingState } from '@/components/LoadingState';
import { Modal } from '@/components/Modal';
import { ModalActions } from '@/components/ModalActions';
import { NameInput } from '@/components/NameInput';
import { QueryError } from '@/components/QueryError';
import { runSave } from '@/lib/recordSave';
import { useNameField } from '@/lib/useNameField';
import { renderErrorText, templateTextError } from '@/pages/Configuration/intendedHelpers';

export const EXPORT_NAME_MAX = 100;
export const EXPORT_TEXT_MAX = 262_144;
const PREVIEW_LIMIT = 20;

const STARTER = '{% for obj in queryset %}\n{{ obj.id }}\n{% endfor %}\n';

interface Props {
  template: ExportTemplate | null;
  objectTypes: ExportObjectTypeInfo[];
  onClose: () => void;
}

/** The rendered preview: the text, or the error with its line. */
export function ExportPreviewView({ result }: { result: NonNullable<ReturnType<typeof usePreviewExportTemplate>['data']> }) {
  if (result.error) {
    return (
      <Callout tone="danger" title="The template did not render">
        {/* 'export' is the name the server renders a template under. */}
        {renderErrorText(result.error, 'export')}
      </Callout>
    );
  }
  return (
    <>
      <div className="text-muted" style={{ fontSize: 'var(--text-sm)', marginBottom: 'var(--space-1)' }}>
        Rendered with the first {result.count.toLocaleString()} of {result.total.toLocaleString()} objects.
      </div>
      {result.output ? (
        <pre className="drift-diff-viewer" aria-label="Rendered output">
          {result.output}
        </pre>
      ) : (
        <EmptyState compact message="The template rendered no text." />
      )}
    </>
  );
}

/** Creates or edits an export template, with a preview against current data. */
export function ExportTemplateModal({ template, objectTypes, onClose }: Props) {
  const id = useId();
  const create = useCreateExportTemplate();
  const update = useUpdateExportTemplate();
  const preview = usePreviewExportTemplate();
  const name = useNameField(
    template?.name ?? '',
    EXPORT_NAME_MAX,
    'Name',
    (n) => `An export template named "${n}" already exists for this object type.`,
  );
  const [objectType, setObjectType] = useState<ExportObjectType>(template?.object_type ?? 'host');
  const [description, setDescription] = useState(template?.description ?? '');
  const [text, setText] = useState(template?.template_text ?? STARTER);
  const [mimeType, setMimeType] = useState(template?.mime_type ?? 'text/plain');
  const [extension, setExtension] = useState(template?.file_extension ?? 'txt');
  const [asAttachment, setAsAttachment] = useState(template?.as_attachment ?? true);
  const [textError, setTextError] = useState<string | undefined>();
  const [failure, setFailure] = useState<string | null>(null);
  const tooLong = text.length > EXPORT_TEXT_MAX ? `The template must be ${EXPORT_TEXT_MAX.toLocaleString()} characters or fewer.` : undefined;
  const shownTextError = tooLong ?? textError;
  const typeInfo = objectTypes.find((t) => t.key === objectType);

  const submit = () => {
    name.touch();
    if (name.error || tooLong) return;
    setTextError(undefined);
    const data = {
      name: name.value.trim(),
      object_type: objectType,
      description,
      template_text: text,
      mime_type: mimeType,
      file_extension: extension,
      as_attachment: asAttachment,
    };
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

  const runPreview = () => preview.mutate({ object_type: objectType, template_text: text, limit: PREVIEW_LIMIT });

  let result = null;
  if (preview.isPending) result = <LoadingState text="Rendering…" />;
  else if (preview.isError) result = <QueryError what="the preview" error={preview.error} onRetry={runPreview} />;
  else if (preview.data) result = <ExportPreviewView result={preview.data} />;

  return (
    <Modal
      isOpen
      onClose={onClose}
      size="large"
      title={template ? `Edit export template ${template.name}` : 'Add export template'}
      footer={
        <ModalActions
          onClose={onClose}
          primaryLabel={template ? 'Save template' : 'Add template'}
          primaryBusy={create.isPending || update.isPending}
          primaryBusyLabel="Saving…"
          onPrimary={submit}
        />
      }
    >
      <SaveFailure what="template" message={failure} />
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(min(100%, 420px), 1fr))',
          gap: 'var(--space-5)',
          alignItems: 'start',
        }}
      >
        <div>
          <NameInput id={id} label="Name" field={name} max={EXPORT_NAME_MAX} help={`Up to ${EXPORT_NAME_MAX} characters, unique per object type ignoring case. Also names the file.`} />
          <div className="form-group">
            <label className="form-label" htmlFor={`${id}-type`}>
              Object type
            </label>
            <select
              id={`${id}-type`}
              className="form-select"
              value={objectType}
              onChange={(e) => setObjectType(e.target.value as ExportObjectType)}
            >
              {objectTypes.map((t) => (
                <option key={t.key} value={t.key}>
                  {t.label}
                </option>
              ))}
            </select>
          </div>
          <DescriptionInput id={id} value={description} onChange={setDescription} />
          <div style={{ display: 'flex', gap: 'var(--space-3)', flexWrap: 'wrap' }}>
            <div className="form-group" style={{ flex: '2 1 12rem' }}>
              <label className="form-label" htmlFor={`${id}-mime`}>
                MIME type
              </label>
              <input
                id={`${id}-mime`}
                className="form-input"
                value={mimeType}
                maxLength={100}
                placeholder="text/csv"
                onChange={(e) => setMimeType(e.target.value)}
              />
            </div>
            <div className="form-group" style={{ flex: '1 1 6rem' }}>
              <label className="form-label" htmlFor={`${id}-ext`}>
                File extension
              </label>
              <input
                id={`${id}-ext`}
                className="form-input"
                value={extension}
                maxLength={17}
                placeholder="csv"
                onChange={(e) => setExtension(e.target.value)}
              />
            </div>
          </div>
          <div className="form-group">
            <label className="form-check">
              <input type="checkbox" checked={asAttachment} onChange={(e) => setAsAttachment(e.target.checked)} />{' '}
              Download as a file
            </label>
            <div className="form-help">Unchecked, the browser shows the rendered text instead.</div>
          </div>
          <div className="form-group">
            <label className="form-label" htmlFor={`${id}-text`}>
              Template (Jinja2)
            </label>
            <textarea
              id={`${id}-text`}
              className="form-textarea drift-baseline-textarea"
              value={text}
              rows={18}
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
              Uses <code>queryset</code> (a list of objects), <code>now</code> (UTC) and <code>object_type</code>.
              {typeInfo && typeInfo.fields.length > 0 && <> Each object has {typeInfo.fields.join(', ')}.</>}
            </div>
            <FieldError id={`${id}-text-error`}>{shownTextError}</FieldError>
          </div>
        </div>
        <section aria-label="Preview" className="card-inset">
          <h3 style={{ margin: '0 0 var(--space-2)' }}>Preview</h3>
          <div className="form-help" style={{ marginTop: 0 }}>
            Renders the text, unsaved, with the first {PREVIEW_LIMIT} objects of the type. Nothing is stored.
          </div>
          <div style={{ marginBottom: 'var(--space-3)' }}>
            <BusyButton className="btn btn-sm btn-primary" busy={preview.isPending} busyLabel="Rendering…" onClick={runPreview}>
              Preview
            </BusyButton>
          </div>
          {result}
        </section>
      </div>
    </Modal>
  );
}
