import { useState } from 'react';

import { type HostVariables, type PreviewResult, usePreviewIntended, useIntendedVariables } from '@/api/intendedConfig';
import { BusyButton } from '@/components/BusyButton';
import { Callout } from '@/components/Callout';
import { EmptyState } from '@/components/EmptyState';
import { LoadingState } from '@/components/LoadingState';
import { QueryError } from '@/components/QueryError';
import { idToSelect, selectToId } from '@/lib/deviceModel';

import { renderErrorText } from './intendedHelpers';
import { useIntendedScopeLookups } from './useIntendedScopeLookups';

/** What a preview rendered: the text, or the error with its line. */
export function PreviewResultView({ result }: { result: PreviewResult }) {
  if (result.error) {
    return (
      <Callout tone="danger" title="The template did not render">
        {renderErrorText(result.error, result.template_name)}
      </Callout>
    );
  }
  return (
    <>
      {result.template_name && (
        <div className="text-muted" style={{ fontSize: 'var(--text-sm)', marginBottom: 'var(--space-1)' }}>
          Rendered from {result.template_name}
        </div>
      )}
      {result.config_text ? (
        <pre className="drift-diff-viewer" aria-label="Rendered configuration">
          {result.config_text}
        </pre>
      ) : (
        <EmptyState compact message="The template rendered no text." />
      )}
    </>
  );
}

/** The variables a template sees for a host, and the contexts merged into `context`. */
export function VariablesView({ data }: { data: HostVariables }) {
  return (
    <>
      <div className="text-muted" style={{ fontSize: 'var(--text-sm)', marginBottom: 'var(--space-1)' }}>
        {data.contexts.length
          ? `Contexts merged, in order: ${data.contexts.map((c) => `${c.name} (${c.weight})`).join(', ')}.`
          : 'No config context applies to this host.'}
      </div>
      <pre className="drift-diff-viewer" aria-label="Template variables">
        {JSON.stringify(data.variables, null, 2)}
      </pre>
    </>
  );
}

/**
 * The template editor's preview: pick a host, render the unsaved text for it
 * (nothing is stored), or show the variables that host's template sees.
 */
export function TemplatePreviewPane({ idPrefix, templateId, text }: { idPrefix: string; templateId: number | null; text: string }) {
  const { hosts, failed } = useIntendedScopeLookups();
  const preview = usePreviewIntended();
  const [hostId, setHostId] = useState<number | null>(null);
  const [view, setView] = useState<'preview' | 'variables' | null>(null);
  const [variablesHostId, setVariablesHostId] = useState<number | null>(null);
  const variables = useIntendedVariables(variablesHostId);
  const hostsFailed = failed.find((f) => f.what === 'inventory groups');

  const runPreview = () => {
    if (hostId === null) return;
    setView('preview');
    preview.mutate({ host_id: hostId, template_text: text, ...(templateId !== null ? { template_id: templateId } : {}) });
  };

  const showVariables = () => {
    if (hostId === null) return;
    setView('variables');
    if (variablesHostId === hostId) void variables.refetch();
    else setVariablesHostId(hostId);
  };

  let result = null;
  if (view === 'preview') {
    if (preview.isPending) result = <LoadingState text="Rendering…" />;
    else if (preview.isError) result = <QueryError what="the preview" error={preview.error} onRetry={runPreview} />;
    else if (preview.data) result = <PreviewResultView result={preview.data} />;
  } else if (view === 'variables') {
    if (variables.isError && !variables.data) result = <QueryError what="the host's variables" query={variables} />;
    else if (variables.isPending) result = <LoadingState text="Loading variables…" />;
    else result = <VariablesView data={variables.data} />;
  }

  return (
    <section aria-label="Preview" className="card-inset">
      <h3 style={{ margin: '0 0 var(--space-2)' }}>Preview</h3>
      {hostsFailed && <QueryError what="hosts" query={hostsFailed.query} />}
      <div className="form-group">
        <label className="form-label" htmlFor={`${idPrefix}-preview-host`}>
          Host
        </label>
        <select
          id={`${idPrefix}-preview-host`}
          className="form-select"
          value={idToSelect(hostId)}
          aria-describedby={`${idPrefix}-preview-help`}
          onChange={(e) => setHostId(selectToId(e.target.value))}
        >
          <option value="">Choose a host…</option>
          {hosts.map((h) => (
            <option key={h.id} value={h.id}>
              {h.name} ({h.ip_address})
            </option>
          ))}
        </select>
        <div className="form-help" id={`${idPrefix}-preview-help`}>
          Renders the text above, unsaved, with this host&apos;s data. Nothing is stored.
        </div>
      </div>
      <div style={{ display: 'flex', gap: 'var(--space-2)', marginBottom: 'var(--space-3)' }}>
        <BusyButton className="btn btn-sm btn-primary" busy={preview.isPending} busyLabel="Rendering…" disabled={hostId === null} onClick={runPreview}>
          Preview
        </BusyButton>
        <BusyButton
          className="btn btn-sm btn-secondary"
          busy={view === 'variables' && variables.isFetching}
          disabled={hostId === null}
          onClick={showVariables}
        >
          Variables
        </BusyButton>
      </div>
      {result}
    </section>
  );
}
