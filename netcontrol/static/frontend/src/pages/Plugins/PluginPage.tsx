import { useId, useState, type FormEvent } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { useParams } from 'react-router';

import {
  cellText,
  formBody,
  initialFormValues,
  pluginTableQueryKey,
  refreshSources,
  submitPluginForm,
  usePluginManifest,
  usePluginTable,
  type FormValues,
  type PluginBlock,
  type PluginFormBlock,
  type PluginFormField,
  type PluginTableBlock,
} from '@/api/plugins';
import { BusyButton } from '@/components/BusyButton';
import { DataTable } from '@/components/DataTable';
import { EmptyState } from '@/components/EmptyState';
import { LoadingState } from '@/components/LoadingState';
import { PageHeader } from '@/components/PageHeader';
import { QueryError } from '@/components/QueryError';

/**
 * Host for a plugin's declarative page (`/plugins/:name/:pageId`). The page
 * definition comes from the `/api/plugins` manifest; every block is rendered
 * by Plexus' own components and its data is read from and sent to the
 * plugin's API only. No plugin code runs in the browser.
 */
export function PluginPage() {
  const { name = '', pageId = '' } = useParams<{ name: string; pageId: string }>();
  const manifest = usePluginManifest();

  if (manifest.isError && !manifest.data) {
    return (
      <div>
        <PageHeader title="Plugin" />
        <QueryError what="plugins" query={manifest} />
      </div>
    );
  }
  if (!manifest.data) {
    return (
      <div>
        <PageHeader title="Plugin" />
        <LoadingState />
      </div>
    );
  }

  const plugin = manifest.data.plugins.find((p) => p.name === name && p.status === 'active');
  const page = plugin?.pages.find((p) => p.id === pageId);
  if (!plugin || !page) {
    return (
      <div>
        <PageHeader title="Plugin" />
        <EmptyState
          message="This plugin page is not available."
          description="The plugin may be switched off, failed to start, or you may not have access to it."
        />
      </div>
    );
  }

  return (
    <div>
      <PageHeader title={page.title} />
      {page.description && <p className="text-muted">{page.description}</p>}
      <div className="stack">
        {page.blocks.map((block) => (
          <div key={block.id} className="card card-sm">
            <Block plugin={plugin.name} block={block} blocks={page.blocks} />
          </div>
        ))}
      </div>
    </div>
  );
}

function Block({ plugin, block, blocks }: { plugin: string; block: PluginBlock; blocks: PluginBlock[] }) {
  switch (block.type) {
    case 'text':
      return <p style={{ margin: 0, whiteSpace: 'pre-wrap' }}>{block.text}</p>;
    case 'table':
      return <TableBlock plugin={plugin} block={block} />;
    case 'form':
      return <FormBlock plugin={plugin} block={block} refreshSources={refreshSources(block, blocks)} />;
    default:
      return null;
  }
}

function TableBlock({ plugin, block }: { plugin: string; block: PluginTableBlock }) {
  const rows = usePluginTable(plugin, block.source);
  return (
    <section>
      {block.title && <h4 style={{ margin: '0 0 0.5rem 0' }}>{block.title}</h4>}
      {rows.isError && !rows.data ? (
        <QueryError what={block.title ? block.title.toLowerCase() : 'table'} query={rows} />
      ) : !rows.data ? (
        <LoadingState variant="inline" />
      ) : rows.data.length === 0 ? (
        <EmptyState compact message={block.empty_text} />
      ) : (
        <DataTable compact aria-label={block.title || undefined}>
          <thead>
            <tr>
              {block.columns.map((c) => (
                <th key={c.key}>{c.label}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {rows.data.map((row, i) => (
              <tr key={cellText(row.id) || i}>
                {block.columns.map((c) => (
                  <td key={c.key}>{cellText(row[c.key])}</td>
                ))}
              </tr>
            ))}
          </tbody>
        </DataTable>
      )}
    </section>
  );
}

function FormBlock({
  plugin,
  block,
  refreshSources,
}: {
  plugin: string;
  block: PluginFormBlock;
  refreshSources: string[];
}) {
  const qc = useQueryClient();
  const [values, setValues] = useState<FormValues>(() => initialFormValues(block.fields));
  const [status, setStatus] = useState<{ kind: 'success' | 'error'; message: string } | null>(null);
  const submit = useMutation({
    mutationFn: (body: Record<string, unknown>) => submitPluginForm(plugin, block, body),
    onSuccess: () => {
      setValues(initialFormValues(block.fields));
      setStatus({ kind: 'success', message: 'Saved' });
      for (const source of refreshSources) {
        void qc.invalidateQueries({ queryKey: pluginTableQueryKey(plugin, source) });
      }
    },
    onError: (err) => setStatus({ kind: 'error', message: `Could not save: ${(err as Error).message}` }),
  });

  const onSubmit = (e: FormEvent) => {
    e.preventDefault();
    setStatus(null);
    const result = formBody(block.fields, values);
    if ('missing' in result) {
      setStatus({ kind: 'error', message: `Enter a valid value for ${result.missing}.` });
      return;
    }
    submit.mutate(result.body);
  };

  return (
    <form onSubmit={onSubmit} noValidate>
      {block.title && <h4 style={{ margin: '0 0 0.5rem 0' }}>{block.title}</h4>}
      <div className="form-row">
        {block.fields.map((f) => (
          <Field
            key={f.name}
            field={f}
            value={values[f.name]}
            onChange={(v) => setValues((prev) => ({ ...prev, [f.name]: v }))}
          />
        ))}
      </div>
      <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginTop: '0.5rem' }}>
        <BusyButton type="submit" className="btn btn-primary" busy={submit.isPending} busyLabel="Saving…">
          {block.submit_label}
        </BusyButton>
        {status && (
          <span role={status.kind === 'error' ? 'alert' : 'status'} className={status.kind === 'error' ? 'error' : 'text-muted'}>
            {status.message}
          </span>
        )}
      </div>
    </form>
  );
}

function Field({
  field,
  value,
  onChange,
}: {
  field: PluginFormField;
  value: string | boolean | undefined;
  onChange: (v: string | boolean) => void;
}) {
  const id = useId();
  const help = field.help ? <div className="form-help" id={`${id}-help`}>{field.help}</div> : null;
  const describedBy = field.help ? `${id}-help` : undefined;
  if (field.type === 'checkbox') {
    return (
      <div className="form-group form-check-field">
        <span className="form-label" aria-hidden="true">&nbsp;</span>
        <label className="form-check">
          <input type="checkbox" checked={value === true} onChange={(e) => onChange(e.target.checked)} aria-describedby={describedBy} />
          <span>{field.label}</span>
        </label>
        {help}
      </div>
    );
  }
  const text = typeof value === 'string' ? value : '';
  const label = (
    <label className="form-label" htmlFor={id}>
      {field.label}
      {field.required && <span aria-hidden="true"> *</span>}
    </label>
  );
  let control;
  if (field.type === 'select') {
    control = (
      <select id={id} className="form-select" value={text} required={field.required} aria-describedby={describedBy} onChange={(e) => onChange(e.target.value)}>
        {!field.required && <option value="">—</option>}
        {field.options.map((o) => (
          <option key={o} value={o}>{o}</option>
        ))}
      </select>
    );
  } else if (field.type === 'textarea') {
    control = (
      <textarea id={id} className="form-input" rows={3} value={text} required={field.required} aria-describedby={describedBy} onChange={(e) => onChange(e.target.value)} />
    );
  } else {
    control = (
      <input
        id={id}
        className="form-input"
        type={field.type === 'number' ? 'number' : 'text'}
        value={text}
        required={field.required}
        aria-describedby={describedBy}
        onChange={(e) => onChange(e.target.value)}
      />
    );
  }
  return (
    <div className="form-group" style={{ flex: field.type === 'textarea' ? '1 1 100%' : '1 1 180px' }}>
      {label}
      {control}
      {help}
    </div>
  );
}
