import { useId, useMemo, useState } from 'react';
import { Link, useSearchParams } from 'react-router';

import {
  type Cable,
  type DcimKind,
  type EndpointInput,
  type EndpointType,
  useCables,
  useDcimHostInterfaces,
  useDeleteCable,
  useSaveCable,
  useTrace,
} from '@/api/dcim';
import { CardHeader, CatalogueBody, Dash, RowActions, SaveFailure } from '@/components/CatalogueParts';
import { DataTable } from '@/components/DataTable';
import { EmptyState } from '@/components/EmptyState';
import { FieldError } from '@/components/FieldError';
import { LoadingState } from '@/components/LoadingState';
import { Modal } from '@/components/Modal';
import { ModalActions } from '@/components/ModalActions';
import { QueryError } from '@/components/QueryError';
import { useConfirmDelete } from '@/components/useConfirmDelete';
import { ENDPOINT_TYPE_LABELS, endpointLabel, traceFromParams, traceLink, traceStatusText } from '@/lib/dcim';
import { runSave } from '@/lib/recordSave';
import { serverFieldErrors } from '@/lib/serverFieldErrors';
import { usePendingKeys } from '@/lib/usePendingKeys';

import { useCanWriteDcim, useChoices, useHostOptions, useRecordOptions } from './hooks';

/** The DCIM page's Cables tab: every cable, adding one between two endpoints, and the trace of a cable end. */
export function CablesTab() {
  const canWrite = useCanWriteDcim();
  const [params, setParams] = useSearchParams();
  const [q, setQ] = useState('');
  const query = useCables({ q });
  const remove = useDeleteCable();
  const confirmDelete = useConfirmDelete();
  const deleting = usePendingKeys<number>();
  const [editing, setEditing] = useState<Cable | 'new' | null>(null);
  const trace = traceFromParams(params);
  const rows = query.data ?? [];
  const showTrace = (ep: EndpointInput) => setParams(new URLSearchParams(traceLink(ep).split('?')[1]));
  const addButton = canWrite && (
    <button type="button" className="btn btn-sm btn-primary" onClick={() => setEditing('new')}>
      Add cable
    </button>
  );
  return (
    <div
      style={{
        display: 'grid',
        gap: '1rem',
        gridTemplateColumns: 'repeat(auto-fit, minmax(min(100%, 30rem), 1fr))',
      }}
    >
      <div className="card">
        <CardHeader
          title="Cables"
          sub={query.data && `${rows.length.toLocaleString()} shown`}
          actions={
            <>
              <input
                className="form-input"
                style={{ width: '14rem' }}
                aria-label="Search cables"
                placeholder="Search label or description"
                value={q}
                onChange={(e) => setQ(e.target.value)}
              />
              {addButton}
            </>
          }
        />
        <CatalogueBody
          query={query}
          what="cables"
          rows={rows}
          empty={
            <EmptyState
              compact
              message={q ? 'No cable matches the search.' : 'No cables yet.'}
              action={q ? undefined : addButton || undefined}
            />
          }
        >
          <DataTable compact aria-label="Cables">
            <thead>
              <tr>
                <th>Label</th>
                <th>Side A</th>
                <th>Side B</th>
                <th>Type</th>
                <th>Status</th>
                <th style={{ textAlign: 'right' }}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((c) => (
                <tr key={c.id}>
                  <td>
                    {c.color && (
                      <span
                        aria-hidden="true"
                        style={{
                          display: 'inline-block',
                          width: 10,
                          height: 10,
                          borderRadius: 2,
                          background: `#${c.color}`,
                          marginRight: 6,
                        }}
                      />
                    )}
                    {c.label || `#${c.id}`}
                  </td>
                  <td>{endpointLabel(c.a)}</td>
                  <td>{endpointLabel(c.b)}</td>
                  <td>{c.type || <Dash />}</td>
                  <td>{c.status}</td>
                  <td style={{ textAlign: 'right' }}>
                    <div className="table-actions" style={{ justifyContent: 'flex-end' }}>
                      <button type="button" className="btn btn-sm btn-secondary" onClick={() => showTrace(c.a)}>
                        Trace
                      </button>
                      {canWrite && (
                        <RowActions
                          label={`cable ${c.label || c.id}`}
                          onEdit={() => setEditing(c)}
                          onDelete={() =>
                            void deleting.run(c.id, () =>
                              confirmDelete('cable', c.label || `#${c.id}`, () => remove.mutateAsync(c.id)),
                            )
                          }
                          deleting={deleting.isPending(c.id)}
                        />
                      )}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </DataTable>
        </CatalogueBody>
        {editing && <CableModal cable={editing === 'new' ? undefined : editing} onClose={() => setEditing(null)} />}
      </div>
      <div className="card">
        <h3 style={{ marginTop: 0 }}>Trace</h3>
        {trace ? <TraceView endpoint={trace} /> : <p className="text-muted">Choose Trace on a cable to follow its path.</p>}
      </div>
    </div>
  );
}

/** The path of a trace drawn top to bottom: endpoints, cables (solid) and pass-throughs (dashed). */
export function TraceView({ endpoint }: { endpoint: EndpointInput }) {
  const q = useTrace(endpoint);
  if (q.isError && !q.data) return <QueryError what="trace" query={q} />;
  if (q.isPending) return <LoadingState text="Tracing…" />;
  const t = q.data;
  const node = (label: string, sub: string, key: string) => (
    <div
      key={key}
      style={{
        border: '1px solid var(--border-color, #555)',
        borderRadius: 6,
        padding: '0.4rem 0.6rem',
      }}
    >
      <div style={{ fontWeight: 600 }}>{label}</div>
      <div className="text-muted" style={{ fontSize: '0.8em' }}>
        {sub}
      </div>
    </div>
  );
  const link = (solid: boolean, text: string, key: string) => (
    <div
      key={key}
      style={{
        display: 'flex',
        alignItems: 'center',
        gap: '0.5rem',
        minHeight: 32,
      }}
    >
      <div
        style={{
          width: 0,
          height: 32,
          marginLeft: '1rem',
          borderLeft: `3px ${solid ? 'solid' : 'dashed'} var(--accent, #6aa0ff)`,
        }}
      />
      <span className="text-muted" style={{ fontSize: '0.85em' }}>
        {text}
      </span>
    </div>
  );
  const items = [node(endpointLabel(t.start), ENDPOINT_TYPE_LABELS[t.start.type] ?? t.start.type, 'start')];
  t.steps.forEach((s, i) => {
    if (s.kind === 'cable') {
      const c = s.cable;
      items.push(link(true, `Cable ${c?.label || `#${c?.id}`}${c?.type ? ` · ${c.type}` : ''}`, `l${i}`));
    } else {
      items.push(link(false, s.position ? `Through, position ${s.position}` : 'Through', `l${i}`));
    }
    items.push(node(endpointLabel(s.far), ENDPOINT_TYPE_LABELS[s.far.type] ?? s.far.type, `n${i}`));
  });
  if (t.power_panel) items.push(link(false, 'Fed from panel', 'panel-l'), node(t.power_panel.name, 'Power panel', 'panel'));
  return (
    <div>
      <p className={t.status === 'complete' ? '' : 'text-muted'} style={{ marginTop: 0 }}>
        {traceStatusText(t.status)}
      </p>
      <div style={{ display: 'flex', flexDirection: 'column' }}>{items}</div>
      {t.start.host_id && (
        <p style={{ marginBottom: 0 }}>
          <Link to={`/devices/${t.start.host_id}`}>Open {t.start.host_name || 'device'}</Link>
        </p>
      )}
    </div>
  );
}

const RECORD_KIND: Partial<Record<EndpointType, DcimKind>> = {
  front_port: 'front_port',
  rear_port: 'rear_port',
  power_port: 'power_port',
  power_outlet: 'power_outlet',
  power_feed: 'power_feed',
};

const recordLabel = (r: Record<string, unknown>) =>
  r.host_name ? `${String(r.host_name)} / ${String(r.name)}` : `${String(r.power_panel_name ?? '')} / ${String(r.name)}`;

function EndpointPicker({
  side,
  value,
  onChange,
  error,
}: {
  side: 'a' | 'b';
  value: EndpointInput;
  onChange: (ep: EndpointInput) => void;
  error?: string;
}) {
  const id = useId();
  const choices = useChoices();
  const hosts = useHostOptions();
  const kind = RECORD_KIND[value.type];
  const records = useRecordOptions(kind ?? 'front_port', recordLabel, kind !== undefined);
  const interfaces = useDcimHostInterfaces(value.type === 'interface' && value.host_id ? value.host_id : null);
  const listId = `${id}-ifaces`;
  return (
    <fieldset className="form-group" style={{ border: 'none', padding: 0 }}>
      <legend className="form-label">Side {side.toUpperCase()}</legend>
      <select
        aria-label={`Side ${side.toUpperCase()} type`}
        className="form-select"
        value={value.type}
        onChange={(e) => onChange({ type: e.target.value as EndpointType })}
      >
        {choices('endpoint_types').map((t) => (
          <option key={t} value={t}>
            {ENDPOINT_TYPE_LABELS[t] ?? t}
          </option>
        ))}
      </select>
      {value.type === 'interface' && (
        <div style={{ display: 'flex', gap: '0.5rem', marginTop: '0.4rem' }}>
          <select
            aria-label={`Side ${side.toUpperCase()} device`}
            className="form-select"
            value={value.host_id ?? ''}
            onChange={(e) =>
              onChange({
                ...value,
                host_id: e.target.value ? Number(e.target.value) : null,
              })
            }
          >
            <option value="">Device…</option>
            {hosts.map((h) => (
              <option key={h.value} value={h.value}>
                {h.label}
              </option>
            ))}
          </select>
          <input
            aria-label={`Side ${side.toUpperCase()} interface`}
            className="form-input"
            list={listId}
            placeholder="Interface"
            value={value.name ?? ''}
            onChange={(e) => onChange({ ...value, name: e.target.value })}
          />
          <datalist id={listId}>
            {(interfaces.data ?? []).map((n) => (
              <option key={n} value={n} />
            ))}
          </datalist>
        </div>
      )}
      {kind && (
        <select
          aria-label={`Side ${side.toUpperCase()} record`}
          className="form-select"
          style={{ marginTop: '0.4rem' }}
          value={value.id ?? ''}
          onChange={(e) =>
            onChange({
              ...value,
              id: e.target.value ? Number(e.target.value) : null,
            })
          }
        >
          <option value="">Choose…</option>
          {records.map((r) => (
            <option key={r.value} value={r.value}>
              {r.label}
            </option>
          ))}
        </select>
      )}
      {value.type === 'circuit_termination' && (
        <input
          aria-label={`Side ${side.toUpperCase()} circuit termination id`}
          className="form-input"
          style={{ marginTop: '0.4rem' }}
          type="number"
          min={1}
          placeholder="Termination id"
          value={value.id ?? ''}
          onChange={(e) =>
            onChange({
              ...value,
              id: e.target.value ? Number(e.target.value) : null,
            })
          }
        />
      )}
      <FieldError>{error}</FieldError>
    </fieldset>
  );
}

function CableModal({ onClose, cable }: { onClose: () => void; cable?: Cable }) {
  const id = useId();
  const save = useSaveCable();
  const choices = useChoices();
  const [a, setA] = useState<EndpointInput>(cable?.a ?? { type: 'interface' });
  const [b, setB] = useState<EndpointInput>(cable?.b ?? { type: 'front_port' });
  const [label, setLabel] = useState(cable?.label ?? '');
  const [type, setType] = useState(cable?.type ?? '');
  const [status, setStatus] = useState(cable?.status ?? 'connected');
  const [color, setColor] = useState(cable?.color ?? '');
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [failure, setFailure] = useState<string | null>(null);
  const colorError = useMemo(() => (color && !/^[0-9a-fA-F]{6}$/.test(color) ? 'Six hex digits, such as 00aaff.' : ''), [color]);

  const submit = () => {
    if (colorError) return;
    setErrors({});
    const clean = (ep: EndpointInput): EndpointInput =>
      ep.type === 'interface'
        ? {
            type: ep.type,
            host_id: ep.host_id ?? null,
            name: (ep.name ?? '').trim(),
          }
        : { type: ep.type, id: ep.id ?? null };
    void runSave(
      () =>
        save.mutateAsync({
          id: cable?.id ?? null,
          data: {
            a: clean(a),
            b: clean(b),
            label: label.trim(),
            type,
            status,
            color,
          },
        }),
      null,
      setFailure,
      onClose,
      (err) => {
        const fields = serverFieldErrors(err);
        if (fields.a || fields.b) {
          setErrors(fields);
          return true;
        }
        return false;
      },
    );
  };

  return (
    <Modal
      isOpen
      onClose={onClose}
      title={cable ? 'Edit cable' : 'Add cable'}
      footer={
        <ModalActions
          onClose={onClose}
          primaryLabel={cable ? 'Save cable' : 'Add cable'}
          primaryBusy={save.isPending}
          primaryBusyLabel="Saving…"
          onPrimary={submit}
        />
      }
    >
      <SaveFailure what="cable" message={failure} />
      <EndpointPicker side="a" value={a} onChange={setA} error={errors.a} />
      <EndpointPicker side="b" value={b} onChange={setB} error={errors.b} />
      <div className="form-group">
        <label className="form-label" htmlFor={`${id}-label`}>
          Label (optional)
        </label>
        <input
          id={`${id}-label`}
          className="form-input"
          value={label}
          maxLength={100}
          onChange={(e) => setLabel(e.target.value)}
        />
      </div>
      <div style={{ display: 'flex', gap: '0.5rem' }}>
        <div className="form-group">
          <label className="form-label" htmlFor={`${id}-type`}>
            Type
          </label>
          <select id={`${id}-type`} className="form-select" value={type} onChange={(e) => setType(e.target.value)}>
            {choices('cable_types').map((t) => (
              <option key={t} value={t}>
                {t || 'Unspecified'}
              </option>
            ))}
          </select>
        </div>
        <div className="form-group">
          <label className="form-label" htmlFor={`${id}-status`}>
            Status
          </label>
          <select id={`${id}-status`} className="form-select" value={status} onChange={(e) => setStatus(e.target.value)}>
            {choices('cable_statuses').map((t) => (
              <option key={t} value={t}>
                {t}
              </option>
            ))}
          </select>
        </div>
        <div className="form-group">
          <label className="form-label" htmlFor={`${id}-color`}>
            Color (hex, optional)
          </label>
          <input
            id={`${id}-color`}
            className="form-input"
            value={color}
            maxLength={6}
            placeholder="00aaff"
            aria-invalid={!!colorError}
            aria-describedby={`${id}-color-error`}
            onChange={(e) => setColor(e.target.value.trim())}
          />
          <FieldError id={`${id}-color-error`}>{colorError}</FieldError>
        </div>
      </div>
    </Modal>
  );
}
