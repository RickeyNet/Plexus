import { useId, useState, type FormEvent } from 'react';

import { Callout } from '@/components/Callout';
import { FieldError } from '@/components/FieldError';
import { LoadingState } from '@/components/LoadingState';
import { Modal } from '@/components/Modal';
import {
  useCreateGraphTemplate,
  useGraphTemplate,
  useUpdateGraphTemplate,
} from '@/api/graphTemplates';
import { parseBoundedInt } from '@/lib/numberInput';

interface Props {
  mode: 'create' | 'edit' | null;
  templateId: number | null;
  onClose: () => void;
}

const DEFAULT_GRID_W = 6;
const DEFAULT_GRID_H = 4;

export function GraphTemplateFormModal({ mode, templateId, onClose }: Props) {
  const formId = useId();
  const isOpen = mode != null;
  const query = useGraphTemplate(mode === 'edit' ? templateId : null);
  const createMut = useCreateGraphTemplate();
  const updateMut = useUpdateGraphTemplate();

  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [graphType, setGraphType] = useState('line');
  const [scope, setScope] = useState('device');
  const [category, setCategory] = useState('system');
  const [titleFormat, setTitleFormat] = useState('');
  const [yAxisLabel, setYAxisLabel] = useState('');
  const [stacked, setStacked] = useState(false);
  const [areaFill, setAreaFill] = useState(true);
  const [gridW, setGridW] = useState(String(DEFAULT_GRID_W));
  const [gridH, setGridH] = useState(String(DEFAULT_GRID_H));
  const [nameError, setNameError] = useState<string | null>(null);
  const [saveError, setSaveError] = useState<string | null>(null);

  // Seed form fields from mode / loaded template data; re-seed when either changes.
  const [prevSeed, setPrevSeed] = useState<{ mode: typeof mode; data: typeof query.data }>({
    mode,
    data: query.data,
  });
  if (prevSeed.mode !== mode || prevSeed.data !== query.data) {
    setPrevSeed({ mode, data: query.data });
    setNameError(null);
    setSaveError(null);
    if (mode === 'create') {
      setName(''); setDescription(''); setGraphType('line'); setScope('device');
      setCategory('system'); setTitleFormat(''); setYAxisLabel('');
      setStacked(false); setAreaFill(true);
      setGridW(String(DEFAULT_GRID_W)); setGridH(String(DEFAULT_GRID_H));
    } else if (mode === 'edit' && query.data) {
      const t = query.data;
      setName(t.name ?? ''); setDescription(t.description ?? '');
      setGraphType(t.graph_type || 'line'); setScope(t.scope || 'device');
      setCategory(t.category || 'system'); setTitleFormat(t.title_format ?? '');
      setYAxisLabel(t.y_axis_label ?? '');
      setStacked(!!t.stacked); setAreaFill(!!t.area_fill);
      setGridW(String(t.grid_w ?? DEFAULT_GRID_W)); setGridH(String(t.grid_h ?? DEFAULT_GRID_H));
    }
  }

  function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setSaveError(null);
    if (!name.trim()) {
      setNameError('Name is required');
      return;
    }
    const data = {
      name: name.trim(),
      description: description.trim(),
      graph_type: graphType,
      scope,
      category,
      title_format: titleFormat.trim(),
      y_axis_label: yAxisLabel.trim(),
      stacked,
      area_fill: areaFill,
      grid_w: parseBoundedInt(gridW, 1, 12, DEFAULT_GRID_W),
      grid_h: parseBoundedInt(gridH, 1, 12, DEFAULT_GRID_H),
    };
    const onError = (err: unknown) => { setSaveError((err as Error).message); };
    if (mode === 'edit' && templateId != null) {
      updateMut.mutate({ id: templateId, data }, { onSuccess: onClose, onError });
    } else {
      createMut.mutate(data, { onSuccess: onClose, onError });
    }
  }

  const pending = createMut.isPending || updateMut.isPending;
  const loading = mode === 'edit' && query.isPending;
  const loadError = mode === 'edit' ? query.error : null;

  return (
    <Modal
      isOpen={isOpen}
      onClose={onClose}
      title={mode === 'edit' ? 'Edit Graph Template' : 'New Graph Template'}
      size="medium"
      footer={
        <>
          <button type="button" className="btn btn-secondary" onClick={onClose}>Cancel</button>
          {!loading && !loadError && (
            <button type="submit" form={formId} className="btn btn-primary" disabled={pending}>
              {pending ? 'Saving…' : mode === 'edit' ? 'Save' : 'Create'}
            </button>
          )}
        </>
      }
    >
      {loading && <LoadingState />}
      {loadError && <Callout tone="danger">Failed to load the template: {(loadError as Error).message}</Callout>}
      {!loading && !loadError && (
        <form id={formId} onSubmit={handleSubmit}>
          {saveError && <Callout tone="danger">{saveError}</Callout>}
          <div className="form-group">
            <label className="form-label" htmlFor={`${formId}-name`}>Name</label>
            <input
              id={`${formId}-name`}
              className="form-input"
              value={name}
              onChange={(e) => {
                setName(e.target.value);
                setNameError(null);
              }}
              placeholder="e.g. CPU Usage"
              required
              aria-invalid={!!nameError}
            />
            <FieldError>{nameError}</FieldError>
          </div>
          <div className="form-group">
            <label className="form-label" htmlFor={`${formId}-description`}>Description</label>
            <input id={`${formId}-description`} className="form-input" value={description} onChange={(e) => setDescription(e.target.value)} placeholder="Optional description" />
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.75rem' }}>
            <div className="form-group">
              <label className="form-label" htmlFor={`${formId}-graph-type`}>Graph Type</label>
              <select id={`${formId}-graph-type`} className="form-select" value={graphType} onChange={(e) => setGraphType(e.target.value)}>
                <option value="line">Line</option>
                <option value="bar">Bar</option>
                <option value="gauge">Gauge</option>
                <option value="heatmap">Heatmap</option>
              </select>
            </div>
            <div className="form-group">
              <label className="form-label" htmlFor={`${formId}-scope`}>Scope</label>
              <select id={`${formId}-scope`} className="form-select" value={scope} onChange={(e) => setScope(e.target.value)}>
                <option value="device">Device</option>
                <option value="interface">Interface</option>
              </select>
            </div>
            <div className="form-group">
              <label className="form-label" htmlFor={`${formId}-category`}>Category</label>
              <select id={`${formId}-category`} className="form-select" value={category} onChange={(e) => setCategory(e.target.value)}>
                <option value="system">System</option>
                <option value="traffic">Traffic</option>
                <option value="availability">Availability</option>
                <option value="custom">Custom</option>
              </select>
            </div>
            <div className="form-group">
              <label className="form-label" htmlFor={`${formId}-title-format`}>Title Format</label>
              <input id={`${formId}-title-format`} className="form-input" value={titleFormat} onChange={(e) => setTitleFormat(e.target.value)} placeholder="$interface Traffic" />
            </div>
            <div className="form-group">
              <label className="form-label" htmlFor={`${formId}-y-axis-label`}>Y-Axis Label</label>
              <input id={`${formId}-y-axis-label`} className="form-input" value={yAxisLabel} onChange={(e) => setYAxisLabel(e.target.value)} placeholder="e.g. Bits/sec" />
            </div>
            <div className="form-group" style={{ display: 'flex', gap: '1rem', alignItems: 'center', paddingTop: '1.5rem' }}>
              <label><input type="checkbox" checked={stacked} onChange={(e) => setStacked(e.target.checked)} /> Stacked</label>
              <label><input type="checkbox" checked={areaFill} onChange={(e) => setAreaFill(e.target.checked)} /> Area Fill</label>
            </div>
            <div className="form-group">
              <label className="form-label" htmlFor={`${formId}-grid-w`}>Grid Width (1-12 columns)</label>
              <input id={`${formId}-grid-w`} className="form-input" type="number" min={1} max={12} value={gridW} onChange={(e) => setGridW(e.target.value)} />
            </div>
            <div className="form-group">
              <label className="form-label" htmlFor={`${formId}-grid-h`}>Grid Height (1-12 rows)</label>
              <input id={`${formId}-grid-h`} className="form-input" type="number" min={1} max={12} value={gridH} onChange={(e) => setGridH(e.target.value)} />
            </div>
          </div>
        </form>
      )}
    </Modal>
  );
}
