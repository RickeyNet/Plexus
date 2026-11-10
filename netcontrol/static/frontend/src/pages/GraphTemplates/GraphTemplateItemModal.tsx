import { useId, useState, type FormEvent } from 'react';

import { Callout } from '@/components/Callout';
import { FieldError } from '@/components/FieldError';
import { Modal } from '@/components/Modal';
import {
  useCreateGraphTemplateItem,
  useUpdateGraphTemplateItem,
  type GraphTemplateItem,
} from '@/api/graphTemplates';
import { parseBoundedInt } from '@/lib/numberInput';

import { CONSOLIDATIONS, LINE_TYPES, METRIC_SUGGESTIONS, withCurrentOption } from './helpers';

const DEFAULT_COLOR = '#10b981';

interface Props {
  templateId: number;
  /** The series being edited, or null to add one. */
  item: GraphTemplateItem | null;
  /** Sort order a new series starts with (after the existing ones). */
  nextSortOrder: number;
  onClose: () => void;
}

/**
 * Add / edit one data series of a graph template. Mount it with a `key` per
 * series so the fields start from that series.
 */
export function GraphTemplateItemModal({ templateId, item, nextSortOrder, onClose }: Props) {
  const formId = useId();
  const createMut = useCreateGraphTemplateItem();
  const updateMut = useUpdateGraphTemplateItem();

  const [label, setLabel] = useState(item?.label ?? '');
  const [metric, setMetric] = useState(item?.metric_name ?? '');
  const [lineType, setLineType] = useState(item?.line_type || 'area');
  const [color, setColor] = useState(item?.color || DEFAULT_COLOR);
  const [consolidation, setConsolidation] = useState(item?.consolidation || 'avg');
  const [sortOrder, setSortOrder] = useState(String(item?.sort_order ?? nextSortOrder));
  const [metricError, setMetricError] = useState<string | null>(null);
  const [saveError, setSaveError] = useState<string | null>(null);
  // A colour input only takes #rrggbb; anything else (blank, a name) becomes the default.
  const colorValue = /^#[0-9a-f]{6}$/i.test(color) ? color : DEFAULT_COLOR;

  function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setSaveError(null);
    if (!metric.trim()) {
      setMetricError('Metric is required');
      return;
    }
    const data = {
      label: label.trim() || metric.trim(),
      metric_name: metric.trim(),
      line_type: lineType,
      color: colorValue,
      consolidation,
      sort_order: parseBoundedInt(sortOrder, 0, 9999, item?.sort_order ?? nextSortOrder),
    };
    const onError = (err: unknown) => { setSaveError((err as Error).message); };
    if (item) {
      updateMut.mutate({ templateId, itemId: item.id, data }, { onSuccess: onClose, onError });
    } else {
      createMut.mutate({ templateId, data }, { onSuccess: onClose, onError });
    }
  }

  const pending = createMut.isPending || updateMut.isPending;

  return (
    <Modal
      isOpen
      onClose={onClose}
      title={item ? 'Edit Data Series' : 'Add Data Series'}
      footer={
        <>
          <button type="button" className="btn btn-secondary" onClick={onClose}>Cancel</button>
          <button type="submit" form={formId} className="btn btn-primary" disabled={pending}>
            {pending ? 'Saving…' : item ? 'Save' : 'Add'}
          </button>
        </>
      }
    >
      <form id={formId} onSubmit={handleSubmit}>
        {saveError && <Callout tone="danger">{saveError}</Callout>}
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.75rem' }}>
          <div className="form-group">
            <label className="form-label" htmlFor={`${formId}-metric`}>Metric</label>
            <input
              id={`${formId}-metric`}
              className="form-input"
              list={`${formId}-metrics`}
              value={metric}
              onChange={(e) => {
                setMetric(e.target.value);
                setMetricError(null);
              }}
              placeholder="e.g. cpu_usage"
              required
              aria-invalid={!!metricError}
            />
            <datalist id={`${formId}-metrics`}>
              {METRIC_SUGGESTIONS.map((m) => <option key={m} value={m} />)}
            </datalist>
            <FieldError>{metricError}</FieldError>
          </div>
          <div className="form-group">
            <label className="form-label" htmlFor={`${formId}-label`}>Label</label>
            <input id={`${formId}-label`} className="form-input" value={label} onChange={(e) => setLabel(e.target.value)} placeholder="Defaults to the metric name" />
          </div>
          <div className="form-group">
            <label className="form-label" htmlFor={`${formId}-line-type`}>Line Type</label>
            <select id={`${formId}-line-type`} className="form-select" value={lineType} onChange={(e) => setLineType(e.target.value)}>
              {withCurrentOption(LINE_TYPES, lineType).map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}
            </select>
          </div>
          <div className="form-group">
            <label className="form-label" htmlFor={`${formId}-consolidation`}>Consolidation</label>
            <select id={`${formId}-consolidation`} className="form-select" value={consolidation} onChange={(e) => setConsolidation(e.target.value)}>
              {withCurrentOption(CONSOLIDATIONS, consolidation).map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}
            </select>
          </div>
          <div className="form-group">
            <label className="form-label" htmlFor={`${formId}-color`}>Color</label>
            <input id={`${formId}-color`} type="color" value={colorValue} onChange={(e) => setColor(e.target.value)} style={{ width: 64, height: 32, padding: 0, border: 'none', background: 'none' }} />
            <span style={{ marginLeft: '0.5rem', fontSize: '0.85rem' }}>{colorValue}</span>
          </div>
          <div className="form-group">
            <label className="form-label" htmlFor={`${formId}-sort`}>Sort Order</label>
            <input id={`${formId}-sort`} className="form-input" type="number" min={0} value={sortOrder} onChange={(e) => setSortOrder(e.target.value)} />
          </div>
        </div>
      </form>
    </Modal>
  );
}
