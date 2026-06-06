import { useState } from 'react';

import {
  type DashboardPanel,
  type PanelPayload,
  useCreatePanel,
  useUpdatePanel,
} from '@/api/dashboard';
import { Modal } from '@/components/Modal';
import { useDialogs } from '@/components/DialogProvider-context';

interface PanelMetricQuery {
  metric?: string;
  host?: string;
  group?: string;
}

interface Props {
  isOpen: boolean;
  onClose: () => void;
  dashboardId: number;
  panel?: DashboardPanel | null;
}

const CHART_TYPES = ['line', 'bar', 'gauge', 'heatmap', 'table'] as const;

const DEFAULTS: PanelPayload = {
  title: '',
  chart_type: 'line',
  metric_query_json: JSON.stringify({ metric: 'cpu_percent', host: '*' }),
  grid_w: 6,
  grid_h: 4,
  grid_x: 0,
  grid_y: 0,
};

function parseQuery(json: string | undefined): PanelMetricQuery {
  if (!json) return {};
  try {
    return JSON.parse(json) as PanelMetricQuery;
  } catch {
    return {};
  }
}

export function PanelModal({ isOpen, onClose, dashboardId, panel }: Props) {
  const { alert } = useDialogs();
  const create = useCreatePanel(dashboardId);
  const update = useUpdatePanel(dashboardId);
  const editing = panel != null;

  const [title, setTitle] = useState('');
  const [chartType, setChartType] = useState('line');
  const [metric, setMetric] = useState('cpu_percent');
  const [host, setHost] = useState('*');
  const [gridW, setGridW] = useState(6);
  const [gridH, setGridH] = useState(4);

  // Seed form fields when the modal opens or the edited panel changes.
  const [prevSeed, setPrevSeed] = useState<{ isOpen: boolean; panel?: DashboardPanel | null }>({
    isOpen,
    panel,
  });
  if (prevSeed.isOpen !== isOpen || prevSeed.panel !== panel) {
    setPrevSeed({ isOpen, panel });
    if (isOpen) {
      if (panel) {
        const q = parseQuery(panel.metric_query_json);
        setTitle(panel.title || '');
        setChartType(panel.chart_type || 'line');
        setMetric(q.metric ?? 'cpu_percent');
        setHost(q.host ?? '*');
        setGridW(panel.grid_w || 6);
        setGridH(panel.grid_h || 4);
      } else {
        setTitle('');
        setChartType('line');
        setMetric('cpu_percent');
        setHost('*');
        setGridW(6);
        setGridH(4);
      }
    }
  }

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    const payload: PanelPayload = {
      ...DEFAULTS,
      title: title.trim() || 'Untitled',
      chart_type: chartType,
      metric_query_json: JSON.stringify({
        metric: metric.trim() || 'cpu_percent',
        host: host.trim() || '*',
      }),
      grid_w: Math.min(Math.max(gridW, 1), 12),
      grid_h: Math.min(Math.max(gridH, 1), 12),
    };

    const onError = (err: unknown) => {
      void alert({ message: (err as Error).message, variant: 'error' });
    };
    if (editing && panel) {
      update.mutate(
        { panelId: panel.id, data: payload },
        { onSuccess: onClose, onError },
      );
    } else {
      create.mutate(payload, { onSuccess: onClose, onError });
    }
  };

  const pending = create.isPending || update.isPending;

  return (
    <Modal isOpen={isOpen} onClose={onClose} title={editing ? 'Edit Panel' : 'Add Panel'}>
      <form onSubmit={handleSubmit}>
        <div className="form-group">
          <label className="form-label">Panel Title</label>
          <input
            type="text"
            className="form-input"
            value={title}
            onChange={(e) => setTitle(e.target.value)}
            autoFocus
          />
        </div>
        <div className="form-group">
          <label className="form-label">Chart Type</label>
          <select
            className="form-select"
            value={chartType}
            onChange={(e) => setChartType(e.target.value)}
          >
            {CHART_TYPES.map((t) => (
              <option key={t} value={t}>
                {t[0].toUpperCase() + t.slice(1)}
              </option>
            ))}
          </select>
        </div>
        <div className="form-group">
          <label className="form-label">Metric</label>
          <input
            type="text"
            className="form-input"
            value={metric}
            onChange={(e) => setMetric(e.target.value)}
            placeholder="e.g. cpu_percent"
          />
        </div>
        <div className="form-group">
          <label className="form-label">Host (ID, &quot;*&quot;, or &quot;$host&quot;)</label>
          <input
            type="text"
            className="form-input"
            value={host}
            onChange={(e) => setHost(e.target.value)}
          />
        </div>
        <div className="form-group" style={{ display: 'flex', gap: '1rem' }}>
          <div style={{ flex: 1 }}>
            <label className="form-label">Width (1-12)</label>
            <input
              type="number"
              className="form-input"
              min={1}
              max={12}
              value={gridW}
              onChange={(e) => setGridW(parseInt(e.target.value, 10) || 6)}
            />
          </div>
          <div style={{ flex: 1 }}>
            <label className="form-label">Height (rows)</label>
            <input
              type="number"
              className="form-input"
              min={1}
              max={12}
              value={gridH}
              onChange={(e) => setGridH(parseInt(e.target.value, 10) || 4)}
            />
          </div>
        </div>
        <div style={{ display: 'flex', gap: '0.5rem', justifyContent: 'flex-end' }}>
          <button type="button" className="btn btn-secondary" onClick={onClose}>
            Cancel
          </button>
          <button type="submit" className="btn btn-primary" disabled={pending}>
            {pending ? 'Saving…' : editing ? 'Save' : 'Add Panel'}
          </button>
        </div>
      </form>
    </Modal>
  );
}
