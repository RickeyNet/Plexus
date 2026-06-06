import { useState, type FormEvent } from 'react';

import { Modal } from '@/components/Modal';
import { useDialogs } from '@/components/DialogProvider-context';
import { useCreateGraphTemplate } from '@/api/graphTemplates';

interface Props {
  isOpen: boolean;
  onClose: () => void;
}

export function GraphTemplateCreateModal({ isOpen, onClose }: Props) {
  const { alert } = useDialogs();
  const createMut = useCreateGraphTemplate();
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [graphType, setGraphType] = useState('line');
  const [scope, setScope] = useState('device');
  const [category, setCategory] = useState('system');
  const [titleFormat, setTitleFormat] = useState('');
  const [yAxisLabel, setYAxisLabel] = useState('');
  const [stacked, setStacked] = useState(false);
  const [areaFill, setAreaFill] = useState(true);

  function reset() {
    setName(''); setDescription(''); setGraphType('line'); setScope('device');
    setCategory('system'); setTitleFormat(''); setYAxisLabel('');
    setStacked(false); setAreaFill(true);
  }

  function handleClose() {
    reset();
    onClose();
  }

  function handleSubmit(e: FormEvent) {
    e.preventDefault();
    if (!name.trim()) {
      void alert('Name is required');
      return;
    }
    createMut.mutate(
      {
        name: name.trim(),
        description: description.trim(),
        graph_type: graphType,
        scope,
        category,
        title_format: titleFormat.trim(),
        y_axis_label: yAxisLabel.trim(),
        stacked,
        area_fill: areaFill,
      },
      {
        onSuccess: handleClose,
        onError: (err) => { void alert({ message: (err as Error).message, variant: 'error' }); },
      },
    );
  }

  return (
    <Modal isOpen={isOpen} onClose={handleClose} title="New Graph Template">
      <form onSubmit={handleSubmit}>
        <div className="form-group">
          <label className="form-label">Name</label>
          <input className="form-input" value={name} onChange={(e) => setName(e.target.value)} placeholder="e.g. CPU Usage" required />
        </div>
        <div className="form-group">
          <label className="form-label">Description</label>
          <input className="form-input" value={description} onChange={(e) => setDescription(e.target.value)} placeholder="Optional description" />
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.75rem' }}>
          <div className="form-group">
            <label className="form-label">Graph Type</label>
            <select className="form-select" value={graphType} onChange={(e) => setGraphType(e.target.value)}>
              <option value="line">Line</option>
              <option value="bar">Bar</option>
              <option value="gauge">Gauge</option>
              <option value="heatmap">Heatmap</option>
            </select>
          </div>
          <div className="form-group">
            <label className="form-label">Scope</label>
            <select className="form-select" value={scope} onChange={(e) => setScope(e.target.value)}>
              <option value="device">Device</option>
              <option value="interface">Interface</option>
            </select>
          </div>
          <div className="form-group">
            <label className="form-label">Category</label>
            <select className="form-select" value={category} onChange={(e) => setCategory(e.target.value)}>
              <option value="system">System</option>
              <option value="traffic">Traffic</option>
              <option value="availability">Availability</option>
              <option value="custom">Custom</option>
            </select>
          </div>
          <div className="form-group">
            <label className="form-label">Title Format</label>
            <input className="form-input" value={titleFormat} onChange={(e) => setTitleFormat(e.target.value)} placeholder="$interface Traffic" />
          </div>
          <div className="form-group">
            <label className="form-label">Y-Axis Label</label>
            <input className="form-input" value={yAxisLabel} onChange={(e) => setYAxisLabel(e.target.value)} placeholder="e.g. Bits/sec" />
          </div>
          <div className="form-group" style={{ display: 'flex', gap: '1rem', alignItems: 'center', paddingTop: '1.5rem' }}>
            <label><input type="checkbox" checked={stacked} onChange={(e) => setStacked(e.target.checked)} /> Stacked</label>
            <label><input type="checkbox" checked={areaFill} onChange={(e) => setAreaFill(e.target.checked)} /> Area Fill</label>
          </div>
        </div>
        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.5rem' }}>
          <button type="button" className="btn btn-secondary" onClick={handleClose}>Cancel</button>
          <button type="submit" className="btn btn-primary" disabled={createMut.isPending}>
            {createMut.isPending ? 'Creating…' : 'Create'}
          </button>
        </div>
      </form>
    </Modal>
  );
}
