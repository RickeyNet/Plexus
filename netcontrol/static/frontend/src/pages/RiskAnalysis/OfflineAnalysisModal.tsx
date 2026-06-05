import { useState } from 'react';

import {
  type OfflineRiskAnalysisResult,
  useRunOfflineRiskAnalysis,
} from '@/api/riskAnalysis';
import { Modal } from '@/components/Modal';
import { useDialogs } from '@/components/DialogProvider-context';

interface Props {
  isOpen: boolean;
  onClose: () => void;
  onAnalyzed: (result: OfflineRiskAnalysisResult) => void;
}

const CHANGE_TYPES = [
  { value: 'policy', label: 'Policy / ACL' },
  { value: 'route', label: 'Route' },
  { value: 'nat', label: 'NAT' },
  { value: 'manual', label: 'Manual' },
];

export function OfflineAnalysisModal({ isOpen, onClose, onAnalyzed }: Props) {
  const { alert } = useDialogs();
  const run = useRunOfflineRiskAnalysis();
  const [changeType, setChangeType] = useState('manual');
  const [config, setConfig] = useState('');
  const [commands, setCommands] = useState('');

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    const c = config.trim();
    const t = commands.trim();
    if (!c) {
      void alert('Current config is required');
      return;
    }
    if (!t) {
      void alert('Proposed commands are required');
      return;
    }
    run.mutate(
      {
        change_type: changeType,
        current_config: c,
        proposed_commands: t.split('\n').filter((l) => l.trim()),
      },
      {
        onSuccess: (result) => {
          setConfig('');
          setCommands('');
          onClose();
          onAnalyzed(result);
        },
        onError: (err) => {
          void alert({
            message: `Offline analysis failed: ${(err as Error).message}`,
            variant: 'error',
          });
        },
      },
    );
  };

  return (
    <Modal isOpen={isOpen} onClose={onClose} title="Offline Risk Analysis">
      <form onSubmit={handleSubmit}>
        <p style={{ fontSize: '0.9em', color: 'var(--text-muted)', marginBottom: '1rem' }}>
          Analyze risk without connecting to devices. Paste the current config and proposed commands.
        </p>
        <div className="form-group">
          <label className="form-label">Change Type</label>
          <select
            className="form-select"
            value={changeType}
            onChange={(e) => setChangeType(e.target.value)}
          >
            {CHANGE_TYPES.map((t) => (
              <option key={t.value} value={t.value}>
                {t.label}
              </option>
            ))}
          </select>
        </div>
        <div className="form-group">
          <label className="form-label">Current Running Config</label>
          <textarea
            className="form-input"
            rows={8}
            value={config}
            onChange={(e) => setConfig(e.target.value)}
            placeholder="Paste current running-config here..."
          />
        </div>
        <div className="form-group">
          <label className="form-label">Proposed Commands (one per line)</label>
          <textarea
            className="form-input"
            rows={6}
            value={commands}
            onChange={(e) => setCommands(e.target.value)}
            placeholder={
              'ip route 10.0.0.0 255.0.0.0 192.168.1.1\nno ip route 172.16.0.0 255.240.0.0 192.168.1.254'
            }
          />
        </div>
        <div style={{ display: 'flex', gap: '0.5rem', justifyContent: 'flex-end' }}>
          <button type="button" className="btn btn-secondary" onClick={onClose}>
            Cancel
          </button>
          <button type="submit" className="btn btn-primary" disabled={run.isPending}>
            {run.isPending ? 'Analyzing…' : 'Analyze'}
          </button>
        </div>
      </form>
    </Modal>
  );
}
