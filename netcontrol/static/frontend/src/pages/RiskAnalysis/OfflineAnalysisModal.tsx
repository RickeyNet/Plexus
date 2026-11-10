import { useId, useState } from 'react';

import {
  type OfflineRiskAnalysisResult,
  useRunOfflineRiskAnalysis,
} from '@/api/riskAnalysis';
import { Callout } from '@/components/Callout';
import { FieldError } from '@/components/FieldError';
import { Modal } from '@/components/Modal';

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
  const formId = useId();
  const run = useRunOfflineRiskAnalysis();
  const [changeType, setChangeType] = useState('manual');
  const [config, setConfig] = useState('');
  const [commands, setCommands] = useState('');
  const [errors, setErrors] = useState<{ config?: string; commands?: string }>({});
  const [runError, setRunError] = useState<string | null>(null);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setRunError(null);
    const c = config.trim();
    const t = commands.trim();
    const nextErrors = {
      config: c ? undefined : 'Current config is required',
      commands: t ? undefined : 'Proposed commands are required',
    };
    setErrors(nextErrors);
    if (nextErrors.config || nextErrors.commands) return;
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
          setRunError(`Offline analysis failed: ${(err as Error).message}`);
        },
      },
    );
  };

  return (
    <Modal
      isOpen={isOpen}
      onClose={onClose}
      title="Offline Risk Analysis"
      footer={
        <>
          <button type="button" className="btn btn-secondary" onClick={onClose}>
            Cancel
          </button>
          <button type="submit" form={formId} className="btn btn-primary" disabled={run.isPending}>
            {run.isPending ? 'Analyzing…' : 'Analyze'}
          </button>
        </>
      }
    >
      <form id={formId} onSubmit={handleSubmit}>
        {runError && <Callout tone="danger">{runError}</Callout>}
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
            onChange={(e) => {
              setConfig(e.target.value);
              setErrors((p) => ({ ...p, config: undefined }));
            }}
            aria-invalid={!!errors.config}
            placeholder="Paste current running-config here..."
          />
          <FieldError>{errors.config}</FieldError>
        </div>
        <div className="form-group">
          <label className="form-label">Proposed Commands (one per line)</label>
          <textarea
            className="form-input"
            rows={6}
            value={commands}
            onChange={(e) => {
              setCommands(e.target.value);
              setErrors((p) => ({ ...p, commands: undefined }));
            }}
            aria-invalid={!!errors.commands}
            placeholder={
              'ip route 10.0.0.0 255.0.0.0 192.168.1.1\nno ip route 172.16.0.0 255.240.0.0 192.168.1.254'
            }
          />
          <FieldError>{errors.commands}</FieldError>
        </div>
      </form>
    </Modal>
  );
}
