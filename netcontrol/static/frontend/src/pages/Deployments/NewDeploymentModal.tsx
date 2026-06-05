import { useMemo, useState } from 'react';

import { useCreateDeployment } from '@/api/deployments';
import {
  useRiskAnalyses,
  useRiskCredentials,
  useRiskInventoryGroups,
  useRiskTemplates,
} from '@/api/riskAnalysis';
import { Modal } from '@/components/Modal';
import { useDialogs } from '@/components/DialogProvider-context';

interface Props {
  isOpen: boolean;
  onClose: () => void;
  onCreated: (id: number) => void;
}

const CHANGE_TYPES = [
  { value: 'template', label: 'Template' },
  { value: 'manual', label: 'Manual' },
  { value: 'policy', label: 'Policy' },
  { value: 'route', label: 'Route' },
  { value: 'nat', label: 'NAT' },
];

export function NewDeploymentModal({ isOpen, onClose, onCreated }: Props) {
  const { alert } = useDialogs();
  const groups = useRiskInventoryGroups();
  const credentials = useRiskCredentials();
  const templates = useRiskTemplates();
  const riskAnalyses = useRiskAnalyses(50);
  const create = useCreateDeployment();

  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [groupId, setGroupId] = useState<string>('');
  const [credentialId, setCredentialId] = useState<string>('');
  const [changeType, setChangeType] = useState('template');
  const [templateId, setTemplateId] = useState<string>('');
  const [riskAnalysisId, setRiskAnalysisId] = useState<string>('');
  const [commands, setCommands] = useState('');

  const approvedAnalyses = useMemo(
    () => (riskAnalyses.data || []).filter((r) => r.approved),
    [riskAnalyses.data],
  );

  const reset = () => {
    setName('');
    setDescription('');
    setGroupId('');
    setCredentialId('');
    setChangeType('template');
    setTemplateId('');
    setRiskAnalysisId('');
    setCommands('');
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    const trimmedName = name.trim();
    if (!trimmedName) {
      void alert('Deployment name is required');
      return;
    }
    if (!groupId) {
      void alert('Inventory group is required');
      return;
    }
    if (!credentialId) {
      void alert('Credential is required');
      return;
    }
    const cmdLines = commands.split('\n').filter((l) => l.trim());
    if (!templateId && !cmdLines.length) {
      void alert('Provide proposed commands or select a template');
      return;
    }

    create.mutate(
      {
        name: trimmedName,
        description: description.trim() || undefined,
        group_id: parseInt(groupId, 10),
        credential_id: parseInt(credentialId, 10),
        change_type: changeType,
        proposed_commands: cmdLines,
        template_id: templateId ? parseInt(templateId, 10) : null,
        risk_analysis_id: riskAnalysisId ? parseInt(riskAnalysisId, 10) : null,
      },
      {
        onSuccess: (result) => {
          reset();
          onClose();
          onCreated(result.id);
        },
        onError: (err) => {
          void alert({
            message: `Create deployment failed: ${(err as Error).message}`,
            variant: 'error',
          });
        },
      },
    );
  };

  return (
    <Modal isOpen={isOpen} onClose={onClose} title="New Deployment">
      <form onSubmit={handleSubmit}>
        <div className="form-group">
          <label className="form-label">Name</label>
          <input
            className="form-input"
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="e.g. ACL Update Production"
          />
        </div>
        <div className="form-group">
          <label className="form-label">Description</label>
          <input
            className="form-input"
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            placeholder="Optional description"
          />
        </div>
        <div className="form-group">
          <label className="form-label">Inventory Group</label>
          <select
            className="form-select"
            value={groupId}
            onChange={(e) => setGroupId(e.target.value)}
          >
            <option value="">- Select -</option>
            {(groups.data || []).map((g) => (
              <option key={g.id} value={g.id}>
                {g.name}
              </option>
            ))}
          </select>
        </div>
        <div className="form-group">
          <label className="form-label">Credential</label>
          <select
            className="form-select"
            value={credentialId}
            onChange={(e) => setCredentialId(e.target.value)}
          >
            <option value="">- Select -</option>
            {(credentials.data || []).map((c) => (
              <option key={c.id} value={c.id}>
                {c.name}
              </option>
            ))}
          </select>
        </div>
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
          <label className="form-label">Template (optional)</label>
          <select
            className="form-select"
            value={templateId}
            onChange={(e) => setTemplateId(e.target.value)}
          >
            <option value="">- None (manual commands) -</option>
            {(templates.data || []).map((t) => (
              <option key={t.id} value={t.id}>
                {t.name}
              </option>
            ))}
          </select>
        </div>
        <div className="form-group">
          <label className="form-label">Linked Risk Analysis (optional)</label>
          <select
            className="form-select"
            value={riskAnalysisId}
            onChange={(e) => setRiskAnalysisId(e.target.value)}
          >
            <option value="">- None -</option>
            {approvedAnalyses.map((r) => (
              <option key={r.id} value={r.id}>
                #{r.id} {r.risk_level} - {r.hostname || r.group_name || ''}
              </option>
            ))}
          </select>
        </div>
        <div className="form-group">
          <label className="form-label">
            Proposed Commands (one per line, or leave empty if using template)
          </label>
          <textarea
            className="form-input"
            rows={5}
            value={commands}
            onChange={(e) => setCommands(e.target.value)}
            style={{ fontFamily: 'var(--font-mono)', fontSize: '0.85rem' }}
            placeholder={'interface GigabitEthernet0/1\n no shutdown'}
          />
        </div>
        <div style={{ display: 'flex', gap: '0.5rem', justifyContent: 'flex-end' }}>
          <button type="button" className="btn btn-secondary" onClick={onClose}>
            Cancel
          </button>
          <button type="submit" className="btn btn-primary" disabled={create.isPending}>
            {create.isPending ? 'Creating…' : 'Create Deployment'}
          </button>
        </div>
      </form>
    </Modal>
  );
}
