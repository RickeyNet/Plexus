import { useState } from 'react';

import {
  type RiskAnalysisRunResult,
  useRiskCredentials,
  useRiskInventoryGroups,
  useRiskTemplates,
  useRunRiskAnalysis,
} from '@/api/riskAnalysis';
import { Modal } from '@/components/Modal';
import { useDialogs } from '@/components/DialogProvider-context';

interface Props {
  isOpen: boolean;
  onClose: () => void;
  onAnalyzed: (result: RiskAnalysisRunResult) => void;
}

const CHANGE_TYPES = [
  { value: 'template', label: 'Template' },
  { value: 'policy', label: 'Policy / ACL' },
  { value: 'route', label: 'Route' },
  { value: 'nat', label: 'NAT' },
  { value: 'manual', label: 'Manual' },
];

export function NewAnalysisModal({ isOpen, onClose, onAnalyzed }: Props) {
  const { alert } = useDialogs();
  const groups = useRiskInventoryGroups();
  const creds = useRiskCredentials();
  const templates = useRiskTemplates();
  const run = useRunRiskAnalysis();

  const [changeType, setChangeType] = useState('template');
  const [groupId, setGroupId] = useState<string>('');
  const [credentialId, setCredentialId] = useState<string>('');
  const [templateId, setTemplateId] = useState<string>('');
  const [commands, setCommands] = useState('');

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    const credId = parseInt(credentialId, 10);
    if (!credId) {
      void alert('Credential is required');
      return;
    }
    const tplId = templateId ? parseInt(templateId, 10) : undefined;
    let proposed: string[] = [];
    if (!tplId) {
      const text = commands.trim();
      if (!text) {
        void alert('Enter proposed commands or select a template');
        return;
      }
      proposed = text.split('\n').filter((l) => l.trim());
    }
    run.mutate(
      {
        change_type: changeType,
        group_id: groupId ? parseInt(groupId, 10) : undefined,
        credential_id: credId,
        template_id: tplId,
        proposed_commands: proposed,
      },
      {
        onSuccess: (result) => {
          setCommands('');
          setTemplateId('');
          onClose();
          onAnalyzed(result);
        },
        onError: (err) => {
          void alert({
            message: `Risk analysis failed: ${(err as Error).message}`,
            variant: 'error',
          });
        },
      },
    );
  };

  return (
    <Modal isOpen={isOpen} onClose={onClose} title="Pre-Change Risk Analysis">
      <form onSubmit={handleSubmit}>
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
          <label className="form-label">Target Group</label>
          <select
            className="form-select"
            value={groupId}
            onChange={(e) => setGroupId(e.target.value)}
          >
            <option value="">- Select a group -</option>
            {(groups.data || []).map((g) => (
              <option key={g.id} value={String(g.id)}>
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
            required
          >
            <option value="">- Select a credential -</option>
            {(creds.data || []).map((c) => (
              <option key={c.id} value={String(c.id)}>
                {c.name}
              </option>
            ))}
          </select>
        </div>
        <div className="form-group">
          <label className="form-label">Source</label>
          <select
            className="form-select"
            value={templateId}
            onChange={(e) => setTemplateId(e.target.value)}
          >
            <option value="">- Enter commands manually -</option>
            {(templates.data || []).map((t) => (
              <option key={t.id} value={String(t.id)}>
                {t.name}
              </option>
            ))}
          </select>
        </div>
        {!templateId && (
          <div className="form-group">
            <label className="form-label">Proposed Commands (one per line)</label>
            <textarea
              className="form-input"
              rows={8}
              value={commands}
              onChange={(e) => setCommands(e.target.value)}
              placeholder={
                'ip route 10.0.0.0 255.0.0.0 192.168.1.1\naccess-list 101 permit ip any 10.0.0.0 0.255.255.255\nip nat inside source list 1 interface GigabitEthernet0/1 overload'
              }
            />
          </div>
        )}
        <div style={{ display: 'flex', gap: '0.5rem', justifyContent: 'flex-end' }}>
          <button type="button" className="btn btn-secondary" onClick={onClose}>
            Cancel
          </button>
          <button type="submit" className="btn btn-primary" disabled={run.isPending}>
            {run.isPending ? 'Analyzing…' : 'Analyze Risk'}
          </button>
        </div>
      </form>
    </Modal>
  );
}
