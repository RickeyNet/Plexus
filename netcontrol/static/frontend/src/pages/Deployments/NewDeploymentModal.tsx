import { useId, useMemo, useState } from 'react';

import { useCreateDeployment } from '@/api/deployments';
import {
  useRiskAnalyses,
  useRiskCredentials,
  useRiskInventoryGroups,
  useRiskTemplates,
} from '@/api/riskAnalysis';
import { Callout } from '@/components/Callout';
import { FieldError } from '@/components/FieldError';
import { Modal } from '@/components/Modal';
import { QueryError } from '@/components/QueryError';
import { changeTypeOptions } from '@/lib/changeTypes';

interface Props {
  isOpen: boolean;
  onClose: () => void;
  onCreated: (id: number) => void;
}

const CHANGE_TYPES = changeTypeOptions(['template', 'manual', 'policy', 'route', 'nat']);

export function NewDeploymentModal({ isOpen, onClose, onCreated }: Props) {
  const formId = useId();
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
  const [errors, setErrors] = useState<{
    name?: string;
    group?: string;
    credential?: string;
    commands?: string;
  }>({});
  const [saveError, setSaveError] = useState<string | null>(null);

  const clearError = (field: keyof typeof errors) =>
    setErrors((prev) => ({ ...prev, [field]: undefined }));

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
    setErrors({});
    setSaveError(null);
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setSaveError(null);
    const trimmedName = name.trim();
    const cmdLines = commands.split('\n').filter((l) => l.trim());
    const nextErrors = {
      name: trimmedName ? undefined : 'Deployment name is required',
      group: groupId ? undefined : 'Inventory group is required',
      credential: credentialId ? undefined : 'Credential is required',
      commands:
        templateId || cmdLines.length ? undefined : 'Provide proposed commands or select a template',
    };
    setErrors(nextErrors);
    if (nextErrors.name || nextErrors.group || nextErrors.credential || nextErrors.commands) return;

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
          setSaveError(`Create deployment failed: ${(err as Error).message}`);
        },
      },
    );
  };

  return (
    <Modal
      isOpen={isOpen}
      onClose={onClose}
      title="New Deployment"
      footer={
        <>
          <button type="button" className="btn btn-secondary" onClick={onClose}>
            Cancel
          </button>
          <button type="submit" form={formId} className="btn btn-primary" disabled={create.isPending}>
            {create.isPending ? 'Creating…' : 'Create Deployment'}
          </button>
        </>
      }
    >
      <form id={formId} onSubmit={handleSubmit}>
        {saveError && <Callout tone="danger">{saveError}</Callout>}
        {groups.isError && !groups.data && (
          <QueryError what="inventory groups" query={groups} />
        )}
        {credentials.isError && !credentials.data && (
          <QueryError what="credentials" query={credentials} />
        )}
        {templates.isError && !templates.data && (
          <QueryError what="templates" query={templates} />
        )}
        {riskAnalyses.isError && !riskAnalyses.data && (
          <QueryError what="risk analyses" query={riskAnalyses} />
        )}
        <div className="form-group">
          <label className="form-label" htmlFor={`${formId}-name`}>Name</label>
          <input
            id={`${formId}-name`}
            className="form-input"
            value={name}
            onChange={(e) => {
              setName(e.target.value);
              clearError('name');
            }}
            aria-invalid={!!errors.name}
            placeholder="e.g. ACL Update Production"
          />
          <FieldError>{errors.name}</FieldError>
        </div>
        <div className="form-group">
          <label className="form-label" htmlFor={`${formId}-description`}>Description</label>
          <input
            id={`${formId}-description`}
            className="form-input"
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            placeholder="Optional description"
          />
        </div>
        <div className="form-group">
          <label className="form-label" htmlFor={`${formId}-group`}>Inventory Group</label>
          <select
            id={`${formId}-group`}
            className="form-select"
            value={groupId}
            onChange={(e) => {
              setGroupId(e.target.value);
              clearError('group');
            }}
            aria-invalid={!!errors.group}
          >
            <option value="">- Select -</option>
            {(groups.data || []).map((g) => (
              <option key={g.id} value={g.id}>
                {g.name}
              </option>
            ))}
          </select>
          <FieldError>{errors.group}</FieldError>
        </div>
        <div className="form-group">
          <label className="form-label" htmlFor={`${formId}-credential`}>Credential</label>
          <select
            id={`${formId}-credential`}
            className="form-select"
            value={credentialId}
            onChange={(e) => {
              setCredentialId(e.target.value);
              clearError('credential');
            }}
            aria-invalid={!!errors.credential}
          >
            <option value="">- Select -</option>
            {(credentials.data || []).map((c) => (
              <option key={c.id} value={c.id}>
                {c.name}
              </option>
            ))}
          </select>
          <FieldError>{errors.credential}</FieldError>
        </div>
        <div className="form-group">
          <label className="form-label" htmlFor={`${formId}-change-type`}>Change Type</label>
          <select
            id={`${formId}-change-type`}
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
          <label className="form-label" htmlFor={`${formId}-template`}>Template (optional)</label>
          <select
            id={`${formId}-template`}
            className="form-select"
            value={templateId}
            onChange={(e) => {
              setTemplateId(e.target.value);
              clearError('commands');
            }}
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
          <label className="form-label" htmlFor={`${formId}-risk-analysis`}>Linked Risk Analysis (optional)</label>
          <select
            id={`${formId}-risk-analysis`}
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
          <label className="form-label" htmlFor={`${formId}-commands`}>
            Proposed Commands (one per line, or leave empty if using template)
          </label>
          <textarea
            id={`${formId}-commands`}
            className="form-input form-code"
            spellCheck={false}
            rows={5}
            value={commands}
            onChange={(e) => {
              setCommands(e.target.value);
              clearError('commands');
            }}
            aria-invalid={!!errors.commands}
            placeholder={'interface GigabitEthernet0/1\n no shutdown'}
          />
          <FieldError>{errors.commands}</FieldError>
        </div>
      </form>
    </Modal>
  );
}
