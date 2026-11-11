import { useId, useState } from 'react';

import {
  type RiskAnalysisRunResult,
  useRiskCredentials,
  useRiskInventoryGroups,
  useRiskTemplates,
  useRunRiskAnalysis,
} from '@/api/riskAnalysis';
import { Callout } from '@/components/Callout';
import { FieldError } from '@/components/FieldError';
import { Modal } from '@/components/Modal';
import { QueryError } from '@/components/QueryError';
import { changeTypeOptions } from '@/lib/changeTypes';

interface Props {
  isOpen: boolean;
  onClose: () => void;
  onAnalyzed: (result: RiskAnalysisRunResult) => void;
}

const CHANGE_TYPES = changeTypeOptions(['template', 'policy', 'route', 'nat', 'manual']);

export function NewAnalysisModal({ isOpen, onClose, onAnalyzed }: Props) {
  const formId = useId();
  const groups = useRiskInventoryGroups();
  const creds = useRiskCredentials();
  const templates = useRiskTemplates();
  const run = useRunRiskAnalysis();

  const [changeType, setChangeType] = useState('template');
  const [groupId, setGroupId] = useState<string>('');
  const [credentialId, setCredentialId] = useState<string>('');
  const [templateId, setTemplateId] = useState<string>('');
  const [commands, setCommands] = useState('');
  const [errors, setErrors] = useState<{ credential?: string; commands?: string }>({});
  const [runError, setRunError] = useState<string | null>(null);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setRunError(null);
    const credId = parseInt(credentialId, 10);
    const tplId = templateId ? parseInt(templateId, 10) : undefined;
    const text = commands.trim();
    const nextErrors = {
      credential: credId ? undefined : 'Credential is required',
      commands: tplId || text ? undefined : 'Enter proposed commands or select a template',
    };
    setErrors(nextErrors);
    if (nextErrors.credential || nextErrors.commands) return;
    const proposed = tplId ? [] : text.split('\n').filter((l) => l.trim());
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
          setRunError(`Risk analysis failed: ${(err as Error).message}`);
        },
      },
    );
  };

  return (
    <Modal
      isOpen={isOpen}
      onClose={onClose}
      title="Pre-Change Risk Analysis"
      footer={
        <>
          <button type="button" className="btn btn-secondary" onClick={onClose}>
            Cancel
          </button>
          <button type="submit" form={formId} className="btn btn-primary" disabled={run.isPending}>
            {run.isPending ? 'Analyzing…' : 'Analyze Risk'}
          </button>
        </>
      }
    >
      <form id={formId} onSubmit={handleSubmit}>
        {runError && <Callout tone="danger">{runError}</Callout>}
        {groups.isError && !groups.data && (
          <QueryError what="inventory groups" query={groups} />
        )}
        {creds.isError && !creds.data && (
          <QueryError what="credentials" query={creds} />
        )}
        {templates.isError && !templates.data && (
          <QueryError what="templates" query={templates} />
        )}
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
          <label className="form-label" htmlFor={`${formId}-target-group`}>Target Group</label>
          <select
            id={`${formId}-target-group`}
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
          <label className="form-label" htmlFor={`${formId}-credential`}>Credential</label>
          <select
            id={`${formId}-credential`}
            className="form-select"
            value={credentialId}
            onChange={(e) => {
              setCredentialId(e.target.value);
              setErrors((p) => ({ ...p, credential: undefined }));
            }}
            aria-invalid={!!errors.credential}
            required
          >
            <option value="">- Select a credential -</option>
            {(creds.data || []).map((c) => (
              <option key={c.id} value={String(c.id)}>
                {c.name}
              </option>
            ))}
          </select>
          <FieldError>{errors.credential}</FieldError>
        </div>
        <div className="form-group">
          <label className="form-label" htmlFor={`${formId}-source`}>Source</label>
          <select
            id={`${formId}-source`}
            className="form-select"
            value={templateId}
            onChange={(e) => {
              setTemplateId(e.target.value);
              setErrors((p) => ({ ...p, commands: undefined }));
            }}
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
            <label className="form-label" htmlFor={`${formId}-proposed-commands`}>Proposed Commands (one per line)</label>
            <textarea
              id={`${formId}-proposed-commands`}
              className="form-input form-code"
              spellCheck={false}
              rows={8}
              value={commands}
              onChange={(e) => {
                setCommands(e.target.value);
                setErrors((p) => ({ ...p, commands: undefined }));
              }}
              aria-invalid={!!errors.commands}
              placeholder={
                'ip route 10.0.0.0 255.0.0.0 192.168.1.1\naccess-list 101 permit ip any 10.0.0.0 0.255.255.255\nip nat inside source list 1 interface GigabitEthernet0/1 overload'
              }
            />
            <FieldError>{errors.commands}</FieldError>
          </div>
        )}
      </form>
    </Modal>
  );
}
