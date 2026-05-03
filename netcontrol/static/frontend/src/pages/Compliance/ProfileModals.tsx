import { useMemo, useState } from 'react';

import { Modal } from '@/components/Modal';
import {
  ProfilePayload,
  useComplianceAssignments,
  useComplianceProfile,
  useCreateAssignment,
  useCreateProfile,
  useCredentials,
  useInventoryGroups,
  useUpdateProfile,
} from '@/api/compliance';

const SEVERITIES = ['low', 'medium', 'high', 'critical'] as const;

const RULES_PLACEHOLDER =
  '[{"name": "NTP configured", "type": "must_contain", "pattern": "ntp server"}]';
const RULES_HELP = (
  <>
    Rule types: <code>must_contain</code>, <code>must_not_contain</code>,{' '}
    <code>regex_match</code>
    <br />
    Each rule: <code>{'{"name": "...", "type": "...", "pattern": "..."}'}</code>
  </>
);

export function NewProfileModal({ onClose }: { onClose: () => void }) {
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [severity, setSeverity] = useState<(typeof SEVERITIES)[number]>('medium');
  const [rulesText, setRulesText] = useState('');
  const [error, setError] = useState<string | null>(null);
  const create = useCreateProfile();

  return (
    <Modal isOpen onClose={onClose} title="Create Compliance Profile">
      <FormBody
        name={name}
        setName={setName}
        description={description}
        setDescription={setDescription}
        severity={severity}
        setSeverity={setSeverity}
        rulesText={rulesText}
        setRulesText={setRulesText}
      />
      {error && <div className="error">{error}</div>}
      <ModalActions
        onClose={onClose}
        primaryLabel="Create"
        primaryDisabled={!name.trim() || create.isPending}
        onPrimary={() => {
          setError(null);
          const parsed = parseRules(rulesText);
          if (parsed.error) {
            setError(parsed.error);
            return;
          }
          create.mutate(
            {
              name: name.trim(),
              description: description.trim(),
              severity,
              rules: parsed.rules,
            } as ProfilePayload,
            {
              onSuccess: () => onClose(),
              onError: (e) => setError((e as Error).message),
            },
          );
        }}
      />
    </Modal>
  );
}

export function EditProfileModal({
  profileId,
  onClose,
}: {
  profileId: number;
  onClose: () => void;
}) {
  const { data: profile, isLoading } = useComplianceProfile(profileId);
  const update = useUpdateProfile();

  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [severity, setSeverity] = useState<(typeof SEVERITIES)[number]>('medium');
  const [rulesText, setRulesText] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [hydrated, setHydrated] = useState(false);

  if (profile && !hydrated) {
    setName(profile.name);
    setDescription(profile.description || '');
    setSeverity((SEVERITIES.find((s) => s === profile.severity) ?? 'medium') as (typeof SEVERITIES)[number]);
    let pretty = '[]';
    try {
      pretty = JSON.stringify(JSON.parse(profile.rules || '[]'), null, 2);
    } catch {
      pretty = profile.rules || '[]';
    }
    setRulesText(pretty);
    setHydrated(true);
  }

  return (
    <Modal isOpen onClose={onClose} title="Edit Compliance Profile">
      {isLoading || !hydrated ? (
        <p className="text-muted">Loading…</p>
      ) : (
        <FormBody
          name={name}
          setName={setName}
          description={description}
          setDescription={setDescription}
          severity={severity}
          setSeverity={setSeverity}
          rulesText={rulesText}
          setRulesText={setRulesText}
        />
      )}
      {error && <div className="error">{error}</div>}
      <ModalActions
        onClose={onClose}
        primaryLabel="Save"
        primaryDisabled={!name.trim() || update.isPending || !hydrated}
        onPrimary={() => {
          setError(null);
          const parsed = parseRules(rulesText);
          if (parsed.error) {
            setError(parsed.error);
            return;
          }
          update.mutate(
            {
              id: profileId,
              data: {
                name: name.trim(),
                description: description.trim(),
                severity,
                rules: parsed.rules,
              },
            },
            {
              onSuccess: () => onClose(),
              onError: (e) => setError((e as Error).message),
            },
          );
        }}
      />
    </Modal>
  );
}

export function AssignProfileModal({
  profileId,
  onClose,
}: {
  profileId: number;
  onClose: () => void;
}) {
  const groups = useInventoryGroups(false);
  const credentials = useCredentials();
  const existing = useComplianceAssignments(profileId);
  const create = useCreateAssignment();

  const [selectedGroups, setSelectedGroups] = useState<Set<number>>(new Set());
  const [credentialId, setCredentialId] = useState<number | null>(null);
  const [hours, setHours] = useState(24);
  const [error, setError] = useState<string | null>(null);

  const assignedGroupIds = useMemo(
    () => new Set((existing.data || []).map((a) => a.group_id)),
    [existing.data],
  );

  const groupList = groups.data || [];
  const credList = credentials.data || [];

  // Default to first credential when loaded
  if (credentialId == null && credList.length > 0) {
    setCredentialId(credList[0].id);
  }

  return (
    <Modal isOpen onClose={onClose} title="Assign Profile to Groups">
      <div className="form-group">
        <label className="form-label">Inventory Groups</label>
        <div style={{ display: 'flex', gap: '0.5rem', marginBottom: '0.5rem' }}>
          <button
            type="button"
            className="btn btn-sm btn-secondary"
            onClick={() => {
              const all = new Set<number>();
              for (const g of groupList) {
                if (!assignedGroupIds.has(g.id)) all.add(g.id);
              }
              setSelectedGroups(all);
            }}
          >
            Select All
          </button>
          <button
            type="button"
            className="btn btn-sm btn-secondary"
            onClick={() => setSelectedGroups(new Set())}
          >
            Deselect All
          </button>
        </div>
        <div
          style={{
            maxHeight: 200,
            overflowY: 'auto',
            border: '1px solid var(--border)',
            borderRadius: '0.5rem',
            padding: '0.5rem 0.75rem',
          }}
        >
          {groupList.length === 0 ? (
            <span className="text-muted">No inventory groups found</span>
          ) : (
            groupList.map((g) => {
              const already = assignedGroupIds.has(g.id);
              const checked = selectedGroups.has(g.id);
              return (
                <label
                  key={g.id}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: '0.5rem',
                    padding: '0.35rem 0',
                    cursor: already ? 'default' : 'pointer',
                  }}
                >
                  <input
                    type="checkbox"
                    disabled={already}
                    checked={checked}
                    onChange={(e) => {
                      const next = new Set(selectedGroups);
                      if (e.target.checked) next.add(g.id);
                      else next.delete(g.id);
                      setSelectedGroups(next);
                    }}
                  />
                  <span>{g.name}</span>
                  {already && (
                    <span style={{ fontSize: '0.8em', color: 'var(--text-muted)' }}>
                      (already assigned)
                    </span>
                  )}
                </label>
              );
            })
          )}
        </div>
      </div>
      <div className="form-group">
        <label className="form-label">Credential</label>
        <select
          className="form-select"
          value={credentialId ?? ''}
          onChange={(e) =>
            setCredentialId(e.target.value ? parseInt(e.target.value, 10) : null)
          }
        >
          <option value="">Select credential…</option>
          {credList.map((c) => (
            <option key={c.id} value={c.id}>
              {c.name}
            </option>
          ))}
        </select>
      </div>
      <div className="form-group">
        <label className="form-label">Scan Interval (hours)</label>
        <input
          type="number"
          min={1}
          max={168}
          className="form-input"
          value={hours}
          onChange={(e) => setHours(parseInt(e.target.value, 10) || 24)}
        />
      </div>
      {error && <div className="error">{error}</div>}
      <ModalActions
        onClose={onClose}
        primaryLabel="Assign"
        primaryDisabled={selectedGroups.size === 0 || credentialId == null}
        onPrimary={async () => {
          setError(null);
          if (credentialId == null) {
            setError('Credential is required');
            return;
          }
          const ids = [...selectedGroups];
          let success = 0;
          let failed = 0;
          for (const groupId of ids) {
            try {
              await create.mutateAsync({
                profile_id: profileId,
                group_id: groupId,
                credential_id: credentialId,
                interval_seconds: hours * 3600,
              });
              success++;
            } catch {
              failed++;
            }
          }
          if (failed === 0) {
            alert(`Profile assigned to ${success} group(s).`);
          } else {
            setError(`Assigned to ${success} group(s), ${failed} failed.`);
            return;
          }
          onClose();
        }}
      />
    </Modal>
  );
}

// ── Shared form pieces ─────────────────────────────────────────────────────

function FormBody({
  name,
  setName,
  description,
  setDescription,
  severity,
  setSeverity,
  rulesText,
  setRulesText,
}: {
  name: string;
  setName: (v: string) => void;
  description: string;
  setDescription: (v: string) => void;
  severity: (typeof SEVERITIES)[number];
  setSeverity: (v: (typeof SEVERITIES)[number]) => void;
  rulesText: string;
  setRulesText: (v: string) => void;
}) {
  return (
    <>
      <div className="form-group">
        <label className="form-label">Profile Name</label>
        <input
          className="form-input"
          placeholder="PCI-DSS Baseline"
          value={name}
          onChange={(e) => setName(e.target.value)}
          autoFocus
        />
      </div>
      <div className="form-group">
        <label className="form-label">Description</label>
        <input
          className="form-input"
          placeholder="Describe the compliance standard"
          value={description}
          onChange={(e) => setDescription(e.target.value)}
        />
      </div>
      <div className="form-group">
        <label className="form-label">Severity</label>
        <select
          className="form-select"
          value={severity}
          onChange={(e) => setSeverity(e.target.value as (typeof SEVERITIES)[number])}
        >
          {SEVERITIES.map((s) => (
            <option key={s} value={s}>
              {s.charAt(0).toUpperCase() + s.slice(1)}
            </option>
          ))}
        </select>
      </div>
      <div className="form-group">
        <label className="form-label">Rules (JSON array)</label>
        <textarea
          className="form-input"
          rows={8}
          placeholder={RULES_PLACEHOLDER}
          value={rulesText}
          onChange={(e) => setRulesText(e.target.value)}
        />
        <div style={{ marginTop: '0.5rem', fontSize: '0.8em', color: 'var(--text-muted)' }}>
          {RULES_HELP}
        </div>
      </div>
    </>
  );
}

function ModalActions({
  onClose,
  primaryLabel,
  primaryDisabled,
  onPrimary,
}: {
  onClose: () => void;
  primaryLabel: string;
  primaryDisabled: boolean;
  onPrimary: () => void;
}) {
  return (
    <div
      style={{
        display: 'flex',
        gap: '0.5rem',
        justifyContent: 'flex-end',
        marginTop: '1rem',
      }}
    >
      <button type="button" className="btn btn-secondary" onClick={onClose}>
        Cancel
      </button>
      <button
        type="button"
        className="btn btn-primary"
        disabled={primaryDisabled}
        onClick={onPrimary}
      >
        {primaryLabel}
      </button>
    </div>
  );
}

function parseRules(rulesText: string): { rules: unknown[]; error?: string } {
  const trimmed = rulesText.trim();
  if (!trimmed) return { rules: [] };
  try {
    const parsed = JSON.parse(trimmed);
    if (!Array.isArray(parsed)) {
      return { rules: [], error: 'Rules must be a JSON array' };
    }
    return { rules: parsed };
  } catch {
    return { rules: [], error: 'Invalid JSON for rules' };
  }
}
