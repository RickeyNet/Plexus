import { useMemo, useState } from 'react';

import { Modal } from '@/components/Modal';
import {
  useComplianceProfiles,
  useCreateMerakiAssignment,
  useMerakiAssignments,
  useMerakiComplianceOrgs,
} from '@/api/compliance';

import { profileHasMerakiRules } from './merakiHelpers';

/**
 * Bind a profile with Meraki rules to one or more Meraki organizations on a
 * schedule. The organization's stored API key is used (read-only); no
 * credential is chosen here.
 */
export function MerakiAssignModal({
  profileId: initialProfileId,
  onClose,
}: {
  profileId?: number;
  onClose: () => void;
}) {
  const profiles = useComplianceProfiles();
  const orgs = useMerakiComplianceOrgs();
  const create = useCreateMerakiAssignment();

  const [profileId, setProfileId] = useState<number | null>(initialProfileId ?? null);
  const [selected, setSelected] = useState<Set<number>>(new Set());
  const [hours, setHours] = useState(24);
  const [error, setError] = useState<string | null>(null);

  const merakiProfiles = useMemo(
    () => (profiles.data || []).filter(profileHasMerakiRules),
    [profiles.data],
  );
  const existing = useMerakiAssignments(profileId ?? undefined);
  const assignedOrgIds = useMemo(
    () => new Set((existing.data || []).map((a) => a.org_ref)),
    [existing.data],
  );

  // Default to the first Meraki profile once loaded (one-time latch).
  const [prevProfiles, setPrevProfiles] = useState(merakiProfiles);
  if (merakiProfiles !== prevProfiles) {
    setPrevProfiles(merakiProfiles);
    if (profileId == null && merakiProfiles.length > 0) setProfileId(merakiProfiles[0].id);
  }

  const orgList = orgs.data || [];

  return (
    <Modal isOpen onClose={onClose} title="Assign Profile to Meraki Organizations">
      <div className="form-group">
        <label className="form-label">Compliance Profile (with Meraki rules)</label>
        <select
          className="form-select"
          value={profileId ?? ''}
          onChange={(e) => {
            setProfileId(e.target.value ? parseInt(e.target.value, 10) : null);
            setSelected(new Set());
          }}
        >
          {merakiProfiles.length === 0 && (
            <option value="">No profiles with Meraki rules - load the built-in profiles</option>
          )}
          {merakiProfiles.map((p) => (
            <option key={p.id} value={p.id}>
              {p.name}
            </option>
          ))}
        </select>
      </div>
      <div className="form-group">
        <label className="form-label">Meraki Organizations</label>
        <div
          style={{
            maxHeight: 200,
            overflowY: 'auto',
            border: '1px solid var(--border)',
            borderRadius: '0.5rem',
            padding: '0.5rem 0.75rem',
          }}
        >
          {orgs.isLoading ? (
            <span className="text-muted">Loading…</span>
          ) : orgList.length === 0 ? (
            <span className="text-muted">
              No Meraki organizations. Register one on the Topology page (Sources).
            </span>
          ) : (
            orgList.map((o) => {
              const already = assignedOrgIds.has(o.id);
              const usable = o.has_api_key || o.is_sample;
              return (
                <label
                  key={o.id}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: '0.5rem',
                    padding: '0.35rem 0',
                    cursor: already || !usable ? 'default' : 'pointer',
                    opacity: usable ? 1 : 0.6,
                  }}
                >
                  <input
                    type="checkbox"
                    disabled={already || !usable}
                    checked={selected.has(o.id)}
                    onChange={(e) => {
                      const next = new Set(selected);
                      if (e.target.checked) next.add(o.id);
                      else next.delete(o.id);
                      setSelected(next);
                    }}
                  />
                  <span>{o.name}</span>
                  {o.is_sample && (
                    <span style={{ fontSize: '0.8em', color: 'var(--text-muted)' }}>(demo data)</span>
                  )}
                  {!usable && (
                    <span style={{ fontSize: '0.8em', color: 'var(--text-muted)' }}>(no API key)</span>
                  )}
                  {already && (
                    <span style={{ fontSize: '0.8em', color: 'var(--text-muted)' }}>(already assigned)</span>
                  )}
                </label>
              );
            })
          )}
        </div>
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
      <div style={{ display: 'flex', gap: '0.5rem', justifyContent: 'flex-end', marginTop: '1rem' }}>
        <button type="button" className="btn btn-secondary" onClick={onClose}>
          Cancel
        </button>
        <button
          type="button"
          className="btn btn-primary"
          disabled={profileId == null || selected.size === 0 || create.isPending}
          onClick={async () => {
            setError(null);
            if (profileId == null) return;
            let failed = 0;
            let lastError = '';
            for (const orgRef of [...selected]) {
              try {
                await create.mutateAsync({
                  profile_id: profileId,
                  org_ref: orgRef,
                  interval_seconds: hours * 3600,
                });
              } catch (e) {
                failed++;
                lastError = (e as Error).message;
              }
            }
            if (failed > 0) {
              setError(`${failed} assignment(s) failed: ${lastError}`);
              return;
            }
            onClose();
          }}
        >
          {create.isPending ? 'Assigning…' : 'Assign'}
        </button>
      </div>
    </Modal>
  );
}
