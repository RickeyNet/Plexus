import { useMemo, useState } from 'react';

import { Modal } from '@/components/Modal';
import {
  useComplianceProfiles,
  useCredentials,
  useInventoryGroups,
  useRunScan,
  useRunScanBulk,
} from '@/api/compliance';

type Scope = 'all' | 'group' | 'single';

export function RunScanModal({ onClose }: { onClose: () => void }) {
  const groups = useInventoryGroups(true);
  const profiles = useComplianceProfiles();
  const credentials = useCredentials();
  const runScan = useRunScan();
  const runBulk = useRunScanBulk();

  const [scope, setScope] = useState<Scope>('all');
  const [groupId, setGroupId] = useState<number | null>(null);
  const [hostId, setHostId] = useState<number | null>(null);
  const [profileId, setProfileId] = useState<number | null>(null);
  const [credentialId, setCredentialId] = useState<number | null>(null);
  const [error, setError] = useState<string | null>(null);

  const allHosts = useMemo(() => {
    const list = (groups.data || []).flatMap((g) =>
      (g.hosts || []).map((h) => ({ ...h, group_name: g.name })),
    );
    return list.sort((a, b) => (a.hostname || '').localeCompare(b.hostname || ''));
  }, [groups.data]);

  const profileList = profiles.data || [];
  const credList = credentials.data || [];
  const groupList = groups.data || [];

  // Auto-select defaults once data loads
  if (profileId == null && profileList.length > 0) setProfileId(profileList[0].id);
  if (groupId == null && groupList.length > 0) setGroupId(groupList[0].id);

  const selectedGroup = groupList.find((g) => g.id === groupId);
  const selectedGroupHostCount = (selectedGroup?.hosts || []).length;

  const hint =
    scope === 'all'
      ? `Scans all ${allHosts.length} host(s) in the inventory.`
      : scope === 'group'
        ? `Scans all ${selectedGroupHostCount} host(s) in the selected group.`
        : '';
  const submitLabel =
    scope === 'all' ? 'Scan All Hosts' : scope === 'group' ? 'Scan Group' : 'Run Scan';

  const isPending = runScan.isPending || runBulk.isPending;

  const onSubmit = async () => {
    setError(null);
    if (profileId == null) {
      setError('Select a compliance profile');
      return;
    }
    if (credentialId == null) {
      setError('Select a credential');
      return;
    }

    if (scope === 'single') {
      if (hostId == null) {
        setError('Select a host');
        return;
      }
      try {
        const res = await runScan.mutateAsync({
          host_id: hostId,
          profile_id: profileId,
          credential_id: credentialId,
        });
        if (res.status === 'compliant') {
          alert(
            `Scan complete — Host is compliant (${res.passed_rules}/${res.total_rules} rules passed)`,
          );
        } else if (res.status === 'error') {
          alert('Scan completed with errors — check findings for details');
        } else {
          alert(
            `Scan complete — ${res.failed_rules} violation(s) found (${res.passed_rules}/${res.total_rules} passed)`,
          );
        }
        onClose();
      } catch (e) {
        setError(`Scan failed: ${(e as Error).message}`);
      }
      return;
    }

    let hostIds: number[] = [];
    if (scope === 'group') {
      if (groupId == null) {
        setError('Select a group');
        return;
      }
      hostIds = (selectedGroup?.hosts || []).map((h) => h.id);
      if (hostIds.length === 0) {
        setError('No hosts in the selected group');
        return;
      }
    }
    // scope === 'all' — empty hostIds tells the backend "scan everything"

    try {
      const res = await runBulk.mutateAsync({
        profile_id: profileId,
        credential_id: credentialId,
        host_ids: hostIds,
      });
      if (res.violations > 0) {
        alert(
          `Scan complete: ${res.hosts_scanned} host(s) scanned, ${res.violations} non-compliant, ${res.errors} error(s)`,
        );
      } else if (res.errors > 0) {
        alert(
          `Scan complete: ${res.hosts_scanned} host(s) scanned, ${res.errors} error(s)`,
        );
      } else {
        alert(`Scan complete: ${res.hosts_scanned} host(s) scanned — all compliant!`);
      }
      onClose();
    } catch (e) {
      setError(`Scan failed: ${(e as Error).message}`);
    }
  };

  return (
    <Modal isOpen onClose={onClose} title="Run Compliance Scan">
      <div className="form-group">
        <label className="form-label">Scope</label>
        <div style={{ display: 'flex', gap: '0.5rem' }}>
          {(['all', 'group', 'single'] as Scope[]).map((s) => (
            <button
              key={s}
              type="button"
              className={`btn btn-sm ${scope === s ? 'btn-primary' : 'btn-secondary'}`}
              onClick={() => setScope(s)}
            >
              {s === 'all' ? 'All Hosts' : s === 'group' ? 'By Group' : 'Single Host'}
            </button>
          ))}
        </div>
      </div>

      {scope === 'group' && (
        <div className="form-group">
          <label className="form-label">Group</label>
          <select
            className="form-select"
            value={groupId ?? ''}
            onChange={(e) =>
              setGroupId(e.target.value ? parseInt(e.target.value, 10) : null)
            }
          >
            {groupList.map((g) => (
              <option key={g.id} value={g.id}>
                {g.name} ({(g.hosts || []).length} hosts)
              </option>
            ))}
          </select>
        </div>
      )}

      {scope === 'single' && (
        <div className="form-group">
          <label className="form-label">Host</label>
          <select
            className="form-select"
            value={hostId ?? ''}
            onChange={(e) =>
              setHostId(e.target.value ? parseInt(e.target.value, 10) : null)
            }
          >
            <option value="">Select a host…</option>
            {allHosts.map((h) => (
              <option key={h.id} value={h.id}>
                {h.hostname} ({h.ip_address}) — {h.group_name}
              </option>
            ))}
          </select>
        </div>
      )}

      <div className="form-group">
        <label className="form-label">Compliance Profile</label>
        <select
          className="form-select"
          value={profileId ?? ''}
          onChange={(e) =>
            setProfileId(e.target.value ? parseInt(e.target.value, 10) : null)
          }
        >
          {profileList.length === 0 && <option value="">No profiles available</option>}
          {profileList.map((p) => (
            <option key={p.id} value={p.id}>
              {p.name}
            </option>
          ))}
        </select>
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
          <option value="">Select a credential…</option>
          {credList.map((c) => (
            <option key={c.id} value={c.id}>
              {c.name}
            </option>
          ))}
        </select>
      </div>

      {hint && (
        <div style={{ fontSize: '0.85em', color: 'var(--text-muted)', marginBottom: '0.5rem' }}>
          {hint}
        </div>
      )}
      {error && <div className="error">{error}</div>}

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
          onClick={onSubmit}
          disabled={isPending}
        >
          {isPending ? 'Scanning…' : submitLabel}
        </button>
      </div>
    </Modal>
  );
}
