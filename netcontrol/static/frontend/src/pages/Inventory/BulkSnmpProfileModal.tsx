import { useId, useState } from 'react';

import { Callout } from '@/components/Callout';
import { Modal } from '@/components/Modal';
import { ModalActions } from '@/components/ModalActions';
import { useSetHostsSnmpProfile, useSnmpProfiles } from '@/api/inventory';

interface Props {
  hostIds: number[];
  onClose: () => void;
}

/**
 * Gives the selected hosts their own SNMP profile, or puts them back on
 * their group's profile, in one request.
 */
export function BulkSnmpProfileModal({ hostIds, onClose }: Props) {
  const id = useId();
  const setProfile = useSetHostsSnmpProfile();
  const profilesQ = useSnmpProfiles();
  // '' = each host uses its group's profile.
  const [profileId, setProfileId] = useState('');
  const count = hostIds.length;
  const hosts = `${count} host${count === 1 ? '' : 's'}`;

  const apply = () => setProfile.mutate({ hostIds, profileId }, { onSuccess: onClose });

  return (
    <Modal
      isOpen
      onClose={onClose}
      title={`Set SNMP profile for ${hosts}`}
      size="small"
      footer={
        <ModalActions
          onClose={onClose}
          primaryLabel="Set profile"
          primaryBusy={setProfile.isPending}
          primaryBusyLabel="Setting…"
          onPrimary={apply}
        />
      }
    >
      {setProfile.error && (
        <Callout tone="danger">
          The SNMP profile was not set: {setProfile.error.message} Check that the profile still exists and try
          again.
        </Callout>
      )}
      <div className="form-group">
        <label className="form-label" htmlFor={`${id}-profile`}>SNMP profile</label>
        <select
          id={`${id}-profile`}
          className="form-select"
          value={profileId}
          onChange={(e) => setProfileId(e.target.value)}
          aria-describedby={`${id}-profile-help`}
        >
          <option value="">Use the group&apos;s profile</option>
          {(profilesQ.data ?? []).map((p) => (
            <option key={p.id} value={p.id}>
              {p.name}
            </option>
          ))}
        </select>
        <div className="form-help" id={`${id}-profile-help`}>
          A profile set here overrides the group&apos;s for {count === 1 ? 'the host' : `all ${hosts}`}.
          &quot;Use the group&apos;s profile&quot; removes {count === 1 ? 'its' : 'their'} own profile.
        </div>
      </div>
    </Modal>
  );
}
