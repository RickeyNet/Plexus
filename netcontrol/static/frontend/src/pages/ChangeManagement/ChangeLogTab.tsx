import { useId, useState } from 'react';
import { Link } from 'react-router';

import type { ObjectChange } from '@/api/objectChanges';
import { ChangelogTimeline } from '@/components/ChangelogPanel';
import { actionLabel, OBJECT_TYPES, objectTypeLabel } from '@/lib/objectChanges';
import { useDebouncedValue } from '@/lib/useDebouncedValue';
import { FormRow, TextField } from '@/pages/Settings/FormFields';

const ACTIONS = ['create', 'update', 'delete'];

/** Where an object of the change log is shown, when it has a page of its own. */
function objectLink(change: ObjectChange): string | null {
  if (change.action === 'delete') return null;
  if (change.object_type === 'host') return `/devices/${change.object_id}`;
  if (change.object_type === 'vlan') return '/ipam/vlans';
  if (change.object_type === 'vrf') return '/ipam/vrfs';
  if (change.object_type === 'group') return '/inventory';
  return null;
}

function ObjectName({ change }: { change: ObjectChange }) {
  const name = `${objectTypeLabel(change.object_type)} ${change.object_label || `#${change.object_id}`}`;
  const to = objectLink(change);
  return to ? <Link to={to}>{name}</Link> : <>{name}</>;
}

/**
 * The global change log: every recorded create, update and delete the user
 * may read (per object type, and only their inventory groups when limited
 * to some), filtered by type, action, user and date.
 */
export function ChangeLogTab() {
  const fid = useId();
  const [objectType, setObjectType] = useState('');
  const [action, setAction] = useState('');
  const [user, setUser] = useState('');
  const [since, setSince] = useState('');
  const [until, setUntil] = useState('');
  const debouncedUser = useDebouncedValue(user.trim());

  return (
    <div className="card card-sm stack">
      <FormRow>
        <div className="form-group" style={{ flex: '0 1 200px' }}>
          <label className="form-label" htmlFor={`${fid}-type`}>
            Object type
          </label>
          <select
            id={`${fid}-type`}
            className="form-select"
            value={objectType}
            onChange={(e) => setObjectType(e.target.value)}
          >
            <option value="">All types</option>
            {OBJECT_TYPES.map((t) => (
              <option key={t} value={t}>
                {objectTypeLabel(t)}
              </option>
            ))}
          </select>
        </div>
        <div className="form-group" style={{ flex: '0 1 160px' }}>
          <label className="form-label" htmlFor={`${fid}-action`}>
            Action
          </label>
          <select id={`${fid}-action`} className="form-select" value={action} onChange={(e) => setAction(e.target.value)}>
            <option value="">All actions</option>
            {ACTIONS.map((a) => (
              <option key={a} value={a}>
                {actionLabel(a)}
              </option>
            ))}
          </select>
        </div>
        <TextField label="User" value={user} onChange={setUser} flex="0 1 200px" autoComplete="off" />
        <TextField label="From" type="date" value={since} onChange={setSince} flex="0 1 170px" />
        <TextField label="To" type="date" value={until} onChange={setUntil} flex="0 1 170px" />
      </FormRow>
      <ChangelogTimeline
        filter={{ object_type: objectType, action, user: debouncedUser, since, until }}
        showObject
        renderObject={(c) => <ObjectName change={c} />}
        emptyMessage="No changes match these filters."
      />
    </div>
  );
}
