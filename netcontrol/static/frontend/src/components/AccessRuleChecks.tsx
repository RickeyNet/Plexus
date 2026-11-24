import { useId, type CSSProperties } from 'react';

import type { AccessGroup } from '@/api/settings';
import type { JobPermissionRule } from '@/api/jobs';
import { AccessGroupChecks } from '@/components/AccessGroupChecks';
import { isAdminsOnly } from '@/lib/accessGroups';

interface Props {
  /** The heading of the group of checkboxes, e.g. "Who may run". */
  title: string;
  /** What an empty rule means, and anything else the reader needs. */
  help: string;
  value: JobPermissionRule;
  onChange: (value: JobPermissionRule) => void;
  /** Undefined while loading or when the list could not be read. */
  accessGroups: AccessGroup[] | undefined;
  accessGroupsFailed: boolean;
  /** Also list ticked ids whose access group was deleted, so they can be unticked. */
  showMissing?: boolean;
  /** Also offer "Admins only" (the rule `{roles: ['admin'], groups: []}`). */
  adminsOnlyOption?: boolean;
  style?: CSSProperties;
}

/** One `{roles, groups}` rule: the user role and the access groups allowed.
 *  Shared by the playbook run/commit permissions and a secret variable's
 *  "Usable by" (netcontrol/job_inputs.py `normalize_rule`). Nothing ticked
 *  is the open rule; admins are always allowed. */
export function AccessRuleChecks({
  title,
  help,
  value,
  onChange,
  accessGroups,
  accessGroupsFailed,
  showMissing = false,
  adminsOnlyOption = false,
  style,
}: Props) {
  const titleId = useId();
  const userRole = value.roles.includes('user');
  // With the "Admins only" option, the admin role is that option alone:
  // ticking the user role or a group replaces it, so unticking them again
  // gives the open rule and not "Admins only".
  const keptRoles = adminsOnlyOption ? value.roles.filter((r) => r !== 'admin') : value.roles;

  return (
    <div className="form-group" role="group" aria-labelledby={titleId} style={style}>
      <span className="form-label" id={titleId}>{title}</span>
      {adminsOnlyOption && (
        <label className="form-check">
          <input
            type="checkbox"
            checked={isAdminsOnly(value)}
            onChange={(e) => onChange({ roles: e.target.checked ? ['admin'] : [], groups: [] })}
          />
          <span>Admins only</span>
        </label>
      )}
      <label className="form-check">
        <input
          type="checkbox"
          checked={userRole}
          onChange={(e) => {
            const rest = keptRoles.filter((r) => r !== 'user');
            onChange({ ...value, roles: e.target.checked ? [...rest, 'user'] : rest });
          }}
        />
        <span>Every user (role: user)</span>
      </label>
      <AccessGroupChecks
        value={value.groups}
        onChange={(groups) => onChange({ ...value, roles: keptRoles, groups })}
        accessGroups={accessGroups}
        showMissing={showMissing}
      />
      {accessGroupsFailed && <div className="form-help">Access groups could not be loaded.</div>}
      <div className="form-help">{help}</div>
    </div>
  );
}
