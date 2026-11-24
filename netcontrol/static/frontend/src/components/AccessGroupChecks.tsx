import type { AccessGroup } from '@/api/settings';
import { missingGroupIds, toggleGroupId } from '@/lib/accessGroups';

interface Props {
  /** The ticked access group ids. */
  value: number[];
  onChange: (value: number[]) => void;
  /** Undefined while loading or when the list could not be read. */
  accessGroups: AccessGroup[] | undefined;
  /** Also list ticked ids whose access group was deleted, so they can be unticked. */
  showMissing?: boolean;
}

/** One checkbox per access group. Renders the rows only: the caller supplies
 *  the group label and the help text around them. */
export function AccessGroupChecks({ value, onChange, accessGroups, showMissing = false }: Props) {
  return (
    <>
      {(accessGroups ?? []).map((g) => (
        <label key={g.id} className="form-check">
          <input
            type="checkbox"
            checked={value.includes(g.id)}
            onChange={(e) => onChange(toggleGroupId(value, g.id, e.target.checked))}
          />
          <span>Access group: {g.name}</span>
        </label>
      ))}
      {showMissing && missingGroupIds(value, accessGroups).map((id) => (
        <label key={id} className="form-check">
          <input type="checkbox" checked onChange={() => onChange(toggleGroupId(value, id, false))} />
          <span>Deleted access group (id {id})</span>
        </label>
      ))}
    </>
  );
}
