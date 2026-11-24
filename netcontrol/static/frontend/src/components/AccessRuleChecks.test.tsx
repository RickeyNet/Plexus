import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';

import type { AccessGroup } from '@/api/settings';

import { isAdminsOnly } from '@/lib/accessGroups';

import { AccessRuleChecks } from './AccessRuleChecks';

const GROUPS = [
  { id: 1, name: 'NOC' },
  { id: 2, name: 'Field' },
] as AccessGroup[];

function render(props: Partial<Parameters<typeof AccessRuleChecks>[0]> = {}) {
  return renderToStaticMarkup(
    <AccessRuleChecks
      title="Usable by"
      help="Nothing ticked: everyone."
      value={{ roles: ['user'], groups: [2, 9] }}
      onChange={() => {}}
      accessGroups={GROUPS}
      accessGroupsFailed={false}
      {...props}
    />,
  );
}

describe('AccessRuleChecks', () => {
  it('labels the group and ticks the role and access groups of the rule', () => {
    const html = render();
    expect(html).toContain('role="group"');
    expect(html).toContain('Usable by');
    expect(html).toContain('Every user (role: user)');
    expect(html).toContain('Access group: NOC');
    expect(html).toContain('Access group: Field');
    expect(html).toContain('Nothing ticked: everyone.');
    // The role and group 2 are ticked, group 1 is not.
    expect(html.match(/checked=""/g)?.length).toBe(2);
    // A deleted group is listed only when asked for.
    expect(html).not.toContain('Deleted access group');
    expect(render({ showMissing: true })).toContain('Deleted access group (id 9)');
  });

  it('offers "Admins only" when asked, ticked for the admin-only rule alone', () => {
    expect(render()).not.toContain('Admins only');
    const html = render({ adminsOnlyOption: true, value: { roles: ['admin'], groups: [] } });
    expect(html).toContain('Admins only');
    expect(html.match(/checked=""/g)?.length).toBe(1);
    expect(render({ adminsOnlyOption: true }).match(/checked=""/g)?.length).toBe(2);

    expect(isAdminsOnly({ roles: ['admin'], groups: [] })).toBe(true);
    expect(isAdminsOnly({ roles: [], groups: [] })).toBe(false);
    expect(isAdminsOnly({ roles: ['admin', 'user'], groups: [] })).toBe(false);
    expect(isAdminsOnly({ roles: ['admin'], groups: [1] })).toBe(false);
  });

  it('says when the access groups could not be loaded', () => {
    expect(render({ accessGroups: undefined, accessGroupsFailed: true })).toContain('Access groups could not be loaded.');
  });
});
