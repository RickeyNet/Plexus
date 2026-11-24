import { describe, expect, it } from 'vitest';

import type { AccessGroup } from '@/api/settings';

import { accessGroupLabels, accessRuleSummary, missingGroupIds, toggleGroupId } from './accessGroups';

const GROUPS = [
  { id: 1, name: 'NOC' },
  { id: 2, name: 'Field' },
] as AccessGroup[];

describe('access group helpers', () => {
  it('finds ticked ids whose group was deleted, only once the list is known', () => {
    expect(missingGroupIds([1, 9], GROUPS)).toEqual([9]);
    expect(missingGroupIds([1, 9], undefined)).toEqual([]);
  });

  it('adds an id at the end or removes it', () => {
    expect(toggleGroupId([2], 1, true)).toEqual([2, 1]);
    expect(toggleGroupId([2, 1], 1, true)).toEqual([2, 1]);
    expect(toggleGroupId([2, 1], 2, false)).toEqual([1]);
  });

  it('labels ids by name, with stand-ins for deleted or unloaded groups', () => {
    expect(accessGroupLabels([2, 9], GROUPS)).toEqual(['Field', 'deleted group 9']);
    expect(accessGroupLabels([2], undefined)).toEqual(['group 2']);
  });

  it('summarises a rule, with the open wording for an empty one', () => {
    expect(accessRuleSummary(undefined, GROUPS, 'everyone')).toBe('everyone');
    expect(accessRuleSummary({ roles: [], groups: [] }, GROUPS, 'everyone')).toBe('everyone');
    expect(accessRuleSummary({ roles: ['user'], groups: [] }, GROUPS, 'everyone')).toBe('users');
    expect(accessRuleSummary({ roles: [], groups: [1, 2] }, GROUPS, 'everyone')).toBe('access groups: NOC, Field');
    expect(accessRuleSummary({ roles: ['user'], groups: [1] }, GROUPS, 'everyone')).toBe('users; access groups: NOC');
    expect(accessRuleSummary({ roles: ['admin'], groups: [] }, GROUPS, 'everyone')).toBe('admins only');
    expect(accessRuleSummary({ roles: ['admin'], groups: [1] }, GROUPS, 'everyone')).toBe('access groups: NOC');
  });
});
