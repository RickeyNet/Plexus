import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';

import type { AuthStatus } from '@/api/auth';

import {
  canWriteGroup,
  canWriteHost,
  hostGroupIds,
  useCanWriteGroup,
  useObjectScope,
  writableGroups,
} from './objectScope';

function Probe({ groupId }: { groupId: number | null }) {
  const scope = useObjectScope();
  const canWrite = useCanWriteGroup(groupId);
  return <span>{`${scope.restricted}:${canWrite}`}</span>;
}

function render(status: AuthStatus | undefined, groupId: number | null): string {
  const qc = new QueryClient();
  if (status) qc.setQueryData(['auth', 'status'], status);
  return renderToStaticMarkup(
    <QueryClientProvider client={qc}>
      <Probe groupId={groupId} />
    </QueryClientProvider>,
  );
}

describe('canWriteGroup', () => {
  it('lets an unrestricted account (or an unknown scope) write anything', () => {
    expect(canWriteGroup(undefined, 4)).toBe(true);
    expect(canWriteGroup({ restricted: false, write_group_ids: [] }, 4)).toBe(true);
    expect(canWriteGroup({ restricted: false, write_group_ids: [] }, null)).toBe(true);
  });

  it('limits a scoped account to its writable groups', () => {
    const scope = { restricted: true, write_group_ids: [2, 3] };
    expect(canWriteGroup(scope, 2)).toBe(true);
    expect(canWriteGroup(scope, 4)).toBe(false);
    expect(canWriteGroup(scope, null)).toBe(false);
    expect(canWriteGroup(scope, undefined)).toBe(false);
  });
});

describe('writableGroups / hostGroupIds / canWriteHost', () => {
  const scope = { restricted: true, write_group_ids: [2] };
  const groups = [
    { id: 1, hosts: [{ id: 10 }] },
    { id: 2, hosts: [{ id: 20 }, { id: 21 }] },
  ];

  it('keeps the writable groups for a scoped account and all of them otherwise', () => {
    expect(writableGroups(scope, groups).map((g) => g.id)).toEqual([2]);
    expect(writableGroups(undefined, groups)).toBe(groups);
    expect(writableGroups({ restricted: false, write_group_ids: [] }, groups)).toBe(groups);
  });

  it('maps hosts to their groups and checks a host through its group', () => {
    const map = hostGroupIds(groups);
    expect(map?.get(21)).toBe(2);
    expect(hostGroupIds(undefined)).toBeUndefined();
    expect(canWriteHost(scope, map, 20)).toBe(true);
    expect(canWriteHost(scope, map, 10)).toBe(false);
    expect(canWriteHost(scope, map, 99)).toBe(false);
    expect(canWriteHost(scope, map, null)).toBe(false);
    // Not loaded yet: left to the server.
    expect(canWriteHost(scope, undefined, 10)).toBe(true);
    expect(canWriteHost(undefined, map, 10)).toBe(true);
  });
});

describe('useObjectScope / useCanWriteGroup', () => {
  it('reads the scope from the auth status', () => {
    const scoped: AuthStatus = { authenticated: true, object_scope: { restricted: true, write_group_ids: [7] } };
    expect(render(scoped, 7)).toContain('true:true');
    expect(render(scoped, 8)).toContain('true:false');
    expect(render({ authenticated: true }, 8)).toContain('false:true');
    expect(render(undefined, 8)).toContain('false:true');
  });
});
