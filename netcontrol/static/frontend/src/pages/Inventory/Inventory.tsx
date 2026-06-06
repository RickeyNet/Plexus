import { useEffect, useMemo, useRef, useState } from 'react';
import { useVirtualizer } from '@tanstack/react-virtual';

import { PageHelp } from '@/components/PageHelp';

import {
  type InventoryGroupFull,
  type InventoryHost,
  inventoryCsvExportUrl,
  useAssignSnmpProfile,
  useBulkDeleteHosts,
  useDeleteHost,
  useDeleteInventoryGroup,
  useGroupSnmpAssignments,
  useInventoryGroupsFull,
  useReorderInventoryGroups,
  useSnmpProfiles,
} from '@/api/inventory';

import { BulkMoveModal } from './BulkMoveModal';
import { BulkSerialModal } from './BulkSerialModal';
import { DiscoveryModal, type DiscoveryMode } from './DiscoveryModal';
import { FetchSerialModal } from './FetchSerialModal';
import { GroupModal } from './GroupModal';
import { HostModal } from './HostModal';
import { SnmpProfilesModal } from './SnmpProfilesModal';
import {
  filterGroups,
  hostMatchesQuery,
  loadCollapsedSet,
  loadCompactMode,
  saveCollapsedSet,
  saveCompactMode,
  sortGroups,
  sortHostsForQuery,
  type InventorySort,
} from './helpers';

type ModalState =
  | { kind: 'none' }
  | { kind: 'create-group' }
  | { kind: 'edit-group'; group: InventoryGroupFull }
  | { kind: 'add-host'; groupId: number }
  | {
      kind: 'edit-host';
      host: InventoryHost & { group_id: number };
    }
  | { kind: 'bulk-move'; sourceGroupId: number; hostIds: number[] }
  | { kind: 'fetch-serial'; hostId: number; hostname?: string }
  | { kind: 'bulk-serial'; groupId: number; groupName?: string }
  | { kind: 'snmp-profiles' }
  | {
      kind: 'discovery';
      mode: DiscoveryMode;
      group: InventoryGroupFull | null;
    };

export function Inventory() {
  const groupsQ = useInventoryGroupsFull(true);
  const profilesQ = useSnmpProfiles();
  const groups = useMemo(() => groupsQ.data ?? [], [groupsQ.data]);
  const groupIds = useMemo(() => groups.map((g) => g.id), [groups]);
  const assignmentsQ = useGroupSnmpAssignments(groupIds);

  const [query, setQuery] = useState('');
  const [sort, setSort] = useState<InventorySort>('custom');
  const [compact, setCompact] = useState<boolean>(() => loadCompactMode());
  const [collapsed, setCollapsed] = useState<Set<number>>(() => loadCollapsedSet());
  const [modal, setModal] = useState<ModalState>({ kind: 'none' });
  const [selectedHosts, setSelectedHosts] = useState<Map<number, Set<number>>>(
    new Map(),
  );
  const [orderOverride, setOrderOverride] = useState<number[] | null>(null);

  const reorder = useReorderInventoryGroups();
  const deleteGroup = useDeleteInventoryGroup();
  const deleteHost = useDeleteHost();
  const bulkDelete = useBulkDeleteHosts();
  const assignProfile = useAssignSnmpProfile();

  // Persist UI prefs.
  useEffect(() => saveCompactMode(compact), [compact]);
  useEffect(() => saveCollapsedSet(collapsed), [collapsed]);

  // Apply user drag order before filter/sort.
  const orderedGroups = useMemo(() => {
    if (!orderOverride) return groups;
    const byId = new Map(groups.map((g) => [g.id, g]));
    const ordered = orderOverride.map((id) => byId.get(id)).filter(Boolean) as InventoryGroupFull[];
    const seen = new Set(orderOverride);
    const tail = groups.filter((g) => !seen.has(g.id));
    return [...ordered, ...tail];
  }, [groups, orderOverride]);

  const filtered = useMemo(
    () => sortGroups(filterGroups(orderedGroups, query), sort),
    [orderedGroups, query, sort],
  );

  const isCustomOrder = sort === 'custom' && !query.trim();

  const toggleCollapsed = (id: number) => {
    setCollapsed((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const toggleAllCollapsed = () => {
    const anyExpanded = filtered.some((g) => !collapsed.has(g.id));
    if (anyExpanded) {
      setCollapsed(new Set(filtered.map((g) => g.id)));
    } else {
      setCollapsed(new Set());
    }
  };

  const allCollapsed =
    filtered.length > 0 && filtered.every((g) => collapsed.has(g.id));

  // Drag-reorder state.
  const dragIdRef = useRef<number | null>(null);
  const onDragStart = (id: number) => {
    dragIdRef.current = id;
  };
  const onDragOver = (e: React.DragEvent, overId: number) => {
    if (!isCustomOrder) return;
    if (dragIdRef.current == null || dragIdRef.current === overId) return;
    e.preventDefault();
  };
  const onDrop = (overId: number) => {
    if (!isCustomOrder) return;
    const dragId = dragIdRef.current;
    dragIdRef.current = null;
    if (dragId == null || dragId === overId) return;
    const current = orderOverride ?? orderedGroups.map((g) => g.id);
    const without = current.filter((id) => id !== dragId);
    const overIdx = without.indexOf(overId);
    const next = [
      ...without.slice(0, overIdx),
      dragId,
      ...without.slice(overIdx),
    ];
    setOrderOverride(next);
    reorder.mutate(next, {
      onError: (err) => alert(`Failed to save group order: ${(err as Error).message}`),
    });
  };

  const handleDeleteGroup = (g: InventoryGroupFull) => {
    if (
      !confirm(
        `Delete group "${g.name}"? This will remove the group and all its hosts. This cannot be undone.`,
      )
    )
      return;
    deleteGroup.mutate(g.id, {
      onError: (err) => alert((err as Error).message),
    });
  };

  const handleDeleteHost = (host: InventoryHost) => {
    if (
      !confirm(
        `Delete host "${host.hostname}"? This will permanently remove this host from the inventory.`,
      )
    )
      return;
    deleteHost.mutate(host.id, {
      onError: (err) => alert((err as Error).message),
    });
  };

  const handleBulkDelete = (groupId: number) => {
    const ids = Array.from(selectedHosts.get(groupId) ?? []);
    if (!ids.length) return;
    if (
      !confirm(
        `Delete ${ids.length} host(s)? This cannot be undone.`,
      )
    )
      return;
    bulkDelete.mutate(ids, {
      onSuccess: () => {
        setSelectedHosts((prev) => {
          const next = new Map(prev);
          next.delete(groupId);
          return next;
        });
      },
      onError: (err) => alert((err as Error).message),
    });
  };

  const exportCsv = () => {
    window.open(inventoryCsvExportUrl(), '_blank');
  };

  const closeModal = () => setModal({ kind: 'none' });

  return (
    <div>
      <div className="page-header" style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', flexWrap: 'wrap' }}>
        <h2 style={{ margin: 0, flex: '0 0 auto' }}>Inventory</h2>
        <div style={{ display: 'flex', gap: '0.4rem', marginLeft: 'auto', flexWrap: 'wrap' }}>
          <button
            type="button"
            className="btn btn-sm btn-secondary"
            onClick={() => setModal({ kind: 'snmp-profiles' })}
          >
            SNMP Profiles
          </button>
          <button
            type="button"
            className="btn btn-sm btn-secondary"
            onClick={() =>
              setModal({ kind: 'discovery', mode: 'global', group: null })
            }
          >
            Discover Devices
          </button>
          <button
            type="button"
            className="btn btn-sm btn-secondary"
            onClick={exportCsv}
          >
            Export CSV
          </button>
          <button
            type="button"
            className="btn btn-sm btn-primary"
            onClick={() => setModal({ kind: 'create-group' })}
          >
            + New Group
          </button>
        </div>
      </div>

      <PageHelp
        pageKey="inventory"
        title="Manage Your Devices"
        text="Add, edit, and organize network devices into groups. Devices added here are used across monitoring, backups, compliance, and automation features."
      />

      <div
        className="card"
        style={{
          padding: '0.75rem',
          marginBottom: '0.75rem',
          display: 'flex',
          gap: '0.5rem',
          flexWrap: 'wrap',
          alignItems: 'center',
        }}
      >
        <input
          className="form-input"
          placeholder="Search groups, hosts, IPs…"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          style={{ maxWidth: 280, flex: '1 1 200px' }}
        />
        <select
          className="form-select"
          value={sort}
          onChange={(e) => setSort(e.target.value as InventorySort)}
          style={{ maxWidth: 200 }}
          title="Sort"
        >
          <option value="custom">Custom order</option>
          <option value="name_asc">Name A→Z</option>
          <option value="name_desc">Name Z→A</option>
          <option value="hosts_desc">Most hosts</option>
          <option value="hosts_asc">Fewest hosts</option>
        </select>
        <button
          type="button"
          className="btn btn-sm btn-secondary"
          onClick={() => setCompact((v) => !v)}
        >
          {compact ? 'Comfortable' : 'Compact'}
        </button>
        <button
          type="button"
          className="btn btn-sm btn-secondary"
          onClick={toggleAllCollapsed}
          disabled={filtered.length === 0}
        >
          {allCollapsed ? 'Expand All' : 'Collapse All'}
        </button>
      </div>

      {groupsQ.isPending && <p className="text-muted">Loading inventory…</p>}
      {groupsQ.error && (
        <p style={{ color: 'var(--danger)' }}>
          Error loading inventory: {(groupsQ.error as Error).message}
        </p>
      )}
      {!groupsQ.isPending && filtered.length === 0 && (
        <div
          className="card"
          style={{ padding: '1.5rem', textAlign: 'center', color: 'var(--text-muted)' }}
        >
          {query ? 'No groups match your search.' : 'No inventory groups. Click "+ New Group" to create one.'}
        </div>
      )}

      {filtered.map((group) => (
        <GroupCard
          key={group.id}
          group={group}
          query={query}
          compact={compact}
          collapsed={collapsed.has(group.id)}
          draggable={isCustomOrder}
          selectedSet={selectedHosts.get(group.id) ?? new Set()}
          assignedProfileId={assignmentsQ.data?.[group.id] ?? ''}
          snmpProfiles={profilesQ.data ?? []}
          onAssignProfile={(profileId) =>
            assignProfile.mutate(
              { groupId: group.id, profileId },
              { onError: (e) => alert((e as Error).message) },
            )
          }
          onToggleCollapse={() => toggleCollapsed(group.id)}
          onDragStart={() => onDragStart(group.id)}
          onDragOver={(e) => onDragOver(e, group.id)}
          onDrop={() => onDrop(group.id)}
          onSelectionChange={(set) =>
            setSelectedHosts((prev) => {
              const next = new Map(prev);
              if (set.size === 0) next.delete(group.id);
              else next.set(group.id, set);
              return next;
            })
          }
          onEditGroup={() => setModal({ kind: 'edit-group', group })}
          onDeleteGroup={() => handleDeleteGroup(group)}
          onSyncDiscovery={() =>
            setModal({ kind: 'discovery', mode: 'sync', group })
          }
          onBulkSerial={() =>
            setModal({ kind: 'bulk-serial', groupId: group.id, groupName: group.name })
          }
          onAddHost={() => setModal({ kind: 'add-host', groupId: group.id })}
          onEditHost={(host) =>
            setModal({
              kind: 'edit-host',
              host: { ...host, group_id: group.id },
            })
          }
          onDeleteHost={handleDeleteHost}
          onFetchSerial={(host) =>
            setModal({
              kind: 'fetch-serial',
              hostId: host.id,
              hostname: host.hostname,
            })
          }
          onBulkMove={() => {
            const ids = Array.from(selectedHosts.get(group.id) ?? []);
            if (!ids.length) return;
            setModal({
              kind: 'bulk-move',
              sourceGroupId: group.id,
              hostIds: ids,
            });
          }}
          onBulkDelete={() => handleBulkDelete(group.id)}
        />
      ))}

      {modal.kind === 'create-group' && (
        <GroupModal group={null} isCreate onClose={closeModal} />
      )}
      {modal.kind === 'edit-group' && (
        <GroupModal group={modal.group} isCreate={false} onClose={closeModal} />
      )}
      {modal.kind === 'add-host' && (
        <HostModal
          host={null}
          groupId={modal.groupId}
          groups={groups}
          onClose={closeModal}
        />
      )}
      {modal.kind === 'edit-host' && (
        <HostModal
          host={modal.host}
          groupId={null}
          groups={groups}
          onClose={closeModal}
        />
      )}
      {modal.kind === 'bulk-move' && (
        <BulkMoveModal
          hostIds={modal.hostIds}
          sourceGroupId={modal.sourceGroupId}
          groups={groups}
          onClose={() => {
            setSelectedHosts((prev) => {
              const next = new Map(prev);
              next.delete(modal.sourceGroupId);
              return next;
            });
            closeModal();
          }}
        />
      )}
      {modal.kind === 'fetch-serial' && (
        <FetchSerialModal
          hostId={modal.hostId}
          hostname={modal.hostname}
          onClose={closeModal}
        />
      )}
      {modal.kind === 'bulk-serial' && (
        <BulkSerialModal
          groupId={modal.groupId}
          groupName={modal.groupName}
          onClose={closeModal}
        />
      )}
      {modal.kind === 'snmp-profiles' && (
        <SnmpProfilesModal onClose={closeModal} />
      )}
      {modal.kind === 'discovery' && (
        <DiscoveryModal
          mode={modal.mode}
          group={modal.group}
          groups={groups}
          onClose={closeModal}
        />
      )}
    </div>
  );
}

interface GroupCardProps {
  group: InventoryGroupFull;
  query: string;
  compact: boolean;
  collapsed: boolean;
  draggable: boolean;
  selectedSet: Set<number>;
  assignedProfileId: string;
  snmpProfiles: { id: string; name: string }[];
  onAssignProfile: (profileId: string) => void;
  onToggleCollapse: () => void;
  onDragStart: () => void;
  onDragOver: (e: React.DragEvent) => void;
  onDrop: () => void;
  onSelectionChange: (next: Set<number>) => void;
  onEditGroup: () => void;
  onDeleteGroup: () => void;
  onSyncDiscovery: () => void;
  onBulkSerial: () => void;
  onAddHost: () => void;
  onEditHost: (host: InventoryHost) => void;
  onDeleteHost: (host: InventoryHost) => void;
  onFetchSerial: (host: InventoryHost) => void;
  onBulkMove: () => void;
  onBulkDelete: () => void;
}

function GroupCard({
  group,
  query,
  compact,
  collapsed,
  draggable,
  selectedSet,
  assignedProfileId,
  snmpProfiles,
  onAssignProfile,
  onToggleCollapse,
  onDragStart,
  onDragOver,
  onDrop,
  onSelectionChange,
  onEditGroup,
  onDeleteGroup,
  onSyncDiscovery,
  onBulkSerial,
  onAddHost,
  onEditHost,
  onDeleteHost,
  onFetchSerial,
  onBulkMove,
  onBulkDelete,
}: GroupCardProps) {
  const hosts = group.hosts ?? [];
  const sortedHosts = sortHostsForQuery(hosts, query);

  // Virtualize the host rows so only the rows in view are mounted. Each group
  // scrolls inside its own max-height container, so a group with thousands of
  // hosts costs the same handful of <tr> as a group with ten. Small groups
  // never reach the max height, so no scrollbar appears and they render in
  // full - visually identical to before.
  const scrollRef = useRef<HTMLDivElement>(null);
  const rowVirtualizer = useVirtualizer({
    count: sortedHosts.length,
    getScrollElement: () => scrollRef.current,
    estimateSize: () => (compact ? 37 : 45),
    overscan: 12,
  });

  const allSelected = hosts.length > 0 && selectedSet.size === hosts.length;
  const indeterminate = selectedSet.size > 0 && !allSelected;
  const singleSelected = selectedSet.size === 1;
  const selectedHostId = singleSelected ? Array.from(selectedSet)[0] : null;
  const selectedHostObj = selectedHostId != null
    ? hosts.find((h) => h.id === selectedHostId)
    : null;

  const onToggleSelectAll = (checked: boolean) => {
    onSelectionChange(checked ? new Set(hosts.map((h) => h.id)) : new Set());
  };

  const onToggleHost = (hostId: number, checked: boolean) => {
    const next = new Set(selectedSet);
    if (checked) next.add(hostId);
    else next.delete(hostId);
    onSelectionChange(next);
  };

  return (
    <div
      className="card"
      draggable={draggable}
      onDragStart={onDragStart}
      onDragOver={onDragOver}
      onDrop={(e) => {
        e.preventDefault();
        onDrop();
      }}
      style={{
        marginBottom: '0.75rem',
        padding: compact ? '0.5rem 0.75rem' : '0.75rem 1rem',
        opacity: collapsed ? 0.95 : 1,
      }}
    >
      <div
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          gap: '0.5rem',
          flexWrap: 'wrap',
        }}
      >
        <div
          onClick={onToggleCollapse}
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: '0.5rem',
            cursor: 'pointer',
            minWidth: 0,
            flex: 1,
          }}
        >
          {draggable && (
            <span
              title="Drag to reorder"
              aria-hidden
              style={{ color: 'var(--text-muted)', cursor: 'grab' }}
              onClick={(e) => e.stopPropagation()}
            >
              ⋮⋮
            </span>
          )}
          <span aria-hidden style={{ color: 'var(--text-muted)' }}>
            {collapsed ? '▶' : '▼'}
          </span>
          <div style={{ minWidth: 0 }}>
            <div style={{ fontWeight: 600 }}>
              {group.name}{' '}
              <span style={{ color: 'var(--text-muted)', fontWeight: 400 }}>
                ({hosts.length})
              </span>
            </div>
            {group.description && (
              <div
                style={{
                  color: 'var(--text-muted)',
                  fontSize: '0.85em',
                  whiteSpace: 'nowrap',
                  textOverflow: 'ellipsis',
                  overflow: 'hidden',
                }}
              >
                {group.description}
              </div>
            )}
          </div>
        </div>
        <div
          style={{
            display: 'flex',
            gap: '0.25rem',
            alignItems: 'center',
            flexShrink: 0,
          }}
        >
          <select
            className="form-select"
            style={{
              fontSize: '0.75rem',
              padding: '0.2rem 0.4rem',
              height: 'auto',
              minWidth: 130,
            }}
            value={assignedProfileId}
            onChange={(e) => onAssignProfile(e.target.value)}
            title="SNMP Profile"
          >
            <option value="">No SNMP Profile</option>
            {snmpProfiles.map((p) => (
              <option key={p.id} value={p.id}>
                {p.name}
              </option>
            ))}
          </select>
          <button
            type="button"
            className="btn btn-sm btn-secondary"
            onClick={onSyncDiscovery}
          >
            Sync
          </button>
          <button
            type="button"
            className="btn btn-sm btn-secondary"
            onClick={onBulkSerial}
          >
            Fetch Serials
          </button>
          <button
            type="button"
            className="btn btn-sm btn-secondary"
            onClick={onEditGroup}
          >
            Edit
          </button>
          <button
            type="button"
            className="btn btn-sm btn-danger"
            onClick={onDeleteGroup}
          >
            Delete
          </button>
        </div>
      </div>

      {!collapsed && (
        <div style={{ marginTop: '0.5rem' }}>
          <div
            style={{
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
              marginBottom: '0.5rem',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              {hosts.length > 0 && (
                <input
                  type="checkbox"
                  checked={allSelected}
                  ref={(el) => {
                    if (el) el.indeterminate = indeterminate;
                  }}
                  onChange={(e) => onToggleSelectAll(e.target.checked)}
                  title="Select all hosts"
                />
              )}
              <strong>Hosts</strong>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.25rem' }}>
              {selectedSet.size > 0 && (
                <>
                  {singleSelected && selectedHostObj && (
                    <>
                      <button
                        type="button"
                        className="btn btn-sm btn-secondary"
                        onClick={() => onEditHost(selectedHostObj)}
                      >
                        Edit
                      </button>
                      <button
                        type="button"
                        className="btn btn-sm btn-secondary"
                        onClick={() => onFetchSerial(selectedHostObj)}
                      >
                        Serial
                      </button>
                    </>
                  )}
                  <button
                    type="button"
                    className="btn btn-sm btn-secondary"
                    onClick={onBulkMove}
                  >
                    Move
                  </button>
                  <button
                    type="button"
                    className="btn btn-sm btn-danger"
                    onClick={onBulkDelete}
                  >
                    Delete
                  </button>
                </>
              )}
              <button
                type="button"
                className="btn btn-sm btn-primary"
                onClick={onAddHost}
              >
                + Add Host
              </button>
            </div>
          </div>

          {sortedHosts.length === 0 ? (
            <div
              style={{
                color: 'var(--text-muted)',
                padding: '0.75rem',
                textAlign: 'center',
              }}
            >
              No hosts
            </div>
          ) : (
            <div ref={scrollRef} style={{ overflow: 'auto', maxHeight: 480 }}>
              <table className="chart-table" style={{ width: '100%' }}>
                <thead
                  style={{
                    position: 'sticky',
                    top: 0,
                    zIndex: 1,
                    background: 'var(--card-bg, var(--bg-secondary))',
                  }}
                >
                  <tr>
                    <th style={{ width: 32 }}></th>
                    <th>Hostname</th>
                    <th>IP Address</th>
                    <th>Type</th>
                    <th>Model</th>
                    <th>Serial</th>
                    <th>Software</th>
                    <th style={{ width: 110 }}></th>
                  </tr>
                </thead>
                <tbody>
                  {(() => {
                    const items = rowVirtualizer.getVirtualItems();
                    const paddingTop = items.length ? items[0].start : 0;
                    const paddingBottom = items.length
                      ? rowVirtualizer.getTotalSize() - items[items.length - 1].end
                      : 0;
                    return (
                      <>
                        {paddingTop > 0 && (
                          <tr aria-hidden style={{ height: paddingTop }}>
                            <td colSpan={8} style={{ padding: 0, border: 'none' }} />
                          </tr>
                        )}
                        {items.map((vi) => {
                          const host = sortedHosts[vi.index];
                          const isMatch = query && hostMatchesQuery(host, query);
                          return (
                            <tr
                              key={host.id}
                              data-index={vi.index}
                              ref={rowVirtualizer.measureElement}
                              style={{
                                background: isMatch
                                  ? 'var(--highlight-bg, rgba(59,130,246,0.08))'
                                  : undefined,
                              }}
                            >
                              <td>
                                <input
                                  type="checkbox"
                                  checked={selectedSet.has(host.id)}
                                  onChange={(e) =>
                                    onToggleHost(host.id, e.target.checked)
                                  }
                                />
                              </td>
                              <td>{host.hostname}</td>
                              <td>{host.ip_address}</td>
                              <td>{host.device_type || 'cisco_ios'}</td>
                              <td>{host.model || '-'}</td>
                              <td>{host.serial_number || '-'}</td>
                              <td>{host.software_version || '-'}</td>
                              <td>
                                <div style={{ display: 'flex', gap: '0.25rem' }}>
                                  <button
                                    type="button"
                                    className="btn btn-sm btn-secondary"
                                    onClick={() => onEditHost(host)}
                                  >
                                    Edit
                                  </button>
                                  <button
                                    type="button"
                                    className="btn btn-sm btn-danger"
                                    onClick={() => onDeleteHost(host)}
                                  >
                                    Del
                                  </button>
                                </div>
                              </td>
                            </tr>
                          );
                        })}
                        {paddingBottom > 0 && (
                          <tr aria-hidden style={{ height: paddingBottom }}>
                            <td colSpan={8} style={{ padding: 0, border: 'none' }} />
                          </tr>
                        )}
                      </>
                    );
                  })()}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
