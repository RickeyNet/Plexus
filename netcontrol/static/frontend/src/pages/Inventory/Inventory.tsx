import { useEffect, useMemo, useRef, useState } from 'react';
import { useVirtualizer } from '@tanstack/react-virtual';

import { ChangelogPanel } from '@/components/ChangelogPanel';
import { CustomDataFilter } from '@/components/CustomDataFilter';
import { DeleteButton } from '@/components/DeleteButton';
import { EmptyState } from '@/components/EmptyState';
import { ImportDialog } from '@/components/ImportDialog';
import { LoadingState } from '@/components/LoadingState';
import { ExportTemplatesMenu } from '@/components/ExportTemplatesMenu';
import { PageHeader } from '@/components/PageHeader';
import { PageHelp } from '@/components/PageHelp';
import { QueryError } from '@/components/QueryError';
import { useDialogs } from '@/components/DialogProvider-context';
import { KebabMenu, MenuItem, MenuSeparator } from '@/components/Menu';
import { Modal } from '@/components/Modal';
import { TagChip, TagChips } from '@/components/TagChips';
import { clickableProps } from '@/lib/clickable';
import { type CustomDataFilterValue, EMPTY_CUSTOM_DATA_FILTER, isEmptyFilter } from '@/lib/customData';
import { hostModelText } from '@/lib/deviceModel';
import { type FilterDraft, inventoryFilterToDraft } from '@/lib/dynamicGroupFilter';
import { READ_ONLY_GROUP_REASON, TOP_LEVEL_GROUP_REASON, useObjectScope } from '@/lib/objectScope';
import { useLinkedParam } from '@/lib/useLinkedParam';
import { bringIntoView, splitGridStyle, useWideDetail } from '@/lib/wideDetail';

import {
  groupLabel,
  type InventoryGroupFull,
  type InventoryHost,
  inventoryCsvExportUrl,
  inventoryYamlExportUrl,
  useAssignSnmpProfile,
  useBulkDeleteHosts,
  useDeleteHost,
  useDeleteInventoryGroup,
  useGroupSnmpAssignments,
  useInventoryGroupsFull,
  useReorderInventoryGroups,
  useSnmpProfiles,
} from '@/api/inventory';

import { BulkEditModal } from './BulkEditModal';
import { BulkMoveModal } from './BulkMoveModal';
import { BulkSnmpProfileModal } from './BulkSnmpProfileModal';
import { BulkTagModal } from './BulkTagModal';
import { DiscoveryModal, type DiscoveryMode } from './DiscoveryModal';
import { DynamicGroupsModal } from './DynamicGroupsModal';
import { GroupModal } from './GroupModal';
import { HostModal } from './HostModal';
import { HostPanel } from './HostPanel';
import { SerialModal, type SerialTarget } from './SerialModal';
import { SnmpProfilesModal } from './SnmpProfilesModal';
import {
  applyGroupOrder,
  filterGroups,
  filterGroupsByCustomData,
  hiddenByCollapsedAncestor,
  hostMatchesQuery,
  hostSnmpProfileName,
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
  | { kind: 'create-group'; parentId: number | null }
  | { kind: 'edit-group'; group: InventoryGroupFull }
  | { kind: 'add-host'; groupId: number }
  | {
      kind: 'edit-host';
      host: InventoryHost & { group_id: number };
    }
  | { kind: 'bulk-move'; sourceGroupId: number; hostIds: number[] }
  | { kind: 'bulk-tag'; hostIds: number[] }
  | { kind: 'bulk-edit'; hostIds: number[] }
  | { kind: 'bulk-snmp'; hostIds: number[] }
  | { kind: 'serial'; target: SerialTarget }
  | { kind: 'snmp-profiles' }
  | { kind: 'import' }
  | { kind: 'dynamic-groups'; seed: FilterDraft | null }
  | {
      kind: 'discovery';
      mode: DiscoveryMode;
      group: InventoryGroupFull | null;
    };

export function Inventory() {
  const { confirm, alert } = useDialogs();
  const objectScope = useObjectScope();
  const groupsQ = useInventoryGroupsFull(true);
  const profilesQ = useSnmpProfiles();
  const groups = useMemo(() => groupsQ.data ?? [], [groupsQ.data]);
  const groupIds = useMemo(() => groups.map((g) => g.id), [groups]);
  const assignmentsQ = useGroupSnmpAssignments(groupIds);

  const [query, setQuery] = useState('');
  const [dataFilter, setDataFilter] = useState<CustomDataFilterValue>(EMPTY_CUSTOM_DATA_FILTER);
  const [sort, setSort] = useState<InventorySort>('custom');
  const [compact, setCompact] = useState<boolean>(() => loadCompactMode());
  const [collapsed, setCollapsed] = useState<Set<number>>(() => loadCollapsedSet());
  const [modalState, setModal] = useState<ModalState>({ kind: 'none' });
  // `?open=discovery` and `?open=snmp-profiles` (the Dashboard's setup guide)
  // open that dialog once the groups have loaded; closing it drops the parameter.
  const [linkedOpen, clearLinkedOpen] = useLinkedParam('open');
  const linkedModal: ModalState | null =
    modalState.kind !== 'none' || !groupsQ.data
      ? null
      : linkedOpen === 'discovery'
        ? { kind: 'discovery', mode: 'global', group: null }
        : linkedOpen === 'snmp-profiles'
          ? { kind: 'snmp-profiles' }
          : null;
  const modal = linkedModal ?? modalState;
  const [selectedHosts, setSelectedHosts] = useState<Map<number, Set<number>>>(
    new Map(),
  );
  const [orderOverride, setOrderOverride] = useState<number[] | null>(null);
  // The host whose details panel is open (by group, as a host can be listed in several).
  const [openHost, setOpenHost] = useState<{ groupId: number; hostId: number } | null>(null);
  const [wide, toggleWide] = useWideDetail();
  const panelRef = useRef<HTMLDivElement>(null);

  const openGroup = openHost ? groups.find((g) => g.id === openHost.groupId) : undefined;
  const openHostRow = openHost ? openGroup?.hosts?.find((h) => h.id === openHost.hostId) : undefined;
  const openHostDetails = (groupId: number, hostId: number) => {
    setOpenHost({ groupId, hostId });
    // Widened, the panel sits above the groups: bring it into view.
    if (wide) requestAnimationFrame(() => bringIntoView(panelRef.current));
  };

  const reorder = useReorderInventoryGroups();
  const deleteGroup = useDeleteInventoryGroup();
  const deleteHost = useDeleteHost();
  const bulkDelete = useBulkDeleteHosts();
  const assignProfile = useAssignSnmpProfile();

  // Persist UI prefs.
  useEffect(() => saveCompactMode(compact), [compact]);
  useEffect(() => saveCollapsedSet(collapsed), [collapsed]);

  // Apply user drag order before filter/sort. The order applies among
  // siblings; the listing stays a tree (sub-groups under their parent).
  const orderedGroups = useMemo(
    () => (orderOverride ? applyGroupOrder(groups, orderOverride) : groups),
    [groups, orderOverride],
  );

  // The text search and the tag / custom field filter both apply.
  const filtered = useMemo(
    () => sortGroups(filterGroupsByCustomData(filterGroups(orderedGroups, query), dataFilter), sort),
    [orderedGroups, query, dataFilter, sort],
  );
  const hasDataFilter = !isEmptyFilter(dataFilter);
  // The filter hides hosts, so a selection made before it could act on
  // hosts no longer shown: start the selection over.
  const changeDataFilter = (next: CustomDataFilterValue) => {
    setDataFilter(next);
    setSelectedHosts(new Map());
  };
  // A collapsed group hides its sub-groups as well as its hosts.
  const hiddenIds = useMemo(() => hiddenByCollapsedAncestor(filtered, collapsed), [filtered, collapsed]);
  const visible = useMemo(() => filtered.filter((g) => !hiddenIds.has(g.id)), [filtered, hiddenIds]);
  const parentOf = useMemo(() => new Map(groups.map((g) => [g.id, g.parent_id ?? null])), [groups]);
  const subGroupCounts = useMemo(() => {
    const counts = new Map<number, number>();
    for (const g of filtered) {
      if (g.parent_id != null) counts.set(g.parent_id, (counts.get(g.parent_id) ?? 0) + 1);
    }
    return counts;
  }, [filtered]);

  const isCustomOrder = sort === 'custom' && !query.trim() && !hasDataFilter;

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
  // Groups reorder among their siblings only; a move to another parent is
  // made in the group's Edit dialog.
  const areSiblings = (a: number, b: number) => parentOf.get(a) === parentOf.get(b);
  const onDragOver = (e: React.DragEvent, overId: number) => {
    if (!isCustomOrder) return;
    if (dragIdRef.current == null || dragIdRef.current === overId) return;
    if (!areSiblings(dragIdRef.current, overId)) return;
    e.preventDefault();
  };
  const onDrop = (overId: number) => {
    if (!isCustomOrder) return;
    const dragId = dragIdRef.current;
    dragIdRef.current = null;
    if (dragId == null || dragId === overId || !areSiblings(dragId, overId)) return;
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
      onError: (err) => {
        void alert({
          message: `Failed to save group order: ${(err as Error).message}`,
          variant: 'error',
        });
      },
    });
  };

  const handleDeleteGroup = async (g: InventoryGroupFull) => {
    if (
      !(await confirm({
        title: 'Delete group',
        message: `Delete group "${groupLabel(g)}"? This will remove the group and all its hosts. This cannot be undone.`,
        confirmLabel: 'Delete',
      }))
    )
      return;
    deleteGroup.mutate(g.id, {
      onError: (err) => {
        void alert({ message: (err as Error).message, variant: 'error' });
      },
    });
  };

  const handleDeleteHost = async (host: InventoryHost) => {
    if (
      !(await confirm({
        title: 'Delete host',
        message: `Delete host "${host.hostname}"? This will permanently remove this host from the inventory.`,
        confirmLabel: 'Delete',
      }))
    )
      return;
    deleteHost.mutate(host.id, {
      onError: (err) => {
        void alert({ message: (err as Error).message, variant: 'error' });
      },
    });
  };

  const handleBulkDelete = async (groupId: number) => {
    const ids = Array.from(selectedHosts.get(groupId) ?? []);
    if (!ids.length) return;
    if (
      !(await confirm({
        title: 'Delete hosts',
        message: `Delete ${ids.length} host(s)? This cannot be undone.`,
        confirmLabel: 'Delete',
      }))
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
      onError: (err) => {
        void alert({ message: (err as Error).message, variant: 'error' });
      },
    });
  };

  const exportCsv = () => {
    window.open(inventoryCsvExportUrl(), '_blank');
  };

  const closeModal = () => {
    setModal({ kind: 'none' });
    if (linkedOpen !== null) clearLinkedOpen();
  };

  return (
    <div>
      <PageHeader title="Inventory">
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
          onClick={() => setModal({ kind: 'dynamic-groups', seed: null })}
        >
          Dynamic Groups
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
        <a className="btn btn-sm btn-secondary" href={inventoryYamlExportUrl()} download>
          Export YAML
        </a>
        <ExportTemplatesMenu objectType="host" label="Export template" />
        <button
          type="button"
          className="btn btn-sm btn-secondary"
          onClick={() => setModal({ kind: 'import' })}
          title="Add or update hosts and groups from a CSV, YAML or JSON file"
        >
          Import
        </button>
        <button
          type="button"
          className="btn btn-sm btn-primary"
          onClick={() => setModal({ kind: 'create-group', parentId: null })}
          disabled={objectScope.restricted}
          title={objectScope.restricted ? TOP_LEVEL_GROUP_REASON : undefined}
        >
          + New Group
        </button>
      </PageHeader>

      <PageHelp
        guide="Core-Concepts"
        pageKey="inventory"
        title="Manage Your Devices"
        text="Add, edit, and organize network devices into groups. Devices added here are used across monitoring, backups, compliance, and automation features."
      />

      <div className="card card-sm toolbar">
        <input
          className="form-input form-input-sm"
          placeholder="Search groups, hosts, IPs…"
          aria-label="Search inventory"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          style={{ maxWidth: 280, flex: '1 1 200px' }}
        />
        <CustomDataFilter objectType="host" value={dataFilter} onChange={changeDataFilter} deviceFacets />
        {(hasDataFilter || query.trim() !== '') && !objectScope.restricted && (
          <button
            type="button"
            className="btn btn-sm btn-secondary"
            onClick={() => setModal({ kind: 'dynamic-groups', seed: inventoryFilterToDraft(dataFilter, query) })}
            title="Save the search and filter as a dynamic group (hostname or IP for the search)"
          >
            Save as dynamic group
          </button>
        )}
        <select
          className="form-select form-select-sm"
          value={sort}
          onChange={(e) => setSort(e.target.value as InventorySort)}
          style={{ maxWidth: 200 }}
          title="Sort"
          aria-label="Sort groups"
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

      {groupsQ.isError && !groupsQ.data ? (
        <QueryError what="inventory" query={groupsQ} />
      ) : (
        groupsQ.isPending && <LoadingState text="Loading inventory…" />
      )}
      {profilesQ.isError && !profilesQ.data && (
        <QueryError what="SNMP profiles" query={profilesQ} />
      )}
      {assignmentsQ.isError && !assignmentsQ.data && (
        <QueryError what="SNMP profile assignments" query={assignmentsQ} />
      )}
      <div style={openGroup && openHostRow ? splitGridStyle(wide) : undefined}>
      {openGroup && openHostRow && (
        <div
          ref={panelRef}
          className="card"
          style={{
            minWidth: 0,
            order: wide ? 0 : 1,
            scrollMarginTop: 'var(--space-4)',
            // Beside the groups it stays in view while they scroll.
            ...(wide ? {} : { position: 'sticky', top: 'var(--space-4)', maxHeight: 'calc(100vh - 2 * var(--space-4))', overflowY: 'auto' }),
          }}
        >
          <HostPanel
            key={`${openGroup.id}-${openHostRow.id}`}
            host={openHostRow}
            groupName={groupLabel(openGroup)}
            canWrite={objectScope.canWriteGroup(openGroup.id)}
            wide={wide}
            onToggleWide={toggleWide}
            onEdit={() => setModal({ kind: 'edit-host', host: { ...openHostRow, group_id: openGroup.id } })}
            onClose={() => setOpenHost(null)}
          />
        </div>
      )}
      <div className="stack stack-sm" style={{ minWidth: 0, order: 1 }}>
        {groupsQ.data && filtered.length === 0 && hasDataFilter && (
          <div className="card">
            <EmptyState
              message="No groups or hosts match this filter."
              description={query ? 'The search box narrows the list as well.' : undefined}
              action={
                <button type="button" className="btn btn-sm btn-secondary" onClick={() => changeDataFilter(EMPTY_CUSTOM_DATA_FILTER)}>
                  Clear filter
                </button>
              }
            />
          </div>
        )}
        {groupsQ.data && filtered.length === 0 && !hasDataFilter && (
          <div
            className="card"
            style={{ padding: '1.5rem', textAlign: 'center', color: 'var(--text-muted)' }}
          >
            {query ? 'No groups match your search.' : 'No inventory groups. Click "+ New Group" to create one.'}
          </div>
        )}

        {visible.map((group) => (
          <GroupCard
            key={group.id}
            group={group}
            canWrite={objectScope.canWriteGroup(group.id)}
            subGroupCount={subGroupCounts.get(group.id) ?? 0}
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
                {
                  onError: (e) => {
                    void alert({ message: (e as Error).message, variant: 'error' });
                  },
                },
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
            onAddSubGroup={() => setModal({ kind: 'create-group', parentId: group.id })}
            onDeleteGroup={() => handleDeleteGroup(group)}
            onSyncDiscovery={() =>
              setModal({ kind: 'discovery', mode: 'sync', group })
            }
            onBulkSerial={() =>
              setModal({
                kind: 'serial',
                target: { mode: 'bulk', groupId: group.id, groupName: groupLabel(group) },
              })
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
                kind: 'serial',
                target: { mode: 'single', hostId: host.id, hostname: host.hostname },
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
            onBulkTag={() => {
              const ids = Array.from(selectedHosts.get(group.id) ?? []);
              if (ids.length) setModal({ kind: 'bulk-tag', hostIds: ids });
            }}
            onBulkEdit={() => {
              const ids = Array.from(selectedHosts.get(group.id) ?? []);
              if (ids.length) setModal({ kind: 'bulk-edit', hostIds: ids });
            }}
            onBulkSnmpProfile={() => {
              const ids = Array.from(selectedHosts.get(group.id) ?? []);
              if (ids.length) setModal({ kind: 'bulk-snmp', hostIds: ids });
            }}
            openHostId={openHost?.groupId === group.id ? openHost.hostId : null}
            onOpenHost={(host) => openHostDetails(group.id, host.id)}
          />
        ))}
      </div>
      </div>

      {modal.kind === 'create-group' && (
        <GroupModal group={null} isCreate groups={groups} defaultParentId={modal.parentId} onClose={closeModal} />
      )}
      {modal.kind === 'edit-group' && (
        <GroupModal group={modal.group} isCreate={false} groups={groups} onClose={closeModal} />
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
      {modal.kind === 'bulk-tag' && (
        <BulkTagModal hostIds={modal.hostIds} onClose={closeModal} />
      )}
      {modal.kind === 'bulk-edit' && (
        <BulkEditModal hostIds={modal.hostIds} onClose={closeModal} />
      )}
      {modal.kind === 'bulk-snmp' && (
        <BulkSnmpProfileModal hostIds={modal.hostIds} onClose={closeModal} />
      )}
      {modal.kind === 'serial' && (
        <SerialModal target={modal.target} onClose={closeModal} />
      )}
      {modal.kind === 'snmp-profiles' && (
        <SnmpProfilesModal onClose={closeModal} />
      )}
      {modal.kind === 'import' && <ImportDialog types={['hosts', 'groups']} onClose={closeModal} />}
      {modal.kind === 'dynamic-groups' && (
        <DynamicGroupsModal groups={groups} seed={modal.seed} onClose={closeModal} />
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
  /** The account may change this group (object-level permissions); when
   * false every write control is disabled with the reason. */
  canWrite: boolean;
  /** Sub-groups shown under this group (hidden with it when collapsed). */
  subGroupCount: number;
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
  onAddSubGroup: () => void;
  onDeleteGroup: () => void;
  onSyncDiscovery: () => void;
  onBulkSerial: () => void;
  onAddHost: () => void;
  onEditHost: (host: InventoryHost) => void;
  onDeleteHost: (host: InventoryHost) => void;
  onFetchSerial: (host: InventoryHost) => void;
  onBulkMove: () => void;
  onBulkDelete: () => void;
  onBulkTag: () => void;
  onBulkEdit: () => void;
  onBulkSnmpProfile: () => void;
  /** The host whose details panel is open, marked on its row. */
  openHostId?: number | null;
  /** A row click opens the host's details; without it rows are not clickable. */
  onOpenHost?: (host: InventoryHost) => void;
}

/** How far each level of sub-groups is indented. */
const GROUP_INDENT_REM = 1.5;

export function GroupCard({
  group,
  canWrite,
  subGroupCount,
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
  onAddSubGroup,
  onDeleteGroup,
  onSyncDiscovery,
  onBulkSerial,
  onAddHost,
  onEditHost,
  onDeleteHost,
  onFetchSerial,
  onBulkMove,
  onBulkDelete,
  onBulkTag,
  onBulkEdit,
  onBulkSnmpProfile,
  openHostId = null,
  onOpenHost,
}: GroupCardProps) {
  const hosts = group.hosts ?? [];
  const sortedHosts = sortHostsForQuery(hosts, query);
  // Write controls of a group the account may only read: disabled, with why.
  const readOnly = !canWrite;
  const readOnlyTitle = readOnly ? READ_ONLY_GROUP_REASON : undefined;
  const [showChanges, setShowChanges] = useState(false);

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
      className="card card-sm"
      draggable={draggable}
      onDragStart={onDragStart}
      onDragOver={onDragOver}
      onDrop={(e) => {
        e.preventDefault();
        onDrop();
      }}
      style={{
        marginLeft: `${(group.depth ?? 0) * GROUP_INDENT_REM}rem`,
        padding: compact ? 'var(--space-2) var(--space-3)' : undefined,
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
          {...clickableProps(onToggleCollapse)}
          aria-expanded={!collapsed}
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
            <div style={{ fontWeight: 600 }} title={groupLabel(group)}>
              {group.name}{' '}
              <span style={{ color: 'var(--text-muted)', fontWeight: 400 }}>
                ({hosts.length}
                {subGroupCount > 0 &&
                  `, ${subGroupCount} sub-group${subGroupCount === 1 ? '' : 's'}`}
                )
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
            {group.tags && group.tags.length > 0 && (
              <div style={{ marginTop: 'var(--space-1)' }}>
                <TagChips tags={group.tags} max={3} />
              </div>
            )}
          </div>
        </div>
        <div
          className="toolbar"
          style={{ gap: 'var(--space-1)', marginBottom: 0, flexShrink: 0 }}
        >
          <select
            className="form-select form-select-sm"
            style={{ minWidth: 130 }}
            value={assignedProfileId}
            onChange={(e) => onAssignProfile(e.target.value)}
            disabled={readOnly}
            title={readOnlyTitle ?? "The group's SNMP profile; a host's own profile overrides it"}
            aria-label={`SNMP profile for ${groupLabel(group)}`}
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
            disabled={readOnly}
            title={readOnlyTitle}
          >
            Sync
          </button>
          <KebabMenu label={`Actions for ${groupLabel(group)}`}>
            <MenuItem onSelect={onBulkSerial} disabled={readOnly} title={readOnlyTitle}>
              Fetch Serials
            </MenuItem>
            <MenuItem onSelect={onEditGroup} disabled={readOnly} title={readOnlyTitle}>
              Edit
            </MenuItem>
            <MenuItem onSelect={onAddSubGroup} disabled={readOnly} title={readOnlyTitle}>
              New Sub-group
            </MenuItem>
            <MenuItem onSelect={() => setShowChanges(true)}>Changelog</MenuItem>
            <MenuSeparator />
            <MenuItem danger onSelect={onDeleteGroup} disabled={readOnly} title={readOnlyTitle}>
              Delete
            </MenuItem>
          </KebabMenu>
        </div>
      </div>

      {!collapsed && (
        <div style={{ marginTop: '0.5rem' }}>
          <div
            style={{
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
              flexWrap: 'wrap',
              gap: '0.5rem',
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
                  aria-label={`Select all hosts in ${groupLabel(group)}`}
                />
              )}
              <strong>Hosts</strong>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', flexWrap: 'wrap', gap: '0.25rem' }}>
              {selectedSet.size > 0 && (
                <>
                  {singleSelected && selectedHostObj && (
                    <button
                      type="button"
                      className="btn btn-sm btn-secondary"
                      onClick={() => onFetchSerial(selectedHostObj)}
                      disabled={readOnly}
                      title={readOnlyTitle}
                    >
                      Serial
                    </button>
                  )}
                  <button
                    type="button"
                    className="btn btn-sm btn-secondary"
                    onClick={onBulkMove}
                    disabled={readOnly}
                    title={readOnlyTitle}
                  >
                    Move
                  </button>
                  <button
                    type="button"
                    className="btn btn-sm btn-secondary"
                    onClick={onBulkTag}
                    disabled={readOnly}
                    title={readOnlyTitle}
                  >
                    Tag…
                  </button>
                  <button
                    type="button"
                    className="btn btn-sm btn-secondary"
                    onClick={onBulkEdit}
                    disabled={readOnly}
                    title={readOnlyTitle}
                  >
                    Edit…
                  </button>
                  <button
                    type="button"
                    className="btn btn-sm btn-secondary"
                    onClick={onBulkSnmpProfile}
                    disabled={readOnly}
                    title={readOnlyTitle}
                  >
                    Set SNMP…
                  </button>
                  <DeleteButton onClick={onBulkDelete} disabled={readOnly} title={readOnlyTitle} />
                </>
              )}
              <button
                type="button"
                className="btn btn-sm btn-primary"
                onClick={onAddHost}
                disabled={readOnly}
                title={readOnlyTitle}
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
              <table className="data-table">
                <thead
                  style={{
                    position: 'sticky',
                    top: 0,
                    zIndex: 1,
                    background: 'var(--card-bg)',
                  }}
                >
                  <tr>
                    <th style={{ width: 32 }}></th>
                    <th>Hostname</th>
                    <th>IP Address</th>
                    <th>Platform</th>
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
                          const ownSnmpProfile = hostSnmpProfileName(host, snmpProfiles);
                          return (
                            <tr
                              key={host.id}
                              data-index={vi.index}
                              ref={rowVirtualizer.measureElement}
                              className={
                                onOpenHost
                                  ? `row-clickable${openHostId === host.id ? ' row-selected' : ''}`
                                  : undefined
                              }
                              aria-current={openHostId === host.id ? 'true' : undefined}
                              title={onOpenHost ? "Show the host's details" : undefined}
                              {...(onOpenHost ? clickableProps(() => onOpenHost(host), { role: null }) : {})}
                              style={{
                                background: isMatch
                                  ? 'var(--primary-soft)'
                                  : undefined,
                              }}
                            >
                              {/* The checkbox and buttons do their own thing, not open the panel. */}
                              <td onClick={(e) => e.stopPropagation()}>
                                <input
                                  type="checkbox"
                                  checked={selectedSet.has(host.id)}
                                  onChange={(e) =>
                                    onToggleHost(host.id, e.target.checked)
                                  }
                                  aria-label={`Select ${host.hostname}`}
                                />
                              </td>
                              <td>
                                {host.hostname}
                                {(host.role || host.lifecycle_status || ownSnmpProfile) && (
                                  <div style={{ marginTop: 'var(--space-1)' }}>
                                    <span className="tag-chips">
                                      {host.role && (
                                        <TagChip color={host.role.color} title="Role">
                                          <span className="sr-only">Role: </span>
                                          {host.role.name}
                                        </TagChip>
                                      )}
                                      {host.lifecycle_status && (
                                        <TagChip color={host.lifecycle_status.color} title="Lifecycle status">
                                          <span className="sr-only">Lifecycle status: </span>
                                          {host.lifecycle_status.name}
                                        </TagChip>
                                      )}
                                      {ownSnmpProfile && (
                                        <TagChip color={null} title="This host's own SNMP profile (overrides the group's)">
                                          SNMP: {ownSnmpProfile}
                                        </TagChip>
                                      )}
                                    </span>
                                  </div>
                                )}
                                {host.tags && host.tags.length > 0 && (
                                  <div style={{ marginTop: 'var(--space-1)' }}>
                                    <TagChips tags={host.tags} max={3} />
                                  </div>
                                )}
                              </td>
                              <td>{host.ip_address}</td>
                              <td>{host.device_type || 'cisco_ios'}</td>
                              <td title={host.hardware && host.model ? `Discovered model: ${host.model}` : undefined}>
                                {hostModelText(host)}
                              </td>
                              <td>
                                {host.serial_number || '-'}
                                {host.aws_instance_id && (
                                  <div
                                    className="text-muted"
                                    style={{ fontSize: '0.78rem' }}
                                    title="AWS instance ID"
                                  >
                                    {host.aws_instance_id}
                                  </div>
                                )}
                              </td>
                              <td>{host.software_version || '-'}</td>
                              <td onClick={(e) => e.stopPropagation()}>
                                <div style={{ display: 'flex', gap: '0.25rem' }}>
                                  <button
                                    type="button"
                                    className="btn btn-sm btn-secondary"
                                    onClick={() => onEditHost(host)}
                                    disabled={readOnly}
                                    title={readOnlyTitle}
                                  >
                                    Edit
                                  </button>
                                  <DeleteButton
                                    onClick={() => onDeleteHost(host)}
                                    disabled={readOnly}
                                    title={readOnlyTitle}
                                  />
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
      {showChanges && (
        <Modal isOpen onClose={() => setShowChanges(false)} title={`Changelog: ${groupLabel(group)}`} size="large">
          <ChangelogPanel objectType="group" objectId={group.id} title={null} />
        </Modal>
      )}
    </div>
  );
}
