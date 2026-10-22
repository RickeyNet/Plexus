import { useMemo, useState } from 'react';

import {
  BULK_ADD_MAX_HOSTS,
  GROUP_PATH_SEPARATOR,
  groupLabel,
  useBulkAddHosts,
  type BulkAddHostsResult,
} from '@/api/inventory';
import { useInventoryGroupsLite, type TopologyEdge, type TopologyNode } from '@/api/topology';
import { Modal } from '@/components/Modal';
import { DEVICE_TYPES } from '@/lib/deviceTypes';

import { InventoryGroupPicker } from './InventoryGroupPicker';
import {
  buildBulkAddBody,
  buildInventoryAddRows,
  filterInventoryAddRows,
  GROUP_NAME_MAX,
  resolvedGroupPath,
  suggestedGroups,
  type BulkAddGrouping,
} from './inventoryAdd';

interface Props {
  isOpen: boolean;
  /** The nodes on the current map. */
  nodes: readonly TopologyNode[];
  /** The links on the current map (who reported each SNMP neighbor). */
  edges: readonly TopologyEdge[];
  onClose: () => void;
  /** Called after a bulk add that added at least one host. */
  onAdded: (result: BulkAddHostsResult) => void;
}

type GroupMode = BulkAddGrouping['mode'];

/**
 * Add many map devices that are not inventory hosts (CDP/LLDP neighbors,
 * external SNMP neighbors, cloud instances) to inventory, so Plexus can SSH
 * to them without re-typing them. By default each device goes into a
 * sub-group named after its site under a group named after its source
 * (`Meraki / HQ`; each level created when missing); the user can rename those
 * sub-groups, or put every device into one existing group.
 */
export function BulkAddToInventoryModal({ isOpen, nodes, edges, onClose, onAdded }: Props) {
  const groupsQuery = useInventoryGroupsLite();
  const groups = useMemo(() => groupsQuery.data ?? [], [groupsQuery.data]);
  const bulkAdd = useBulkAddHosts();

  // Meraki hardware has no CLI, so it is hidden unless asked for.
  const [showManaged, setShowManaged] = useState(false);
  const rows = useMemo(
    () => buildInventoryAddRows(nodes, DEVICE_TYPES, showManaged, edges),
    [nodes, edges, showManaged],
  );
  const [query, setQuery] = useState('');
  const shown = useMemo(() => filterInventoryAddRows(rows, query), [rows, query]);
  const [selected, setSelected] = useState<Set<string>>(() => new Set());
  const [typeChoices, setTypeChoices] = useState<Record<string, string>>({});
  const [mode, setMode] = useState<GroupMode>('auto');
  const [renames, setRenames] = useState<Record<string, string>>({});
  const [pickedGroupId, setPickedGroupId] = useState<number | null>(null);
  const groupId = pickedGroupId ?? groups[0]?.id ?? null;
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<BulkAddHostsResult | null>(null);

  const usedGroups = useMemo(() => suggestedGroups(rows, selected), [rows, selected]);
  const groupName = (id: number | null) => {
    const group = groups.find((g) => g.id === id);
    return group ? groupLabel(group) : id != null ? `#${id}` : '';
  };
  const allShownSelected = shown.length > 0 && shown.every((r) => selected.has(r.ip));
  const tooMany = selected.size > BULK_ADD_MAX_HOSTS;
  const noGroup = mode === 'single' && groupId == null;

  function toggle(ip: string) {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(ip)) next.delete(ip);
      else next.add(ip);
      return next;
    });
  }

  function toggleAllShown() {
    setSelected((prev) => {
      const next = new Set(prev);
      for (const r of shown) {
        if (allShownSelected) next.delete(r.ip);
        else next.add(r.ip);
      }
      return next;
    });
  }

  async function handleSubmit() {
    if (noGroup || selected.size === 0 || tooMany) return;
    const grouping: BulkAddGrouping =
      mode === 'single' && groupId != null ? { mode: 'single', groupId } : { mode: 'auto', renames };
    setError(null);
    try {
      const res = await bulkAdd.mutateAsync(buildBulkAddBody(rows, selected, typeChoices, grouping));
      setResult(res);
      setSelected(new Set());
      if (res.added.length) onAdded(res);
    } catch (e) {
      setError((e as Error).message);
    }
  }

  return (
    <Modal isOpen={isOpen} onClose={onClose} title="Add to Inventory" size="large">
      {result ? (
        <BulkAddSummary result={result} groupName={groupName} onDone={onClose} onBack={() => setResult(null)} />
      ) : rows.length === 0 && !showManaged ? (
        <p className="text-muted">
          Every device on the map with an IP address is already in inventory, apart from Meraki hardware.{' '}
          <button type="button" className="btn btn-sm btn-secondary" onClick={() => setShowManaged(true)}>
            Show Meraki devices
          </button>
        </p>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
          <p className="text-muted" style={{ margin: 0, fontSize: '0.85rem' }}>
            Devices on the map that are not inventory hosts. Added hosts can be reached over SSH for route
            captures, config backups and path tracing. An IP already in inventory is skipped.
          </p>
          <div>
            <label className="form-label">Group</label>
            <div style={{ display: 'flex', gap: '1rem', flexWrap: 'wrap', fontSize: '0.85rem' }}>
              <label style={{ display: 'flex', gap: '0.3rem', alignItems: 'center' }}>
                <input type="radio" name="bulk-add-group-mode" checked={mode === 'auto'} onChange={() => setMode('auto')} />
                Automatic by source and site
              </label>
              <label style={{ display: 'flex', gap: '0.3rem', alignItems: 'center' }}>
                <input type="radio" name="bulk-add-group-mode" checked={mode === 'single'} onChange={() => setMode('single')} />
                One group
              </label>
            </div>
          </div>
          {mode === 'single' ? (
            <InventoryGroupPicker groups={groups} value={groupId} onChange={setPickedGroupId} onError={setError} />
          ) : (
            <div>
              <div className="text-muted" style={{ fontSize: '0.8rem', marginBottom: '0.3rem' }}>
                {usedGroups.length
                  ? 'Groups that will be used (a group that does not exist is created; rename a sub-group before adding):'
                  : 'Each device goes into a sub-group per site under a group per source (Meraki, AWS, …), or under Discovered neighbors named after the inventory group that reported it. Select devices to see and rename their groups.'}
              </div>
              {usedGroups.length > 0 && (
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.4rem 0.75rem' }}>
                  {usedGroups.map(({ group, path, count }) => {
                    const parents = path.slice(0, -1);
                    const leaf = path[path.length - 1];
                    return (
                      <label key={group} style={{ display: 'flex', gap: '0.3rem', alignItems: 'center', fontSize: '0.8rem' }}>
                        {parents.length > 0 && (
                          <span className="text-muted">{parents.join(GROUP_PATH_SEPARATOR)}{GROUP_PATH_SEPARATOR}</span>
                        )}
                        <input
                          className="form-input"
                          aria-label={`Name of group ${group}`}
                          title={`Suggested: ${leaf}`}
                          maxLength={GROUP_NAME_MAX}
                          style={{ width: '14rem' }}
                          value={renames[group] ?? leaf}
                          onChange={(e) => setRenames((prev) => ({ ...prev, [group]: e.target.value }))}
                        />
                        <span className="text-muted">({count})</span>
                      </label>
                    );
                  })}
                </div>
              )}
            </div>
          )}
          <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap', alignItems: 'center' }}>
            <input
              className="form-input"
              type="search"
              placeholder="Filter by name, IP, platform, site or group"
              aria-label="Filter devices"
              style={{ flex: '1 1 12rem', minWidth: 0 }}
              value={query}
              onChange={(e) => setQuery(e.target.value)}
            />
            <button type="button" className="btn btn-sm btn-secondary" onClick={toggleAllShown} disabled={!shown.length}>
              {allShownSelected ? 'Clear shown' : 'Select all shown'}
            </button>
            <span className="text-muted" style={{ fontSize: '0.8rem' }}>
              {selected.size} of {rows.length} selected
            </span>
            <label style={{ display: 'flex', gap: '0.3rem', alignItems: 'center', fontSize: '0.8rem' }}>
              <input type="checkbox" checked={showManaged} onChange={(e) => setShowManaged(e.target.checked)} />
              Show Meraki devices (no CLI; ICMP only)
            </label>
          </div>
          <div style={{ overflow: 'auto', maxHeight: '50vh' }}>
            <table className="data-table" style={{ width: '100%' }}>
              <thead>
                <tr>
                  <th aria-label="Selected" />
                  <th>Label</th>
                  <th>IP</th>
                  <th>Platform</th>
                  <th>Site / group</th>
                  {mode === 'auto' && <th>Group</th>}
                  <th>Device type</th>
                </tr>
              </thead>
              <tbody>
                {shown.map((r) => (
                  <tr key={r.ip}>
                    <td>
                      <input
                        type="checkbox"
                        aria-label={`Select ${r.label}`}
                        checked={selected.has(r.ip)}
                        onChange={() => toggle(r.ip)}
                      />
                    </td>
                    <td style={{ wordBreak: 'break-word' }}>{r.label}</td>
                    <td style={{ whiteSpace: 'nowrap' }}>{r.ip}</td>
                    <td className="text-muted" style={{ wordBreak: 'break-word' }}>{r.platform || '-'}</td>
                    <td className="text-muted" style={{ wordBreak: 'break-word' }}>{r.site || '-'}</td>
                    {mode === 'auto' && (
                      <td style={{ wordBreak: 'break-word' }}>{resolvedGroupPath(r, renames).join(GROUP_PATH_SEPARATOR)}</td>
                    )}
                    <td>
                      <select
                        className="form-select"
                        aria-label={`Device type for ${r.label}`}
                        value={typeChoices[r.ip] ?? r.deviceType}
                        onChange={(e) => setTypeChoices((prev) => ({ ...prev, [r.ip]: e.target.value }))}
                      >
                        {DEVICE_TYPES.map((t) => (
                          <option key={t.value} value={t.value}>{t.label}</option>
                        ))}
                      </select>
                    </td>
                  </tr>
                ))}
                {!shown.length && (
                  <tr>
                    <td colSpan={mode === 'auto' ? 7 : 6} className="text-muted">No device matches the filter.</td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
          {tooMany && (
            <div style={{ color: 'var(--danger)' }}>
              At most {BULK_ADD_MAX_HOSTS} devices can be added at once.
            </div>
          )}
          {error && <div style={{ color: 'var(--danger)' }}>{error}</div>}
          <div style={{ display: 'flex', gap: '0.5rem', justifyContent: 'flex-end', flexWrap: 'wrap' }}>
            <button type="button" className="btn btn-secondary" onClick={onClose}>Cancel</button>
            <button
              type="button"
              className="btn btn-primary"
              onClick={handleSubmit}
              disabled={bulkAdd.isPending || noGroup || selected.size === 0 || tooMany}
            >
              {bulkAdd.isPending ? 'Adding…' : selected.size ? `Add ${selected.size} to inventory` : 'Add to inventory'}
            </button>
          </div>
        </div>
      )}
    </Modal>
  );
}

/** How many added hosts went into each group, in first-seen order. */
function addedPerGroup(result: BulkAddHostsResult): [string, number][] {
  const counts = new Map<string, number>();
  for (const h of result.added) {
    const label = h.group_path || h.group_name;
    counts.set(label, (counts.get(label) ?? 0) + 1);
  }
  return [...counts];
}

function BulkAddSummary({
  result,
  groupName,
  onDone,
  onBack,
}: {
  result: BulkAddHostsResult;
  groupName: (id: number | null) => string;
  onDone: () => void;
  onBack: () => void;
}) {
  const perGroup = addedPerGroup(result);
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
      <p style={{ margin: 0 }}>
        <strong>{result.added.length}</strong> added, <strong>{result.skipped.length}</strong> skipped,{' '}
        <strong>{result.errors.length}</strong> failed.
      </p>
      {result.groups_created.length > 0 && (
        <p style={{ margin: 0 }}>
          Created groups: {result.groups_created.map((g) => groupLabel(g)).join(', ')}
        </p>
      )}
      {perGroup.length > 0 && (
        <div>
          <div className="form-label">Added</div>
          <ul style={{ margin: 0, paddingLeft: '1.2rem' }}>
            {perGroup.map(([name, count]) => (
              <li key={`g-${name}`}>
                {name}: {count}
              </li>
            ))}
          </ul>
        </div>
      )}
      {result.skipped.length > 0 && (
        <div>
          <div className="form-label">Skipped</div>
          <ul style={{ margin: 0, paddingLeft: '1.2rem' }}>
            {result.skipped.map((s) => (
              <li key={`s-${s.ip_address}-${s.hostname}`}>
                {s.hostname} ({s.ip_address}): {s.reason}
                {s.group_id != null && ` (group ${groupName(s.group_id)})`}
              </li>
            ))}
          </ul>
        </div>
      )}
      {result.errors.length > 0 && (
        <div>
          <div className="form-label">Errors</div>
          <ul style={{ margin: 0, paddingLeft: '1.2rem', color: 'var(--danger)' }}>
            {result.errors.map((e) => (
              <li key={`e-${e.ip_address}-${e.hostname}`}>
                {e.hostname} ({e.ip_address}): {e.error}
              </li>
            ))}
          </ul>
        </div>
      )}
      <div style={{ display: 'flex', gap: '0.5rem', justifyContent: 'flex-end', flexWrap: 'wrap' }}>
        <button type="button" className="btn btn-secondary" onClick={onBack}>Add more</button>
        <button type="button" className="btn btn-primary" onClick={onDone}>Done</button>
      </div>
    </div>
  );
}
