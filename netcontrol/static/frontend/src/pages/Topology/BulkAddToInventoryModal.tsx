import { useId, useMemo, useRef, useState, type ReactNode } from 'react';

import {
  BULK_ADD_MAX_HOSTS,
  GROUP_PATH_SEPARATOR,
  groupLabel,
  useBulkAddHosts,
  type BulkAddHostsResult,
  type BulkAddRun,
  useInventoryGroups,
} from '@/api/inventory';
import { type TopologyEdge, type TopologyNode } from '@/api/topology';
import { Callout } from '@/components/Callout';
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

/** Table rows drawn at a time: a map of thousands of devices stays responsive. */
const ROWS_PER_PAGE = 250;
/** Entries listed per section of the summary. */
const SUMMARY_LIST_MAX = 100;

/**
 * Add many map devices that are not inventory hosts (CDP/LLDP neighbors,
 * external SNMP neighbors, cloud instances) to inventory, so Plexus can SSH
 * to them without re-typing them. By default each device goes into a
 * sub-group named after its site under a group named after its source
 * (`Meraki / HQ`; each level created when missing); the user can rename those
 * sub-groups, or put every device into one existing group. Any number of
 * devices can be added: they are sent BULK_ADD_MAX_HOSTS at a time, with
 * progress and a stop between requests. A device inventory already has
 * (same AWS instance, serial, address or name) is skipped, not duplicated.
 */
export function BulkAddToInventoryModal({ isOpen, nodes, edges, onClose, onAdded }: Props) {
  const fid = useId();
  const groupsQuery = useInventoryGroups();
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
  const [rowLimit, setRowLimit] = useState(ROWS_PER_PAGE);
  const drawn = useMemo(() => shown.slice(0, rowLimit), [shown, rowLimit]);
  const [selected, setSelected] = useState<Set<string>>(() => new Set());
  const [typeChoices, setTypeChoices] = useState<Record<string, string>>({});
  const [mode, setMode] = useState<GroupMode>('auto');
  const [renames, setRenames] = useState<Record<string, string>>({});
  const [pickedGroupId, setPickedGroupId] = useState<number | null>(null);
  const groupId = pickedGroupId ?? groups[0]?.id ?? null;
  const [error, setError] = useState<string | null>(null);
  const [run, setRun] = useState<BulkAddRun | null>(null);
  const [progress, setProgress] = useState<{ done: number; total: number } | null>(null);
  const stopRequested = useRef(false);

  const usedGroups = useMemo(() => suggestedGroups(rows, selected), [rows, selected]);
  const groupName = (id: number | null) => {
    const group = groups.find((g) => g.id === id);
    return group ? groupLabel(group) : id != null ? `#${id}` : '';
  };
  const allShownSelected = shown.length > 0 && shown.every((r) => selected.has(r.ip));
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
    if (noGroup || selected.size === 0) return;
    const grouping: BulkAddGrouping =
      mode === 'single' && groupId != null ? { mode: 'single', groupId } : { mode: 'auto', renames };
    const body = buildBulkAddBody(rows, selected, typeChoices, grouping);
    setError(null);
    stopRequested.current = false;
    setProgress({ done: 0, total: body.hosts.length });
    try {
      const res = await bulkAdd.mutateAsync({
        body,
        onProgress: (done, total) => setProgress({ done, total }),
        shouldStop: () => stopRequested.current,
      });
      setRun(res);
      // Devices not sent (stopped, or a request failed) stay selected for the next run.
      const sent = new Set(body.hosts.slice(0, res.attempted).map((h) => h.ip_address));
      setSelected((prev) => new Set([...prev].filter((ip) => !sent.has(ip))));
      if (res.result.added.length) onAdded(res.result);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setProgress(null);
    }
  }

  return (
    <Modal
      isOpen={isOpen}
      onClose={onClose}
      title="Add to Inventory"
      size="large"
      footer={
        run ? (
          <>
            <button type="button" className="btn btn-secondary" onClick={() => setRun(null)}>
              {selected.size ? `Review the other ${selected.size}` : 'Add more'}
            </button>
            <button type="button" className="btn btn-primary" onClick={onClose}>Done</button>
          </>
        ) : progress ? (
          <button
            type="button"
            className="btn btn-secondary"
            onClick={() => {
              stopRequested.current = true;
            }}
            disabled={progress.total <= BULK_ADD_MAX_HOSTS}
            title="Stop once the batch being added is done"
          >
            Stop after this batch
          </button>
        ) : rows.length === 0 && !showManaged ? undefined : (
          <>
            <button type="button" className="btn btn-secondary" onClick={onClose}>Cancel</button>
            <button
              type="button"
              className="btn btn-primary"
              onClick={handleSubmit}
              disabled={bulkAdd.isPending || noGroup || selected.size === 0}
            >
              {selected.size ? `Add ${selected.size} to inventory` : 'Add to inventory'}
            </button>
          </>
        )
      }
    >
      {run ? (
        <BulkAddSummary run={run} groupName={groupName} />
      ) : progress ? (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }} aria-live="polite">
          <p style={{ margin: 0 }}>
            Adding {progress.done} of {progress.total} devices…
          </p>
          <progress max={progress.total} value={progress.done} style={{ width: '100%' }} />
          {progress.total > BULK_ADD_MAX_HOSTS && (
            <p className="text-muted" style={{ margin: 0, fontSize: '0.85rem' }}>
              Sent {BULK_ADD_MAX_HOSTS} at a time. Stopping ends the run after the current batch; the devices not sent
              stay selected.
            </p>
          )}
        </div>
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
            captures, config backups and path tracing. A device already in inventory (same AWS instance, serial,
            IP or interface address, or name) is skipped, so nothing is added twice. Any number can be added; they
            are sent {BULK_ADD_MAX_HOSTS} at a time.
          </p>
          <div>
            <span className="form-label" id={`${fid}-group-mode`}>Group</span>
            <div
              role="radiogroup"
              aria-labelledby={`${fid}-group-mode`}
              style={{ display: 'flex', gap: '1rem', flexWrap: 'wrap', fontSize: '0.85rem' }}
            >
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
          <div className="toolbar" style={{ marginBottom: 0 }}>
            <input
              className="form-input form-input-sm"
              type="search"
              placeholder="Filter by name, IP, platform, site or group"
              aria-label="Filter devices"
              style={{ flex: '1 1 12rem', minWidth: 0 }}
              value={query}
              onChange={(e) => {
                setQuery(e.target.value);
                setRowLimit(ROWS_PER_PAGE);
              }}
            />
            <button type="button" className="btn btn-sm btn-secondary" onClick={toggleAllShown} disabled={!shown.length}>
              {allShownSelected ? `Clear all ${shown.length} matching` : `Select all ${shown.length} matching`}
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
            <table className="data-table">
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
                {drawn.map((r) => (
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
          {shown.length > drawn.length && (
            <div style={{ display: 'flex', gap: '0.75rem', alignItems: 'center', fontSize: '0.8rem' }}>
              <span className="text-muted">
                Showing {drawn.length} of {shown.length}. Select all matching ticks every one, shown or not.
              </span>
              <button
                type="button"
                className="btn btn-sm btn-secondary"
                onClick={() => setRowLimit((n) => n + ROWS_PER_PAGE)}
              >
                Show {Math.min(ROWS_PER_PAGE, shown.length - drawn.length)} more
              </button>
            </div>
          )}
          {error && <Callout tone="danger">{error}</Callout>}
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

/** The first SUMMARY_LIST_MAX items, then a line naming how many more there are. */
function Capped<T>({ items, render }: { items: readonly T[]; render: (item: T) => ReactNode }) {
  return (
    <>
      {items.slice(0, SUMMARY_LIST_MAX).map(render)}
      {items.length > SUMMARY_LIST_MAX && <li className="text-muted">…and {items.length - SUMMARY_LIST_MAX} more</li>}
    </>
  );
}

function BulkAddSummary({ run, groupName }: { run: BulkAddRun; groupName: (id: number | null) => string }) {
  const { result } = run;
  const perGroup = addedPerGroup(result);
  const unsent = run.total - run.attempted;
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
      <p style={{ margin: 0 }}>
        <strong>{result.added.length}</strong> added, <strong>{result.skipped.length}</strong> skipped,{' '}
        <strong>{result.errors.length}</strong> failed.
      </p>
      {run.error && (
        <Callout tone="danger">
          Adding stopped after {run.attempted} of {run.total} devices: {run.error}. The {unsent} not sent are still
          selected.
        </Callout>
      )}
      {run.stopped && (
        <Callout tone="warning">
          Stopped after {run.attempted} of {run.total} devices. The {unsent} not sent are still selected.
        </Callout>
      )}
      {result.groups_created.length > 0 && (
        <p style={{ margin: 0 }}>
          Created groups: {result.groups_created.map((g) => groupLabel(g)).join(', ')}
        </p>
      )}
      {perGroup.length > 0 && (
        <div>
          <div className="form-label">Added</div>
          <ul style={{ margin: 0, paddingLeft: '1.2rem' }}>
            <Capped
              items={perGroup}
              render={([name, count]) => (
                <li key={`g-${name}`}>
                  {name}: {count}
                </li>
              )}
            />
          </ul>
        </div>
      )}
      {result.skipped.length > 0 && (
        <div>
          <div className="form-label">Skipped</div>
          <ul style={{ margin: 0, paddingLeft: '1.2rem' }}>
            <Capped
              items={result.skipped}
              render={(s) => (
                <li key={`s-${s.ip_address}-${s.hostname}`}>
                  {s.hostname} ({s.ip_address}): {s.reason}
                  {s.group_id != null && ` (group ${groupName(s.group_id)})`}
                </li>
              )}
            />
          </ul>
        </div>
      )}
      {result.errors.length > 0 && (
        <div>
          <div className="form-label">Errors</div>
          <ul style={{ margin: 0, paddingLeft: '1.2rem', color: 'var(--danger)' }}>
            <Capped
              items={result.errors}
              render={(e) => (
                <li key={`e-${e.ip_address}-${e.hostname}`}>
                  {e.hostname} ({e.ip_address}): {e.error}
                </li>
              )}
            />
          </ul>
        </div>
      )}
    </div>
  );
}
