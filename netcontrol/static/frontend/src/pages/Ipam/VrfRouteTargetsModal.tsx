import { useState } from 'react';

import { useDcimList } from '@/api/dcim';
import { type VrfDetail, type VrfRouteTargets, useSetVrfRouteTargets } from '@/api/networkObjects';
import { SaveFailure } from '@/components/CatalogueParts';
import { DataTable } from '@/components/DataTable';
import { EmptyState } from '@/components/EmptyState';
import { LoadingState } from '@/components/LoadingState';
import { Modal } from '@/components/Modal';
import { ModalActions } from '@/components/ModalActions';
import { runSave } from '@/lib/recordSave';

import { DetailSection } from './NetworkObjectParts';

const idsOf = (rts: VrfRouteTargets | undefined, side: 'import' | 'export') => new Set((rts?.[side] ?? []).map((r) => r.id));

/** Picks the route targets a VRF imports and exports from every route target. */
export function VrfRouteTargetsModal({ vrf, onClose }: { vrf: VrfDetail; onClose: () => void }) {
  const all = useDcimList('route_target');
  const save = useSetVrfRouteTargets();
  const [imports, setImports] = useState(() => idsOf(vrf.route_targets, 'import'));
  const [exports, setExports] = useState(() => idsOf(vrf.route_targets, 'export'));
  const [failure, setFailure] = useState<string | null>(null);

  const toggle = (set: Set<number>, update: (next: Set<number>) => void, id: number) => {
    const next = new Set(set);
    if (next.has(id)) next.delete(id);
    else next.add(id);
    update(next);
  };

  const submit = () =>
    void runSave(
      () => save.mutateAsync({ vrfId: vrf.id, importIds: [...imports], exportIds: [...exports] }),
      null,
      setFailure,
      onClose,
    );

  const rows = all.data ?? [];
  return (
    <Modal
      isOpen
      onClose={onClose}
      size="small"
      title={`Route targets of VRF ${vrf.name}`}
      footer={
        <ModalActions
          onClose={onClose}
          primaryLabel="Save route targets"
          primaryBusy={save.isPending}
          primaryBusyLabel="Saving…"
          onPrimary={submit}
        />
      }
    >
      <SaveFailure what="route targets" message={failure} />
      {all.isPending ? (
        <LoadingState text="Loading route targets…" />
      ) : rows.length === 0 ? (
        <EmptyState compact message="No route targets yet." description="Add them on the Route targets tab first." />
      ) : (
        <DataTable compact aria-label="Route targets" maxHeight={360}>
          <thead>
            <tr>
              <th>Route target</th>
              <th>Import</th>
              <th>Export</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((r) => (
              <tr key={r.id}>
                <td>{String(r.name)}</td>
                <td>
                  <input
                    type="checkbox"
                    aria-label={`Import ${String(r.name)}`}
                    checked={imports.has(r.id)}
                    onChange={() => toggle(imports, setImports, r.id)}
                  />
                </td>
                <td>
                  <input
                    type="checkbox"
                    aria-label={`Export ${String(r.name)}`}
                    checked={exports.has(r.id)}
                    onChange={() => toggle(exports, setExports, r.id)}
                  />
                </td>
              </tr>
            ))}
          </tbody>
        </DataTable>
      )}
    </Modal>
  );
}

/** The VRF detail's route target list, with the editor for admins. */
export function VrfRouteTargetsSection({ vrf, canEdit }: { vrf: VrfDetail; canEdit: boolean }) {
  const [editing, setEditing] = useState(false);
  const rts = vrf.route_targets ?? { import: [], export: [] };
  const rows = [
    ...rts.import.map((r) => ({ ...r, direction: 'Import' })),
    ...rts.export.map((r) => ({ ...r, direction: 'Export' })),
  ];
  return (
    <div>
      <DetailSection title="Route targets" count={rows.length} empty="The VRF imports and exports no route target.">
        <DataTable compact aria-label={`Route targets of VRF ${vrf.name}`} maxHeight={240}>
          <thead>
            <tr>
              <th>Route target</th>
              <th>Direction</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((r) => (
              <tr key={`${r.direction}|${r.id}`}>
                <td>{r.name}</td>
                <td>{r.direction}</td>
              </tr>
            ))}
          </tbody>
        </DataTable>
      </DetailSection>
      {canEdit && (
        <button type="button" className="btn btn-sm btn-secondary" style={{ marginTop: '0.4rem' }} onClick={() => setEditing(true)}>
          Edit route targets
        </button>
      )}
      {editing && <VrfRouteTargetsModal vrf={vrf} onClose={() => setEditing(false)} />}
    </div>
  );
}
