import { type ReactNode, useState } from 'react';

import { CustomDataError } from '@/api/customData';
import {
  type DeviceRole,
  type DeviceType,
  type HostStatus,
  type Manufacturer,
  useDeleteDeviceRole,
  useDeleteDeviceType,
  useDeleteHostStatus,
  useDeleteManufacturer,
  useDeviceRoles,
  useDeviceTypes,
  useHostStatuses,
  useManufacturers,
} from '@/api/deviceModel';
import { Badge } from '@/components/Badge';
import { CatalogueBody, RowActions } from '@/components/CatalogueParts';
import { DataTable } from '@/components/DataTable';
import { useDialogs } from '@/components/DialogProvider-context';
import { EmptyState } from '@/components/EmptyState';
import { TagChip } from '@/components/TagChips';
import { countObjects } from '@/lib/customData';
import { usePendingKeys } from '@/lib/usePendingKeys';

import { ColorRecordModal, DeviceTypeModal, ManufacturerModal } from './DeviceModelModals';
import { SectionCard } from './SectionCard';

const hostCount = (n: number) => countObjects(n, 'host');
const right = { textAlign: 'right' } as const;

interface DeleteRequest {
  /** "role", "device type"... */
  noun: string;
  name: string;
  /** Hosts (or device types) known to use the record: the server's 409 is then the confirmation. */
  inUse: boolean;
  /** Extra text for the first confirmation. */
  note?: string;
  /** What the affected hosts lose, when it is not `noun` itself. */
  hostsLose?: string;
  remove: (confirm: boolean) => Promise<unknown>;
}

/**
 * Deletes a catalogue record. An unused one is confirmed here first; one in
 * use is sent at once, and the server's 409 (its message and the number of
 * hosts affected) is shown in the confirmation, then sent again with
 * `confirm`. Returns the per-row busy state.
 */
function useCatalogueDelete() {
  const { confirm, alert } = useDialogs();
  const pending = usePendingKeys<string>();

  const run = (key: string, req: DeleteRequest) =>
    pending.run(key, async () => {
      const title = `Delete ${req.noun}`;
      const fail = (err: unknown) =>
        alert({ message: `The ${req.noun} "${req.name}" was not deleted: ${(err as Error).message} Try again.`, variant: 'error' });
      if (!req.inUse) {
        const agreed = await confirm({
          title,
          message: `Delete ${req.noun} "${req.name}"?${req.note ? ` ${req.note}` : ''} This cannot be undone.`,
          confirmLabel: title,
        });
        if (!agreed) return;
      }
      try {
        await req.remove(false);
        return;
      } catch (err) {
        if (!(err instanceof CustomDataError && err.status === 409)) {
          await fail(err);
          return;
        }
        const affected =
          err.affected === null ? '' : ` ${hostCount(err.affected)} will have no ${req.hostsLose ?? req.noun} afterwards.`;
        const agreed = await confirm({
          title,
          message: `${err.message}${affected} This cannot be undone.`,
          confirmLabel: title,
        });
        if (!agreed) return;
      }
      try {
        await req.remove(true);
      } catch (err) {
        await fail(err);
      }
    });

  return { run, isPending: pending.isPending };
}

function Description({ text }: { text: string }) {
  if (!text) return null;
  return (
    <div className="form-help" style={{ margin: 0 }}>
      {text}
    </div>
  );
}

function NewButton({ label, onClick, disabled }: { label: string; onClick: () => void; disabled?: boolean }) {
  return (
    <button type="button" className="btn btn-sm btn-primary" onClick={onClick} disabled={disabled}>
      {label}
    </button>
  );
}

function Toolbar({ show, children }: { show: boolean; children: ReactNode }) {
  if (!show) return null;
  return <div style={{ display: 'flex', justifyContent: 'flex-end' }}>{children}</div>;
}

// ── Manufacturers ──────────────────────────────────────────────────────────

function ManufacturersSection() {
  const q = useManufacturers();
  const remove = useDeleteManufacturer();
  const deleter = useCatalogueDelete();
  const [editing, setEditing] = useState<Manufacturer | 'new' | null>(null);
  const rows = q.data ?? [];
  const newButton = <NewButton label="New manufacturer" onClick={() => setEditing('new')} />;

  const handleDelete = (m: Manufacturer) =>
    void deleter.run(`m:${m.id}`, {
      noun: 'manufacturer',
      hostsLose: 'device type',
      name: m.name,
      inUse: m.host_count > 0,
      note:
        m.device_type_count > 0
          ? `Its ${m.device_type_count === 1 ? 'device type is' : `${m.device_type_count} device types are`} deleted too.`
          : undefined,
      remove: (confirm) => remove.mutateAsync({ id: m.id, confirm }),
    });

  return (
    <div className="stack stack-sm">
      <Toolbar show={rows.length > 0}>{newButton}</Toolbar>
      <CatalogueBody
        query={q}
        what="manufacturers"
        rows={rows}
        empty={
          <EmptyState
            compact
            message="No manufacturers yet."
            description="Discovery adds the manufacturers it finds. Add one by hand to define device types before discovery runs."
            action={newButton}
          />
        }
      >
        <DataTable compact aria-label="Manufacturers">
          <thead>
            <tr>
              <th>Name</th>
              <th style={right}>Device types</th>
              <th style={right}>Hosts</th>
              <th style={right}>Actions</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((m) => (
              <tr key={m.id}>
                <td>
                  {m.name}
                  <Description text={m.description} />
                </td>
                <td style={right}>{m.device_type_count.toLocaleString()}</td>
                <td style={right}>{m.host_count.toLocaleString()}</td>
                <td style={right}>
                  <RowActions
                    label={`manufacturer ${m.name}`}
                    onEdit={() => setEditing(m)}
                    onDelete={() => handleDelete(m)}
                    deleting={deleter.isPending(`m:${m.id}`)}
                  />
                </td>
              </tr>
            ))}
          </tbody>
        </DataTable>
      </CatalogueBody>
      {editing && <ManufacturerModal manufacturer={editing === 'new' ? null : editing} onClose={() => setEditing(null)} />}
    </div>
  );
}

// ── Device types ───────────────────────────────────────────────────────────

function DeviceTypesSection() {
  const q = useDeviceTypes();
  const manufacturersQ = useManufacturers();
  const remove = useDeleteDeviceType();
  const deleter = useCatalogueDelete();
  const [editing, setEditing] = useState<DeviceType | 'new' | null>(null);
  const rows = q.data ?? [];
  const noManufacturers = manufacturersQ.isSuccess && manufacturersQ.data.length === 0;
  const newButton = <NewButton label="New device type" onClick={() => setEditing('new')} disabled={noManufacturers} />;

  const handleDelete = (t: DeviceType) =>
    void deleter.run(`t:${t.id}`, {
      noun: 'device type',
      name: `${t.manufacturer} ${t.model}`,
      inUse: t.host_count > 0,
      remove: (confirm) => remove.mutateAsync({ id: t.id, confirm }),
    });

  return (
    <div className="stack stack-sm">
      <Toolbar show={rows.length > 0}>{newButton}</Toolbar>
      <CatalogueBody
        query={q}
        what="device types"
        rows={rows}
        empty={
          <EmptyState
            compact
            message="No device types yet."
            description={
              noManufacturers
                ? 'Add a manufacturer first, then its device types.'
                : 'A device type is a hardware model of one manufacturer, such as C9300-48P.'
            }
            action={newButton}
          />
        }
      >
        <DataTable compact aria-label="Device types">
          <thead>
            <tr>
              <th>Model</th>
              <th>Manufacturer</th>
              <th>Part number</th>
              <th style={right}>U height</th>
              <th style={right}>Hosts</th>
              <th style={right}>Actions</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((t) => (
              <tr key={t.id}>
                <td>
                  {t.model}
                  <Description text={t.description} />
                </td>
                <td>{t.manufacturer}</td>
                <td>{t.part_number || <span className="text-muted">-</span>}</td>
                <td style={right}>{t.u_height}</td>
                <td style={right}>{t.host_count.toLocaleString()}</td>
                <td style={right}>
                  <RowActions
                    label={`device type ${t.manufacturer} ${t.model}`}
                    onEdit={() => setEditing(t)}
                    onDelete={() => handleDelete(t)}
                    deleting={deleter.isPending(`t:${t.id}`)}
                  />
                </td>
              </tr>
            ))}
          </tbody>
        </DataTable>
      </CatalogueBody>
      {editing && <DeviceTypeModal deviceType={editing === 'new' ? null : editing} onClose={() => setEditing(null)} />}
    </div>
  );
}

// ── Roles ──────────────────────────────────────────────────────────────────

function RolesSection() {
  const q = useDeviceRoles();
  const remove = useDeleteDeviceRole();
  const deleter = useCatalogueDelete();
  const [editing, setEditing] = useState<DeviceRole | 'new' | null>(null);
  const rows = q.data ?? [];
  const newButton = <NewButton label="New role" onClick={() => setEditing('new')} />;

  const handleDelete = (r: DeviceRole) =>
    void deleter.run(`r:${r.id}`, {
      noun: 'role',
      name: r.name,
      inUse: r.host_count > 0,
      remove: (confirm) => remove.mutateAsync({ id: r.id, confirm }),
    });

  return (
    <div className="stack stack-sm">
      <Toolbar show={rows.length > 0}>{newButton}</Toolbar>
      <CatalogueBody
        query={q}
        what="roles"
        rows={rows}
        empty={
          <EmptyState
            compact
            message="No roles yet."
            description="A role says what a host does, such as Router or Firewall."
            action={newButton}
          />
        }
      >
        <DataTable compact aria-label="Roles">
          <thead>
            <tr>
              <th>Role</th>
              <th>Description</th>
              <th style={right}>Hosts</th>
              <th style={right}>Actions</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((r) => (
              <tr key={r.id}>
                <td>
                  <TagChip color={r.color}>{r.name}</TagChip>
                </td>
                <td>{r.description || <span className="text-muted">-</span>}</td>
                <td style={right}>{r.host_count.toLocaleString()}</td>
                <td style={right}>
                  <RowActions
                    label={`role ${r.name}`}
                    onEdit={() => setEditing(r)}
                    onDelete={() => handleDelete(r)}
                    deleting={deleter.isPending(`r:${r.id}`)}
                  />
                </td>
              </tr>
            ))}
          </tbody>
        </DataTable>
      </CatalogueBody>
      {editing && <ColorRecordModal kind="role" record={editing === 'new' ? null : editing} onClose={() => setEditing(null)} />}
    </div>
  );
}

// ── Lifecycle statuses ─────────────────────────────────────────────────────

function StatusesSection() {
  const q = useHostStatuses();
  const remove = useDeleteHostStatus();
  const deleter = useCatalogueDelete();
  const [editing, setEditing] = useState<HostStatus | 'new' | null>(null);
  const rows = q.data ?? [];
  const newButton = <NewButton label="New status" onClick={() => setEditing('new')} />;

  const handleDelete = (s: HostStatus) =>
    void deleter.run(`s:${s.id}`, {
      noun: 'lifecycle status',
      name: s.name,
      inUse: s.host_count > 0,
      remove: (confirm) => remove.mutateAsync({ id: s.id, confirm }),
    });

  return (
    <div className="stack stack-sm">
      <Toolbar show={rows.length > 0}>{newButton}</Toolbar>
      <CatalogueBody
        query={q}
        what="lifecycle statuses"
        rows={rows}
        empty={
          <EmptyState
            compact
            message="No lifecycle statuses yet."
            description="A status says where a host is in its life, such as Planned, Active or Retired."
            action={newButton}
          />
        }
      >
        <DataTable compact aria-label="Lifecycle statuses">
          <thead>
            <tr>
              <th>Status</th>
              <th>Description</th>
              <th style={right}>Hosts</th>
              <th style={right}>Actions</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((s) => (
              <tr key={s.id}>
                <td>
                  <span className="tag-chips">
                    <TagChip color={s.color}>{s.name}</TagChip>
                    {s.is_default && (
                      <Badge size="sm" title="New hosts get this status">
                        Default
                      </Badge>
                    )}
                  </span>
                </td>
                <td>{s.description || <span className="text-muted">-</span>}</td>
                <td style={right}>{s.host_count.toLocaleString()}</td>
                <td style={right}>
                  <RowActions
                    label={`status ${s.name}`}
                    onEdit={() => setEditing(s)}
                    // The default status cannot be deleted; make another one the default first.
                    onDelete={s.is_default ? undefined : () => handleDelete(s)}
                    deleting={deleter.isPending(`s:${s.id}`)}
                  />
                </td>
              </tr>
            ))}
          </tbody>
        </DataTable>
      </CatalogueBody>
      {editing && (
        <ColorRecordModal kind="status" record={editing === 'new' ? null : editing} onClose={() => setEditing(null)} />
      )}
    </div>
  );
}

/** Settings tab where admins curate the manufacturer, device type, role and lifecycle status catalogues. */
export function DeviceModelTab() {
  return (
    <div className="stack">
      <SectionCard title="Manufacturers">
        <ManufacturersSection />
      </SectionCard>
      <SectionCard title="Device types">
        <DeviceTypesSection />
      </SectionCard>
      <SectionCard title="Roles">
        <RolesSection />
      </SectionCard>
      <SectionCard title="Lifecycle statuses">
        <StatusesSection />
      </SectionCard>
    </div>
  );
}
