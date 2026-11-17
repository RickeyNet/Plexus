import { useId, useState } from 'react';

import { type CircuitType, useCircuitTypes, useDeleteCircuitType, useSaveCircuitType } from '@/api/circuits';
import { CardHeader, CatalogueBody, Dash, DescriptionInput, RowActions, SaveFailure } from '@/components/CatalogueParts';
import { ChangelogPanel } from '@/components/ChangelogPanel';
import { DataTable } from '@/components/DataTable';
import { EmptyState } from '@/components/EmptyState';
import { FieldError } from '@/components/FieldError';
import { Modal } from '@/components/Modal';
import { ModalActions } from '@/components/ModalActions';
import { NameInput } from '@/components/NameInput';
import { CIRCUIT_NAME_MAX } from '@/lib/circuits';
import { clickableProps } from '@/lib/clickable';
import { runSave } from '@/lib/recordSave';
import { serverFieldErrors } from '@/lib/serverFieldErrors';
import { useNameField } from '@/lib/useNameField';
import { usePendingKeys } from '@/lib/usePendingKeys';
import { SplitLayout } from '@/pages/Ipam/NetworkObjectParts';

import { useCanWriteCircuits, useConfirmDelete } from './hooks';

const RIGHT = { textAlign: 'right' } as const;

/** The circuit types (Internet, MPLS...), and the selected one's change log. */
export function CircuitTypesTab() {
  const canWrite = useCanWriteCircuits();
  const q = useCircuitTypes();
  const remove = useDeleteCircuitType();
  const confirmDelete = useConfirmDelete();
  const deleting = usePendingKeys<number>();
  const [editing, setEditing] = useState<CircuitType | 'new' | null>(null);
  const [selectedId, setSelectedId] = useState<number | null>(null);
  const rows = q.data ?? [];
  const selected = rows.find((t) => t.id === selectedId) ?? null;

  const addButton = canWrite && (
    <button type="button" className="btn btn-sm btn-primary" onClick={() => setEditing('new')}>
      Add circuit type
    </button>
  );

  const list = (
    <>
      <CardHeader
        title="Circuit types"
        sub={q.data && `${rows.length.toLocaleString()} type${rows.length === 1 ? '' : 's'}`}
        actions={rows.length > 0 && addButton}
      />
      <CatalogueBody
        query={q}
        what="circuit types"
        rows={rows}
        empty={
          <EmptyState
            compact
            message="No circuit types yet."
            description="A circuit type says what kind of service a circuit is, such as Internet or MPLS. Every circuit has one."
            action={addButton || undefined}
          />
        }
      >
        <DataTable compact aria-label="Circuit types">
          <thead>
            <tr>
              <th>Name</th>
              <th style={RIGHT}>Circuits</th>
              <th>Description</th>
              {canWrite && <th style={RIGHT}>Actions</th>}
            </tr>
          </thead>
          <tbody>
            {rows.map((t) => (
              <tr
                key={t.id}
                className={`row-clickable${t.id === selectedId ? ' row-selected' : ''}`}
                aria-current={t.id === selectedId ? 'true' : undefined}
                {...clickableProps(() => setSelectedId(t.id), { role: null })}
              >
                <td style={{ fontWeight: 600 }}>{t.name}</td>
                <td style={RIGHT}>{t.circuit_count.toLocaleString()}</td>
                <td>{t.description || <Dash />}</td>
                {canWrite && (
                  <td style={RIGHT} onClick={(e) => e.stopPropagation()}>
                    <RowActions
                      label={`circuit type ${t.name}`}
                      onEdit={() => setEditing(t)}
                      onDelete={() =>
                        void deleting.run(t.id, async () => {
                          if (await confirmDelete('circuit type', t.name, () => remove.mutateAsync(t.id))) {
                            if (selectedId === t.id) setSelectedId(null);
                          }
                        })
                      }
                      deleting={deleting.isPending(t.id)}
                    />
                  </td>
                )}
              </tr>
            ))}
          </tbody>
        </DataTable>
      </CatalogueBody>
      {editing && <CircuitTypeModal type={editing === 'new' ? null : editing} onClose={() => setEditing(null)} />}
    </>
  );

  const detail = selected ? (
    <div style={{ display: 'grid', gap: '1rem' }}>
      <div>
        <h3 style={{ margin: 0 }}>{selected.name}</h3>
        <div className="text-muted" style={{ fontSize: '0.9em' }}>
          {selected.circuit_count.toLocaleString()} circuit{selected.circuit_count === 1 ? '' : 's'}
          {selected.description ? ` · ${selected.description}` : ''}
        </div>
      </div>
      <ChangelogPanel objectType="circuit_type" objectId={selected.id} pageSize={10} />
    </div>
  ) : (
    <>
      <h3 style={{ margin: '0 0 0.75rem' }}>Circuit type details</h3>
      <p className="text-muted" style={{ margin: 0 }}>
        Select a circuit type to see its change log.
      </p>
    </>
  );

  return <SplitLayout list={list} detail={detail} />;
}

function CircuitTypeModal({ type, onClose }: { type: CircuitType | null; onClose: () => void }) {
  const id = useId();
  const save = useSaveCircuitType();
  const name = useNameField(type?.name ?? '', CIRCUIT_NAME_MAX, 'Name', (n) => `A circuit type named "${n}" already exists.`);
  const [description, setDescription] = useState(type?.description ?? '');
  const [failure, setFailure] = useState<string | null>(null);
  const [serverErrors, setServerErrors] = useState<Record<string, string>>({});

  const submit = () => {
    name.touch();
    if (name.error) return;
    setServerErrors({});
    void runSave(
      () => save.mutateAsync({ id: type?.id ?? null, data: { name: name.trimmed, description: description.trim() } }),
      name,
      setFailure,
      onClose,
      (err) => {
        const fields = serverFieldErrors(err);
        setServerErrors(fields);
        return Object.keys(fields).length > 0;
      },
    );
  };

  return (
    <Modal
      isOpen
      onClose={onClose}
      size="small"
      title={type ? `Edit circuit type ${type.name}` : 'Add circuit type'}
      footer={
        <ModalActions
          onClose={onClose}
          primaryLabel={type ? 'Save circuit type' : 'Add circuit type'}
          primaryBusy={save.isPending}
          primaryBusyLabel="Saving…"
          onPrimary={submit}
        />
      }
    >
      <SaveFailure what="circuit type" message={failure} />
      <NameInput id={id} label="Name" field={name} max={CIRCUIT_NAME_MAX} help="Unique, ignoring case. For example Internet or MPLS." />
      <FieldError>{serverErrors.name}</FieldError>
      <DescriptionInput id={id} value={description} error={serverErrors.description} onChange={setDescription} />
    </Modal>
  );
}
