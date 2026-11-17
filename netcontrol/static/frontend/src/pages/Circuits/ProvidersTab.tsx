import { useId, useState } from 'react';

import {
  type CircuitProvider,
  type ProviderNetwork,
  useCircuitProvider,
  useCircuitProviders,
  useDeleteProvider,
  useDeleteProviderNetwork,
  useSaveProvider,
  useSaveProviderNetwork,
} from '@/api/circuits';
import { CardHeader, CatalogueBody, Dash, DescriptionInput, RowActions, SaveFailure } from '@/components/CatalogueParts';
import { ChangelogPanel } from '@/components/ChangelogPanel';
import { DataTable } from '@/components/DataTable';
import { EmptyState } from '@/components/EmptyState';
import { FieldError } from '@/components/FieldError';
import { LoadingState } from '@/components/LoadingState';
import { Modal } from '@/components/Modal';
import { ModalActions } from '@/components/ModalActions';
import { NameInput } from '@/components/NameInput';
import { QueryError } from '@/components/QueryError';
import { CIRCUIT_COMMENTS_MAX, CIRCUIT_DESCRIPTION_MAX, CIRCUIT_NAME_MAX, CIRCUIT_TEXT_MAX } from '@/lib/circuits';
import { clickableProps } from '@/lib/clickable';
import { runSave } from '@/lib/recordSave';
import { serverFieldErrors } from '@/lib/serverFieldErrors';
import { useNameField } from '@/lib/useNameField';
import { usePendingKeys } from '@/lib/usePendingKeys';
import { DetailSection, SplitLayout } from '@/pages/Ipam/NetworkObjectParts';

import { useCanWriteCircuits, useConfirmDelete } from './hooks';
import { DetailRow, TextField } from './parts';

const RIGHT = { textAlign: 'right' } as const;

/** The circuit providers; the selected one's details, provider networks and change log. */
export function ProvidersTab() {
  const canWrite = useCanWriteCircuits();
  const q = useCircuitProviders();
  const remove = useDeleteProvider();
  const confirmDelete = useConfirmDelete();
  const deleting = usePendingKeys<number>();
  const [editing, setEditing] = useState<CircuitProvider | 'new' | null>(null);
  const [selectedId, setSelectedId] = useState<number | null>(null);
  const rows = q.data ?? [];

  const addButton = canWrite && (
    <button type="button" className="btn btn-sm btn-primary" onClick={() => setEditing('new')}>
      Add provider
    </button>
  );

  const list = (
    <>
      <CardHeader
        title="Providers"
        sub={q.data && `${rows.length.toLocaleString()} provider${rows.length === 1 ? '' : 's'}`}
        actions={rows.length > 0 && addButton}
      />
      <CatalogueBody
        query={q}
        what="providers"
        rows={rows}
        empty={
          <EmptyState
            compact
            message="No providers yet."
            description="A provider is the carrier a circuit is bought from. Add one before adding its circuits."
            action={addButton || undefined}
          />
        }
      >
        <DataTable compact aria-label="Providers">
          <thead>
            <tr>
              <th>Name</th>
              <th>Account</th>
              <th style={RIGHT}>Circuits</th>
              <th style={RIGHT}>Networks</th>
              <th>NOC contact</th>
              {canWrite && <th style={RIGHT}>Actions</th>}
            </tr>
          </thead>
          <tbody>
            {rows.map((p) => (
              <tr
                key={p.id}
                className={`row-clickable${p.id === selectedId ? ' row-selected' : ''}`}
                aria-current={p.id === selectedId ? 'true' : undefined}
                title="Show the provider's details"
                {...clickableProps(() => setSelectedId(p.id), { role: null })}
              >
                <td style={{ fontWeight: 600 }}>{p.name}</td>
                <td>{p.account || <Dash />}</td>
                <td style={RIGHT}>{p.circuit_count.toLocaleString()}</td>
                <td style={RIGHT}>{p.network_count.toLocaleString()}</td>
                <td>{p.noc_contact || <Dash />}</td>
                {canWrite && (
                  <td style={RIGHT} onClick={(e) => e.stopPropagation()}>
                    <RowActions
                      label={`provider ${p.name}`}
                      onEdit={() => setEditing(p)}
                      onDelete={() =>
                        void deleting.run(p.id, async () => {
                          if (await confirmDelete('provider', p.name, () => remove.mutateAsync(p.id))) {
                            if (selectedId === p.id) setSelectedId(null);
                          }
                        })
                      }
                      deleting={deleting.isPending(p.id)}
                    />
                  </td>
                )}
              </tr>
            ))}
          </tbody>
        </DataTable>
      </CatalogueBody>
      {editing && <ProviderModal provider={editing === 'new' ? null : editing} onClose={() => setEditing(null)} />}
    </>
  );

  return <SplitLayout list={list} detail={<ProviderDetailPanel id={selectedId} canWrite={canWrite} />} />;
}

function ProviderDetailPanel({ id, canWrite }: { id: number | null; canWrite: boolean }) {
  const q = useCircuitProvider(id);
  const remove = useDeleteProviderNetwork();
  const confirmDelete = useConfirmDelete();
  const deleting = usePendingKeys<number>();
  const [editing, setEditing] = useState<ProviderNetwork | 'new' | null>(null);
  if (id === null) {
    return (
      <>
        <h3 style={{ margin: '0 0 0.75rem' }}>Provider details</h3>
        <p className="text-muted" style={{ margin: 0 }}>
          Select a provider to see its contacts, provider networks and change log.
        </p>
      </>
    );
  }
  if (q.isError && !q.data) return <QueryError what="provider details" query={q} />;
  if (q.isPending) return <LoadingState text="Loading provider details…" />;
  const p = q.data;
  return (
    <div style={{ display: 'grid', gap: '1rem' }}>
      <h3 style={{ margin: 0 }}>{p.name}</h3>
      <div style={{ display: 'grid', gap: '0.3rem' }}>
        <DetailRow label="Account">{p.account || <Dash />}</DetailRow>
        <DetailRow label="Portal">
          {p.portal_url ? (
            <a href={p.portal_url} target="_blank" rel="noopener noreferrer">
              {p.portal_url}
            </a>
          ) : (
            <Dash />
          )}
        </DetailRow>
        <DetailRow label="NOC contact">{p.noc_contact || <Dash />}</DetailRow>
        <DetailRow label="Admin contact">{p.admin_contact || <Dash />}</DetailRow>
        {p.comments && <DetailRow label="Comments">{p.comments}</DetailRow>}
      </div>
      <DetailSection title="Provider networks" count={p.networks.length} empty="No provider networks.">
        <DataTable compact aria-label={`Provider networks of ${p.name}`} maxHeight={240}>
          <thead>
            <tr>
              <th>Name</th>
              <th style={RIGHT}>Terminations</th>
              {canWrite && <th style={RIGHT}>Actions</th>}
            </tr>
          </thead>
          <tbody>
            {p.networks.map((n) => (
              <tr key={n.id}>
                <td title={n.description || undefined}>{n.name}</td>
                <td style={RIGHT}>{n.termination_count.toLocaleString()}</td>
                {canWrite && (
                  <td style={RIGHT}>
                    <RowActions
                      label={`provider network ${n.name}`}
                      onEdit={() => setEditing(n)}
                      onDelete={() =>
                        void deleting.run(n.id, async () => {
                          await confirmDelete('provider network', n.name, () => remove.mutateAsync(n.id));
                        })
                      }
                      deleting={deleting.isPending(n.id)}
                    />
                  </td>
                )}
              </tr>
            ))}
          </tbody>
        </DataTable>
      </DetailSection>
      {canWrite && (
        <div>
          <button type="button" className="btn btn-sm btn-secondary" onClick={() => setEditing('new')}>
            Add provider network
          </button>
        </div>
      )}
      <ChangelogPanel objectType="circuit_provider" objectId={p.id} pageSize={10} />
      {editing && (
        <ProviderNetworkModal
          providerId={p.id}
          network={editing === 'new' ? null : editing}
          onClose={() => setEditing(null)}
        />
      )}
    </div>
  );
}

function ProviderModal({ provider, onClose }: { provider: CircuitProvider | null; onClose: () => void }) {
  const id = useId();
  const save = useSaveProvider();
  const name = useNameField(provider?.name ?? '', CIRCUIT_NAME_MAX, 'Name', (n) => `A provider named "${n}" already exists.`);
  const [fields, setFields] = useState({
    account: provider?.account ?? '',
    portal_url: provider?.portal_url ?? '',
    noc_contact: provider?.noc_contact ?? '',
    admin_contact: provider?.admin_contact ?? '',
    comments: provider?.comments ?? '',
  });
  const [failure, setFailure] = useState<string | null>(null);
  const [serverErrors, setServerErrors] = useState<Record<string, string>>({});
  const urlError =
    fields.portal_url.trim() && !/^https?:\/\//i.test(fields.portal_url.trim())
      ? 'Portal URL must start with http:// or https://.'
      : serverErrors.portal_url;

  const set = (key: keyof typeof fields) => (v: string) => {
    setFields((prev) => ({ ...prev, [key]: v }));
    setServerErrors((prev) => ({ ...prev, [key]: '' }));
  };

  const submit = () => {
    name.touch();
    if (name.error || urlError) return;
    setServerErrors({});
    const data = Object.fromEntries(Object.entries(fields).map(([k, v]) => [k, v.trim()]));
    void runSave(
      () => save.mutateAsync({ id: provider?.id ?? null, data: { name: name.trimmed, ...data } }),
      name,
      setFailure,
      onClose,
      (err) => {
        const errs = serverFieldErrors(err);
        setServerErrors(errs);
        return Object.keys(errs).length > 0;
      },
    );
  };

  return (
    <Modal
      isOpen
      onClose={onClose}
      title={provider ? `Edit provider ${provider.name}` : 'Add provider'}
      footer={
        <ModalActions
          onClose={onClose}
          primaryLabel={provider ? 'Save provider' : 'Add provider'}
          primaryBusy={save.isPending}
          primaryBusyLabel="Saving…"
          onPrimary={submit}
        />
      }
    >
      <SaveFailure what="provider" message={failure} />
      <NameInput id={id} label="Name" field={name} max={CIRCUIT_NAME_MAX} help="The carrier's name. Unique, ignoring case." />
      <FieldError>{serverErrors.name}</FieldError>
      <TextField id={`${id}-account`} label="Account (optional)" value={fields.account} onChange={set('account')} error={serverErrors.account} max={CIRCUIT_TEXT_MAX} />
      <TextField
        id={`${id}-portal`}
        label="Portal URL (optional)"
        value={fields.portal_url}
        onChange={set('portal_url')}
        error={urlError}
        max={500}
        placeholder="https://portal.example.com"
      />
      <TextField id={`${id}-noc`} label="NOC contact (optional)" value={fields.noc_contact} onChange={set('noc_contact')} error={serverErrors.noc_contact} max={CIRCUIT_DESCRIPTION_MAX} />
      <TextField id={`${id}-admin`} label="Admin contact (optional)" value={fields.admin_contact} onChange={set('admin_contact')} error={serverErrors.admin_contact} max={CIRCUIT_DESCRIPTION_MAX} />
      <TextField id={`${id}-comments`} label="Comments (optional)" value={fields.comments} onChange={set('comments')} error={serverErrors.comments} max={CIRCUIT_COMMENTS_MAX} multiline />
    </Modal>
  );
}

function ProviderNetworkModal({
  providerId,
  network,
  onClose,
}: {
  providerId: number;
  network: ProviderNetwork | null;
  onClose: () => void;
}) {
  const id = useId();
  const save = useSaveProviderNetwork();
  const name = useNameField(network?.name ?? '', CIRCUIT_NAME_MAX, 'Name', (n) => `The provider already has a network named "${n}".`);
  const [description, setDescription] = useState(network?.description ?? '');
  const [failure, setFailure] = useState<string | null>(null);
  const [serverErrors, setServerErrors] = useState<Record<string, string>>({});

  const submit = () => {
    name.touch();
    if (name.error) return;
    setServerErrors({});
    const data = { name: name.trimmed, description: description.trim() };
    void runSave(
      () => save.mutateAsync({ id: network?.id ?? null, data: network ? data : { ...data, provider_id: providerId } }),
      name,
      setFailure,
      onClose,
      (err) => {
        const errs = serverFieldErrors(err);
        setServerErrors(errs);
        return Object.keys(errs).length > 0;
      },
    );
  };

  return (
    <Modal
      isOpen
      onClose={onClose}
      size="small"
      title={network ? `Edit provider network ${network.name}` : 'Add provider network'}
      footer={
        <ModalActions
          onClose={onClose}
          primaryLabel={network ? 'Save provider network' : 'Add provider network'}
          primaryBusy={save.isPending}
          primaryBusyLabel="Saving…"
          onPrimary={submit}
        />
      }
    >
      <SaveFailure what="provider network" message={failure} />
      <NameInput id={id} label="Name" field={name} max={CIRCUIT_NAME_MAX} help="Unique within the provider, ignoring case. For example its MPLS cloud." />
      <FieldError>{serverErrors.name}</FieldError>
      <DescriptionInput id={id} value={description} error={serverErrors.description} onChange={setDescription} />
    </Modal>
  );
}
