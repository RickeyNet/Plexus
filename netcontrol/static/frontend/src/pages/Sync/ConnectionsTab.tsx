import { useId, useState } from 'react';

import { useServiceCredentialsList } from '@/api/settings';
import {
  type SyncConnection,
  type SyncConnectionInput,
  useDeleteSyncConnection,
  useSaveSyncConnection,
  useSyncCatalog,
  useSyncConnections,
  useTestSyncConnection,
} from '@/api/sync';
import { Badge } from '@/components/Badge';
import { BusyButton } from '@/components/BusyButton';
import { CardHeader, CatalogueBody, Dash, RowActions, SaveFailure } from '@/components/CatalogueParts';
import { DataTable } from '@/components/DataTable';
import { useDialogs } from '@/components/DialogProvider-context';
import { EmptyState } from '@/components/EmptyState';
import { FieldError } from '@/components/FieldError';
import { Modal } from '@/components/Modal';
import { ModalActions } from '@/components/ModalActions';
import { formatBackendDateTime } from '@/lib/datetime';
import { serverFieldErrors } from '@/lib/serverFieldErrors';
import {
  AUTH_LABEL,
  type ConnectionErrors,
  KIND_LABEL,
  SYNC_NAME_MAX,
  type SyncKind,
  TIMEOUT_MAX,
  TIMEOUT_MIN,
  validateConnection,
} from '@/lib/sync';
import { usePendingKeys } from '@/lib/usePendingKeys';
import { TextField } from '@/pages/Circuits/parts';
import { CheckboxField } from '@/pages/Settings/FormFields';

import { useConfirmDelete, useIsAdmin } from './hooks';

const RIGHT = { textAlign: 'right' } as const;

/** The remote systems jobs sync with. Admins add, edit, test and delete them. */
export function ConnectionsTab() {
  const isAdmin = useIsAdmin();
  const q = useSyncConnections();
  const remove = useDeleteSyncConnection();
  const test = useTestSyncConnection();
  const confirmDelete = useConfirmDelete();
  const { alert } = useDialogs();
  const busy = usePendingKeys<string>();
  const [editing, setEditing] = useState<SyncConnection | 'new' | null>(null);
  const rows = q.data ?? [];

  const addButton = isAdmin && (
    <button type="button" className="btn btn-sm btn-primary" onClick={() => setEditing('new')}>
      Add connection
    </button>
  );

  const runTest = (c: SyncConnection) =>
    void busy.run(`test-${c.id}`, async () => {
      try {
        const result = await test.mutateAsync(c.id);
        await alert({
          title: result.ok ? 'Connection works' : 'Connection test failed',
          message: result.message,
          variant: result.ok ? 'default' : 'error',
        });
      } catch (err) {
        await alert({ title: 'Connection not tested', message: (err as Error).message, variant: 'error' });
      }
    });

  return (
    <div className="card">
      <CardHeader
        title="Connections"
        sub={q.data && `${rows.length.toLocaleString()} connection${rows.length === 1 ? '' : 's'}`}
        actions={rows.length > 0 && addButton}
      />
      <CatalogueBody
        query={q}
        what="connections"
        rows={rows}
        empty={
          <EmptyState
            compact
            message="No connections yet."
            description={
              isAdmin
                ? 'A connection is a NetBox, Nautobot or ServiceNow instance and the service credential Plexus signs in with.'
                : 'An admin adds the NetBox, Nautobot or ServiceNow instances Plexus syncs with.'
            }
            action={addButton || undefined}
          />
        }
      >
        <DataTable compact aria-label="Sync connections">
          <thead>
            <tr>
              <th>Name</th>
              <th>System</th>
              <th>Address</th>
              <th>Credential</th>
              <th>Last test</th>
              <th style={RIGHT}>Jobs</th>
              {isAdmin && <th style={RIGHT}>Actions</th>}
            </tr>
          </thead>
          <tbody>
            {rows.map((c) => (
              <tr key={c.id}>
                <td style={{ fontWeight: 600 }}>
                  {c.name}
                  {c.description && <div className="text-muted">{c.description}</div>}
                </td>
                <td>{KIND_LABEL[c.kind] ?? c.kind}</td>
                <td>
                  <code>{c.base_url}</code>
                  {!c.verify_tls && (
                    <Badge size="sm" tone="warning" style={{ marginLeft: 'var(--space-2)' }}>
                      TLS not verified
                    </Badge>
                  )}
                </td>
                <td>
                  {c.credential_name || <Dash />}
                  <div className="text-muted">{AUTH_LABEL[c.auth_type] ?? c.auth_type}</div>
                </td>
                <td>
                  {c.last_test_ok === null ? (
                    <span className="text-muted">Never</span>
                  ) : (
                    <span title={c.last_test_message}>
                      <Badge size="sm" tone={c.last_test_ok ? 'success' : 'danger'}>
                        {c.last_test_ok ? 'OK' : 'Failed'}
                      </Badge>{' '}
                      <span className="text-muted">{formatBackendDateTime(c.last_test_at)}</span>
                    </span>
                  )}
                </td>
                <td style={RIGHT}>{c.job_count.toLocaleString()}</td>
                {isAdmin && (
                  <td style={RIGHT}>
                    <div className="table-actions" style={{ justifyContent: 'flex-end' }}>
                      <BusyButton
                        className="btn btn-sm btn-secondary"
                        busy={busy.isPending(`test-${c.id}`)}
                        busyLabel="Testing…"
                        aria-label={`Test connection ${c.name}`}
                        onClick={() => runTest(c)}
                      >
                        Test
                      </BusyButton>
                      <RowActions
                        label={`connection ${c.name}`}
                        onEdit={() => setEditing(c)}
                        onDelete={() =>
                          void busy.run(`delete-${c.id}`, () =>
                            confirmDelete('connection', c.name, () => remove.mutateAsync(c.id)),
                          )
                        }
                        deleting={busy.isPending(`delete-${c.id}`)}
                      />
                    </div>
                  </td>
                )}
              </tr>
            ))}
          </tbody>
        </DataTable>
      </CatalogueBody>
      {editing && (
        <ConnectionModal connection={editing === 'new' ? null : editing} onClose={() => setEditing(null)} />
      )}
    </div>
  );
}

interface ConnectionModalProps {
  connection: SyncConnection | null;
  onClose: () => void;
}

function ConnectionModal({ connection, onClose }: ConnectionModalProps) {
  const id = useId();
  const save = useSaveSyncConnection();
  const catalog = useSyncCatalog();
  const credentials = useServiceCredentialsList();
  const [draft, setDraft] = useState<SyncConnectionInput>(() => ({
    name: connection?.name ?? '',
    kind: connection?.kind ?? 'netbox',
    base_url: connection?.base_url ?? '',
    auth_type: connection?.auth_type ?? 'token',
    credential_id: connection?.credential_id ?? null,
    verify_tls: connection?.verify_tls ?? true,
    ca_pem: null,
    timeout_seconds: connection?.timeout_seconds ?? 30,
    description: connection?.description ?? '',
  }));
  const [touched, setTouched] = useState<Partial<Record<keyof ConnectionErrors, boolean>>>({});
  const [failure, setFailure] = useState<string | null>(null);
  const [serverErrors, setServerErrors] = useState<Record<string, string>>({});

  const errors = validateConnection(draft);
  const shown = (f: keyof ConnectionErrors) => (touched[f] ? errors[f] : undefined) ?? serverErrors[f];
  const touch = (f: keyof ConnectionErrors) => setTouched((t) => ({ ...t, [f]: true }));
  const set = (patch: Partial<SyncConnectionInput>) => {
    setDraft((d) => ({ ...d, ...patch }));
    setServerErrors({});
  };
  const kindInfo = catalog.data?.kinds.find((k) => k.id === draft.kind);
  const authTypes = kindInfo?.auth_types ?? (draft.kind === 'servicenow' ? ['basic', 'oauth'] : ['token']);

  const submit = () => {
    setTouched({ name: true, base_url: true, credential_id: true, timeout_seconds: true });
    if (Object.keys(errors).length > 0) return;
    setFailure(null);
    save.mutate(
      { id: connection?.id ?? null, data: { ...draft, name: draft.name.trim(), base_url: draft.base_url.trim() } },
      {
        onSuccess: onClose,
        onError: (err) => {
          const fields = serverFieldErrors(err);
          setServerErrors(fields);
          if (!Object.keys(fields).length) setFailure(err.message);
        },
      },
    );
  };

  const selectKind = (kind: SyncKind) => {
    const allowed = catalog.data?.kinds.find((k) => k.id === kind)?.auth_types ?? [];
    set({ kind, auth_type: allowed.includes(draft.auth_type) ? draft.auth_type : (allowed[0] ?? 'token') });
  };

  return (
    <Modal
      isOpen
      onClose={onClose}
      title={connection ? `Edit connection ${connection.name}` : 'Add connection'}
      footer={
        <ModalActions
          onClose={onClose}
          primaryLabel={connection ? 'Save connection' : 'Add connection'}
          primaryBusy={save.isPending}
          primaryBusyLabel="Saving…"
          onPrimary={submit}
        />
      }
    >
      <SaveFailure what="connection" message={failure} />
      <div className="form-row">
        <div style={{ flex: '2 1 14rem' }} onBlur={() => touch('name')}>
          <TextField
            id={`${id}-name`}
            label="Name"
            value={draft.name}
            max={SYNC_NAME_MAX}
            autoFocus
            error={shown('name')}
            onChange={(name) => set({ name })}
          />
        </div>
        <div className="form-group" style={{ flex: '1 1 10rem' }}>
          <label className="form-label" htmlFor={`${id}-kind`}>
            System
          </label>
          <select
            id={`${id}-kind`}
            className="form-select"
            value={draft.kind}
            disabled={!!connection?.job_count}
            onChange={(e) => selectKind(e.target.value as SyncKind)}
          >
            {(Object.keys(KIND_LABEL) as SyncKind[]).map((k) => (
              <option key={k} value={k}>
                {KIND_LABEL[k]}
              </option>
            ))}
          </select>
          {kindInfo && <div className="form-help">{kindInfo.notes}</div>}
        </div>
      </div>
      <div onBlur={() => touch('base_url')}>
        <TextField
          id={`${id}-url`}
          label="Address"
          value={draft.base_url}
          max={500}
          placeholder="https://netbox.example.com"
          help="The https address of the instance (a path prefix is allowed). Credentials never go in the address."
          error={shown('base_url')}
          onChange={(base_url) => set({ base_url })}
        />
      </div>
      <div className="form-row">
        <div className="form-group" style={{ flex: '1 1 12rem' }}>
          <label className="form-label" htmlFor={`${id}-auth`}>
            Sign-in
          </label>
          <select
            id={`${id}-auth`}
            className="form-select"
            value={draft.auth_type}
            onChange={(e) => set({ auth_type: e.target.value as SyncConnectionInput['auth_type'] })}
          >
            {authTypes.map((a) => (
              <option key={a} value={a}>
                {AUTH_LABEL[a] ?? a}
              </option>
            ))}
          </select>
        </div>
        <div className="form-group" style={{ flex: '1 1 14rem' }}>
          <label className="form-label" htmlFor={`${id}-cred`}>
            Service credential
          </label>
          <select
            id={`${id}-cred`}
            className="form-select"
            value={draft.credential_id ?? ''}
            aria-invalid={!!shown('credential_id')}
            aria-describedby={`${id}-cred-help ${id}-cred-error`}
            onChange={(e) => set({ credential_id: e.target.value ? Number(e.target.value) : null })}
            onBlur={() => touch('credential_id')}
          >
            <option value="">Pick a credential</option>
            {(credentials.data || []).map((c) => (
              <option key={c.id} value={c.id}>
                {c.name}
                {c.username ? ` (${c.username})` : ''}
              </option>
            ))}
          </select>
          <div className="form-help" id={`${id}-cred-help`}>
            {draft.auth_type === 'token'
              ? 'The API token is the credential’s password.'
              : draft.auth_type === 'oauth'
                ? 'The client id is the credential’s username, the client secret its password.'
                : 'The credential’s username and password.'}
          </div>
          <FieldError id={`${id}-cred-error`}>{shown('credential_id')}</FieldError>
        </div>
      </div>
      <div className="form-row">
        <div className="form-group" style={{ flex: '0 1 10rem' }}>
          <label className="form-label" htmlFor={`${id}-timeout`}>
            Timeout (seconds)
          </label>
          <input
            id={`${id}-timeout`}
            type="number"
            className="form-input"
            min={TIMEOUT_MIN}
            max={TIMEOUT_MAX}
            value={draft.timeout_seconds}
            aria-invalid={!!shown('timeout_seconds')}
            aria-describedby={`${id}-timeout-error`}
            onChange={(e) => set({ timeout_seconds: Number(e.target.value) })}
            onBlur={() => touch('timeout_seconds')}
          />
          <FieldError id={`${id}-timeout-error`}>{shown('timeout_seconds')}</FieldError>
        </div>
        <CheckboxField
          inRow
          label="Verify the TLS certificate"
          checked={draft.verify_tls}
          onChange={(verify_tls) => set({ verify_tls })}
        />
      </div>
      <TextField
        id={`${id}-ca`}
        label="CA bundle (PEM, optional)"
        value={draft.ca_pem ?? ''}
        max={64 * 1024}
        multiline
        placeholder={connection?.has_ca_pem ? 'A bundle is stored; paste a new one to replace it.' : '-----BEGIN CERTIFICATE-----'}
        help="Trust only these certificates for this connection (an internal CA)."
        error={serverErrors.ca_pem}
        onChange={(text) => set({ ca_pem: text || null })}
      />
      {connection?.has_ca_pem && (
        <CheckboxField
          label="Remove the stored CA bundle"
          checked={draft.ca_pem === ''}
          onChange={(remove) => set({ ca_pem: remove ? '' : null })}
        />
      )}
      <TextField
        id={`${id}-desc`}
        label="Description"
        value={draft.description}
        max={1000}
        onChange={(description) => set({ description })}
      />
    </Modal>
  );
}
