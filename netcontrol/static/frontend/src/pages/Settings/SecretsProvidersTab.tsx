import { useId, useState } from 'react';

import { useAuthStatus } from '@/api/auth';
import {
  type SecretsProvider,
  useDeleteSecretsProvider,
  useSecretsProviders,
  useTestSecretsProvider,
} from '@/api/secretsProviders';
import { Badge } from '@/components/Badge';
import { Callout } from '@/components/Callout';
import { DataTable } from '@/components/DataTable';
import { DeleteButton } from '@/components/DeleteButton';
import { useDialogs } from '@/components/DialogProvider-context';
import { EmptyState } from '@/components/EmptyState';
import { FieldError } from '@/components/FieldError';
import { LoadingState } from '@/components/LoadingState';
import { Modal } from '@/components/Modal';
import { ModalActions } from '@/components/ModalActions';
import { QueryError } from '@/components/QueryError';
import { PATH_HELP, isProviderType, providerTypeLabel, testFailureText } from '@/lib/secretsProviders';
import { usePendingKeys } from '@/lib/usePendingKeys';

import { SecretsProviderModal } from './SecretsProviderModal';

const RIGHT = { textAlign: 'right' } as const;

function usageText(p: SecretsProvider): string {
  const parts = [];
  if (p.credential_count) parts.push(`${p.credential_count} credential${p.credential_count === 1 ? '' : 's'}`);
  if (p.secret_variable_count)
    parts.push(`${p.secret_variable_count} secret variable${p.secret_variable_count === 1 ? '' : 's'}`);
  return parts.join(', ') || 'Not used';
}

/** Resolves one reference on the server and shows success or failure only. */
function TestReferenceModal({ provider, onClose }: { provider: SecretsProvider; onClose: () => void }) {
  const id = useId();
  const test = useTestSecretsProvider();
  const [path, setPath] = useState('');
  const [key, setKey] = useState('');
  const [pathError, setPathError] = useState<string | undefined>();

  const run = () => {
    if (!path.trim()) {
      setPathError('Enter the path of a secret to read');
      return;
    }
    test.mutate({ id: provider.id, path: path.trim(), key: key.trim() });
  };
  const result = test.data;

  return (
    <Modal
      isOpen
      size="small"
      onClose={onClose}
      title={`Test ${provider.name}`}
      footer={
        <ModalActions
          onClose={onClose}
          primaryLabel="Test reference"
          primaryBusy={test.isPending}
          primaryBusyLabel="Testing…"
          onPrimary={run}
        />
      }
    >
      <form
        onSubmit={(e) => {
          e.preventDefault();
          run();
        }}
      >
        <p className="form-help" style={{ marginTop: 0 }}>
          Plexus reads the secret and reports whether it worked. The value is never shown or logged.
        </p>
        <div className="form-group">
          <label className="form-label" htmlFor={`${id}-path`}>
            Path
          </label>
          <input
            id={`${id}-path`}
            className="form-input"
            value={path}
            onChange={(e) => {
              setPath(e.target.value);
              setPathError(undefined);
            }}
            aria-invalid={!!pathError}
            aria-describedby={`${id}-path-help`}
            autoComplete="off"
            spellCheck={false}
          />
          <div className="form-help" id={`${id}-path-help`}>
            {isProviderType(provider.provider_type) ? PATH_HELP[provider.provider_type] : ''}
          </div>
          <FieldError>{pathError}</FieldError>
        </div>
        <div className="form-group">
          <label className="form-label" htmlFor={`${id}-key`}>
            Key (optional)
          </label>
          <input
            id={`${id}-key`}
            className="form-input"
            value={key}
            onChange={(e) => setKey(e.target.value)}
            autoComplete="off"
            spellCheck={false}
          />
        </div>
        <button type="submit" hidden />
      </form>
      <div role="status">
        {test.isError && <Callout tone="danger">The test did not run: {test.error.message}</Callout>}
        {result?.ok && <Callout tone="success">The reference resolved.</Callout>}
        {result && !result.ok && (
          <Callout tone="danger">{testFailureText(result.code ?? '', result.message ?? 'The reference did not resolve.')}</Callout>
        )}
      </div>
    </Modal>
  );
}

/** Settings tab: HashiCorp Vault, AWS Secrets Manager and Azure Key Vault
 *  providers that credentials and secret variables can reference. Only admins
 *  add, edit, delete and test providers (the server refuses anyone else);
 *  other readers see the list. */
export function SecretsProvidersTab() {
  const isAdmin = useAuthStatus().data?.role === 'admin';
  const query = useSecretsProviders();
  const remove = useDeleteSecretsProvider();
  const deleting = usePendingKeys<number>();
  const { confirm, alert } = useDialogs();
  const [editing, setEditing] = useState<SecretsProvider | 'new' | null>(null);
  const [testing, setTesting] = useState<SecretsProvider | null>(null);

  const rows = query.data?.providers ?? [];
  const addButton = isAdmin ? (
    <button type="button" className="btn btn-sm btn-primary" onClick={() => setEditing('new')}>
      Add secrets provider
    </button>
  ) : undefined;

  const handleDelete = (provider: SecretsProvider) =>
    void deleting.run(provider.id, async () => {
      const agreed = await confirm({
        title: 'Delete secrets provider',
        message: `Delete the secrets provider "${provider.name}"? The secrets it holds are not changed.`,
        confirmLabel: 'Delete provider',
      });
      if (!agreed) return;
      try {
        await remove.mutateAsync(provider.id);
      } catch (err) {
        await alert({
          title: 'Provider not deleted',
          message: `The secrets provider "${provider.name}" was not deleted: ${(err as Error).message}`,
          variant: 'error',
        });
      }
    });

  if (query.isError && !query.data) return <QueryError what="secrets providers" query={query} />;
  if (query.isPending) return <LoadingState />;

  return (
    <div className="stack stack-sm">
      {rows.length > 0 && addButton && <div style={{ display: 'flex', justifyContent: 'flex-end' }}>{addButton}</div>}
      {rows.length === 0 ? (
        <EmptyState
          compact
          message="No secrets providers yet."
          description={
            isAdmin
              ? 'Add HashiCorp Vault, AWS Secrets Manager or Azure Key Vault, then point credentials and secret variables at secrets kept there instead of storing them in Plexus.'
              : 'An admin adds HashiCorp Vault, AWS Secrets Manager or Azure Key Vault providers here.'
          }
          action={addButton}
        />
      ) : (
        <DataTable compact aria-label="Secrets providers">
          <thead>
            <tr>
              <th>Name</th>
              <th>Type</th>
              <th>Used by</th>
              <th>Cache</th>
              {isAdmin && <th style={RIGHT}>Actions</th>}
            </tr>
          </thead>
          <tbody>
            {rows.map((provider) => (
              <tr key={provider.id}>
                <td>
                  {provider.name}
                  {!provider.enabled && (
                    <>
                      {' '}
                      <Badge tone="neutral" size="sm">
                        Disabled
                      </Badge>
                    </>
                  )}
                  {provider.sdk.status !== 'ok' && (
                    <>
                      {' '}
                      <Badge tone="warning" size="sm" title={`Install ${provider.sdk.missing.join(', ')} on the server`}>
                        SDK not installed
                      </Badge>
                    </>
                  )}
                  {provider.description && (
                    <div className="form-help" style={{ margin: 0 }}>
                      {provider.description}
                    </div>
                  )}
                </td>
                <td>
                  {providerTypeLabel(provider.provider_type)}
                  {provider.allow_user_credentials && (
                    <div className="form-help" style={{ margin: 0 }}>
                      Open to personal credentials
                    </div>
                  )}
                </td>
                <td>{usageText(provider)}</td>
                <td>{provider.cache_ttl ? `${provider.cache_ttl.toLocaleString()} s` : 'Off'}</td>
                {isAdmin && (
                  <td style={RIGHT}>
                    <div style={{ display: 'inline-flex', gap: 'var(--space-1)', flexWrap: 'wrap', justifyContent: 'flex-end' }}>
                      <button type="button" className="btn btn-sm btn-secondary" onClick={() => setTesting(provider)}>
                        Test
                      </button>
                      <button type="button" className="btn btn-sm btn-secondary" onClick={() => setEditing(provider)}>
                        Edit
                      </button>
                      <DeleteButton
                        busy={deleting.isPending(provider.id)}
                        onClick={() => handleDelete(provider)}
                        aria-label={`Delete secrets provider ${provider.name}`}
                      />
                    </div>
                  </td>
                )}
              </tr>
            ))}
          </tbody>
        </DataTable>
      )}
      {isAdmin && editing && (
        <SecretsProviderModal
          key={editing === 'new' ? 'new' : editing.id}
          provider={editing === 'new' ? null : editing}
          onClose={() => setEditing(null)}
        />
      )}
      {isAdmin && testing && <TestReferenceModal provider={testing} onClose={() => setTesting(null)} />}
    </div>
  );
}
