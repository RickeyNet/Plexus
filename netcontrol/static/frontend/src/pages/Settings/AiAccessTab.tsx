import { useState } from 'react';

import {
  McpSettings,
  useMcpSettings,
  useMcpTokens,
  useRevokeMcpToken,
  useUpdateMcpSettings,
} from '@/api/settings';
import { Badge } from '@/components/Badge';
import { BusyButton } from '@/components/BusyButton';
import { Callout } from '@/components/Callout';
import { CopyButton } from '@/components/CopyButton';
import { DataTable } from '@/components/DataTable';
import { useDialogs } from '@/components/DialogProvider-context';
import { EmptyState } from '@/components/EmptyState';
import { LoadingState } from '@/components/LoadingState';
import { QueryError } from '@/components/QueryError';
import { formatBackendDate, formatBackendDateTime } from '@/lib/datetime';
import { usePendingKeys } from '@/lib/usePendingKeys';

import { DATA_NOTICE, TokenStatus, endpointUrl, tokenStatus } from './aiAccess';
import { CheckboxField, CheckboxRow, FormRow, NumberField } from './FormFields';
import { McpTokenModal } from './McpTokenModal';
import { SaveBar } from './SaveBar';
import { SectionCard } from './SectionCard';
import { FormStatus } from './StatusLine';
import { useSavedDraft } from './useSavedDraft';

const STATUS_TONE: Record<TokenStatus, 'success' | 'warning' | 'neutral'> = {
  active: 'success',
  expired: 'warning',
  revoked: 'neutral',
};
const STATUS_LABEL: Record<TokenStatus, string> = { active: 'Active', expired: 'Expired', revoked: 'Revoked' };

function EndpointSection() {
  const query = useMcpSettings();
  const update = useUpdateMcpSettings();
  const { draft, setDraft, dirty, discard, markSaved } = useSavedDraft<McpSettings>(query.data);
  const [status, setStatus] = useState<FormStatus | null>(null);

  if (!draft) {
    if (query.isError) return <QueryError what="AI access settings" query={query} />;
    return <LoadingState />;
  }
  const url = endpointUrl(window.location.origin);

  return (
    <form
      onSubmit={(e) => {
        e.preventDefault();
        setStatus(null);
        update.mutate(draft, {
          onSuccess: (saved) => {
            markSaved(saved);
            setStatus({
              kind: 'success',
              message: saved.enabled ? 'Saved. The MCP endpoint is on.' : 'Saved. The MCP endpoint is off.',
            });
          },
          onError: (err) =>
            setStatus({
              kind: 'error',
              message: `The settings were not saved: ${(err as Error).message} Check the values and save again.`,
            }),
        });
      }}
    >
      <CheckboxRow>
        <CheckboxField
          label="Enable the MCP endpoint"
          checked={draft.enabled}
          onChange={(v) => setDraft({ ...draft, enabled: v })}
          help="While off, the endpoint answers 404 and no token works."
        />
      </CheckboxRow>

      <div className="form-group">
        <span className="form-label">Endpoint URL</span>
        <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center', flexWrap: 'wrap' }}>
          <code style={{ overflowWrap: 'anywhere' }}>{url}</code>
          <CopyButton text={url} label="Copy URL" />
        </div>
        <div className="form-help">
          AI clients must be able to reach this address. Cloud-hosted connectors that need OAuth are not
          supported.
        </div>
      </div>

      <FormRow>
        <NumberField
          label="Result size limit (bytes)"
          value={draft.max_result_bytes}
          min={10000}
          max={1000000}
          step={1000}
          flex="0 1 220px"
          help="10,000 to 1,000,000. Larger results are cut short and say so."
          onChange={(v) => setDraft({ ...draft, max_result_bytes: v })}
        />
        <NumberField
          label="Rows per page"
          value={draft.max_rows}
          min={10}
          max={1000}
          flex="0 1 180px"
          help="10 to 1,000. Lists continue with a cursor."
          onChange={(v) => setDraft({ ...draft, max_rows: v })}
        />
        <NumberField
          label="Calls per token per minute"
          value={draft.calls_per_minute}
          min={1}
          max={600}
          flex="0 1 220px"
          help="1 to 600. Further calls are refused until the minute passes."
          onChange={(v) => setDraft({ ...draft, calls_per_minute: v })}
        />
      </FormRow>

      <SaveBar
        name="AI Access"
        dirty={dirty}
        busy={update.isPending}
        label="Save AI Access Settings"
        status={status}
        onDiscard={discard}
      />
    </form>
  );
}

function TokensSection() {
  const { confirm, alert } = useDialogs();
  const tokens = useMcpTokens();
  const revoke = useRevokeMcpToken();
  const revoking = usePendingKeys<number>();
  const [creating, setCreating] = useState(false);

  const createButton = (
    <button type="button" className="btn btn-sm btn-primary" onClick={() => setCreating(true)}>
      Create token
    </button>
  );
  const rows = tokens.data?.tokens || [];

  return (
    <div className="stack stack-sm">
      {rows.length > 0 && <div style={{ display: 'flex', justifyContent: 'flex-end' }}>{createButton}</div>}

      {tokens.isLoading && <LoadingState text="Loading tokens…" />}
      {tokens.isError && !tokens.data && <QueryError what="tokens" query={tokens} />}
      {tokens.data && rows.length === 0 && (
        <EmptyState
          compact
          message="No tokens yet."
          description="Create a token for each AI client that should read Plexus data."
          action={createButton}
        />
      )}

      {rows.length > 0 && (
        <DataTable compact aria-label="MCP tokens">
          <thead>
            <tr>
              <th>Name</th>
              <th>Owner</th>
              <th>Categories</th>
              <th>Expires</th>
              <th>Last used</th>
              <th style={{ textAlign: 'right' }}>Calls</th>
              <th>Status</th>
              <th style={{ textAlign: 'right' }}>Actions</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((token) => {
              const status = tokenStatus(token);
              return (
                <tr key={token.id}>
                  <td>
                    {token.name}
                    <div className="form-help" style={{ margin: 0 }}>
                      <code>{token.token_prefix}…</code>
                    </div>
                  </td>
                  <td>{token.owner_username || 'Deleted user'}</td>
                  <td>
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.25rem' }}>
                      {token.categories.map((category) => (
                        <Badge key={category} tone="info" size="sm">
                          {category}
                        </Badge>
                      ))}
                    </div>
                  </td>
                  <td>{token.expires_at ? formatBackendDate(token.expires_at) : 'Never'}</td>
                  <td>{token.last_used_at ? formatBackendDateTime(token.last_used_at) : 'Never'}</td>
                  <td style={{ textAlign: 'right' }}>{token.call_count.toLocaleString()}</td>
                  <td>
                    <Badge tone={STATUS_TONE[status]} size="sm">
                      {STATUS_LABEL[status]}
                    </Badge>
                  </td>
                  <td style={{ textAlign: 'right' }}>
                    {status !== 'revoked' && (
                      <BusyButton
                        className="btn btn-sm btn-danger"
                        busy={revoking.isPending(token.id)}
                        busyLabel="Revoking…"
                        onClick={async () => {
                          const agreed = await confirm({
                            title: 'Revoke token',
                            message: `Revoke the token '${token.name}'? Clients using it stop working at once. This cannot be undone.`,
                            confirmLabel: 'Revoke token',
                            confirmVariant: 'danger',
                          });
                          if (!agreed) return;
                          await revoking.run(token.id, async () => {
                            try {
                              await revoke.mutateAsync(token.id);
                            } catch (e) {
                              void alert({
                                message: `The token '${token.name}' was not revoked: ${(e as Error).message} Try again.`,
                                variant: 'error',
                              });
                            }
                          });
                        }}
                      >
                        Revoke token
                      </BusyButton>
                    )}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </DataTable>
      )}

      {creating && (
        <McpTokenModal categories={tokens.data?.categories || []} onClose={() => setCreating(false)} />
      )}
    </div>
  );
}

/** Settings tab for the read-only MCP endpoint AI clients connect to. */
export function AiAccessTab() {
  return (
    <div className="stack">
      <Callout tone="info" role="note">
        {DATA_NOTICE}
      </Callout>
      <SectionCard title="MCP endpoint">
        <EndpointSection />
      </SectionCard>
      <SectionCard title="Tokens">
        <TokensSection />
      </SectionCard>
    </div>
  );
}
