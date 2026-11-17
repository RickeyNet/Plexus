import { useId, useState } from 'react';

import {
  ChatPlatform,
  useChatUserMappings,
  useCreateChatUserMapping,
  useDeleteChatUserMapping,
} from '@/api/chatops';
import { useAdminUsers } from '@/api/settings';
import { BusyButton } from '@/components/BusyButton';
import { Callout } from '@/components/Callout';
import { DataTable } from '@/components/DataTable';
import { useDialogs } from '@/components/DialogProvider-context';
import { EmptyState } from '@/components/EmptyState';
import { FieldError } from '@/components/FieldError';
import { LoadingState } from '@/components/LoadingState';
import { QueryError } from '@/components/QueryError';
import { CHAT_ID_HINT, MappingFormErrors, validateMapping } from '@/lib/chatops';
import { formatBackendDateTime } from '@/lib/datetime';
import { usePendingKeys } from '@/lib/usePendingKeys';

const PLATFORM_LABEL: Record<ChatPlatform, string> = { slack: 'Slack', webex: 'Webex', teams: 'Teams' };

function AddMappingForm() {
  const fid = useId();
  const users = useAdminUsers();
  const create = useCreateChatUserMapping();
  const [platform, setPlatform] = useState<ChatPlatform>('slack');
  const [chatUserId, setChatUserId] = useState('');
  const [label, setLabel] = useState('');
  const [userId, setUserId] = useState<number | null>(null);
  const [errors, setErrors] = useState<MappingFormErrors>({});
  const [failure, setFailure] = useState<string | null>(null);

  return (
    <form
      onSubmit={(e) => {
        e.preventDefault();
        setFailure(null);
        const found = validateMapping({ chatUserId, userId });
        setErrors(found);
        if (Object.keys(found).length || userId === null) return;
        create.mutate(
          { platform, chat_user_id: chatUserId.trim(), chat_label: label.trim(), user_id: userId },
          {
            onSuccess: () => {
              setChatUserId('');
              setLabel('');
            },
            onError: (err) => setFailure(`The mapping was not added: ${(err as Error).message}`),
          },
        );
      }}
    >
      {failure && <Callout tone="danger">{failure}</Callout>}
      <div style={{ display: 'flex', gap: 'var(--space-3)', flexWrap: 'wrap', alignItems: 'flex-start' }}>
        <div className="form-group" style={{ flex: '0 1 140px' }}>
          <label className="form-label" htmlFor={`${fid}-platform`}>Platform</label>
          <select
            id={`${fid}-platform`}
            className="form-select"
            value={platform}
            onChange={(e) => setPlatform(e.target.value as ChatPlatform)}
          >
            {(Object.keys(PLATFORM_LABEL) as ChatPlatform[]).map((p) => (
              <option key={p} value={p}>{PLATFORM_LABEL[p]}</option>
            ))}
          </select>
        </div>
        <div className="form-group" style={{ flex: '1 1 240px' }}>
          <label className="form-label" htmlFor={`${fid}-chat-id`}>Chat user id</label>
          <input
            id={`${fid}-chat-id`}
            className="form-input"
            value={chatUserId}
            aria-invalid={!!errors.chatUserId}
            aria-describedby={`${fid}-chat-id-err ${fid}-chat-id-help`}
            onChange={(e) => {
              setErrors({ ...errors, chatUserId: undefined });
              setChatUserId(e.target.value);
            }}
          />
          <FieldError id={`${fid}-chat-id-err`}>{errors.chatUserId}</FieldError>
          <div className="form-help" id={`${fid}-chat-id-help`}>{CHAT_ID_HINT[platform]}</div>
        </div>
        <div className="form-group" style={{ flex: '1 1 160px' }}>
          <label className="form-label" htmlFor={`${fid}-label`}>Label (optional)</label>
          <input id={`${fid}-label`} className="form-input" value={label} onChange={(e) => setLabel(e.target.value)} />
        </div>
        <div className="form-group" style={{ flex: '1 1 180px' }}>
          <label className="form-label" htmlFor={`${fid}-user`}>Plexus user</label>
          <select
            id={`${fid}-user`}
            className="form-select"
            value={userId ?? ''}
            aria-invalid={!!errors.userId}
            aria-describedby={`${fid}-user-err`}
            onChange={(e) => {
              setErrors({ ...errors, userId: undefined });
              setUserId(e.target.value ? Number(e.target.value) : null);
            }}
          >
            <option value="">Choose a user</option>
            {(users.data ?? []).map((u) => (
              <option key={u.id} value={u.id}>
                {u.username}
                {u.role === 'admin' ? ' (admin)' : ''}
              </option>
            ))}
          </select>
          <FieldError id={`${fid}-user-err`}>{errors.userId}</FieldError>
          {users.isError && <FieldError>The user list did not load.</FieldError>}
        </div>
        <div className="form-group" style={{ alignSelf: 'flex-end' }}>
          <BusyButton type="submit" className="btn btn-primary" busy={create.isPending} busyLabel="Adding…">
            Add mapping
          </BusyButton>
        </div>
      </div>
    </form>
  );
}

/** Chat identities and the Plexus user each one's commands run as. */
export function ChatOpsMappings() {
  const { confirm, alert } = useDialogs();
  const mappings = useChatUserMappings();
  const remove = useDeleteChatUserMapping();
  const removing = usePendingKeys<number>();
  const rows = mappings.data ?? [];

  return (
    <div className="stack stack-sm">
      <p className="text-muted" style={{ margin: 0 }}>
        A command runs with the mapped user&apos;s permissions. Chat users with no mapping get help and nothing else;
        the help text shows them the id to give an admin.
      </p>
      <AddMappingForm />
      {mappings.isError && !mappings.data && <QueryError what="user mappings" query={mappings} />}
      {mappings.isPending && <LoadingState text="Loading mappings…" />}
      {mappings.data && rows.length === 0 && <EmptyState compact message="No chat users are mapped yet." />}
      {rows.length > 0 && (
        <DataTable compact aria-label="Chat user mappings">
          <thead>
            <tr>
              <th>Platform</th>
              <th>Chat user</th>
              <th>Plexus user</th>
              <th>Added</th>
              <th style={{ textAlign: 'right' }}>Actions</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((m) => (
              <tr key={m.id}>
                <td>{PLATFORM_LABEL[m.platform] ?? m.platform}</td>
                <td>
                  <code>{m.chat_user_id}</code>
                  {m.chat_label && <div className="text-muted">{m.chat_label}</div>}
                </td>
                <td>{m.username || 'Deleted user'}</td>
                <td>
                  {formatBackendDateTime(m.created_at)} by {m.created_by || '-'}
                </td>
                <td style={{ textAlign: 'right' }}>
                  <BusyButton
                    className="btn btn-sm btn-danger"
                    busy={removing.isPending(m.id)}
                    busyLabel="Removing…"
                    onClick={async () => {
                      const agreed = await confirm({
                        title: 'Remove mapping',
                        message: `Remove the mapping of ${m.chat_user_id} to ${m.username}? Their chat commands stop working at once.`,
                        confirmLabel: 'Remove mapping',
                        confirmVariant: 'danger',
                      });
                      if (!agreed) return;
                      await removing.run(m.id, async () => {
                        try {
                          await remove.mutateAsync(m.id);
                        } catch (e) {
                          void alert({ message: `The mapping was not removed: ${(e as Error).message}`, variant: 'error' });
                        }
                      });
                    }}
                  >
                    Remove
                  </BusyButton>
                </td>
              </tr>
            ))}
          </tbody>
        </DataTable>
      )}
    </div>
  );
}
