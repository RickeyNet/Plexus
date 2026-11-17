import { useId, useMemo, useState } from 'react';

import {
  ChatCommandInfo,
  ChatPlatformInfo,
  useChatOps,
  useDeleteChatBot,
  useUpdateChatBot,
} from '@/api/chatops';
import { Badge } from '@/components/Badge';
import { BusyButton } from '@/components/BusyButton';
import { CopyButton } from '@/components/CopyButton';
import { useDialogs } from '@/components/DialogProvider-context';
import { FieldError } from '@/components/FieldError';
import { LoadingState } from '@/components/LoadingState';
import { QueryError } from '@/components/QueryError';
import { BotFormErrors, inboundUrl, toggleCommand, validateBotForm } from '@/lib/chatops';

import { ChatOpsLog } from './ChatOpsLog';
import { ChatOpsMappings } from './ChatOpsMappings';
import { ChatOpsPresets } from './ChatOpsPresets';
import { CheckboxField, CheckboxRow, FormRow, TextField } from './FormFields';
import { SaveBar } from './SaveBar';
import { SectionCard } from './SectionCard';
import { FormStatus } from './StatusLine';
import { useSavedDraft } from './useSavedDraft';

const PATH_LABEL: Record<string, string> = {
  commands: 'Slash command request URL',
  interactivity: 'Interactivity request URL',
  webhook: 'Webhook URL',
};

interface BotDraft {
  name: string;
  enabled: boolean;
  allowed: string[];
  secret: string;
  token: string;
  clearToken: boolean;
}

function botDraft(info: ChatPlatformInfo, defaults: string[]): BotDraft {
  return {
    name: info.bot?.name ?? info.label,
    enabled: info.bot?.enabled ?? true,
    allowed: info.bot?.allowed_commands ?? defaults,
    secret: '',
    token: '',
    clearToken: false,
  };
}

interface BotSectionProps {
  info: ChatPlatformInfo;
  commands: ChatCommandInfo[];
  defaults: string[];
}

function BotSection({ info, commands, defaults }: BotSectionProps) {
  const fid = useId();
  const { confirm, alert } = useDialogs();
  const update = useUpdateChatBot();
  const remove = useDeleteChatBot();
  const server = useMemo(() => botDraft(info, defaults), [info, defaults]);
  const { draft, setDraft, dirty, discard, markSaved } = useSavedDraft<BotDraft>(server);
  const [status, setStatus] = useState<FormStatus | null>(null);
  const [errors, setErrors] = useState<BotFormErrors>({});
  if (!draft) return <LoadingState />;

  const order = commands.map((c) => c.name);
  const configured = info.bot !== null;
  const origin = window.location.origin;

  return (
    <form
      onSubmit={(e) => {
        e.preventDefault();
        setStatus(null);
        const found = validateBotForm(
          info.platform,
          { secret: draft.secret, token: draft.token },
          !!info.bot?.signing_secret_configured,
        );
        setErrors(found);
        if (Object.keys(found).length) return;
        update.mutate(
          {
            platform: info.platform,
            body: {
              name: draft.name,
              enabled: draft.enabled,
              allowed_commands: draft.allowed,
              signing_secret: draft.secret.trim() || null,
              bot_token: draft.token.trim() || null,
              clear_bot_token: draft.clearToken,
            },
          },
          {
            onSuccess: (bot) => {
              markSaved({
                name: bot.name,
                enabled: bot.enabled,
                allowed: bot.allowed_commands,
                secret: '',
                token: '',
                clearToken: false,
              });
              setStatus({
                kind: 'success',
                message: `Saved. The ${info.label} bot is ${bot.enabled ? 'on' : 'off'}.`,
              });
            },
            onError: (err) =>
              setStatus({ kind: 'error', message: `The bot was not saved: ${(err as Error).message}` }),
          },
        );
      }}
    >
      <FormRow>
        <TextField
          label="Display name"
          flex="1 1 220px"
          value={draft.name}
          onChange={(v) => setDraft({ ...draft, name: v })}
        />
        <CheckboxField
          inRow
          label="Enabled"
          checked={draft.enabled}
          onChange={(v) => setDraft({ ...draft, enabled: v })}
        />
      </FormRow>

      <FormRow>
        <div className="form-group" style={{ flex: '1 1 260px' }}>
          <label className="form-label" htmlFor={`${fid}-secret`}>{info.secret_label}</label>
          <input
            id={`${fid}-secret`}
            className="form-input"
            type="password"
            autoComplete="new-password"
            value={draft.secret}
            placeholder={info.bot?.signing_secret_configured ? 'Stored. Leave blank to keep it.' : ''}
            aria-invalid={!!errors.secret}
            aria-describedby={`${fid}-secret-err`}
            onChange={(e) => {
              setErrors({ ...errors, secret: undefined });
              setDraft({ ...draft, secret: e.target.value });
            }}
          />
          <FieldError id={`${fid}-secret-err`}>{errors.secret}</FieldError>
        </div>
        {info.has_bot_token && (
          <div className="form-group" style={{ flex: '1 1 260px' }}>
            <label className="form-label" htmlFor={`${fid}-token`}>{info.token_label}</label>
            <input
              id={`${fid}-token`}
              className="form-input"
              type="password"
              autoComplete="new-password"
              value={draft.token}
              placeholder={info.bot?.bot_token_configured ? 'Stored. Leave blank to keep it.' : ''}
              aria-invalid={!!errors.token}
              aria-describedby={`${fid}-token-err ${fid}-token-help`}
              onChange={(e) => {
                setErrors({ ...errors, token: undefined });
                setDraft({ ...draft, token: e.target.value, clearToken: false });
              }}
            />
            <FieldError id={`${fid}-token-err`}>{errors.token}</FieldError>
            <div className="form-help" id={`${fid}-token-help`}>
              Used to post replies and alert notifications.
            </div>
          </div>
        )}
      </FormRow>
      {info.has_bot_token && info.bot?.bot_token_configured && (
        <CheckboxRow>
          <CheckboxField
            label="Remove the stored bot token"
            checked={draft.clearToken}
            onChange={(v) => setDraft({ ...draft, clearToken: v, token: '' })}
          />
        </CheckboxRow>
      )}

      <div className="form-group" role="group" aria-labelledby={`${fid}-commands`}>
        <span className="form-label" id={`${fid}-commands`}>Allowed commands</span>
        <CheckboxRow>
          {commands.map((command) => (
            <CheckboxField
              key={command.name}
              label={
                <>
                  <code>{command.name}</code>
                  {command.write && (
                    <>
                      {' '}
                      <Badge tone="warning" size="sm">changes Plexus</Badge>
                    </>
                  )}
                </>
              }
              checked={draft.allowed.includes(command.name)}
              onChange={(on) => setDraft({ ...draft, allowed: toggleCommand(draft.allowed, command.name, on, order) })}
            />
          ))}
        </CheckboxRow>
        <div className="form-help">
          help is always on. Each command still needs the caller&apos;s own Plexus feature (and its .write key for
          ack and run).
        </div>
      </div>

      <div className="form-group">
        <span className="form-label">Addresses to give {info.label}</span>
        {Object.entries(info.paths).map(([purpose, path]) => (
          <div key={purpose} style={{ display: 'flex', gap: 'var(--space-2)', alignItems: 'center', flexWrap: 'wrap' }}>
            <span className="text-muted">{PATH_LABEL[purpose] ?? purpose}:</span>
            <code style={{ overflowWrap: 'anywhere' }}>{inboundUrl(origin, path)}</code>
            <CopyButton text={inboundUrl(origin, path)} label="Copy URL" />
          </div>
        ))}
      </div>

      <SaveBar
        name={`${info.label} bot`}
        dirty={dirty}
        busy={update.isPending}
        label={configured ? `Save ${info.label} Bot` : `Set Up ${info.label} Bot`}
        status={status}
        onDiscard={() => {
          setErrors({});
          discard();
        }}
      >
        {configured && (
          <BusyButton
            type="button"
            className="btn btn-danger"
            busy={remove.isPending}
            busyLabel="Removing…"
            onClick={async () => {
              const agreed = await confirm({
                title: 'Remove bot',
                message: `Remove the ${info.label} bot? Its stored secrets are deleted and ${info.label} commands stop working at once. User mappings are kept.`,
                confirmLabel: 'Remove bot',
                confirmVariant: 'danger',
              });
              if (!agreed) return;
              try {
                await remove.mutateAsync(info.platform);
              } catch (e) {
                void alert({ message: `The bot was not removed: ${(e as Error).message}`, variant: 'error' });
              }
            }}
          >
            Remove bot
          </BusyButton>
        )}
      </SaveBar>
    </form>
  );
}

/** Settings tab for the Slack, Webex and Teams command bots (docs/chatops.md). */
export function ChatOpsTab() {
  const overview = useChatOps();
  if (overview.isError && !overview.data) return <QueryError what="ChatOps settings" query={overview} />;
  if (!overview.data) return <LoadingState />;
  const { platforms, commands, default_commands: defaults } = overview.data;
  return (
    <div className="stack">
      {platforms.map((info) => (
        <SectionCard
          key={info.platform}
          title={
            <>
              {info.label}{' '}
              <Badge tone={info.bot?.enabled ? 'success' : 'neutral'} size="sm">
                {info.bot ? (info.bot.enabled ? 'On' : 'Off') : 'Not set up'}
              </Badge>
            </>
          }
        >
          <BotSection info={info} commands={commands} defaults={defaults} />
        </SectionCard>
      ))}
      <SectionCard title="User mappings">
        <ChatOpsMappings />
      </SectionCard>
      <SectionCard title="Job presets">
        <ChatOpsPresets />
      </SectionCard>
      <SectionCard title="Command log">
        <ChatOpsLog />
      </SectionCard>
    </div>
  );
}
