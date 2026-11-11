import { type FormEvent, useId, useState } from 'react';
import type { UseQueryResult } from '@tanstack/react-query';

import type { CloudPullResult, CloudSyncConfig, CloudSyncConfigResponse, CloudSyncCursor, CloudSyncStatus } from '@/api/cloud';
import { BusyButton } from '@/components/BusyButton';
import { Callout } from '@/components/Callout';
import { LoadingState } from '@/components/LoadingState';
import { QueryError } from '@/components/QueryError';
import { formatBackendDateTime } from '@/lib/datetime';
import { parseBoundedInt } from '@/lib/numberInput';
import { useFlashMessage } from '@/lib/useFlashMessage';
import { CheckboxField, FormRow } from '@/pages/Settings/FormFields';
import { providerLabel, pullOutcome } from './helpers';

const DEFAULT_INTERVAL_SECONDS = 300;
const DEFAULT_LOOKBACK_MINUTES = 15;

/** The parts of a sync-config mutation this panel uses. */
interface SaveMutation {
  mutateAsync: (cfg: CloudSyncConfig) => Promise<unknown>;
  isPending: boolean;
}

/** The parts of a pull mutation this panel uses; null pulls every eligible account. */
interface PullMutation {
  mutateAsync: (accountId: number | null) => Promise<CloudPullResult>;
  isPending: boolean;
}

interface Props {
  kind: 'Flow' | 'Traffic';
  syncConfig: UseQueryResult<CloudSyncConfigResponse>;
  syncCursors: UseQueryResult<{ cursors: CloudSyncCursor[] }>;
  updateConfig: SaveMutation;
  triggerPull: PullMutation;
  selectedAccountId: number | null;
}

/**
 * The scheduled-pull settings, manual pull buttons, last run and per-account
 * cursors of the flow or traffic sync. Save and pull results are shown here,
 * beside the buttons that started them.
 */
export function SyncControls(props: Props) {
  return (
    <section className="stack stack-sm">
      <h3 style={{ margin: 0 }}>{props.kind} sync</h3>
      <SyncPanel {...props} />
    </section>
  );
}

function SyncPanel({ kind, syncConfig, syncCursors, updateConfig, triggerPull, selectedAccountId }: Props) {
  const noun = kind.toLowerCase();
  const { message, flash } = useFlashMessage();

  // A form seeded with defaults could be saved over the real settings, so it
  // is only rendered once the settings have loaded.
  if (syncConfig.isError && !syncConfig.data) {
    return <QueryError what={`${noun} sync settings`} query={syncConfig} />;
  }
  if (syncConfig.isPending) return <div className="card"><LoadingState /></div>;

  const config = syncConfig.data.config;
  const status = syncConfig.data.status ?? null;

  async function save(cfg: CloudSyncConfig) {
    try {
      await updateConfig.mutateAsync(cfg);
      flash('success', `Cloud ${noun} sync settings saved`);
    } catch (e) {
      flash('error', `Saving ${noun} sync settings failed: ${(e as Error).message}`);
    }
  }

  async function pull(accountId: number | null) {
    const label = accountId ? `Cloud ${noun} pull (selected account)` : `Cloud ${noun} pull`;
    try {
      const outcome = pullOutcome(label, await triggerPull.mutateAsync(accountId));
      flash(outcome.kind, outcome.text);
    } catch (e) {
      flash('error', `Cloud ${noun} pull failed: ${(e as Error).message}`);
    }
  }

  return (
    <div className="card stack stack-sm">
      <SyncSettingsForm
        kind={kind}
        config={config}
        isSaving={updateConfig.isPending}
        isPulling={triggerPull.isPending}
        selectedAccountId={selectedAccountId}
        onSave={save}
        onPull={pull}
      />
      {message && (
        <Callout tone={message.kind === 'success' ? 'success' : 'danger'}>{message.text}</Callout>
      )}
      <div className="text-muted">{statusLabel(kind, status)}</div>
      {Array.isArray(status?.errors) && status.errors.length > 0 && (
        <details>
          <summary style={{ color: 'var(--danger)', cursor: 'pointer' }}>
            {status.errors.length} sync error(s) — expand for details
          </summary>
          <ul style={{ margin: 'var(--space-1) 0 0 var(--space-4)', padding: 0 }}>
            {status.errors.map((err, i) => (
              <li key={i} style={{ color: 'var(--danger)', fontSize: 'var(--text-sm)' }}>{String(err)}</li>
            ))}
          </ul>
        </details>
      )}
      <SyncCursors kind={kind} syncCursors={syncCursors} />
    </div>
  );
}

interface FormProps {
  kind: 'Flow' | 'Traffic';
  config: CloudSyncConfig | null;
  isSaving: boolean;
  isPulling: boolean;
  selectedAccountId: number | null;
  onSave: (cfg: CloudSyncConfig) => Promise<void>;
  onPull: (accountId: number | null) => Promise<void>;
}

function SyncSettingsForm({ kind, config, isSaving, isPulling, selectedAccountId, onSave, onPull }: FormProps) {
  const fid = useId();
  const [enabled, setEnabled] = useState(Boolean(config?.enabled));
  // Number fields hold their raw text so they can be cleared and retyped.
  const [intervalText, setIntervalText] = useState(String(config?.interval_seconds ?? DEFAULT_INTERVAL_SECONDS));
  const [lookbackText, setLookbackText] = useState(String(config?.lookback_minutes ?? DEFAULT_LOOKBACK_MINUTES));

  const [prevConfig, setPrevConfig] = useState(config);
  // Re-seed the editable fields when the saved settings change.
  if (config !== prevConfig) {
    setPrevConfig(config);
    setEnabled(Boolean(config?.enabled));
    setIntervalText(String(config?.interval_seconds ?? DEFAULT_INTERVAL_SECONDS));
    setLookbackText(String(config?.lookback_minutes ?? DEFAULT_LOOKBACK_MINUTES));
  }

  function handleSubmit(e: FormEvent) {
    e.preventDefault();
    void onSave({
      enabled,
      interval_seconds: parseBoundedInt(intervalText, 60, 3600, DEFAULT_INTERVAL_SECONDS),
      lookback_minutes: parseBoundedInt(lookbackText, 1, 1440, DEFAULT_LOOKBACK_MINUTES),
    });
  }

  return (
    <form onSubmit={handleSubmit}>
      <FormRow>
        <CheckboxField
          inRow
          label={kind === 'Flow' ? 'Pull flow logs on a schedule' : 'Pull traffic metrics on a schedule'}
          checked={enabled}
          onChange={setEnabled}
        />
        <div className="form-group" style={{ flex: '0 1 180px' }}>
          <label className="form-label" htmlFor={`${fid}-interval`}>Interval (seconds)</label>
          <input
            id={`${fid}-interval`}
            className="form-input"
            type="number"
            min={60}
            max={3600}
            value={intervalText}
            aria-describedby={`${fid}-interval-help`}
            onChange={(e) => setIntervalText(e.target.value)}
          />
          <div className="form-help" id={`${fid}-interval-help`}>60 to 3600</div>
        </div>
        <div className="form-group" style={{ flex: '0 1 180px' }}>
          <label className="form-label" htmlFor={`${fid}-lookback`}>Lookback (minutes)</label>
          <input
            id={`${fid}-lookback`}
            className="form-input"
            type="number"
            min={1}
            max={1440}
            value={lookbackText}
            aria-describedby={`${fid}-lookback-help`}
            onChange={(e) => setLookbackText(e.target.value)}
          />
          <div className="form-help" id={`${fid}-lookback-help`}>1 to 1440</div>
        </div>
      </FormRow>
      <div style={{ display: 'flex', gap: 'var(--space-2)', flexWrap: 'wrap' }}>
        <BusyButton type="submit" className="btn btn-secondary" busy={isSaving} busyLabel="Saving…">
          Save sync settings
        </BusyButton>
        <BusyButton className="btn btn-primary" busy={isPulling} onClick={() => void onPull(null)}>
          Pull all
        </BusyButton>
        <BusyButton
          className="btn btn-secondary"
          busy={isPulling}
          disabled={!selectedAccountId}
          title={selectedAccountId ? undefined : 'Select an account in the filter above to pull only that account'}
          onClick={() => {
            if (selectedAccountId) void onPull(selectedAccountId);
          }}
        >
          Pull selected account
        </BusyButton>
      </div>
      <div className="form-help">
        Saved: {config?.enabled ? 'on a schedule' : 'manual only'}, every {config?.interval_seconds ?? DEFAULT_INTERVAL_SECONDS} s,
        lookback {config?.lookback_minutes ?? DEFAULT_LOOKBACK_MINUTES} min.
      </div>
    </form>
  );
}

function statusLabel(kind: 'Flow' | 'Traffic', status: CloudSyncStatus | null): string {
  const noun = kind.toLowerCase();
  if (!status) return `No ${noun} sync action recorded yet.`;
  const source = status.source === 'scheduled' ? 'Scheduled' : 'Manual';
  const scope = status.scope === 'account'
    ? status.account_name || `Account #${status.account_id}`
    : 'all eligible accounts';
  const ingested = Number(status.ingested ?? 0).toLocaleString();
  const errCount = Array.isArray(status.errors) ? status.errors.length : 0;
  const outcome = status.ok === false ? 'failed' : 'completed';
  return `${formatBackendDateTime(status.last_run_at)}: ${source} ${noun} sync ${outcome} for ${scope}. Ingested ${ingested}.${errCount ? ` Errors: ${errCount}.` : ''}`;
}

function SyncCursors({ kind, syncCursors }: { kind: 'Flow' | 'Traffic'; syncCursors: Props['syncCursors'] }) {
  if (syncCursors.isError && !syncCursors.data) return <QueryError what="sync cursors" query={syncCursors} />;
  if (syncCursors.isPending) return <LoadingState variant="inline" />;
  const cursors = syncCursors.data.cursors ?? [];
  if (!cursors.length) {
    return (
      <div className="text-muted">
        No {kind.toLowerCase()} sync cursors yet. Run a manual pull or wait for the scheduler.
      </div>
    );
  }
  return (
    <div style={{ overflowX: 'auto' }}>
      <table className="data-table">
        <thead>
          <tr><th>Account / subscription / project</th><th>Provider</th><th>Last pull end</th><th>Updated</th></tr>
        </thead>
        <tbody>
          {cursors.map((c, i) => (
            <tr key={`${c.provider ?? ''}-${c.account_id ?? `row-${i}`}`}>
              <td>{c.account_name || `Account #${c.account_id}`}</td>
              <td>{providerLabel(c.provider)}</td>
              <td>{formatBackendDateTime(c.last_pull_end)}</td>
              <td>{formatBackendDateTime(c.updated_at)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
