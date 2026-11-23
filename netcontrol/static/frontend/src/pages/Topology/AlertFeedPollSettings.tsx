import { useState } from 'react';

import { BusyButton } from '@/components/BusyButton';
import { formatBackendDateTime } from '@/lib/datetime';

export interface AlertFeedPollConfig {
  poll_enabled: boolean;
  interval_seconds: number;
  excluded_sources: number[];
}

export interface AlertFeedPollSource {
  id: number;
  name: string;
  has_api_key: boolean;
  excluded: boolean;
  last_ok_at: string;
  last_error: string;
  /** The feed's own status text, shown in a Feed column when given. */
  status?: string;
}

export type AlertFeedPollUpdate = Partial<AlertFeedPollConfig>;

interface AlertFeedPollSettingsProps {
  config: AlertFeedPollConfig | null;
  minSeconds: number;
  maxSeconds: number;
  lastPollAt: string;
  lastPollError: string;
  sources: AlertFeedPollSource[];
  saving: boolean;
  polling: boolean;
  onUpdate: (body: AlertFeedPollUpdate) => unknown;
  onPoll: () => void;
  /** The poll switch's label ("Poll assurance alerts"). */
  pollLabel: string;
  /** What one poll costs ("One API call per organization per poll"). */
  costNote: string;
  /** The heading of the source column ("Organization"). */
  sourceHeading: string;
  /** The vendor, for the per-source checkbox label ("Meraki"). */
  vendor: string;
}

/**
 * The poll part of an alert feed's settings (administrators only): the poll
 * switch and interval, Poll Now, and the per-source opt-out with each
 * source's last success and error. Shared by the Meraki alerts and the vendor
 * alert feeds (the Cato events feed).
 */
export function AlertFeedPollSettings({
  config,
  minSeconds,
  maxSeconds,
  lastPollAt,
  lastPollError,
  sources,
  saving,
  polling,
  onUpdate,
  onPoll,
  pollLabel,
  costNote,
  sourceHeading,
  vendor,
}: AlertFeedPollSettingsProps) {
  const [pollEnabled, setPollEnabled] = useState(true);
  const [seconds, setSeconds] = useState(60);
  const [prevConfig, setPrevConfig] = useState(config);
  // Re-seed the editable fields when the stored settings load or change.
  if (config !== prevConfig) {
    setPrevConfig(config);
    setPollEnabled(Boolean(config?.poll_enabled));
    setSeconds(config?.interval_seconds ?? 60);
  }
  const pollDirty = config !== null && (pollEnabled !== config.poll_enabled || seconds !== config.interval_seconds);
  const showStatus = sources.some((s) => s.status !== undefined);

  function toggleSource(id: number, polled: boolean) {
    const excluded = new Set(config?.excluded_sources ?? []);
    if (polled) excluded.delete(id);
    else excluded.add(id);
    void onUpdate({ excluded_sources: [...excluded] });
  }

  return (
    <>
      <div style={{ display: 'flex', gap: '1rem', alignItems: 'center', flexWrap: 'wrap' }}>
        <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', margin: 0 }}>
          <input type="checkbox" checked={pollEnabled} disabled={!config} onChange={(e) => setPollEnabled(e.target.checked)} />
          {pollLabel}
        </label>
        <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', margin: 0 }}>
          Every
          <input
            className="form-input"
            type="number"
            style={{ width: '6rem' }}
            min={minSeconds}
            max={maxSeconds}
            value={seconds}
            disabled={!config}
            onChange={(e) => setSeconds(parseInt(e.target.value, 10) || minSeconds)}
          />
          seconds
        </label>
        <BusyButton
          className="btn btn-secondary btn-sm"
          busy={saving}
          disabled={!pollDirty}
          onClick={() => void onUpdate({ poll_enabled: pollEnabled, interval_seconds: seconds })}
        >
          Save
        </BusyButton>
        <BusyButton className="btn btn-secondary btn-sm" busy={polling} busyLabel="Polling…" onClick={onPoll}>
          Poll Now
        </BusyButton>
      </div>
      <div className="text-muted" style={{ fontSize: '0.85em' }}>
        {costNote} ({minSeconds} to {maxSeconds} seconds), outbound only. Last poll:{' '}
        {formatBackendDateTime(lastPollAt || null)}
        {lastPollError ? ` (${lastPollError})` : ''}.
      </div>

      {sources.length > 0 && (
        <table className="data-table">
          <thead>
            <tr>
              <th>Poll</th>
              <th>{sourceHeading}</th>
              {showStatus && <th>Feed</th>}
              <th>Last success</th>
              <th>Last error</th>
            </tr>
          </thead>
          <tbody>
            {sources.map((s) => (
              <tr key={s.id}>
                <td>
                  <input
                    type="checkbox"
                    aria-label={`Poll ${vendor} alerts of ${s.name}`}
                    checked={!s.excluded}
                    disabled={saving}
                    onChange={(e) => toggleSource(s.id, e.target.checked)}
                  />
                </td>
                <td>
                  {s.name}
                  {!s.has_api_key && <span className="text-muted" style={{ fontSize: '0.85em' }}> no API key</span>}
                </td>
                {showStatus && <td>{s.status ?? '-'}</td>}
                <td style={{ whiteSpace: 'nowrap' }}>{formatBackendDateTime(s.last_ok_at || null)}</td>
                <td>{s.last_error || '-'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </>
  );
}
