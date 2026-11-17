import { useId, useState } from 'react';

import { useChatCommandLog } from '@/api/chatops';
import { Badge } from '@/components/Badge';
import { DataTable } from '@/components/DataTable';
import { EmptyState } from '@/components/EmptyState';
import { LoadingState } from '@/components/LoadingState';
import { QueryError } from '@/components/QueryError';
import { outcomeTone } from '@/lib/chatops';
import { formatBackendDateTime } from '@/lib/datetime';

const OUTCOMES = ['ok', 'denied', 'unmapped', 'error', 'unknown', 'rate_limited'];

/** The newest 200 commands received, filterable by platform and outcome. */
export function ChatOpsLog() {
  const fid = useId();
  const [platform, setPlatform] = useState('');
  const [outcome, setOutcome] = useState('');
  const log = useChatCommandLog(platform, outcome);
  const rows = log.data ?? [];

  return (
    <div className="stack stack-sm">
      <div className="toolbar">
        <label className="form-label" htmlFor={`${fid}-platform`} style={{ margin: 0 }}>Platform</label>
        <select
          id={`${fid}-platform`}
          className="form-select form-select-sm"
          value={platform}
          onChange={(e) => setPlatform(e.target.value)}
        >
          <option value="">All</option>
          <option value="slack">Slack</option>
          <option value="webex">Webex</option>
          <option value="teams">Teams</option>
        </select>
        <label className="form-label" htmlFor={`${fid}-outcome`} style={{ margin: 0 }}>Outcome</label>
        <select
          id={`${fid}-outcome`}
          className="form-select form-select-sm"
          value={outcome}
          onChange={(e) => setOutcome(e.target.value)}
        >
          <option value="">All</option>
          {OUTCOMES.map((o) => (
            <option key={o} value={o}>{o}</option>
          ))}
        </select>
      </div>
      {log.isError && !log.data && <QueryError what="the command log" query={log} />}
      {log.isPending && <LoadingState text="Loading the command log…" />}
      {log.data && rows.length === 0 && <EmptyState compact message="No commands received yet." />}
      {rows.length > 0 && (
        <DataTable compact aria-label="ChatOps command log">
          <thead>
            <tr>
              <th>Time</th>
              <th>Platform</th>
              <th>Chat user</th>
              <th>Plexus user</th>
              <th>Command</th>
              <th>Outcome</th>
              <th style={{ textAlign: 'right' }}>ms</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((r) => (
              <tr key={r.id}>
                <td>{formatBackendDateTime(r.created_at)}</td>
                <td>{r.platform}</td>
                <td>
                  <code>{r.chat_user_id}</code>
                  {r.chat_user_name && <div className="text-muted">{r.chat_user_name}</div>}
                </td>
                <td>{r.username || '-'}</td>
                <td>
                  <code>{[r.command, r.arguments].filter(Boolean).join(' ')}</code>
                </td>
                <td>
                  <Badge tone={outcomeTone(r.outcome)} size="sm">{r.outcome}</Badge>
                  {r.detail && <div className="text-muted">{r.detail}</div>}
                </td>
                <td style={{ textAlign: 'right' }}>{r.duration_ms}</td>
              </tr>
            ))}
          </tbody>
        </DataTable>
      )}
    </div>
  );
}
