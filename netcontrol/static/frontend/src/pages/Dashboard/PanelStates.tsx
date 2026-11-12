import type { ReactNode } from 'react';

import { EmptyState } from '@/components/EmptyState';
import { type FailedQuery, QueryError } from '@/components/QueryError';
import { type TimeRangePreset, useTimeRange } from '@/lib/timeRange-context';
import { describePreset, widerPreset } from '@/lib/timeRangeMap';

// What a Dashboard panel shows in place of its chart. Each says why the
// panel is empty and offers the one thing that fixes it. A panel whose data
// is not set up at all is not rendered: it is listed on the Not set up yet
// card instead (setupGuide.ts).

interface PanelEmptyProps {
  message: ReactNode;
  description?: ReactNode;
  action?: ReactNode;
}

/** An empty state the height of the chart it stands in for. */
export function PanelEmpty({ message, description, action }: PanelEmptyProps) {
  return (
    <div className="dashboard-response-empty">
      <EmptyState compact message={message} description={description} action={action} />
    </div>
  );
}

interface PanelRangeEmptyProps {
  /** What is missing, lower case plural: "response-time samples". */
  what: string;
  /** The range the panel asked for, when it clamps the page's range. */
  shown?: TimeRangePreset;
  /** The ranges the panel supports, when not all of them. */
  allowed?: readonly TimeRangePreset[];
  /** Why there may be nothing, when widening the range will not help. */
  hint?: ReactNode;
}

/**
 * Set up, but nothing in the selected time range: says which range and
 * offers the next longer one, which changes the range of the whole page.
 */
export function PanelRangeEmpty({ what, shown, allowed, hint }: PanelRangeEmptyProps) {
  const { range, setRange } = useTimeRange();
  const current = shown ?? range;
  const wider = widerPreset(current, allowed);
  return (
    <PanelEmpty
      message={`No ${what} in ${describePreset(current)}`}
      description={wider ? 'There may be some in a longer time range.' : hint}
      action={
        wider && (
          <button type="button" className="btn btn-sm btn-secondary" onClick={() => setRange(wider)}>
            Show {describePreset(wider)}
          </button>
        )
      }
    />
  );
}

/** The request failed: what failed, why, and Retry. */
export function PanelError({ what, query }: { what: string; query: FailedQuery }) {
  return (
    <div className="dashboard-response-empty">
      <QueryError what={what} query={query} />
    </div>
  );
}
