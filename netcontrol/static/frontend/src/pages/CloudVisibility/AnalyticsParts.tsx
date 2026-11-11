// Layout pieces shared by the Flow and Traffic tabs.
import { type ReactNode, useId } from 'react';

import { EmptyState } from '@/components/EmptyState';
import { LoadingState } from '@/components/LoadingState';
import { type FailedQuery, QueryError } from '@/components/QueryError';
import { FormRow } from '@/pages/Settings/FormFields';
import { type AnalyticsFilterState, BUCKET_OPTIONS, TOP_LIMIT_MAX, TOP_LIMIT_MIN, WINDOW_OPTIONS } from './analytics';

const FIELD_STYLE = { flex: '0 1 200px' };

interface FiltersProps {
  filters: AnalyticsFilterState;
  /** Label of the top-list size field ("Top talkers shown"). */
  limitLabel: string;
  /** Extra `.form-group` fields shown after the time window. */
  children?: ReactNode;
}

/** The view filters card: time window, extra fields, top-list size, timeline bucket. */
export function AnalyticsFilters({ filters, limitLabel, children }: FiltersProps) {
  const fid = useId();
  return (
    <div className="card card-sm">
      <FormRow>
        <div className="form-group" style={FIELD_STYLE}>
          <label className="form-label" htmlFor={`${fid}-window`}>Time window</label>
          <select
            id={`${fid}-window`}
            className="form-select"
            value={filters.hours}
            onChange={(e) => filters.setHours(parseInt(e.target.value, 10))}
          >
            {WINDOW_OPTIONS.map((o) => <option key={o.hours} value={o.hours}>{o.label}</option>)}
          </select>
        </div>
        {children}
        <div className="form-group" style={FIELD_STYLE}>
          <label className="form-label" htmlFor={`${fid}-limit`}>{limitLabel}</label>
          <input
            id={`${fid}-limit`}
            className="form-input"
            type="number"
            min={TOP_LIMIT_MIN}
            max={TOP_LIMIT_MAX}
            value={filters.limitText}
            aria-describedby={`${fid}-limit-help`}
            onChange={(e) => filters.setLimitText(e.target.value)}
          />
          <div className="form-help" id={`${fid}-limit-help`}>{TOP_LIMIT_MIN} to {TOP_LIMIT_MAX} rows</div>
        </div>
        <div className="form-group" style={FIELD_STYLE}>
          <label className="form-label" htmlFor={`${fid}-bucket`}>Timeline bucket</label>
          <select
            id={`${fid}-bucket`}
            className="form-select"
            value={filters.bucketMinutes}
            onChange={(e) => filters.setBucketMinutes(parseInt(e.target.value, 10))}
          >
            {BUCKET_OPTIONS.map((o) => <option key={o.minutes} value={o.minutes}>{o.label}</option>)}
          </select>
        </div>
      </FormRow>
    </div>
  );
}

/** Field wrapper for an extra filter passed to <AnalyticsFilters>, sized like the built-in ones. */
export function AnalyticsFilterField({ children }: { children: ReactNode }) {
  return <div className="form-group" style={FIELD_STYLE}>{children}</div>;
}

interface SectionProps {
  title: ReactNode;
  /** Heading level: h3 for a tab section, h4 for a part of one. */
  level?: 'h3' | 'h4';
  query: FailedQuery & { isError: boolean; isPending: boolean; data?: unknown };
  /** What failed to load, lower case ("top talkers"). */
  what: string;
  /** The empty-state message when the loaded data has nothing to show; false or omitted otherwise. */
  empty?: string | false;
  children: ReactNode;
}

/** A titled block with the error, loading and empty states of its query, in that order. */
export function AnalyticsSection({ title, level = 'h4', query, what, empty, children }: SectionProps) {
  const Heading = level;
  let body: ReactNode;
  if (query.isError && !query.data) body = <QueryError what={what} query={query} />;
  else if (query.isPending) body = <LoadingState />;
  else if (empty) body = <EmptyState compact message={empty} />;
  else body = children;
  return (
    <section className="stack stack-sm">
      <Heading style={{ margin: 0 }}>{title}</Heading>
      {body}
    </section>
  );
}
