import { Callout } from './Callout';

/** The part of a TanStack Query result this component reads. */
export interface FailedQuery {
  error: unknown;
  isFetching: boolean;
  refetch: () => unknown;
}

export interface QueryErrorProps {
  /** What failed to load, lower case, e.g. "login rules". Rendered as "Failed to load login rules". */
  what: string;
  /** The failed query: supplies the error detail, the Retry action and its busy state. */
  query?: FailedQuery;
  /** For a request that is not a query: the error. A non-Error value shows no detail. */
  error?: unknown;
  /** For a request that is not a query: the Retry action. Omit when it cannot be retried. */
  onRetry?: () => void;
  /** For a request that is not a query: disables Retry while the retry runs. */
  isRetrying?: boolean;
  className?: string;
}

/**
 * The one "request failed" state: a danger Callout that names what failed
 * and offers Retry. Render it when `query.isError && !query.data`, and
 * check that before any loading or "no data yet" check, or a failed
 * request shows as endless loading or as an empty list.
 */
export function QueryError({ what, query, error, onRetry, isRetrying, className }: QueryErrorProps) {
  const cause = query ? query.error : error;
  const retry = query ? () => void query.refetch() : onRetry;
  const retrying = query ? query.isFetching : Boolean(isRetrying);
  const detail = cause instanceof Error && cause.message ? `: ${cause.message}` : '';
  return (
    <Callout
      tone="danger"
      className={className}
      action={
        retry && (
          <button type="button" className="btn btn-sm btn-secondary" onClick={retry} disabled={retrying}>
            {retrying ? 'Retrying…' : 'Retry'}
          </button>
        )
      }
    >
      Failed to load {what}
      {detail}
    </Callout>
  );
}
