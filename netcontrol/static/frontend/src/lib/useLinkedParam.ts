import { useCallback } from 'react';
import { useLocation, useNavigate, useSearchParams } from 'react-router';

/**
 * A query parameter that links into a page with something already open (a
 * dialog, a form): its value, or null when absent, and a function that drops
 * it from the URL (`replace`, so Back does not reopen it). Call the drop when
 * the linked thing closes, so a reload does not open it again.
 */
export function useLinkedParam(name: string): [string | null, () => void] {
  const [searchParams, setSearchParams] = useSearchParams();
  const value = searchParams.get(name);
  const clear = useCallback(() => {
    setSearchParams(
      (current) => {
        if (!current.has(name)) return current;
        const next = new URLSearchParams(current);
        next.delete(name);
        return next;
      },
      { replace: true },
    );
  }, [name, setSearchParams]);
  return [value, clear];
}

/**
 * A filter kept in a query parameter, for a panel other pages (or other
 * panels of the same page) link to already filtered: the parsed value (null
 * when absent or not a value `parse` accepts, so a bad link shows the
 * panel unfiltered) and a setter. The setter writes the parameter (null
 * drops it) with `replace` and drops the `#anchor`, so changing the filter
 * on the page neither adds history entries nor scrolls back to the anchor.
 */
export function useParamFilter<T>(
  name: string,
  parse: (value: string | null) => T | null,
): [T | null, (value: string | null) => void] {
  const [searchParams] = useSearchParams();
  const { pathname } = useLocation();
  const navigate = useNavigate();
  const value = parse(searchParams.get(name));
  const set = useCallback(
    (next: string | null) => {
      const params = new URLSearchParams(searchParams);
      if (next == null || next === '') params.delete(name);
      else params.set(name, next);
      const search = params.toString();
      void navigate({ pathname, search: search ? `?${search}` : '' }, { replace: true });
    },
    [name, navigate, pathname, searchParams],
  );
  return [value, set];
}
