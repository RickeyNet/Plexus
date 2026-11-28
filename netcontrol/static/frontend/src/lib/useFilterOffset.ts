import { useState } from 'react';

/**
 * The page offset of a server-paged list, back at 0 whenever `filter`
 * changes (compared as JSON), so a new search or filter starts on the first
 * page. Resets during render (prev-value guard), not in an effect, so no
 * request is sent for the old offset with the new filter.
 */
export function useFilterOffset(filter: unknown): [number, (offset: number) => void] {
  const key = JSON.stringify(filter);
  const [state, setState] = useState({ key, offset: 0 });
  if (state.key !== key) {
    setState({ key, offset: 0 });
  }
  const offset = state.key === key ? state.offset : 0;
  return [offset, (next: number) => setState({ key, offset: next })];
}
