import { createContext, useContext } from 'react';

export interface AddSourceApi {
  /** Whether this user may add a source; hide the action when false. */
  available: boolean;
  /** Opens the Add source dialog over the current page. */
  open: () => void;
}

export const AddSourceContext = createContext<AddSourceApi>({ available: false, open: () => {} });

/** The app-wide Add source action: one dialog, opened from the sidebar and the Dashboard. */
export function useAddSource(): AddSourceApi {
  return useContext(AddSourceContext);
}
