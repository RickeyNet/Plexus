import { lazy, type ReactNode, Suspense, useMemo, useState } from 'react';

import { useAuthStatus } from '@/api/auth';
import { addSourceAccess, canAddSource } from '@/lib/addSource';

import { AddSourceContext, type AddSourceApi } from './AddSourceProvider-context';

// The dialog and the source forms behind it load on first use, so they stay
// out of the shell bundle.
const AddSourceDialog = lazy(() =>
  import('@/pages/Topology/AddSourceDialog').then((m) => ({ default: m.AddSourceDialog })),
);

/**
 * Holds the one Add source dialog of the app, so the sidebar and any page
 * can open it (useAddSource) without leaving the page they are on.
 */
export function AddSourceProvider({ children }: { children: ReactNode }) {
  const { data: auth } = useAuthStatus();
  const access = useMemo(() => addSourceAccess(auth), [auth]);
  const available = canAddSource(access);
  const [isOpen, setIsOpen] = useState(false);
  const api = useMemo<AddSourceApi>(() => ({ available, open: () => setIsOpen(true) }), [available]);

  return (
    <AddSourceContext.Provider value={api}>
      {children}
      {isOpen && available && (
        <Suspense fallback={null}>
          <AddSourceDialog access={access} onClose={() => setIsOpen(false)} />
        </Suspense>
      )}
    </AddSourceContext.Provider>
  );
}
