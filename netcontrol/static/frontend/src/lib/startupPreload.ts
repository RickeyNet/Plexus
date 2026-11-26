import type { QueryClient } from '@tanstack/react-query';

import { authStatusQueryOptions } from '@/api/auth';
import { prefetchRoute } from '@/lib/pageLoaders';

// Called from main.tsx before the first render. App renders nothing until
// /auth/status answers, so without this the current page's chunk (and the
// queries it starts) wait a full round trip behind the auth check. Both
// requests start here in parallel; App still gates every page on auth.
// The prefetch fills the cache entry useAuthStatus reads, so the hook does
// not send a second request. /login maps to no page chunk, so a visitor
// landing there downloads nothing extra.
export function startEarlyLoads(queryClient: QueryClient, pathname: string): void {
  void queryClient.prefetchQuery(authStatusQueryOptions);
  prefetchRoute(pathname);
}
