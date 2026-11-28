import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { BrowserRouter } from 'react-router';

// The one stylesheet, built by Vite (minified, hashed, cached as immutable
// under /assets). It stays in netcontrol/static/css, so /static/css/style.css
// still answers for anything outside the SPA that links it.
import '../../css/style.css';
import { App } from '@/App';
import { AddSourceProvider } from '@/components/AddSourceProvider';
import { DialogProvider } from '@/components/DialogProvider';
import { initAppearance } from '@/lib/appearance';
import { startEarlyLoads } from '@/lib/startupPreload';
import { bindQueryClient as bindPollNowQueryClient } from '@/pages/Monitoring/pollNowStore';
import { TimeRangeProvider } from '@/lib/timeRange';

initAppearance();

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: 1,
      refetchOnWindowFocus: false,
      staleTime: 30_000,
    },
  },
});

bindPollNowQueryClient(queryClient);
startEarlyLoads(queryClient, window.location.pathname);

const rootEl = document.getElementById('root');
if (!rootEl) throw new Error('#root missing in index.html');

createRoot(rootEl).render(
  <StrictMode>
    <QueryClientProvider client={queryClient}>
      <TimeRangeProvider>
        <BrowserRouter>
          <DialogProvider>
            <AddSourceProvider>
              <App />
            </AddSourceProvider>
          </DialogProvider>
        </BrowserRouter>
      </TimeRangeProvider>
    </QueryClientProvider>
  </StrictMode>,
);
