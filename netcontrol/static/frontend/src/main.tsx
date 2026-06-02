import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { BrowserRouter } from 'react-router-dom';

import { App } from '@/App';
import { DialogProvider } from '@/components/DialogProvider';
import { initAppearance } from '@/lib/appearance';
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

const rootEl = document.getElementById('root');
if (!rootEl) throw new Error('#root missing in index.html');

createRoot(rootEl).render(
  <StrictMode>
    <QueryClientProvider client={queryClient}>
      <TimeRangeProvider>
        <BrowserRouter basename="/frontend">
          <DialogProvider>
            <App />
          </DialogProvider>
        </BrowserRouter>
      </TimeRangeProvider>
    </QueryClientProvider>
  </StrictMode>,
);
