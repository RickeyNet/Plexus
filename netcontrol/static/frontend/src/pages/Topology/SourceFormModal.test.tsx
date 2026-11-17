import type { ReactNode } from 'react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it, vi } from 'vitest';

import type { OrgBuildOptions } from '@/api/meraki';

import { SourceFormModal } from './SourceFormModal';

// The real Modal portals into document.body, which the node test environment
// has none of; render its body in place instead.
vi.mock('@/components/Modal', () => ({
  Modal: ({ children, footer }: { children: ReactNode; footer?: ReactNode }) => (
    <div role="dialog">
      {children}
      {footer}
    </div>
  ),
}));

function render(): string {
  return renderToStaticMarkup(
    <QueryClientProvider client={new QueryClient()}>
      <SourceFormModal provider="opnsense" existing={null} defaultOptions={{} as OrgBuildOptions} onClose={() => {}} />
    </QueryClientProvider>,
  );
}

describe('SourceFormModal secret fields', () => {
  it('hides the OPNsense API key and secret and offers to show each', () => {
    const html = render();
    expect(html).toMatch(/<input[^>]*id="[^"]*opnsense-api-key"[^>]*type="password"/);
    expect(html).toMatch(/<input[^>]*id="[^"]*opnsense-api-secret"[^>]*type="password"/);
    expect(html).toContain('aria-label="Show API key"');
    expect(html).toContain('aria-label="Show API secret"');
    expect(html.match(/aria-pressed="false"/g)).toHaveLength(2);
  });
});
