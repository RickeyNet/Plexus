import type { ReactNode } from 'react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it, vi } from 'vitest';

import type { TopologyMuteCreate, TopologyMuteTarget } from '@/api/monitoring';
import { isMuteReasonValid, muteRequestBody, submitMute } from '@/pages/Dashboard/sourceHealth';

import { MuteEntityModal } from './MuteEntityModal';

// The real Modal portals into document.body, which the node test environment
// has none of; render its title, body and footer in place instead.
vi.mock('@/components/Modal', () => ({
  Modal: ({ title, children, footer }: { title?: string; children: ReactNode; footer?: ReactNode }) => (
    <div role="dialog">
      <h3>{title}</h3>
      {children}
      <div className="modal-footer">{footer}</div>
    </div>
  ),
}));

const DEVICE: TopologyMuteTarget = {
  provider: 'meraki',
  org_ref: 7,
  entity_type: 'device',
  entity_id: 'd:Q2XX-AAAA-0001',
  name: 'Branch-12 MX',
  site: 'Branch-12',
};

function render(target: TopologyMuteTarget): string {
  return renderToStaticMarkup(
    <QueryClientProvider client={new QueryClient()}>
      <MuteEntityModal target={target} onClose={() => {}} />
    </QueryClientProvider>,
  );
}

function muteButton(html: string): string {
  const m = /<button[^>]*>(?:(?!<\/button>).)*Mute<\/button>/s.exec(html.split('modal-footer')[1] ?? '');
  return m?.[0] ?? '';
}

describe('MuteEntityModal', () => {
  it('Mute is disabled until a reason is typed', () => {
    const html = render(DEVICE);
    expect(html).toContain('<h3>Mute alerts</h3>');
    expect(muteButton(html)).toContain('disabled');
    expect(isMuteReasonValid('')).toBe(false);
    expect(isMuteReasonValid('   ')).toBe(false);
    expect(isMuteReasonValid('x'.repeat(501))).toBe(false);
    expect(isMuteReasonValid('Not installed yet')).toBe(true);
    expect(isMuteReasonValid('x'.repeat(500))).toBe(true);
  });

  it('hides the site choice when the target has no site', () => {
    const withSite = render(DEVICE);
    expect(withSite).toContain('This device only');
    expect(withSite).toContain('Everything at site Branch-12');
    expect(withSite).toContain('Muted entities are left off the Dashboard and send no notifications until unmuted.');

    const tunnel = render({ ...DEVICE, entity_type: 'tunnel', entity_id: 'vpn:a>b', name: 'Hub - Branch-12', site: '' });
    expect(tunnel).toContain('This tunnel only');
    expect(tunnel).not.toContain('Everything at site');
    expect(render({ ...DEVICE, entity_type: 'vpn_connection', site: '' })).toContain('This VPN connection only');
  });

  it('posts scope "site" with the site name when that choice is picked', async () => {
    const post = vi.fn((body: TopologyMuteCreate) => Promise.resolve(body));
    const onDone = vi.fn();
    const error = await submitMute(post, muteRequestBody(DEVICE, 'site', '  Not installed yet  '), onDone);
    expect(error).toBeNull();
    expect(post).toHaveBeenCalledWith({
      provider: 'meraki',
      org_ref: 7,
      scope: 'site',
      site: 'Branch-12',
      reason: 'Not installed yet',
    });
    expect(onDone).toHaveBeenCalledTimes(1);
  });

  it('posts scope "entity" with entity_type and entity_id by default', async () => {
    const html = render(DEVICE);
    // The first choice, this entity only, is the one checked.
    expect(/<input[^>]*value="entity"[^>]*checked/.test(html) || /<input[^>]*checked[^>]*value="entity"/.test(html)).toBe(
      true,
    );
    const post = vi.fn((body: TopologyMuteCreate) => Promise.resolve(body));
    await submitMute(post, muteRequestBody(DEVICE, 'entity', 'Spare'), () => {});
    expect(post).toHaveBeenCalledWith({
      provider: 'meraki',
      org_ref: 7,
      scope: 'entity',
      entity_type: 'device',
      entity_id: 'd:Q2XX-AAAA-0001',
      reason: 'Spare',
    });
  });

  it('shows the server error and stays open when the request fails', async () => {
    const onDone = vi.fn();
    const post = vi.fn(() => Promise.reject(new Error('No tracked entity matches this mute')));
    const error = await submitMute(post, muteRequestBody(DEVICE, 'entity', 'Spare'), onDone);
    expect(error).toBe('No tracked entity matches this mute');
    expect(onDone).not.toHaveBeenCalled();
  });
});
