import { renderToStaticMarkup } from 'react-dom/server';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import type { AuthConfig, SamlConfig } from '@/api/settings';
import { importSamlMetadata } from '@/api/settings';

import { SamlPanel } from './AuthTab';
import { samlProblem, splitPemBlocks } from './oidcSettings';

const client = vi.hoisted(() => ({ apiRequest: vi.fn() }));
const state = vi.hoisted(() => ({
  importer: {} as Record<string, unknown>,
  sp: {} as Record<string, unknown>,
}));

vi.mock('@/api/client', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@/api/client')>();
  return { ...actual, apiRequest: client.apiRequest };
});

vi.mock('@/api/settings', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@/api/settings')>();
  return { ...actual, useImportSamlMetadata: () => state.importer, useSamlSpInfo: () => state.sp };
});

const CERT = '-----BEGIN CERTIFICATE-----\nMIIBexample\n-----END CERTIFICATE-----';

const SAML: SamlConfig = {
  enabled: true,
  idp_entity_id: 'https://idp.example.com/saml',
  idp_sso_url: 'https://idp.example.com/saml/sso',
  idp_certs: [CERT],
  idp_metadata_url: '',
  sp_entity_id: '',
  acs_url: '',
  ca_cert_file: '',
  username_attribute: 'uid',
  email_attribute: 'mail',
  display_name_attribute: 'displayName',
  groups_attribute: 'groups',
  admin_groups: ['plexus-admins'],
  default_role: 'user',
  default_group_ids: [],
  sync_groups: true,
  group_mappings: [{ group: 'netops', access_group_id: 2 }],
  button_label: 'Sign in with Example SAML',
  primary: false,
};

const draft = { saml: SAML } as unknown as AuthConfig;
const groups = [{ id: 2, name: 'Network team', description: '', feature_keys: [] }];

describe('saml settings helpers', () => {
  it('flags what the server would refuse', () => {
    expect(samlProblem(SAML)).toBeNull();
    expect(samlProblem({ ...SAML, idp_entity_id: ' ' })).toMatch(/entity ID/);
    expect(samlProblem({ ...SAML, idp_sso_url: '' })).toMatch(/SSO URL/);
    expect(samlProblem({ ...SAML, idp_certs: [] })).toMatch(/certificate/);
    expect(samlProblem({ ...SAML, enabled: false, idp_certs: [], idp_entity_id: '' })).toBeNull();
    expect(samlProblem({ ...SAML, idp_sso_url: 'http://idp.example.com/sso' })).toMatch(/https/);
    expect(samlProblem({ ...SAML, acs_url: 'ftp://plexus.example.com' })).toMatch(/ACS/);
    expect(samlProblem({ ...SAML, idp_certs: Array.from({ length: 6 }, () => CERT) })).toMatch(/5/);
    expect(samlProblem({ ...SAML, button_label: 'x'.repeat(61) })).toMatch(/60/);
  });

  it('splits pasted PEM blocks and keeps bare base64', () => {
    expect(splitPemBlocks(`${CERT}\n\n${CERT}\n`)).toEqual([CERT, CERT]);
    expect(splitPemBlocks(' MIIBexample ')).toEqual(['MIIBexample']);
    expect(splitPemBlocks('  ')).toEqual([]);
  });
});

describe('importSamlMetadata', () => {
  beforeEach(() => {
    client.apiRequest.mockReset();
    client.apiRequest.mockResolvedValue({ ok: true });
  });

  it('posts to the admin import route', async () => {
    await importSamlMetadata({ url: 'https://idp.example.com/saml/metadata' });
    expect(client.apiRequest).toHaveBeenCalledWith('/admin/auth-config/saml/metadata', {
      method: 'POST',
      body: { url: 'https://idp.example.com/saml/metadata' },
    });
  });
});

describe('SamlPanel', () => {
  beforeEach(() => {
    state.importer = { isPending: false, isError: false, data: undefined, mutate: () => {} };
    state.sp = {
      data: {
        sp_entity_id: 'https://plexus.example.com/api/auth/saml/metadata',
        acs_url: 'https://plexus.example.com/api/auth/saml/acs',
        metadata_url: 'https://plexus.example.com/api/auth/saml/metadata',
        certs: [{ fingerprint: 'AB:CD:EF:01:23:45:67:89:AB:CD', not_after: '2030-01-01' }],
      },
    };
  });

  it('renders the SP values, IdP fields, attributes and mappings', () => {
    const html = renderToStaticMarkup(<SamlPanel draft={draft} setDraft={() => {}} groups={groups} />);
    expect(html).toContain('Single sign-on (SAML 2.0)');
    expect(html).toContain('value="https://plexus.example.com/api/auth/saml/acs"');
    expect(html).toContain('value="https://idp.example.com/saml"');
    expect(html).toContain('MIIBexample');
    expect(html).toContain('until 2030-01-01');
    expect(html).toContain('value="displayName"');
    expect(html).toContain('Groups attribute value');
    expect(html).toContain('value="netops"');
    expect(html).toContain('Network team');
  });

  it('shows the import result', () => {
    state.importer = {
      ...state.importer,
      data: { ok: false, error: 'the IdP metadata has no signing certificate', idp_certs: [] },
    };
    const html = renderToStaticMarkup(<SamlPanel draft={draft} setDraft={() => {}} groups={groups} />);
    expect(html).toContain('the IdP metadata has no signing certificate');
  });

  it('renders nothing on a server without SAML', () => {
    const html = renderToStaticMarkup(
      <SamlPanel draft={{} as unknown as AuthConfig} setDraft={() => {}} groups={groups} />,
    );
    expect(html).toBe('');
  });
});
