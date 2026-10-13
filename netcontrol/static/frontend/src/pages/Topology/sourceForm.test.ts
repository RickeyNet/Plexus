import { describe, expect, it } from 'vitest';

import type { MerakiOrg } from '@/api/meraki';

import {
  CATO_BASE_URL,
  DEFAULT_BASE_URL,
  FALLBACK_APPGATE_OPTIONS,
  FALLBACK_CATO_OPTIONS,
  FALLBACK_FMC_OPTIONS,
  FALLBACK_OPTIONS,
} from './merakiHelpers';
import {
  appgateForm,
  catoForm,
  defaultOptionsFor,
  fmcForm,
  isSourceFormReady,
  merakiForm,
} from './sourceForm';

function org(over: Partial<MerakiOrg>): MerakiOrg {
  return {
    id: 1,
    name: 'Acme',
    provider: 'meraki',
    org_id: '123',
    base_url: DEFAULT_BASE_URL,
    has_api_key: true,
    options: FALLBACK_OPTIONS,
    building: false,
    ...over,
  };
}

describe('merakiForm', () => {
  it('opens a new entry on the defaults with a blank secret', () => {
    const v = merakiForm.fromRecord(null, FALLBACK_OPTIONS);
    expect(v).toMatchObject({ name: '', org_id: '', base_url: DEFAULT_BASE_URL, secret: '', network_tags: '' });
    expect(v.requests_per_second).toBe(FALLBACK_OPTIONS.requests_per_second);
  });

  it('round-trips tags as comma-separated text and omits the provider', () => {
    const existing = org({ options: { ...FALLBACK_OPTIONS, network_tags: ['east', 'west'] } });
    const v = merakiForm.fromRecord(existing, FALLBACK_OPTIONS);
    expect(v.network_tags).toBe('east, west');
    const body = merakiForm.toPayload({ ...v, network_tags: ' a, ,b ', name: ' Acme ' });
    expect(body.provider).toBeUndefined();
    expect(body.name).toBe('Acme');
    expect(body.api_key).toBeUndefined();
    expect(body.options).toMatchObject({ network_tags: ['a', 'b'], include_lldp_cdp: true });
    expect(body.options).not.toHaveProperty('secret');
    expect(body.options).not.toHaveProperty('name');
  });

  it('sends a trimmed secret only when one is typed', () => {
    const v = merakiForm.fromRecord(null, FALLBACK_OPTIONS);
    expect(merakiForm.toPayload({ ...v, secret: '  key  ' }).api_key).toBe('key');
  });
});

describe('catoForm', () => {
  it('defaults the API URL and tags the provider', () => {
    const v = catoForm.fromRecord(null, FALLBACK_CATO_OPTIONS);
    expect(v.base_url).toBe(CATO_BASE_URL);
    const body = catoForm.toPayload({ ...v, name: 'C', org_id: ' 42 ' });
    expect(body).toMatchObject({ provider: 'cato', org_id: '42', options: FALLBACK_CATO_OPTIONS });
  });
});

describe('fmcForm', () => {
  it('fills options an older entry lacks from the defaults and trims the username', () => {
    const existing = org({ provider: 'fmc', options: { username: 'u' } as never });
    const v = fmcForm.fromRecord(existing, FALLBACK_FMC_OPTIONS);
    expect(v.include_routing).toBe(true);
    expect(v.username).toBe('u');
    const body = fmcForm.toPayload({ ...v, username: ' admin ' });
    expect(body.provider).toBe('fmc');
    expect(body.options).toMatchObject({ username: 'admin', include_routing: true });
  });
});

describe('appgateForm', () => {
  it('falls back to the local identity provider', () => {
    const v = appgateForm.fromRecord(null, FALLBACK_APPGATE_OPTIONS);
    expect(v.org_id).toBe('local');
    expect(appgateForm.toPayload({ ...v, org_id: '  ' }).org_id).toBe('local');
  });
});

describe('isSourceFormReady', () => {
  const fields = [
    { name: 'name', required: true },
    { name: 'secret', required: 'create' as const },
    { name: 'org_id' },
  ];
  it('requires the secret only when adding', () => {
    const values = { name: 'x', secret: '', org_id: '' };
    expect(isSourceFormReady(fields, values, false)).toBe(false);
    expect(isSourceFormReady(fields, values, true)).toBe(true);
    expect(isSourceFormReady(fields, { ...values, name: ' ' }, true)).toBe(false);
  });
});

describe('defaultOptionsFor', () => {
  it('prefers the server defaults and falls back otherwise', () => {
    const server = { ...FALLBACK_CATO_OPTIONS, include_users: false };
    expect(defaultOptionsFor('cato', { cato_default_options: server })).toBe(server);
    expect(defaultOptionsFor('appgate', undefined)).toBe(FALLBACK_APPGATE_OPTIONS);
  });
});
