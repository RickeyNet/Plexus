import { describe, expect, it } from 'vitest';

import type { MerakiOrg } from '@/api/meraki';

import {
  CATO_BASE_URL,
  DEFAULT_BASE_URL,
  FALLBACK_APPGATE_OPTIONS,
  FALLBACK_CATO_OPTIONS,
  FALLBACK_FMC_OPTIONS,
  FALLBACK_OPNSENSE_OPTIONS,
  FALLBACK_OPTIONS,
} from './merakiHelpers';
import {
  appgateForm,
  catoForm,
  defaultOptionsFor,
  fmcForm,
  isSourceFormReady,
  joinOpnsenseCredential,
  merakiForm,
  OPNSENSE_KEY_FIELD,
  OPNSENSE_SECRET_FIELD,
  opnsenseForm,
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
    auto_collect: true,
    collect_interval_seconds: 0,
    next_collection_at: null,
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

describe('joinOpnsenseCredential', () => {
  it('joins the trimmed key and secret with one colon', () => {
    expect(joinOpnsenseCredential('  key123 ', ' secret456  ')).toEqual({ apiKey: 'key123:secret456', error: null });
  });
  it('keeps the stored credential when both are blank', () => {
    expect(joinOpnsenseCredential('', '  ')).toEqual({ apiKey: null, error: null });
  });
  it('needs both halves or neither', () => {
    expect(joinOpnsenseCredential('key123', '').error).toMatch(/both/);
    expect(joinOpnsenseCredential('', 'secret456').error).toMatch(/both/);
    expect(joinOpnsenseCredential('key123', '').apiKey).toBeNull();
  });
  it('refuses a colon in the key, which would split the credential in the wrong place', () => {
    expect(joinOpnsenseCredential('key:123', 'secret456').error).toMatch(/colon/);
  });
});

describe('opnsenseForm', () => {
  const existing = org({
    id: 7,
    name: 'Branch firewall',
    provider: 'opnsense',
    org_id: 'local',
    base_url: 'https://fw1.example.com',
    has_api_key: true,
    options: { ...FALLBACK_OPNSENSE_OPTIONS, include_vpn: false },
  });

  it('opens with blank credential halves and the local org id', () => {
    const v = opnsenseForm.fromRecord(null, FALLBACK_OPNSENSE_OPTIONS);
    expect(v.org_id).toBe('local');
    expect(v[OPNSENSE_KEY_FIELD]).toBe('');
    expect(v[OPNSENSE_SECRET_FIELD]).toBe('');
    expect(v.verify_tls).toBe(true);
    expect(v.config_backup).toBe(true);
  });

  it('sends the joined credential as api_key and only build options as options', () => {
    const v = opnsenseForm.fromRecord(null, FALLBACK_OPNSENSE_OPTIONS);
    const body = opnsenseForm.toPayload({
      ...v,
      name: ' Branch firewall ',
      base_url: 'https://fw1.example.com',
      [OPNSENSE_KEY_FIELD]: ' key123 ',
      [OPNSENSE_SECRET_FIELD]: 'secret456',
      include_routes: false,
    });
    expect(body).toMatchObject({
      name: 'Branch firewall',
      provider: 'opnsense',
      org_id: 'local',
      base_url: 'https://fw1.example.com',
      api_key: 'key123:secret456',
    });
    expect(body.options).toEqual({ ...FALLBACK_OPNSENSE_OPTIONS, include_routes: false });
  });

  it('round-trips an existing entry and keeps the stored credential when both halves are blank', () => {
    const v = opnsenseForm.fromRecord(existing, FALLBACK_OPNSENSE_OPTIONS);
    expect(v.include_vpn).toBe(false);
    const body = opnsenseForm.toPayload(v);
    expect(body.api_key).toBeUndefined();
    expect(body.options).toEqual({ ...FALLBACK_OPNSENSE_OPTIONS, include_vpn: false });
    expect(opnsenseForm.validate(v, true)).toBeNull();
  });

  it('blocks saving an edit with only one half of the credential', () => {
    const v = opnsenseForm.fromRecord(existing, FALLBACK_OPNSENSE_OPTIONS);
    expect(opnsenseForm.validate({ ...v, [OPNSENSE_KEY_FIELD]: 'key123' }, true)).toMatch(/both/);
    // When adding, both halves are required fields; that check reports a missing half.
    expect(opnsenseForm.validate({ ...v, [OPNSENSE_KEY_FIELD]: 'key123' }, false)).toBeNull();
    expect(opnsenseForm.validate({ ...v, [OPNSENSE_KEY_FIELD]: 'a:b', [OPNSENSE_SECRET_FIELD]: 'c' }, false)).toMatch(
      /colon/,
    );
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
    expect(defaultOptionsFor('opnsense', undefined)).toBe(FALLBACK_OPNSENSE_OPTIONS);
    const opnsense = { ...FALLBACK_OPNSENSE_OPTIONS, config_backup: false };
    expect(defaultOptionsFor('opnsense', { opnsense_default_options: opnsense })).toBe(opnsense);
  });
});

describe('scheduled collection fields', () => {
  it('open on the entry and are sent as fields, not build options', () => {
    const v = catoForm.fromRecord(
      org({ provider: 'cato', auto_collect: false, collect_interval_seconds: 900 }),
      FALLBACK_CATO_OPTIONS,
    );
    expect(v).toMatchObject({ auto_collect: false, collect_interval_minutes: 15 });
    const body = catoForm.toPayload({ ...v, collect_interval_minutes: 30 });
    expect(body.auto_collect).toBe(false);
    expect(body.collect_interval_seconds).toBe(1800);
    expect(body.options).not.toHaveProperty('auto_collect');
    expect(body.options).not.toHaveProperty('collect_interval_minutes');
  });

  it('default to on with the global interval', () => {
    const body = merakiForm.toPayload(merakiForm.fromRecord(null, FALLBACK_OPTIONS));
    expect(body.auto_collect).toBe(true);
    expect(body.collect_interval_seconds).toBe(0);
  });
});
