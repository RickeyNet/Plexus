import { describe, expect, it } from 'vitest';

import type { McpTokenRecord } from '@/api/settings';

import {
  CATEGORY_HELP,
  connectionSnippets,
  endpointUrl,
  tokenStatus,
  utcDateAfter,
  validateTokenForm,
} from './aiAccess';

const BASE = 'https://plexus.example.com';
const TOKEN = 'plx_mcp_exampletoken';

function record(over: Partial<McpTokenRecord> = {}): McpTokenRecord {
  return {
    id: 1,
    name: 'report-bot',
    token_prefix: 'plx_mcp_abcd',
    owner_user_id: 1,
    owner_username: 'admin',
    owner_role: 'admin',
    categories: ['inventory'],
    expires_at: '',
    created_at: '2026-01-01 00:00:00',
    created_by: 'admin',
    last_used_at: '',
    call_count: 0,
    revoked_at: '',
    ...over,
  };
}

describe('endpointUrl', () => {
  it('appends the MCP path to the origin', () => {
    expect(endpointUrl(BASE)).toBe('https://plexus.example.com/mcp');
    expect(endpointUrl(`${BASE}/`)).toBe('https://plexus.example.com/mcp');
  });
});

describe('connectionSnippets', () => {
  const snippets = connectionSnippets(BASE, TOKEN);

  it('covers Claude Code, Claude Desktop and a generic client', () => {
    expect(snippets.map((s) => s.label)).toEqual(['Claude Code', 'Claude Desktop', 'Other MCP clients']);
  });

  it('puts the endpoint and the token in every snippet', () => {
    for (const snippet of snippets) {
      expect(snippet.text).toContain('https://plexus.example.com/mcp');
      expect(snippet.text).toContain(TOKEN);
    }
  });

  it('starts the Claude Code snippet with the CLI command', () => {
    expect(snippets[0].text.startsWith('claude mcp add')).toBe(true);
    expect(snippets[0].text).toContain('--transport http');
    expect(snippets[0].text).toContain(`Authorization: Bearer ${TOKEN}`);
  });

  it('gives Claude Desktop valid JSON', () => {
    const parsed = JSON.parse(snippets[1].text);
    expect(JSON.stringify(parsed)).toContain(`Bearer ${TOKEN}`);
  });
});

describe('tokenStatus', () => {
  const now = new Date('2026-06-15T12:00:00Z');

  it('is active with no expiry or a future one', () => {
    expect(tokenStatus(record(), now)).toBe('active');
    expect(tokenStatus(record({ expires_at: '2026-06-16' }), now)).toBe('active');
  });

  it('is active through the whole expiry day', () => {
    expect(tokenStatus(record({ expires_at: '2026-06-15' }), now)).toBe('active');
  });

  it('is expired after the expiry day', () => {
    expect(tokenStatus(record({ expires_at: '2026-06-14' }), now)).toBe('expired');
  });

  it('is revoked whatever the expiry', () => {
    expect(tokenStatus(record({ revoked_at: '2026-06-01 10:00:00', expires_at: '2026-06-14' }), now)).toBe(
      'revoked',
    );
  });
});

describe('utcDateAfter', () => {
  it('counts days from the UTC date', () => {
    const lateEvening = new Date('2026-06-15T23:30:00Z');
    expect(utcDateAfter(0, lateEvening)).toBe('2026-06-15');
    expect(utcDateAfter(1, lateEvening)).toBe('2026-06-16');
    expect(utcDateAfter(90, lateEvening)).toBe('2026-09-13');
    expect(utcDateAfter(365, lateEvening)).toBe('2027-06-15');
  });
});

describe('validateTokenForm', () => {
  const now = new Date('2026-06-15T12:00:00Z');
  const MAX_DAYS = 365;
  const valid = {
    name: 'report-bot',
    ownerId: 1,
    ownerIsAdmin: true,
    categories: ['inventory'],
    expiresAt: '2026-09-13',
  };
  const validate = (form: typeof valid | (Omit<typeof valid, 'ownerId'> & { ownerId: number | null })) =>
    validateTokenForm(form, MAX_DAYS, now);

  it('accepts a complete form', () => {
    expect(validate(valid)).toEqual({});
    expect(validate({ ...valid, categories: ['audit'], expiresAt: '2026-12-31' })).toEqual({});
  });

  it('rejects an empty or overlong name', () => {
    expect(validate({ ...valid, name: '   ' }).name).toBeTruthy();
    expect(validate({ ...valid, name: 'n'.repeat(81) }).name).toBeTruthy();
  });

  it('rejects a missing owner', () => {
    expect(validate({ ...valid, ownerId: null }).owner).toBeTruthy();
  });

  it('rejects no categories', () => {
    expect(validate({ ...valid, categories: [] }).categories).toBeTruthy();
  });

  it('rejects the audit category for a non-admin owner', () => {
    const errors = validate({ ...valid, ownerIsAdmin: false, categories: ['inventory', 'audit'] });
    expect(errors.categories).toContain('admin');
  });

  it('rejects a missing or malformed expiry date', () => {
    expect(validate({ ...valid, expiresAt: '' }).expiresAt).toBe('Enter an expiry date.');
    expect(validate({ ...valid, expiresAt: 'next week' }).expiresAt).toContain('YYYY-MM-DD');
  });

  it('accepts an expiry date from today to the maximum', () => {
    expect(validate({ ...valid, expiresAt: '2026-06-15' })).toEqual({});
    expect(validate({ ...valid, expiresAt: '2027-06-15' })).toEqual({});
  });

  it('rejects an expiry date in the past or beyond the maximum', () => {
    expect(validate({ ...valid, expiresAt: '2026-06-14' }).expiresAt).toBe('Choose today or a later date.');
    expect(validate({ ...valid, expiresAt: '2027-06-16' }).expiresAt).toContain('at most 365 days');
  });
});

describe('CATEGORY_HELP', () => {
  it('describes every category the server offers', () => {
    for (const key of ['inventory', 'configs', 'compliance', 'monitoring', 'topology', 'software', 'traffic', 'audit']) {
      expect(CATEGORY_HELP[key]).toBeTruthy();
    }
  });
});
