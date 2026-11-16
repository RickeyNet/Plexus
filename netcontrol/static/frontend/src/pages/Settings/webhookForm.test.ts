import { describe, expect, it } from 'vitest';

import type { Webhook } from '@/api/webhooks';

import { EMPTY_DRAFT, deliveryTone, draftFromWebhook, parseIdList, payloadFromDraft, toggleIn } from './webhookForm';

const HOOK: Webhook = {
  id: 4,
  name: 'inventory',
  enabled: true,
  url: 'https://hooks.example.com/plexus',
  http_method: 'POST',
  content_type: 'application/json',
  object_types: ['host', 'group'],
  actions: ['create', 'delete'],
  filters: { group_id: [3, 7], role: ['core'] },
  headers: { Authorization: '••••••••' },
  has_secret: true,
  secret: '••••••••',
  body_template: '',
  verify_tls: true,
  ca_bundle: '',
  timeout_seconds: 10,
  max_retries: 3,
  concurrency: 2,
};

describe('webhook form helpers', () => {
  it('parses id lists', () => {
    expect(parseIdList(' 1, 2 3,,2 ')).toEqual(['1', '2', '3']);
    expect(parseIdList('')).toEqual([]);
  });

  it('round-trips a webhook through the draft, keeping masks and other filters', () => {
    const draft = draftFromWebhook(HOOK);
    expect(draft.group_ids).toBe('3, 7');
    expect(draft.headers).toEqual([{ name: 'Authorization', value: '••••••••' }]);
    const payload = payloadFromDraft(draft);
    expect(payload.filters).toEqual({ role: ['core'], group_id: ['3', '7'] });
    expect(payload.headers).toEqual({ Authorization: '••••••••' });
    expect(payload.secret).toBe('••••••••');
  });

  it('drops blank header rows and an empty group filter', () => {
    const payload = payloadFromDraft({ ...EMPTY_DRAFT, headers: [{ name: ' ', value: 'x' }] });
    expect(payload.headers).toEqual({});
    expect(payload.filters).toEqual({});
  });

  it('toggles in catalog order and maps delivery tones', () => {
    const all = ['create', 'update', 'delete'];
    expect(toggleIn(['delete'], 'create', true, all)).toEqual(['create', 'delete']);
    expect(toggleIn(['create', 'delete'], 'create', false, all)).toEqual(['delete']);
    expect(deliveryTone('success')).toBe('success');
    expect(deliveryTone('blocked')).toBe('danger');
    expect(deliveryTone('other')).toBe('neutral');
  });
});
