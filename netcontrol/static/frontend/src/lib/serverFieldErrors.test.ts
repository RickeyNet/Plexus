import { describe, expect, it } from 'vitest';

import { ApiError } from '@/api/client';
import { CustomDataError } from '@/api/customData';

import { pickFieldErrors, serverFieldErrors } from './serverFieldErrors';

describe('serverFieldErrors', () => {
  it('reads detail.fields from an apiRequest failure', () => {
    const body = {
      ok: false,
      error: { code: 'http_error', message: 'Use sw-<n>.' },
      detail: { message: 'Use sw-<n>.', fields: { hostname: 'Use sw-<n>.' }, violations: [] },
    };
    expect(serverFieldErrors(new ApiError(422, body, '422 Use sw-<n>.'))).toEqual({ hostname: 'Use sw-<n>.' });
  });

  it('passes a detailRequest failure through', () => {
    expect(serverFieldErrors(new CustomDataError('bad', 422, { name: 'Too long.' }))).toEqual({ name: 'Too long.' });
  });

  it('is empty for anything else', () => {
    expect(serverFieldErrors(new ApiError(500, 'oops', '500'))).toEqual({});
    expect(serverFieldErrors(new Error('network'))).toEqual({});
  });
});

describe('pickFieldErrors', () => {
  it('splits mapped fields from the rest, first message per key', () => {
    const { picked, rest } = pickFieldErrors(
      { hostname: 'A', ip_address: 'B', site_id: 'C', name: 'D' },
      { hostname: 'name', name: 'name', ip_address: 'ip' } as const,
    );
    expect(picked).toEqual({ name: 'A', ip: 'B' });
    expect(rest).toEqual({ site_id: 'C' });
  });
});
