import { describe, expect, it } from 'vitest';

import { errorMessage, formatErrorDetail } from './client';

describe('errorMessage', () => {
  it("reads the message of the app's {ok, error} envelope", () => {
    const body = { ok: false, error: { code: 'http_error', message: "Invalid AWS instance ID 'foo'" } };
    expect(errorMessage(body)).toBe("Invalid AWS instance ID 'foo'");
    expect(errorMessage({ ok: false, error: 'git fetch failed' })).toBe('git fetch failed');
  });

  it("falls back to FastAPI's detail, and to nothing", () => {
    expect(errorMessage({ detail: 'Deployment not found' })).toBe('Deployment not found');
    expect(errorMessage({ detail: [{ msg: 'Field required', loc: ['body', 'name'] }] })).toBe('name: Field required');
    expect(errorMessage({ ok: false, error: { code: 'x', message: '' } })).toBeNull();
    expect(errorMessage('plain text')).toBeNull();
    expect(errorMessage(null)).toBeNull();
  });
});

describe('formatErrorDetail', () => {
  it('returns a plain string detail unchanged', () => {
    expect(formatErrorDetail('Deployment not found')).toBe('Deployment not found');
  });

  it('flattens a FastAPI 422 validation array into field: message pairs', () => {
    const detail = [
      { type: 'missing', loc: ['body', 'name'], msg: 'Field required' },
      { type: 'less_than', loc: ['query', 'limit'], msg: 'Input should be >= 1' },
    ];
    // Must NOT be "[object Object],[object Object]".
    expect(formatErrorDetail(detail)).toBe(
      'name: Field required; limit: Input should be >= 1',
    );
  });

  it('handles a single validation object', () => {
    expect(formatErrorDetail({ msg: 'bad value', loc: ['body', 'x'] })).toBe('bad value');
  });

  it('returns null for null/undefined', () => {
    expect(formatErrorDetail(null)).toBeNull();
    expect(formatErrorDetail(undefined)).toBeNull();
  });

  it('drops loc container prefixes but keeps nested field paths', () => {
    const detail = [{ msg: 'too long', loc: ['body', 'image_map', 'key'] }];
    expect(formatErrorDetail(detail)).toBe('image_map.key: too long');
  });
});
