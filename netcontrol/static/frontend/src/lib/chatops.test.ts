import { describe, expect, it } from 'vitest';

import {
  inboundUrl,
  outcomeTone,
  toggleCommand,
  validateBotForm,
  validateMapping,
  validatePreset,
} from './chatops';

describe('inboundUrl', () => {
  it('joins the origin and the path without a double slash', () => {
    expect(inboundUrl('https://plexus.example.com/', '/api/chatops/webex')).toBe(
      'https://plexus.example.com/api/chatops/webex',
    );
  });
});

describe('outcomeTone', () => {
  it('maps each outcome to a badge tone', () => {
    expect(outcomeTone('ok')).toBe('success');
    expect(outcomeTone('denied')).toBe('warning');
    expect(outcomeTone('unmapped')).toBe('warning');
    expect(outcomeTone('error')).toBe('danger');
    expect(outcomeTone('unknown')).toBe('neutral');
  });
});

describe('toggleCommand', () => {
  const order = ['device', 'alerts', 'ack', 'run'];
  it('adds and removes in catalogue order', () => {
    expect(toggleCommand(['run', 'device'], 'alerts', true, order)).toEqual(['device', 'alerts', 'run']);
    expect(toggleCommand(['device', 'alerts'], 'device', false, order)).toEqual(['alerts']);
  });
});

describe('validateBotForm', () => {
  it('needs a secret until one is stored', () => {
    expect(validateBotForm('slack', { secret: '', token: '' }, false).secret).toBeTruthy();
    expect(validateBotForm('slack', { secret: '', token: '' }, true)).toEqual({});
  });
  it('checks lengths and the Teams base64 token', () => {
    expect(validateBotForm('slack', { secret: 'short', token: '' }, false).secret).toBeTruthy();
    expect(validateBotForm('teams', { secret: 'not base64 !!', token: '' }, false).secret).toMatch(/base64/);
    expect(validateBotForm('teams', { secret: btoa('teams-security-token'), token: '' }, false)).toEqual({});
    expect(validateBotForm('webex', { secret: 'webex-secret-1', token: 'tiny' }, false).token).toBeTruthy();
  });
});

describe('validateMapping', () => {
  it('requires an id without spaces and a user', () => {
    expect(validateMapping({ chatUserId: '', userId: null })).toEqual({
      chatUserId: 'Enter the chat user id or e-mail.',
      userId: 'Choose the Plexus user the commands run as.',
    });
    expect(validateMapping({ chatUserId: 'U0 123', userId: 1 }).chatUserId).toBeTruthy();
    expect(validateMapping({ chatUserId: 'ana@example.com', userId: 1 })).toEqual({});
  });
});

describe('validatePreset', () => {
  it('mirrors the server name rule and needs a job number', () => {
    expect(validatePreset({ name: 'nightly backup', jobId: '12' })).toEqual({});
    expect(validatePreset({ name: '!bad', jobId: '12' }).name).toBeTruthy();
    expect(validatePreset({ name: 'push confirm', jobId: '12' }).name).toMatch(/confirm/);
    expect(validatePreset({ name: 'ok', jobId: 'x' }).jobId).toBeTruthy();
    expect(validatePreset({ name: 'ok', jobId: '0' }).jobId).toBeTruthy();
  });
});
