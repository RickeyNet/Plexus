import type { ChatPlatform } from '@/api/chatops';

/** Where each platform shows the id a user mapping needs. */
export const CHAT_ID_HINT: Record<ChatPlatform, string> = {
  slack: 'The Slack member ID (profile, ⋮, Copy member ID), for example U0123ABCD.',
  webex: 'The person’s Webex e-mail address or person ID.',
  teams: 'The Microsoft Entra object ID of the user (aadObjectId), or their Teams user id.',
};

/** The public address a platform must call for an inbound path. */
export function inboundUrl(origin: string, path: string): string {
  return `${origin.replace(/\/+$/, '')}${path}`;
}

export type OutcomeTone = 'success' | 'warning' | 'danger' | 'neutral';

export function outcomeTone(outcome: string): OutcomeTone {
  if (outcome === 'ok') return 'success';
  if (outcome === 'denied' || outcome === 'unmapped' || outcome === 'rate_limited') return 'warning';
  if (outcome === 'error') return 'danger';
  return 'neutral';
}

/** ``list`` with ``name`` on or off, kept in catalogue order. */
export function toggleCommand(list: string[], name: string, on: boolean, order: string[]): string[] {
  const next = new Set(list);
  if (on) next.add(name);
  else next.delete(name);
  return order.filter((c) => next.has(c));
}

export interface BotForm {
  secret: string;
  token: string;
}

export type BotFormErrors = Partial<Record<keyof BotForm, string>>;

const BASE64 = /^[A-Za-z0-9+/]+={0,2}$/;

/** Mirrors the server: a secret is needed until one is stored; 8 to 512 characters. */
export function validateBotForm(
  platform: ChatPlatform,
  form: BotForm,
  secretConfigured: boolean,
): BotFormErrors {
  const errors: BotFormErrors = {};
  const secret = form.secret.trim();
  if (!secret && !secretConfigured) errors.secret = 'Enter the secret the platform signs requests with.';
  else if (secret && (secret.length < 8 || secret.length > 512)) errors.secret = 'Use 8 to 512 characters.';
  else if (secret && platform === 'teams' && (!BASE64.test(secret) || secret.length % 4 !== 0))
    errors.secret = 'Paste the security token exactly as Teams shows it (base64).';
  const token = form.token.trim();
  if (token && (token.length < 8 || token.length > 512)) errors.token = 'Use 8 to 512 characters.';
  return errors;
}

export interface MappingForm {
  chatUserId: string;
  userId: number | null;
}

export type MappingFormErrors = Partial<Record<keyof MappingForm, string>>;

export function validateMapping(form: MappingForm): MappingFormErrors {
  const errors: MappingFormErrors = {};
  const id = form.chatUserId.trim();
  if (!id) errors.chatUserId = 'Enter the chat user id or e-mail.';
  else if (/\s/.test(id)) errors.chatUserId = 'The id has no spaces.';
  else if (id.length > 200) errors.chatUserId = 'Use 200 characters or fewer.';
  if (form.userId === null) errors.userId = 'Choose the Plexus user the commands run as.';
  return errors;
}

export interface PresetForm {
  name: string;
  jobId: string;
}

export type PresetFormErrors = Partial<Record<keyof PresetForm, string>>;

const PRESET_NAME = /^[A-Za-z0-9][A-Za-z0-9 ._-]{0,79}$/;

export function validatePreset(form: PresetForm): PresetFormErrors {
  const errors: PresetFormErrors = {};
  const name = form.name.trim();
  if (!name) errors.name = 'Enter the name people type after /plexus run.';
  else if (!PRESET_NAME.test(name))
    errors.name = 'Use up to 80 letters, digits, spaces, dots, dashes or underscores.';
  else if (/ confirm$/i.test(name)) errors.name = 'The name cannot end with "confirm".';
  if (!/^\d+$/.test(form.jobId.trim()) || Number(form.jobId) < 1)
    errors.jobId = 'Enter the number of a job to copy, from the Jobs page.';
  return errors;
}
