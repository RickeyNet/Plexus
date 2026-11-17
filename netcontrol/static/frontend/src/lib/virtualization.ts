/**
 * Pure helpers of the Virtualization page: VM status labels and tones, the
 * optional number inputs, the address list input, and size formatting.
 * The server validates every value again (docs/virtualization.md).
 */
import type { Tone } from '@/lib/severity';

export const VM_NAME_MAX = 100;
export const INTERFACE_NAME_MAX = 64;
export const PLATFORM_MAX = 100;
export const COMMENTS_MAX = 5000;

export const VM_STATUSES = ['active', 'offline', 'planned', 'staged', 'failed', 'decommissioning'] as const;

const STATUS_TONES: Record<string, Tone> = {
  active: 'success',
  offline: 'neutral',
  planned: 'info',
  staged: 'info',
  failed: 'danger',
  decommissioning: 'warning',
};

export function vmStatusTone(status: string): Tone {
  return STATUS_TONES[status] ?? 'neutral';
}

export function vmStatusLabel(status: string): string {
  return status ? status[0].toUpperCase() + status.slice(1) : '-';
}

/**
 * An optional whole-number input: '' is null (unset), a whole number from 0
 * to `max` is that number, anything else is `undefined` (invalid).
 */
export function parseOptionalCount(text: string, max: number): number | null | undefined {
  const trimmed = text.trim();
  if (trimmed === '') return null;
  if (!/^\d+$/.test(trimmed)) return undefined;
  const n = Number(trimmed);
  return n <= max ? n : undefined;
}

/** The text of an optional number for an input ('' for null). */
export function countToText(value: number | null | undefined): string {
  return value === null || value === undefined ? '' : String(value);
}

/** The addresses typed one per line or separated by commas or spaces, in order, without duplicates. */
export function parseAddressList(text: string): string[] {
  const out: string[] = [];
  for (const part of text.split(/[\s,]+/)) {
    const value = part.trim();
    if (value && !out.includes(value)) out.push(value);
  }
  return out;
}

/** Memory for a table cell: 8192 -> "8 GB", 1536 -> "1.5 GB", 512 -> "512 MB". */
export function formatMemory(mb: number | null | undefined): string {
  if (mb === null || mb === undefined) return '-';
  if (mb < 1024) return `${mb} MB`;
  const gb = mb / 1024;
  return `${Number.isInteger(gb) ? gb : gb.toFixed(1)} GB`;
}

const PROVIDER_LABELS: Record<string, string> = { aws: 'AWS', azure: 'Azure', gcp: 'GCP' };

/** "AWS instance web-1 (account-name)" for a VM linked to a cloud resource; '' otherwise. */
export function cloudResourceLabel(vm: {
  cloud_provider: string | null;
  cloud_resource_type: string | null;
  cloud_resource_name: string | null;
  cloud_account_name: string | null;
}): string {
  if (!vm.cloud_provider) return '';
  const provider = PROVIDER_LABELS[vm.cloud_provider] ?? vm.cloud_provider.toUpperCase();
  const kind = vm.cloud_resource_type === 'vm' ? 'VM' : (vm.cloud_resource_type ?? 'resource');
  const name = vm.cloud_resource_name ? ` ${vm.cloud_resource_name}` : '';
  const account = vm.cloud_account_name ? ` (${vm.cloud_account_name})` : '';
  return `${provider} ${kind}${name}${account}`;
}
