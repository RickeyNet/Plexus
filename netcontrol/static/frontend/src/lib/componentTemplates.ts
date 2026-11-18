import type { InstantiateResult } from '@/api/dcim';

/** Device type component templates: labels and the summary of an instantiation. */

export const COMPONENT_TYPES = ['interface', 'console_port', 'power_port', 'rear_port', 'front_port', 'module_bay'] as const;
export type ComponentType = (typeof COMPONENT_TYPES)[number];

export const COMPONENT_TYPE_LABELS: Record<ComponentType, string> = {
  interface: 'Interface',
  console_port: 'Console port',
  power_port: 'Power port',
  rear_port: 'Rear port',
  front_port: 'Front port',
  module_bay: 'Module bay',
};

export function componentTypeLabel(type: unknown): string {
  return COMPONENT_TYPE_LABELS[type as ComponentType] ?? String(type ?? '');
}

/** The DCIM record kind (as the result names it) to a plural label. */
const CREATED_LABELS: Record<string, [string, string]> = {
  console_port: ['console port', 'console ports'],
  power_port: ['power port', 'power ports'],
  rear_port: ['rear port', 'rear ports'],
  front_port: ['front port', 'front ports'],
  module: ['module bay', 'module bays'],
};

/** One line per outcome of `POST /api/hosts/{id}/components/instantiate`. */
export function instantiateSummary(result: InstantiateResult): string {
  if (result.device_type_id === null) return 'The device has no device type, so there is nothing to create.';
  const parts: string[] = [];
  const created = Object.entries(result.created)
    .filter(([, names]) => names.length > 0)
    .map(([kind, names]) => {
      const [one, many] = CREATED_LABELS[kind] ?? [kind, kind];
      return `${names.length} ${names.length === 1 ? one : many} (${names.join(', ')})`;
    });
  parts.push(created.length ? `Created ${created.join('; ')}.` : 'Nothing new to create: the device has every component already.');
  if (result.skipped > 0) {
    const noun = result.skipped === 1 ? 'component' : 'components';
    parts.push(`${result.skipped} ${noun} existed already and stayed as they were.`);
  }
  for (const error of result.errors) parts.push(`${error.name}: ${error.message}`);
  const { expected, missing } = result.interfaces;
  if (expected.length > 0) {
    parts.push(
      missing.length === 0
        ? 'The device reports every interface the device type lists.'
        : `Interfaces the device type lists that the device has not reported yet: ${missing.join(', ')}.`,
    );
  }
  return parts.join(' ');
}
