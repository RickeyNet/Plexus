import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';

import type { CustomField, ObjectType } from '@/api/customData';
import type { FormValues } from '@/lib/customData';

import { CustomFieldsForm } from './CustomFieldsForm';

let nextId = 1;
const field = (key: string, partial: Partial<CustomField> = {}): CustomField => ({
  id: nextId++,
  key,
  label: key,
  field_type: 'text',
  choices: [],
  object_types: ['host'],
  required: false,
  default_value: '',
  description: '',
  sort_order: 0,
  ...partial,
});

function render(
  fields: CustomField[],
  values: FormValues = {},
  errors: Record<string, string> = {},
  objectType: ObjectType = 'host',
): string {
  const qc = new QueryClient();
  qc.setQueryData(['custom-data', 'fields', objectType], fields);
  return renderToStaticMarkup(
    <QueryClientProvider client={qc}>
      <CustomFieldsForm objectType={objectType} values={values} onChange={() => {}} errors={errors} />
    </QueryClientProvider>,
  );
}

/** The opening tag of the control whose label reads `label`. */
function controlFor(html: string, label: string): string {
  const labelMatch = new RegExp(`<label class="form-label" for="([^"]+)">${label}`).exec(html);
  if (!labelMatch) throw new Error(`no label ${label}`);
  const control = new RegExp(`<(input|select)[^>]*id="${labelMatch[1]}"[^>]*>`).exec(html);
  if (!control) throw new Error(`no control for ${label}`);
  return control[0];
}

describe('CustomFieldsForm', () => {
  it('renders an input of the right kind for each of the six types', () => {
    const html = render([
      field('owner', { label: 'Owner', sort_order: 1 }),
      field('units', { label: 'Rack units', field_type: 'number', sort_order: 2 }),
      field('managed', { label: 'Managed', field_type: 'boolean', sort_order: 3 }),
      field('eol', { label: 'End of support', field_type: 'date', sort_order: 4 }),
      field('docs', { label: 'Runbook', field_type: 'url', sort_order: 5 }),
      field('env', { label: 'Environment', field_type: 'select', choices: ['prod', 'lab'], sort_order: 6 }),
    ], { units: 10.5, eol: '2026-02-28' });
    expect(controlFor(html, 'Owner')).toContain('type="text"');
    expect(controlFor(html, 'Rack units')).toContain('type="number"');
    expect(controlFor(html, 'Rack units')).toContain('value="10.5"');
    expect(controlFor(html, 'End of support')).toContain('type="date"');
    expect(controlFor(html, 'Runbook')).toContain('type="url"');
    expect(controlFor(html, 'Environment')).toMatch(/^<select/);
    expect(html).toContain('<option value="" selected="">Not set</option>');
    expect(html).toMatch(/<label class="form-check"><input type="checkbox"[^>]*\/><span>Managed<\/span><\/label>/);
    // Display order follows sort_order.
    expect(html.indexOf('Owner')).toBeLessThan(html.indexOf('Environment'));
  });

  it('marks required fields and shows the description as help', () => {
    const html = render([field('owner', { label: 'Owner', required: true, description: 'Team that runs it' })]);
    expect(html).toContain('Owner<span class="form-required" aria-hidden="true"> *</span>');
    expect(controlFor(html, 'Owner')).toContain('aria-required="true"');
    expect(html).toContain('Team that runs it');
  });

  it('shows the error under its field', () => {
    const html = render(
      [field('owner', { label: 'Owner' }), field('site', { label: 'Site' })],
      {},
      { site: 'Site is required.' },
    );
    expect(controlFor(html, 'Site')).toContain('aria-invalid="true"');
    expect(controlFor(html, 'Owner')).toContain('aria-invalid="false"');
    const siteAt = html.indexOf('>Site<');
    const errorAt = html.indexOf('Site is required.');
    expect(errorAt).toBeGreaterThan(siteAt);
    expect(html.slice(siteAt, errorAt)).not.toContain('>Owner<');
  });

  it('keeps a removed select choice visible', () => {
    const html = render(
      [field('env', { label: 'Environment', field_type: 'select', choices: ['prod'] })],
      { env: 'lab' },
    );
    expect(html).toContain('<option value="lab" selected="">lab (removed)</option>');
    expect(html).toContain('<option value="prod">prod</option>');
  });

  it('renders nothing when no field applies', () => {
    expect(render([], {}, {}, 'group')).toBe('');
    expect(render([field('owner', { object_types: ['host'] })], {}, {}, 'group')).toBe('');
  });
});
