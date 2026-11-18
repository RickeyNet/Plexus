import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';

import type { ComputedField, CustomField, FullObjectData, ObjectTypeInfo, RelationshipGroup } from '@/api/customData';
import { computedRows, definitionErrors, fieldRows, relationshipTitle } from '@/lib/customData';

import { ObjectDataPanel } from './ObjectDataPanel';

const field = (key: string, label: string, sort = 0): CustomField => ({
  id: sort + 1,
  key,
  label,
  field_type: 'text',
  choices: [],
  object_types: ['vrf'],
  required: false,
  default_value: '',
  description: '',
  sort_order: sort,
});

const computed = (key: string, label: string): ComputedField => ({
  id: 1,
  key,
  label,
  object_type: 'vrf',
  template: '{{ obj.name }}',
  description: '',
  sort_order: 0,
});

const group = (side: 'source' | 'destination', links: RelationshipGroup['links'] = []): RelationshipGroup => ({
  relationship: {
    id: 7,
    key: 'transit',
    label: 'Carries',
    source_type: 'circuit',
    destination_type: 'vrf',
    cardinality: 'one-to-many',
    description: '',
  },
  side,
  peer_type: side === 'source' ? 'vrf' : 'circuit',
  links,
});

function render(data: FullObjectData, writable: boolean): string {
  const qc = new QueryClient();
  qc.setQueryData(['custom-data', 'object', 'full', 'vrf:5'], data);
  qc.setQueryData(['custom-data', 'fields', 'vrf'], [field('owner', 'Owner', 1), field('site_code', 'Site code', 2)]);
  qc.setQueryData(['custom-data', 'computed', 'vrf'], [computed('display', 'Display name')]);
  const types: ObjectTypeInfo[] = [{ key: 'vrf', label: 'VRF', generic: true, readable: true, writable }];
  qc.setQueryData(['custom-data', 'types'], types);
  return renderToStaticMarkup(
    <QueryClientProvider client={qc}>
      <ObjectDataPanel objectType="vrf" objectId={5} />
    </QueryClientProvider>,
  );
}

describe('ObjectDataPanel', () => {
  const data: FullObjectData = {
    tags: [{ id: 1, name: 'core', color: 'teal' }],
    fields: { owner: 'net ops', retired: 'yes' },
    computed_fields: { display: 'BLUE' },
    relationships: [group('destination', [{ id: 3, peer_id: 9, peer_label: 'CID-100' }])],
  };

  it('shows tags, values, computed fields and related objects', () => {
    const html = render(data, false);
    expect(html).toContain('core');
    expect(html).toContain('Owner');
    expect(html).toContain('net ops');
    expect(html).toContain('retired');
    expect(html).toContain('Display name');
    expect(html).toContain('BLUE');
    expect(html).toContain('Carries (from circuits)');
    expect(html).toContain('CID-100');
  });

  it('offers editing and linking only when the caller may change the type', () => {
    expect(render(data, false)).not.toContain('Edit tags and fields');
    expect(render(data, false)).not.toContain('Unlink');
    const html = render(data, true);
    expect(html).toContain('Edit tags and fields');
    expect(html).toContain('Link circuit');
    expect(html).toContain('aria-label="Unlink CID-100"');
  });

  it('says when there is nothing and hides empty computed fields', () => {
    const html = render({ tags: [], fields: {}, computed_fields: {}, relationships: [group('source')] }, false);
    expect(html).toContain('No tags or custom field values.');
    expect(html).not.toContain('Computed fields');
    expect(html).toContain('None linked.');
  });

  it('shows the loading state before the data arrives', () => {
    const qc = new QueryClient();
    const html = renderToStaticMarkup(
      <QueryClientProvider client={qc}>
        <ObjectDataPanel objectType="rack" objectId={1} />
      </QueryClientProvider>,
    );
    expect(html).toContain('Loading tags and custom fields');
  });
});

describe('panel helpers', () => {
  it('orders values by field and keeps unknown keys last', () => {
    expect(fieldRows([field('a', 'A', 2), field('b', 'B', 1)], { b: 1, a: '', z: true })).toEqual([
      ['B', '1'],
      ['z', 'true'],
    ]);
  });

  it('labels computed values and shows a dash for an empty one', () => {
    expect(computedRows([computed('d', 'Display')], { d: '', x: 'y' })).toEqual([
      ['Display', '—'],
      ['x', 'y'],
    ]);
  });

  it('names the direction of a relationship', () => {
    expect(relationshipTitle(group('source'))).toBe('Carries (to VRFs)');
    expect(relationshipTitle(group('destination'))).toBe('Carries (from circuits)');
  });

  it('checks a definition key only when it is new', () => {
    expect(definitionErrors('Bad', ' ', true)).toEqual({
      key: expect.stringContaining('lowercase') as unknown as string,
      label: 'Enter a label.',
    });
    expect(definitionErrors('Bad', 'Ok', false)).toEqual({});
    expect(definitionErrors('good_key', 'Ok', true)).toEqual({});
  });
});
