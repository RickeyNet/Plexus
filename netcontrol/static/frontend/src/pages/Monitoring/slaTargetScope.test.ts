import { describe, expect, it } from 'vitest';

import type { SlaTarget } from '@/api/monitoring';

import { ENTITY_TYPE_LABELS, INTEGRATION_PROVIDERS, slaTargetScopeLabel } from './slaTargetScope';

const base: SlaTarget = {
  id: 1,
  name: 'Gateway loss',
  metric: 'packet_loss',
  target_value: 1,
  warning_value: 3,
  enabled: true,
};

describe('slaTargetScopeLabel', () => {
  it('names hosts, groups and global targets as before', () => {
    expect(slaTargetScopeLabel(base)).toBe('Global');
    expect(slaTargetScopeLabel({ ...base, provider: '' })).toBe('Global');
    expect(slaTargetScopeLabel({ ...base, group_id: 2, group_name: 'Branch' })).toBe('Group: Branch');
    expect(slaTargetScopeLabel({ ...base, host_id: 3, host_name: 'fw1.example.com' })).toBe('Host: fw1.example.com');
  });

  it('names an integration target by its integration and entity type', () => {
    expect(slaTargetScopeLabel({ ...base, provider: 'opnsense', entity_type: 'uplink' })).toBe(
      'Integration: OPNsense, uplinks (gateways)',
    );
    expect(slaTargetScopeLabel({ ...base, provider: 'cato', entity_type: '' })).toBe('Integration: Cato, all entities');
  });

  it('shows an entity type it has no label for as it is', () => {
    expect(slaTargetScopeLabel({ ...base, provider: 'aws', entity_type: 'gateway' })).toBe('Integration: AWS, gateway');
  });
});

describe('integration scope lists', () => {
  it('offers every integration once, OPNsense among them', () => {
    expect(new Set(INTEGRATION_PROVIDERS).size).toBe(INTEGRATION_PROVIDERS.length);
    expect(INTEGRATION_PROVIDERS).toContain('opnsense');
    expect(INTEGRATION_PROVIDERS).toContain('aws');
  });

  it('labels the entity types the server accepts', () => {
    expect(Object.keys(ENTITY_TYPE_LABELS)).toEqual([
      'device',
      'site',
      'uplink',
      'tunnel',
      'vpn_connection',
      'circuit',
      'peering',
      'link',
      'service',
    ]);
  });
});
