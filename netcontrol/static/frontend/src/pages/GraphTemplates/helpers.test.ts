import { describe, expect, it } from 'vitest';

import type { GraphTreeNode } from '@/api/graphTemplates';

import {
  hostGraphLabel,
  linkDiff,
  nodeDescendantIds,
  nodePayload,
  orderTreeNodes,
  parseDeviceTypes,
  splitDeviceTypes,
  validateNodeForm,
  withCurrentOption,
  LINE_TYPES,
  type NodeFormValues,
} from './helpers';

const node = (id: number, parent: number | null, sort: number, title = `n${id}`): GraphTreeNode => ({
  id,
  parent_node_id: parent,
  sort_order: sort,
  title,
  node_type: 'header',
});

describe('parseDeviceTypes', () => {
  it('parses a JSON array of strings', () => {
    expect(parseDeviceTypes('["cisco_ios","arista_eos"]')).toEqual(['cisco_ios', 'arista_eos']);
  });

  it('returns [] for missing, malformed or non-array values', () => {
    expect(parseDeviceTypes(undefined)).toEqual([]);
    expect(parseDeviceTypes('')).toEqual([]);
    expect(parseDeviceTypes('not json')).toEqual([]);
    expect(parseDeviceTypes('{"a":1}')).toEqual([]);
  });

  it('drops non-string entries', () => {
    expect(parseDeviceTypes('["cisco_ios", 3, null]')).toEqual(['cisco_ios']);
  });
});

describe('splitDeviceTypes', () => {
  it('trims entries and drops blanks', () => {
    expect(splitDeviceTypes(' cisco_ios, ,cisco_nxos ,')).toEqual(['cisco_ios', 'cisco_nxos']);
    expect(splitDeviceTypes('   ')).toEqual([]);
  });
});

describe('linkDiff', () => {
  it('lists the links to add and remove', () => {
    expect(linkDiff([1, 2, 3], [2, 3, 4, 5])).toEqual({ toLink: [4, 5], toUnlink: [1] });
  });

  it('is empty when nothing changed', () => {
    expect(linkDiff(new Set([1, 2]), [2, 1])).toEqual({ toLink: [], toUnlink: [] });
  });
});

describe('withCurrentOption', () => {
  it('keeps the list when the value is known or blank', () => {
    expect(withCurrentOption(LINE_TYPES, 'area')).toHaveLength(LINE_TYPES.length);
    expect(withCurrentOption(LINE_TYPES, '')).toHaveLength(LINE_TYPES.length);
  });

  it('appends an unknown saved value', () => {
    const out = withCurrentOption(LINE_TYPES, 'step');
    expect(out[out.length - 1]).toEqual({ value: 'step', label: 'step' });
  });
});

describe('orderTreeNodes', () => {
  it('nests children under parents, siblings by sort order then id', () => {
    const nodes = [
      node(1, null, 2),
      node(2, null, 1),
      node(3, 1, 5),
      node(4, 1, 0),
      node(5, 4, 0),
      node(6, null, 1),
    ];
    expect(orderTreeNodes(nodes).map((e) => [e.item.id, e.depth])).toEqual([
      [2, 0],
      [6, 0],
      [1, 0],
      [4, 1],
      [5, 2],
      [3, 1],
    ]);
  });

  it('puts nodes with a missing parent at the top and keeps cycle members', () => {
    const nodes = [node(1, 99, 0), node(2, 3, 0), node(3, 2, 0)];
    const ids = orderTreeNodes(nodes).map((e) => e.item.id);
    expect(ids[0]).toBe(1);
    expect([...ids].sort()).toEqual([1, 2, 3]);
  });
});

describe('nodeDescendantIds', () => {
  it('collects children at any depth, not the node itself', () => {
    const nodes = [node(1, null, 0), node(2, 1, 0), node(3, 2, 0), node(4, null, 0)];
    expect([...nodeDescendantIds(nodes, 1)].sort()).toEqual([2, 3]);
    expect(nodeDescendantIds(nodes, 4).size).toBe(0);
  });
});

describe('hostGraphLabel', () => {
  it('prefers the title and adds the instance when the title lacks it', () => {
    expect(hostGraphLabel({ id: 1, host_id: 1, graph_template_id: 1, title: 'Traffic', instance_label: 'Gi0/1' }))
      .toBe('Traffic (Gi0/1)');
    expect(hostGraphLabel({ id: 1, host_id: 1, graph_template_id: 1, title: 'Gi0/1 Traffic', instance_label: 'Gi0/1' }))
      .toBe('Gi0/1 Traffic');
  });

  it('falls back to the template name, then the id', () => {
    expect(hostGraphLabel({ id: 7, host_id: 1, graph_template_id: 1, template_name: 'CPU Usage' })).toBe('CPU Usage');
    expect(hostGraphLabel({ id: 7, host_id: 1, graph_template_id: 1 })).toBe('Graph #7');
  });
});

describe('node form', () => {
  const base: NodeFormValues = {
    title: '',
    nodeType: 'header',
    sortOrder: 0,
    parentId: null,
    hostId: null,
    graphId: null,
  };

  it('requires a title on header nodes', () => {
    expect(validateNodeForm(base, '')).toEqual({ title: 'Title is required' });
    expect(validateNodeForm({ ...base, title: 'Branch sites' }, '')).toEqual({});
  });

  it('requires a host for device nodes and a host graph for graph nodes', () => {
    expect(validateNodeForm({ ...base, nodeType: 'device' }, '').host).toBeDefined();
    const g = validateNodeForm({ ...base, nodeType: 'graph', hostId: 4 }, '');
    expect(g.host).toBeUndefined();
    expect(g.graph).toBeDefined();
  });

  it('lets a device node default its title to the host name', () => {
    const v = { ...base, nodeType: 'device' as const, hostId: 4 };
    expect(validateNodeForm(v, 'edge-rtr-01')).toEqual({});
    expect(nodePayload(v, 'edge-rtr-01')).toMatchObject({ title: 'edge-rtr-01', host_id: 4, graph_id: null });
  });

  it('clears host and graph when a node becomes a header', () => {
    const p = nodePayload({ ...base, title: 'Core', hostId: 4, graphId: 9, parentId: 2 }, '');
    expect(p).toEqual({
      title: 'Core',
      node_type: 'header',
      sort_order: 0,
      parent_node_id: 2,
      host_id: null,
      graph_id: null,
    });
  });

  it('sends host and graph for graph nodes', () => {
    const p = nodePayload({ ...base, nodeType: 'graph', title: ' Uplink ', hostId: 4, graphId: 9 }, 'ignored');
    expect(p).toMatchObject({ title: 'Uplink', node_type: 'graph', host_id: 4, graph_id: 9 });
  });
});
