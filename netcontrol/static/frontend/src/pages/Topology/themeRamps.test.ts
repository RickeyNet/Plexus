import { describe, expect, it } from 'vitest';

import type { TopologyEdge } from '@/api/topology';

import {
  edgeStatusLinkColor,
  edgeStatusTone,
  isEdgeDown,
  stpStyle,
  stpTone,
  utilColor,
  utilShadow,
  type TopoStatusColors,
} from './helpers';

const STATUS: TopoStatusColors = {
  success: '#008000',
  warning: '#ff8000',
  danger: '#ff0000',
  info: '#0000ff',
  violet: '#800080',
  muted: '#808080',
};

describe('utilColor', () => {
  it('runs from the theme success color through warning to danger', () => {
    expect(utilColor(0, STATUS).color).toBe('#008000');
    expect(utilColor(50, STATUS).color).toBe('#ff8000');
    expect(utilColor(100, STATUS).color).toBe('#ff0000');
    expect(utilColor(75, STATUS)).toEqual({ color: '#ff4000', highlight: '#ff4000', hover: '#ff4000', opacity: 0.9 });
  });
});

describe('utilShadow', () => {
  it('tints the shadow with the band the utilization is in', () => {
    expect(utilShadow(10, STATUS)).toBe('rgba(0,128,0,0.3)');
    expect(utilShadow(60, STATUS)).toBe('rgba(255,128,0,0.3)');
    expect(utilShadow(90, STATUS)).toBe('rgba(255,0,0,0.4)');
  });
});

describe('stpTone', () => {
  it('maps port states to a status tone', () => {
    expect(stpTone('forwarding')).toBe('success');
    expect(stpTone('Listening')).toBe('warning');
    expect(stpTone('blocking')).toBe('danger');
    expect(stpTone('discarding')).toBe('danger');
    expect(stpTone(null)).toBeNull();
    expect(stpTone('unknown')).toBeNull();
  });
});

describe('stpStyle', () => {
  it('colors each port state from the theme status colors', () => {
    expect(stpStyle('forwarding', STATUS)?.color.color).toBe('#008000');
    expect(stpStyle('LEARNING', STATUS)?.color.color).toBe('#ff8000');
    expect(stpStyle('blocking', STATUS)).toEqual({
      color: { color: '#ff0000', highlight: '#ff0000', hover: '#ff0000', opacity: 0.95 },
      width: 6,
      dashes: [4, 3],
      shadow: 'rgba(255,0,0,0.45)',
    });
    expect(stpStyle('unknown', STATUS)).toBeNull();
  });
});

function link(protocol: string, status?: string): TopologyEdge {
  return { id: 'e', from: 'a', to: 'b', protocol, source: 'meraki', provider: 'opnsense', status };
}

describe('edgeStatusTone', () => {
  it('reads a degraded uplink or tunnel as a warning, distinct from down', () => {
    expect(edgeStatusTone(link('wan', 'degraded'))).toBe('warning');
    expect(edgeStatusTone(link('vpn-ipsec', 'Degraded'))).toBe('warning');
    expect(edgeStatusTone(link('wan', 'failed'))).toBe('danger');
    expect(edgeStatusTone(link('vpn-ipsec', 'unreachable'))).toBe('danger');
  });

  it('leaves healthy and unknown statuses of every provider to the protocol colour', () => {
    for (const status of ['active', 'ready', 'reachable', 'connecting', 'unknown', '', undefined]) {
      expect(edgeStatusTone(link('wan', status))).toBeNull();
    }
  });

  it('counts only down links as down, so a degraded tunnel still carries a path', () => {
    expect(isEdgeDown(link('wan', 'failed'))).toBe(true);
    expect(isEdgeDown(link('vpn-ipsec', 'unreachable'))).toBe(true);
    expect(isEdgeDown(link('wan', 'degraded'))).toBe(false);
  });
});

describe('edgeStatusLinkColor', () => {
  it('draws a degraded link in the warning colour and a down one in danger', () => {
    expect(edgeStatusLinkColor(link('wan', 'degraded'), STATUS)).toEqual({
      color: '#ff8000',
      highlight: '#ff8000',
      hover: '#ff8000',
      opacity: 0.9,
    });
    expect(edgeStatusLinkColor(link('vpn-ipsec', 'unreachable'), STATUS)).toEqual({
      color: '#ff0000',
      highlight: '#ff0000',
      hover: '#ff0000',
      opacity: 0.9,
    });
  });

  it('has no colour for a healthy link', () => {
    expect(edgeStatusLinkColor(link('wan', 'active'), STATUS)).toBeNull();
    expect(edgeStatusLinkColor(link('vpn-ipsec', 'reachable'), STATUS)).toBeNull();
  });
});
