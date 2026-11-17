import { describe, expect, it } from 'vitest';

import type { HardwareNotice, SupportContract } from '@/api/lifecycle';

import {
  contractDraft,
  contractErrors,
  contractInput,
  contractStateInfo,
  coverageInfo,
  formatCost,
  formatDateWithDays,
  formatDays,
  noticeDraft,
  noticeErrors,
  noticeInput,
  noticeTarget,
  stageInfo,
  viaLabel,
} from './lifecycle';

const notice = (over: Partial<HardwareNotice> = {}): HardwareNotice => ({
  id: 1,
  device_type_id: 4,
  device_type_model: 'EX-1000',
  device_type_part_number: '',
  manufacturer_name: 'Example Networks',
  part_number: '',
  end_of_sale: '2026-01-31',
  end_of_sw_maintenance: '',
  end_of_security_fixes: '',
  end_of_support: '2031-01-31',
  documentation_url: '',
  comments: '',
  host_count: 2,
  stage: 'end_of_sale',
  next: null,
  created_by: '',
  created_at: '',
  updated_at: '',
  updated_by: '',
  ...over,
});

describe('labels', () => {
  it('names stages, coverage and contract states with a tone', () => {
    expect(stageInfo('end_of_support')).toEqual({ label: 'End of support', tone: 'danger' });
    expect(stageInfo('none').tone).toBe('neutral');
    expect(stageInfo('other')).toEqual({ label: 'other', tone: 'neutral' });
    expect(coverageInfo('expiring')).toEqual({ label: 'Expiring', tone: 'warning' });
    expect(coverageInfo('x').label).toBe('x');
    expect(contractStateInfo('covered').label).toBe('Active');
    expect(contractStateInfo('x').tone).toBe('neutral');
  });

  it('formats days, dates and costs', () => {
    expect(formatDays(null)).toBe('-');
    expect(formatDays(0)).toBe('today');
    expect(formatDays(1)).toBe('in 1 day');
    expect(formatDays(-3)).toBe('3 days ago');
    expect(formatDateWithDays('2027-01-31', 75)).toBe('2027-01-31 (in 75 days)');
    expect(formatDateWithDays('2027-01-31', null)).toBe('2027-01-31');
    expect(formatDateWithDays(null, 3)).toBe('-');
    expect(formatCost(null, 'USD')).toBe('-');
    expect(formatCost('1500.5', 'USD')).toMatch(/^1,?500\.50 USD$/);
    expect(formatCost('12.00', '')).toBe('12.00');
  });

  it('names a notice target and how it applies', () => {
    expect(noticeTarget(notice())).toBe('Example Networks EX-1000');
    expect(noticeTarget(notice({ device_type_id: 9, device_type_model: null, manufacturer_name: null }))).toBe('Device type #9');
    expect(noticeTarget(notice({ device_type_id: null, part_number: 'EX-LC-8' }))).toBe('Part EX-LC-8');
    expect(viaLabel(['device_type', 'module'])).toBe('device type, module');
    expect(viaLabel(undefined)).toBe('');
  });
});

describe('notice dialog', () => {
  it('drafts from a notice and back', () => {
    const d = noticeDraft(notice());
    expect(d.target).toBe('device_type');
    expect(noticeErrors(d)).toEqual({});
    expect(noticeInput({ ...d, part_number: 'ignored' })).toMatchObject({ device_type_id: 4, part_number: '' });
    const byPart = noticeDraft(notice({ device_type_id: null, part_number: 'EX-LC-8' }));
    expect(byPart.target).toBe('part_number');
    expect(noticeInput({ ...byPart, device_type_id: 4, part_number: ' EX-LC-8 ' })).toMatchObject({
      device_type_id: null,
      part_number: 'EX-LC-8',
    });
    expect(noticeDraft(null).target).toBe('device_type');
  });

  it('flags missing targets, bad dates, order and links', () => {
    const blank = noticeDraft(null);
    expect(noticeErrors(blank)).toEqual({ device_type_id: 'Choose a device type.' });
    expect(Object.keys(noticeErrors({ ...blank, target: 'part_number' }))).toEqual(['part_number']);
    expect(noticeErrors({ ...blank, target: 'part_number', part_number: 'A B' }).part_number).toMatch(/spaces/);
    const errors = noticeErrors({
      ...noticeDraft(notice()),
      end_of_sale: '2026-02-30',
      end_of_security_fixes: '2030-01-01',
      end_of_support: '2029-01-01',
      documentation_url: 'docs.example.com',
    });
    expect(Object.keys(errors).sort()).toEqual(['documentation_url', 'end_of_sale', 'end_of_support']);
  });
});

describe('contract dialog', () => {
  const contract: SupportContract = {
    id: 3,
    provider: 'Example Support Co',
    contract_id: 'SC-1',
    start_date: '2026-01-01',
    end_date: '2027-01-01',
    cost: '100.00',
    currency: 'USD',
    support_level: '8x5',
    description: '',
    comments: '',
    host_count: 2,
    hosts: [
      { id: 5, hostname: 'b', ip_address: '192.0.2.5' },
      { id: 2, hostname: 'a', ip_address: '192.0.2.2' },
    ],
    state: 'covered',
    created_by: '',
    created_at: '',
    updated_at: '',
    updated_by: '',
  };

  it('drafts from a contract and back', () => {
    const d = contractDraft(contract);
    expect(d.host_ids).toEqual([5, 2]);
    expect(contractErrors(d)).toEqual({});
    expect(contractInput({ ...d, cost: ' ', currency: 'eur', host_ids: [5, 2, 5] })).toMatchObject({
      cost: null,
      currency: 'EUR',
      host_ids: [2, 5],
    });
    expect(contractDraft(null).host_ids).toEqual([]);
  });

  it('flags missing names, bad dates, order, cost and currency', () => {
    const errors = contractErrors({
      ...contractDraft(null),
      start_date: '2026-05-01',
      end_date: '2026-04-01',
      cost: '1.234',
      currency: 'dollars',
    });
    expect(Object.keys(errors).sort()).toEqual(['contract_id', 'cost', 'currency', 'end_date', 'provider']);
    expect(contractErrors({ ...contractDraft(contract), start_date: 'soon' }).start_date).toMatch(/YYYY-MM-DD/);
  });
});
