import { describe, expect, it } from 'vitest';

import { authMethod, buildAuthConfig, isAllRegions, providerForm } from './accountForm';

describe('buildAuthConfig', () => {
  it('saves an AWS access key with the sync settings that were filled in', () => {
    const result = buildAuthConfig(
      providerForm('aws'),
      'access_key',
      {
        access_key_id: ' AKIA123 ',
        secret_access_key: 's3cret',
        role_arn: 'arn:left-over-from-another-method',
        log_group_name: '/aws/vpc/flow-logs',
        resource_ids: 'i-1, i-2\ni-3',
        metric_names: '',
      },
      '123456789012',
      '',
    );
    expect(result).toEqual({
      config: {
        access_key_id: 'AKIA123',
        secret_access_key: 's3cret',
        log_group_name: '/aws/vpc/flow-logs',
        resource_ids: ['i-1', 'i-2', 'i-3'],
      },
    });
  });

  it('asks for the fields a sign-in needs, and for nothing with server credentials', () => {
    const aws = providerForm('aws');
    expect(buildAuthConfig(aws, 'access_key', { access_key_id: 'AKIA123' }, '', '')).toEqual({
      error: 'Secret access key is required',
    });
    expect(buildAuthConfig(aws, 'assume_role', { role_arn: 'arn:aws:iam::1:role/r' }, '', '')).toEqual({
      config: { role_arn: 'arn:aws:iam::1:role/r' },
    });
    expect(buildAuthConfig(aws, 'server', {}, '', '')).toEqual({ config: {} });
  });

  it('saves the identifier where Azure and GCP sync read it', () => {
    expect(buildAuthConfig(providerForm('azure'), 'server', {}, ' sub-1 ', '')).toEqual({
      config: { subscription_id: 'sub-1' },
    });
    const key = '{"type": "service_account", "project_id": "p"}';
    expect(buildAuthConfig(providerForm('gcp'), 'service_account', { service_account_json: key }, 'p', '')).toEqual({
      config: { project_id: 'p', service_account_json: { type: 'service_account', project_id: 'p' } },
    });
    expect(
      buildAuthConfig(providerForm('gcp'), 'service_account', { service_account_json: 'not json' }, 'p', ''),
    ).toEqual({ error: 'Key file contents is not valid JSON' });
  });

  it('lays additional settings on top', () => {
    const aws = providerForm('aws');
    expect(buildAuthConfig(aws, 'server', {}, '', '{"profile_name": "prod", "period_seconds": 60}')).toEqual({
      config: { profile_name: 'prod', period_seconds: 60 },
    });
    expect(buildAuthConfig(aws, 'server', {}, '', '[1]')).toEqual({
      error: 'Additional settings must be a JSON object',
    });
    expect(buildAuthConfig(aws, 'server', {}, '', '{')).toEqual({ error: 'Additional settings are not valid JSON' });
  });
});

describe('AWS temporary credentials', () => {
  it('saves a session token with the access key, and leaves it out when empty', () => {
    const aws = providerForm('aws');
    expect(
      buildAuthConfig(
        aws,
        'access_key',
        { access_key_id: 'ASIA123', secret_access_key: 's3cret', session_token: ' IQoJtoken ' },
        '',
        '',
      ),
    ).toEqual({ config: { access_key_id: 'ASIA123', secret_access_key: 's3cret', session_token: 'IQoJtoken' } });
    expect(buildAuthConfig(aws, 'access_key', { access_key_id: 'AKIA123', secret_access_key: 's3cret' }, '', '')).toEqual({
      config: { access_key_id: 'AKIA123', secret_access_key: 's3cret' },
    });
    expect(
      buildAuthConfig(aws, 'assume_role', { role_arn: 'arn:aws:iam::1:role/r', session_token: 'tok' }, '', ''),
    ).toEqual({ config: { role_arn: 'arn:aws:iam::1:role/r', session_token: 'tok' } });
  });

  it('saves a server profile name only when one is given', () => {
    const aws = providerForm('aws');
    expect(buildAuthConfig(aws, 'server', { profile_name: 'corp-sso' }, '', '')).toEqual({
      config: { profile_name: 'corp-sso' },
    });
  });
});

describe('authMethod', () => {
  it('falls back to the first sign-in of the provider', () => {
    expect(authMethod(providerForm('azure'), 'access_key').key).toBe('service_principal');
    expect(authMethod(providerForm('other'), 'anything').key).toBe('server');
  });
});

describe('isAllRegions', () => {
  it('recognises the scope that reads every region', () => {
    expect(isAllRegions(' All ')).toBe(true);
    expect(isAllRegions('*')).toBe(true);
    expect(isAllRegions('us-east-1, us-west-2')).toBe(false);
    expect(isAllRegions(null)).toBe(false);
  });
});
