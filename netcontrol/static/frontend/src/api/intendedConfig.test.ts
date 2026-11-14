import { beforeEach, describe, expect, it, vi } from 'vitest';

import { CustomDataError } from './customData';
import { intendedConfigApi, intendedHostsPath } from './intendedConfig';

const client = vi.hoisted(() => ({ apiRequest: vi.fn() }));

vi.mock('./client', async (importOriginal) => {
  const actual = await importOriginal<typeof import('./client')>();
  return { ...actual, apiRequest: client.apiRequest };
});

describe('intendedHostsPath', () => {
  it('keeps only the filters that are set', () => {
    expect(intendedHostsPath({ group_id: null, compliance: '', status: '' })).toBe('/intended-config/hosts');
    expect(intendedHostsPath({ group_id: 4, compliance: 'non_compliant', status: 'error' })).toBe(
      '/intended-config/hosts?group_id=4&compliance=non_compliant&status=error',
    );
  });
});

describe('intendedConfigApi', () => {
  beforeEach(() => {
    client.apiRequest.mockReset();
    client.apiRequest.mockResolvedValue({});
  });

  it('posts generate with the body it is given', async () => {
    client.apiRequest.mockResolvedValue({ hosts: 3, generated: 2, changed: 1, errors: 0, no_template: 1 });
    await expect(intendedConfigApi.generate({})).resolves.toEqual({ hosts: 3, generated: 2, changed: 1, errors: 0, no_template: 1 });
    expect(client.apiRequest).toHaveBeenCalledWith('/intended-config/generate', { method: 'POST', body: {} });
    await intendedConfigApi.generate({ host_ids: [7] });
    expect(client.apiRequest).toHaveBeenLastCalledWith('/intended-config/generate', { method: 'POST', body: { host_ids: [7] } });
  });

  it('unwraps the template and context lists', async () => {
    client.apiRequest.mockResolvedValueOnce({ templates: [{ id: 1 }] }).mockResolvedValueOnce({ contexts: [{ id: 2 }] });
    expect(await intendedConfigApi.templates()).toEqual([{ id: 1 }]);
    expect(await intendedConfigApi.contexts()).toEqual([{ id: 2 }]);
    expect(client.apiRequest).toHaveBeenNthCalledWith(1, '/intended-config/templates', undefined);
    expect(client.apiRequest).toHaveBeenNthCalledWith(2, '/intended-config/contexts', undefined);
  });

  it('sends writes, preview and reads to their routes', async () => {
    const tpl = {
      name: 'edge',
      kind: 'device' as const,
      device_type: 'cisco_ios',
      role_id: 2,
      site_id: null,
      group_id: null,
      template_text: 'hostname {{ host.name }}\n',
      description: '',
      enabled: true,
    };
    await intendedConfigApi.createTemplate(tpl);
    expect(client.apiRequest).toHaveBeenLastCalledWith('/intended-config/templates', { method: 'POST', body: tpl });
    await intendedConfigApi.updateTemplate(5, tpl);
    expect(client.apiRequest).toHaveBeenLastCalledWith('/intended-config/templates/5', { method: 'PUT', body: tpl });
    await intendedConfigApi.deleteContext(6);
    expect(client.apiRequest).toHaveBeenLastCalledWith('/intended-config/contexts/6', { method: 'DELETE' });
    await intendedConfigApi.preview({ host_id: 9, template_text: 'x' });
    expect(client.apiRequest).toHaveBeenLastCalledWith('/intended-config/preview', { method: 'POST', body: { host_id: 9, template_text: 'x' } });
    await intendedConfigApi.variables(9);
    expect(client.apiRequest).toHaveBeenLastCalledWith('/intended-config/hosts/9/variables', undefined);
    await intendedConfigApi.host(9);
    expect(client.apiRequest).toHaveBeenLastCalledWith('/intended-config/hosts/9', undefined);
  });

  it('turns a syntax error 400 into an error that names the line', async () => {
    const { ApiError } = await import('./client');
    client.apiRequest.mockRejectedValue(new ApiError(400, { detail: { message: "unexpected '}'", line: 3 } }, 'Bad Request'));
    const err = await intendedConfigApi.createTemplate({
      name: 'x',
      kind: 'device',
      device_type: '',
      role_id: null,
      site_id: null,
      group_id: null,
      template_text: '{{ }',
      description: '',
      enabled: true,
    }).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(CustomDataError);
    expect((err as CustomDataError).message).toBe("unexpected '}'");
    expect((err as CustomDataError).line).toBe(3);
    expect((err as CustomDataError).status).toBe(400);
  });
});
