import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';

import type { ConfigValue, ProviderPayload, ProviderType } from '@/lib/secretsProviders';

import { apiRequest } from './client';

// External secrets providers (HashiCorp Vault, AWS Secrets Manager, Azure Key
// Vault). See docs/secrets-providers.md. Provider secrets are write-only: the
// API lists which are stored (`secrets_set`), never their values.

export interface SdkStatus {
  status: 'ok' | 'sdk_not_installed' | string;
  missing: string[];
}

export interface SecretsProvider {
  id: number;
  name: string;
  provider_type: ProviderType | string;
  description: string;
  enabled: boolean;
  allow_user_credentials: boolean;
  cache_ttl: number;
  config: Record<string, ConfigValue>;
  secrets_set: string[];
  credential_count: number;
  secret_variable_count: number;
  sdk: SdkStatus;
  updated_at?: string;
  updated_by?: string;
}

export interface SecretsProviderType {
  type: ProviderType;
  label: string;
  secrets: string[];
  sdk: SdkStatus;
}

export interface SecretsProviderList {
  providers: SecretsProvider[];
  types: SecretsProviderType[];
}

/** A provider a credential may reference (names and types only). */
export interface ReferenceProvider {
  id: number;
  name: string;
  provider_type: ProviderType | string;
}

export interface ReferenceTestResult {
  ok: boolean;
  code?: string;
  message?: string;
}

const ROOT = ['secrets-providers'] as const;

export function useSecretsProviders(enabled = true) {
  return useQuery<SecretsProviderList>({
    queryKey: ROOT,
    queryFn: () => apiRequest<SecretsProviderList>('/secrets-providers'),
    enabled,
  });
}

/** The enabled providers the caller may point a credential or secret at. */
export function useReferenceProviders(enabled = true) {
  return useQuery<ReferenceProvider[]>({
    queryKey: [...ROOT, 'references'],
    queryFn: () => apiRequest<ReferenceProvider[]>('/credentials/secrets-providers'),
    enabled,
  });
}

export function useCreateSecretsProvider() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: ProviderPayload) =>
      apiRequest<{ id: number }>('/secrets-providers', { method: 'POST', body }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ROOT }),
  });
}

export function useUpdateSecretsProvider() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, body }: { id: number; body: Partial<ProviderPayload> }) =>
      apiRequest<{ ok: boolean }>(`/secrets-providers/${id}`, { method: 'PUT', body }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ROOT }),
  });
}

export function useDeleteSecretsProvider() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: number) => apiRequest<{ ok: boolean }>(`/secrets-providers/${id}`, { method: 'DELETE' }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ROOT }),
  });
}

/** Resolves one reference on the server: success or failure, never the value. */
export function useTestSecretsProvider() {
  return useMutation({
    mutationFn: ({ id, path, key }: { id: number; path: string; key: string }) =>
      apiRequest<ReferenceTestResult>(`/secrets-providers/${id}/test`, { method: 'POST', body: { path, key } }),
  });
}
