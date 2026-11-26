import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';

import { apiRequest } from './client';

export type ChatPlatform = 'slack' | 'webex' | 'teams';

export interface ChatBot {
  platform: ChatPlatform;
  name: string;
  enabled: boolean;
  allowed_commands: string[];
  signing_secret_configured: boolean;
  bot_token_configured: boolean;
  updated_at: string;
  updated_by: string;
}

export interface ChatPlatformInfo {
  platform: ChatPlatform;
  label: string;
  secret_label: string;
  has_bot_token: boolean;
  token_label: string;
  /** Inbound endpoint paths by purpose (commands, interactivity, webhook). */
  paths: Record<string, string>;
  bot: ChatBot | null;
}

export interface ChatCommandInfo {
  name: string;
  usage: string;
  summary: string;
  features: string[];
  write: boolean;
}

export interface ChatOpsOverview {
  platforms: ChatPlatformInfo[];
  commands: ChatCommandInfo[];
  default_commands: string[];
}

export interface ChatBotUpdate {
  name: string;
  enabled: boolean;
  allowed_commands: string[];
  signing_secret?: string | null;
  bot_token?: string | null;
  clear_bot_token?: boolean;
}

export interface ChatUserMapping {
  id: number;
  platform: ChatPlatform;
  chat_user_id: string;
  chat_label: string;
  user_id: number;
  username: string;
  role: string;
  created_by: string;
  created_at: string;
}

export interface ChatUserMappingCreate {
  platform: ChatPlatform;
  chat_user_id: string;
  chat_label: string;
  user_id: number;
}

export interface ChatJobPreset {
  id: number;
  name: string;
  description: string;
  playbook_name: string;
  source_job_id: number | null;
  targets: string;
  commit: boolean;
  enabled: boolean;
  updated_at: string;
  updated_by: string;
}

export interface ChatJobPresetCreate {
  name: string;
  description: string;
  job_id: number;
  commit: boolean;
  enabled: boolean;
}

export type ChatOutcome = 'ok' | 'denied' | 'unmapped' | 'error' | 'unknown' | 'rate_limited';

export interface ChatCommandLogRow {
  id: number;
  created_at: string;
  platform: ChatPlatform | string;
  chat_user_id: string;
  chat_user_name: string;
  username: string;
  command: string;
  arguments: string;
  outcome: ChatOutcome | string;
  detail: string;
  duration_ms: number;
}

const ROOT = ['admin', 'chatops'] as const;

export function useChatOps() {
  return useQuery<ChatOpsOverview>({
    queryKey: [...ROOT, 'overview'],
    queryFn: ({ signal }) => apiRequest('/admin/chatops', { signal }),
  });
}

export function useUpdateChatBot() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ platform, body }: { platform: ChatPlatform; body: ChatBotUpdate }) =>
      apiRequest<ChatBot>(`/admin/chatops/bots/${platform}`, { method: 'PUT', body }),
    onSuccess: () => qc.invalidateQueries({ queryKey: [...ROOT, 'overview'] }),
  });
}

export function useDeleteChatBot() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (platform: ChatPlatform) => apiRequest(`/admin/chatops/bots/${platform}`, { method: 'DELETE' }),
    onSuccess: () => qc.invalidateQueries({ queryKey: [...ROOT, 'overview'] }),
  });
}

export function useChatUserMappings() {
  return useQuery<ChatUserMapping[]>({
    queryKey: [...ROOT, 'mappings'],
    queryFn: ({ signal }) => apiRequest('/admin/chatops/mappings', { signal }),
  });
}

export function useCreateChatUserMapping() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: ChatUserMappingCreate) =>
      apiRequest<ChatUserMapping>('/admin/chatops/mappings', { method: 'POST', body }),
    onSuccess: () => qc.invalidateQueries({ queryKey: [...ROOT, 'mappings'] }),
  });
}

export function useDeleteChatUserMapping() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: number) => apiRequest(`/admin/chatops/mappings/${id}`, { method: 'DELETE' }),
    onSuccess: () => qc.invalidateQueries({ queryKey: [...ROOT, 'mappings'] }),
  });
}

export function useChatJobPresets() {
  return useQuery<ChatJobPreset[]>({
    queryKey: [...ROOT, 'presets'],
    queryFn: ({ signal }) => apiRequest('/admin/chatops/presets', { signal }),
  });
}

export function useCreateChatJobPreset() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: ChatJobPresetCreate) =>
      apiRequest<ChatJobPreset>('/admin/chatops/presets', { method: 'POST', body }),
    onSuccess: () => qc.invalidateQueries({ queryKey: [...ROOT, 'presets'] }),
  });
}

export function useUpdateChatJobPreset() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, body }: { id: number; body: { description: string; commit: boolean; enabled: boolean } }) =>
      apiRequest<ChatJobPreset>(`/admin/chatops/presets/${id}`, { method: 'PUT', body }),
    onSuccess: () => qc.invalidateQueries({ queryKey: [...ROOT, 'presets'] }),
  });
}

export function useDeleteChatJobPreset() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: number) => apiRequest(`/admin/chatops/presets/${id}`, { method: 'DELETE' }),
    onSuccess: () => qc.invalidateQueries({ queryKey: [...ROOT, 'presets'] }),
  });
}

export function useChatCommandLog(platform: string, outcome: string) {
  const params = new URLSearchParams({ limit: '200' });
  if (platform) params.set('platform', platform);
  if (outcome) params.set('outcome', outcome);
  return useQuery<ChatCommandLogRow[]>({
    queryKey: [...ROOT, 'log', platform, outcome],
    queryFn: ({ signal }) => apiRequest(`/admin/chatops/log?${params.toString()}`, { signal }),
  });
}
