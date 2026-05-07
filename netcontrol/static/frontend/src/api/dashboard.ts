import { useQuery } from '@tanstack/react-query';

import { apiRequest } from './client';

export interface DashboardStats {
  total_hosts?: number;
  total_playbooks?: number;
  total_jobs?: number;
}

export interface DashboardGroup {
  id: number;
  name: string;
}

export interface DashboardMonitoring {
  open_alerts?: number;
}

export interface DeviceHealth {
  hostname?: string;
  ip_address?: string;
  group_id?: number;
  group_name?: string;
  model?: string;
  device_type?: string;
  poll_status?: string;
  cpu_percent?: number | null;
  memory_percent?: number | null;
  packet_loss_pct?: number | null;
  if_up_count?: number | null;
  if_down_count?: number | null;
  response_time_ms?: number | null;
  uptime_seconds?: number | null;
  polled_at?: string | null;
}

export interface DashboardAlert {
  severity?: string;
  hostname?: string;
  message?: string;
  metric?: string;
  created_at?: string;
}

export interface DashboardResponse {
  stats?: DashboardStats;
  recent_jobs?: unknown[];
  groups?: DashboardGroup[];
  monitoring?: DashboardMonitoring;
  device_health?: DeviceHealth[];
  open_alerts?: DashboardAlert[];
}

export function useDashboard() {
  return useQuery<DashboardResponse>({
    queryKey: ['dashboard'],
    queryFn: () => apiRequest('/dashboard'),
  });
}
