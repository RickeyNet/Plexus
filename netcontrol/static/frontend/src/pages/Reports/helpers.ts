export function formatDuration(seconds: number | null | undefined): string {
  if (seconds == null) return '-';
  const s = Math.max(0, Math.floor(seconds));
  if (s < 60) return `${s}s`;
  if (s < 3600) {
    const m = Math.floor(s / 60);
    const rem = s % 60;
    return rem ? `${m}m ${rem}s` : `${m}m`;
  }
  if (s < 86400) {
    const h = Math.floor(s / 3600);
    const m = Math.floor((s % 3600) / 60);
    return m ? `${h}h ${m}m` : `${h}h`;
  }
  const d = Math.floor(s / 86400);
  const h = Math.floor((s % 86400) / 3600);
  return h ? `${d}d ${h}h` : `${d}d`;
}

export function formatBps(bps: number | null | undefined): string {
  if (bps == null || bps === 0) return '0 bps';
  if (bps >= 1e9) return (bps / 1e9).toFixed(2) + ' Gbps';
  if (bps >= 1e6) return (bps / 1e6).toFixed(2) + ' Mbps';
  if (bps >= 1e3) return (bps / 1e3).toFixed(2) + ' Kbps';
  return bps.toFixed(0) + ' bps';
}

export function severityBadgeClass(severity: string | null | undefined): string {
  const s = (severity || '').toLowerCase();
  if (s === 'emergency' || s === 'alert' || s === 'critical' || s === 'error') return 'badge-danger';
  if (s === 'warning') return 'badge-warning';
  return 'badge-info';
}

export function availabilityBadgeClass(state: string | null | undefined): string {
  const s = (state || '').toLowerCase();
  if (s === 'up') return 'badge-success';
  if (s === 'down') return 'badge-danger';
  return 'badge-warning';
}

function extractFilename(disposition: string, fallback: string): string {
  const utf8 = disposition.match(/filename\*=UTF-8''([^;]+)/i);
  if (utf8 && utf8[1]) {
    try {
      return decodeURIComponent(utf8[1]).trim() || fallback;
    } catch {
      // fall through
    }
  }
  const basic = disposition.match(/filename="?([^";]+)"?/i);
  if (basic && basic[1]) return basic[1].trim() || fallback;
  return fallback;
}

export async function downloadReportExport(url: string, fallbackName = 'report.bin'): Promise<void> {
  const res = await fetch(url, {
    method: 'GET',
    credentials: 'same-origin',
    cache: 'no-store',
    headers: { Accept: '*/*' },
  });
  if (!res.ok) {
    let reason = `HTTP ${res.status}`;
    const ct = (res.headers.get('content-type') || '').toLowerCase();
    try {
      if (ct.includes('application/json')) {
        const data = await res.json();
        if (data?.detail) reason = String(data.detail);
      } else {
        const text = (await res.text()).trim();
        if (text) reason = text.slice(0, 180);
      }
    } catch {
      // ignore parse errors
    }
    throw new Error(reason);
  }
  const blob = await res.blob();
  if (!blob || blob.size <= 0) throw new Error('Received an empty file.');
  const filename = extractFilename(res.headers.get('content-disposition') || '', fallbackName);
  const blobUrl = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = blobUrl;
  a.download = filename;
  a.style.display = 'none';
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(blobUrl), 1500);
}
