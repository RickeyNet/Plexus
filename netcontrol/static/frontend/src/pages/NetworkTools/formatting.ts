/** Shared display helpers for the Network Tools pages. */

export function formatBytes(bytes: number | null | undefined): string {
  if (!bytes || bytes <= 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(1024));
  const idx = Math.min(i, units.length - 1);
  return `${(bytes / Math.pow(1024, idx)).toFixed(1)} ${units[idx]}`;
}


/**
 * The label of an interface index a flow record carries: its name, with
 * the device when that differs (`LAN (igb1)`), else the index alone
 * (`ifIndex 3`). Index 0 is no interface: traffic the exporter itself
 * sent, or a flow without a route.
 */
export function flowInterfaceLabel(row: {
  if_index: number;
  if_name?: string | null;
  if_device?: string | null;
}): string {
  const name = (row.if_name ?? '').trim();
  const device = (row.if_device ?? '').trim();
  if (name && device && device !== name) return `${name} (${device})`;
  if (name || device) return name || device;
  return row.if_index === 0 ? 'None (index 0)' : `ifIndex ${row.if_index}`;
}
