import type { VendorStatus } from '@/api/deviceDetail';
import { Badge } from '@/components/Badge';
import { formatBackendDateTime } from '@/lib/datetime';

import { Item, ItemNode } from './DeviceInfoBar';
import { formatRuntime, upsBatteryTone, upsOutputTone } from './ups';

const pct = (value: number | null | undefined) => (value != null ? `${value}%` : 'N/A');

/**
 * An APC Smart-UPS's newest state, read by the monitoring poll through its
 * Network Management Card: output and battery state, capacity, runtime,
 * load, and the UPS and card identity. Nothing until the first poll.
 */
export function UpsStatusCard({ vendor }: { vendor: VendorStatus | undefined }) {
  if (!vendor || vendor.kind !== 'apc_ups') return null;
  const ups = vendor.status;
  const card = [ups.nmc_model, ups.nmc_firmware && `firmware ${ups.nmc_firmware}`].filter(Boolean).join(', ');
  return (
    <div className="card card-sm" aria-label="UPS status">
      <div
        className="card-body"
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(140px, 1fr))',
          gap: 'var(--space-2)',
        }}
      >
        <ItemNode
          label="UPS output"
          node={<Badge tone={upsOutputTone(ups.output_status)}>{ups.output_status_label || 'Unknown'}</Badge>}
        />
        <ItemNode
          label="Battery"
          node={
            <span style={{ display: 'flex', gap: 'var(--space-1)', flexWrap: 'wrap' }}>
              <Badge tone={upsBatteryTone(ups.battery_status, ups.battery_needs_replacing)}>
                {ups.battery_status_label || 'Unknown'}
              </Badge>
              {ups.battery_needs_replacing && <Badge tone="warning">Replace battery</Badge>}
            </span>
          }
        />
        <Item label="Battery capacity" value={pct(ups.battery_capacity_pct)} />
        <Item label="Runtime left" value={formatRuntime(ups.runtime_minutes)} />
        <Item label="Output load" value={pct(ups.output_load_pct)} />
        <Item label="UPS model" value={ups.model || 'N/A'} />
        <Item label="UPS firmware" value={ups.firmware || 'N/A'} />
        <Item label="UPS serial" value={ups.serial || 'N/A'} />
        <Item label="Management card" value={card || 'N/A'} />
        <Item label="Read" value={formatBackendDateTime(vendor.polled_at, 'N/A')} />
      </div>
    </div>
  );
}
