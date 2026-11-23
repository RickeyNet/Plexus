import { Link } from 'react-router';

import type { HardwareComponent, HardwareEvent } from '@/api/hardware';
import { Badge } from '@/components/Badge';
import { Dash } from '@/components/CatalogueParts';
import { eventInfo, hardwareEventParts, statusInfo } from '@/lib/hardware';

/** The component status pill: present, missing (not in the last read), removed. */
export function ComponentStatusBadge({ status }: { status: string }) {
  const info = statusInfo(status);
  return (
    <Badge size="sm" tone={info.tone}>
      {info.label}
    </Badge>
  );
}

/** The event type pill: replaced, installed, removed, moved, changed, first read. */
export function EventBadge({ event }: { event: string }) {
  const info = eventInfo(event);
  return (
    <Badge size="sm" tone={info.tone}>
      {info.label}
    </Badge>
  );
}

/** The event as one sentence; another host it came from links to its device page. */
export function EventSentence({ event }: { event: HardwareEvent }) {
  return (
    <>
      {hardwareEventParts(event).map((part, i) =>
        typeof part === 'string' ? (
          <span key={i}>{part}</span>
        ) : part.hostId !== null ? (
          <Link key={i} to={`/devices/${part.hostId}`}>
            {part.hostname}
          </Link>
        ) : (
          <span key={i}>{part.hostname}</span>
        ),
      )}
    </>
  );
}

/** Hardware and firmware revision in one cell. */
export function Revisions({ component }: { component: Pick<HardwareComponent, 'hardware_rev' | 'firmware_rev' | 'software_rev'> }) {
  const { hardware_rev: hw, firmware_rev: fw, software_rev: sw } = component;
  if (!hw && !fw && !sw) return <Dash />;
  return (
    <>
      {hw && <div>HW {hw}</div>}
      {fw && <div>FW {fw}</div>}
      {sw && <div className="text-muted">SW {sw}</div>}
    </>
  );
}

/** Monospace serial, or a dash. */
export function Serial({ value }: { value: string }) {
  return value ? <code style={{ fontFamily: 'var(--font-mono)' }}>{value}</code> : <Dash />;
}
