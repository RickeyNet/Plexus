import type { ReactNode } from 'react';

import { Callout, type CalloutTone } from '@/components/Callout';

/**
 * The banner a background scan reports in (host and Meraki scan progress): a
 * Callout with a Dismiss action once the scan has settled.
 */
export function ScanBanner({
  tone,
  children,
  onDismiss,
}: {
  tone: CalloutTone;
  children: ReactNode;
  onDismiss?: () => void;
}) {
  return (
    <Callout
      tone={tone}
      action={
        onDismiss && (
          <button type="button" className="btn btn-sm btn-ghost" onClick={onDismiss}>
            Dismiss
          </button>
        )
      }
    >
      {children}
    </Callout>
  );
}
