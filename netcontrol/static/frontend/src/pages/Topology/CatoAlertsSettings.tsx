import { VendorAlertsSettings } from './VendorAlertsSettings';

/**
 * The Cato events feed settings (administrators only): the shared vendor
 * alert feed settings for the ``cato`` provider (per-account opt-out and
 * status, and whether its IPS events are kept as security events). See
 * docs/cato-alerts.md.
 */
export function CatoAlertsSettings() {
  return <VendorAlertsSettings provider="cato" />;
}
