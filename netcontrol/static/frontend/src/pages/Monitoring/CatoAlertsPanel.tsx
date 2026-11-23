import { VendorAlertsPanel } from './VendorAlertsPanel';

/**
 * Cato alerts from each account's events feed: site, link and Socket
 * connectivity events, raised on the server and closed by their recovery
 * event. The shared vendor alert panel with the Cato feed's words
 * (``vendorAlertFeeds``); the feed settings are under Topology > Sources and
 * its IPS events under Security events.
 */
export function CatoAlertsPanel() {
  return <VendorAlertsPanel provider="cato" />;
}
