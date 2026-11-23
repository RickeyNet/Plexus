import { useState } from 'react';

import { useMerakiAlerts, usePollMerakiAlerts } from '@/api/merakiAlerts';

import { AlertFeedPanel } from './AlertFeedPanel';
import { merakiAlertRow } from './alertFeed';

/**
 * Meraki alerts from the assurance-alert poll and the webhook receiver,
 * deduplicated across both. Raised on the server like other monitoring
 * alerts; the poll and webhook settings are under Topology > Sources.
 */
export function MerakiAlertsPanel() {
  const [includeResolved, setIncludeResolved] = useState(false);
  const alerts = useMerakiAlerts(includeResolved);
  const poll = usePollMerakiAlerts();

  return (
    <AlertFeedPanel
      title="Meraki alerts"
      description={
        'Alerts from the Meraki dashboard, polled every minute and, when the webhook receiver is set up, pushed as ' +
        'they happen. The same alert from both paths is one row; it closes when Meraki resolves it.'
      }
      what="Meraki alerts"
      sourceNoun="organization"
      emptyText="No Meraki alerts - add a Meraki organization with an API key under Topology."
      rows={alerts.data?.alerts.map(merakiAlertRow)}
      query={alerts}
      includeResolved={includeResolved}
      onIncludeResolved={setIncludeResolved}
      pollBusy={poll.isPending}
      onPoll={(done, failed) => poll.mutate(undefined, { onSuccess: done, onError: failed })}
    />
  );
}
