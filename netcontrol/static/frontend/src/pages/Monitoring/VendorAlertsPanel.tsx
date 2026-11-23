import { useState } from 'react';

import { usePollVendorAlerts, useVendorAlerts } from '@/api/vendorAlerts';

import { AlertFeedPanel } from './AlertFeedPanel';
import { vendorAlertRow } from './alertFeed';
import { vendorAlertFeedText } from './vendorAlertFeeds';

/**
 * The alerts of one vendor alert feed (the Cato events feed, AWS, Azure),
 * raised on the server and closed by their recovery or the next complete
 * read. The words of each feed are in ``vendorAlertFeeds``; its settings are
 * under Topology > Sources (Cato) or Cloud Visibility (AWS, Azure).
 */
export function VendorAlertsPanel({ provider }: { provider: string }) {
  const [includeResolved, setIncludeResolved] = useState(false);
  const alerts = useVendorAlerts(provider, includeResolved);
  const poll = usePollVendorAlerts(provider);
  const text = vendorAlertFeedText(provider);

  return (
    <AlertFeedPanel
      title={text.title}
      description={text.description}
      what={text.title}
      sourceNoun={text.sourceNoun}
      settingsWhere={text.settingsWhere}
      emptyText={text.emptyText}
      rows={alerts.data?.alerts.map(vendorAlertRow)}
      query={alerts}
      includeResolved={includeResolved}
      onIncludeResolved={setIncludeResolved}
      pollBusy={poll.isPending}
      onPoll={(done, failed) => poll.mutate(undefined, { onSuccess: done, onError: failed })}
      subjectHeading={text.subjectHeading}
      sourceHeading={text.sourceHeading}
      viaHeading={text.viaHeading}
    />
  );
}
