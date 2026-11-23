/**
 * The words each vendor alert feed (the Cato events feed, AWS, Azure) uses in
 * its alert panel (Monitoring > Availability) and its settings (Topology >
 * Sources for Cato, Cloud Visibility > Accounts for AWS and Azure). One table,
 * so a feed is one entry here, not another copy of the panel and settings.
 */
export interface VendorAlertFeedText {
  /** The panel and settings title ("Cato alerts"). */
  title: string;
  /** The panel's explanation of what is read and when an alert closes. */
  description: string;
  emptyText: string;
  /** One source ("account", "subscription"). */
  sourceNoun: string;
  /** Where its settings and per-source errors are. */
  settingsWhere: string;
  subjectHeading: string;
  sourceHeading: string;
  viaHeading: string;
  /** The poll switch's label. */
  pollLabel: string;
  /** What one poll costs. */
  costNote: string;
  /** The vendor, for the per-source checkbox label. */
  vendor: string;
  /** Whether the feed carries IPS events (the security events switch). */
  securityEvents: boolean;
}

export const VENDOR_ALERT_FEEDS: Record<string, VendorAlertFeedText> = {
  cato: {
    title: 'Cato alerts',
    description:
      'Connectivity events from the Cato events feed (a site or link disconnected, HA not ready, Socket ' +
      'fail-over, last-mile quality), read every minute. An alert closes when Cato reports the recovery or the ' +
      'next collection shows the site and its links up.',
    emptyText:
      'No Cato alerts - add a Cato account with an API key under Topology; its events feed must be enabled in Cato.',
    sourceNoun: 'account',
    settingsWhere: 'Topology > Sources',
    subjectHeading: 'Site / link',
    sourceHeading: 'Account',
    viaHeading: 'Event',
    pollLabel: 'Read the events feed',
    costNote: 'One eventsFeed call per account per poll, more while a backlog is read',
    vendor: 'Cato',
    securityEvents: true,
  },
  aws: {
    title: 'AWS alerts',
    description:
      'CloudWatch alarms in ALARM state, AWS Health issues and scheduled changes, and impaired EC2 status checks ' +
      'and scheduled events of each AWS account in Cloud Visibility, read every five minutes by default. An alert ' +
      'closes when the next complete read of its region no longer reports it.',
    emptyText: 'No AWS alerts - add an AWS account under Cloud Visibility; see docs/cloud-alerts.md for the IAM actions.',
    sourceNoun: 'account',
    settingsWhere: 'Cloud Visibility > Accounts',
    subjectHeading: 'Resource',
    sourceHeading: 'Account',
    viaHeading: 'Source',
    pollLabel: 'Read AWS alarms and health',
    costNote:
      'Per account and poll: one DescribeAlarms and one DescribeInstanceStatus call per region (more pages for ' +
      'large accounts) and one Health DescribeEvents call',
    vendor: 'AWS',
    securityEvents: false,
  },
  azure: {
    title: 'Azure alerts',
    description:
      'Fired Azure Monitor alerts and Resource Health (a resource Unavailable or Degraded) of each Azure ' +
      'subscription in Cloud Visibility, read every five minutes by default. An alert closes when the next ' +
      'complete read no longer reports it.',
    emptyText:
      'No Azure alerts - add an Azure subscription under Cloud Visibility; its identity needs the Reader or ' +
      'Monitoring Reader role.',
    sourceNoun: 'subscription',
    settingsWhere: 'Cloud Visibility > Accounts',
    subjectHeading: 'Resource',
    sourceHeading: 'Subscription',
    viaHeading: 'Source',
    pollLabel: 'Read Azure alerts and Resource Health',
    costNote: 'Two Azure Resource Manager reads per subscription per poll (more pages for large subscriptions)',
    vendor: 'Azure',
    securityEvents: false,
  },
};

export function vendorAlertFeedText(provider: string): VendorAlertFeedText {
  return (
    VENDOR_ALERT_FEEDS[provider] ?? {
      ...VENDOR_ALERT_FEEDS.cato,
      title: `${provider} alerts`,
      description: '',
      emptyText: 'No alerts.',
      settingsWhere: 'the feed settings',
      vendor: provider,
      securityEvents: false,
    }
  );
}
