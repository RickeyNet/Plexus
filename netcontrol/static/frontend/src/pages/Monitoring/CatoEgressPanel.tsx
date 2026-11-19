import { useCatoEgressFindings, useRunCatoEgressCheck } from '@/api/monitoring';

import { CatoCheckPanel } from './CatoCheckPanel';


/**
 * Cato egress vs cloud allow-lists: cloud filter rules (AWS security groups,
 * Azure NSGs, GCP firewall rules) that admit a Cato account's allocated IPs,
 * checked against the Cato network rule a connection to the protected public
 * address matches. Run on the server after every Cato collection and cloud
 * discovery; warnings alert like other monitoring alerts.
 */
export function CatoEgressPanel() {
  return (
    <CatoCheckPanel
      title="Cato egress vs cloud allow-lists"
      description="Cloud rules that allow a Cato account's allocated IPs, checked against the Cato network rule a connection to the protected public address takes. Runs after every Cato collection and cloud discovery."
      what="Cato egress findings"
      emptyText="No findings - collect a Cato account and an AWS, Azure or GCP account."
      ruleHeader="Cloud rule"
      useFindings={useCatoEgressFindings}
      useRun={useRunCatoEgressCheck}
    />
  );
}
