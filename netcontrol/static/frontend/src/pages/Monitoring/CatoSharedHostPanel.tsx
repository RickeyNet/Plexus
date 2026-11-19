import { useCatoSharedHostFindings, useRunCatoSharedHostCheck } from '@/api/monitoring';

import { CatoCheckPanel } from './CatoCheckPanel';


/**
 * Cato shared hosts vs Azure: the virtual machines a Cato account's Shared
 * Hosts rules name (multi-session VDI hosts), checked for what their
 * per-user tunnel to a Cato Socket needs in Azure: a route for the Cato
 * system range to the Socket, IP forwarding on the Socket's interface and
 * network security groups that let udp/4754 through. Run on the server after
 * every Cato collection and Azure discovery; warnings alert like other
 * monitoring alerts.
 */
export function CatoSharedHostPanel() {
  return (
    <CatoCheckPanel
      title="Cato shared hosts vs Azure"
      description="Azure virtual machines named in a Cato account's Shared Hosts rules, checked for the route to the Cato system range, IP forwarding on the Socket and network security groups that allow the tunnel (udp/4754). Runs after every Cato collection and Azure discovery."
      what="Cato shared host findings"
      emptyText="No findings - collect a Cato account with Shared Hosts rules and an Azure account."
      ruleHeader="Route or rule"
      useFindings={useCatoSharedHostFindings}
      useRun={useRunCatoSharedHostCheck}
    />
  );
}
