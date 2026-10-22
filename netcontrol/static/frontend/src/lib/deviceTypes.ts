/**
 * Device types an inventory host can have: the keys the backend drivers are
 * registered under, with the label the host dialogs show. Shared by the
 * Inventory host dialog and the Topology page's "Add to inventory".
 */
export const DEVICE_TYPES: readonly { value: string; label: string }[] = [
  { value: 'cisco_ios', label: 'Cisco IOS' },
  { value: 'cisco_xe', label: 'Cisco IOS-XE' },
  { value: 'cisco_nxos', label: 'Cisco NX-OS' },
  { value: 'cisco_xr', label: 'Cisco IOS-XR' },
  { value: 'cisco_asa', label: 'Cisco ASA' },
  { value: 'cisco_ftd', label: 'Cisco FTD / Firepower' },
  { value: 'arista_eos', label: 'Arista EOS' },
  { value: 'juniper_junos', label: 'Juniper Junos' },
  { value: 'fortinet', label: 'Fortinet FortiOS' },
  { value: 'paloalto_panos', label: 'Palo Alto PAN-OS' },
  { value: 'aruba_aoscx', label: 'Aruba AOS-CX' },
  { value: 'aruba_osswitch', label: 'Aruba AOS-Switch / HP ProCurve' },
  { value: 'icmp_only', label: 'ICMP-only (ping liveness, no SNMP/SSH)' },
];

/** The device type a new host gets when nothing says otherwise. */
export const DEFAULT_DEVICE_TYPE = 'cisco_ios';
