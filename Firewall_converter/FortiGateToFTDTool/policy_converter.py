#!/usr/bin/env python3
"""
FortiGate Firewall Policy Converter Module
===========================================
This module handles the conversion of FortiGate firewall policies to 
Cisco FTD access rules.

WHAT THIS MODULE DOES:
    - Parses FortiGate 'firewall_policy' section from YAML
    - Extracts policy rules (source, destination, service, action)
    - Maps FortiGate actions to FTD actions (accept -> PERMIT, deny -> DENY)
    - Converts to FTD 'accessrule' format
    - Handles interfaces as security zones
    - Normalizes single values and lists

FORTIGATE YAML FORMAT:
    firewall_policy:
        - POLICY_ID:
            name: "Policy Name"
            uuid: xxxxx
            srcintf: "interface_name" or ["intf1", "intf2"]
            dstintf: "interface_name" or ["intf1", "intf2"]
            action: accept or deny
            srcaddr: "address_name" or ["addr1", "addr2"]
            dstaddr: "address_name" or ["addr1", "addr2"]
            schedule: "always"
            service: "service_name" or ["svc1", "svc2"]

FTD JSON OUTPUT FORMAT:
    {
        "name": "Policy Name",
        "ruleId": 1,
        "sourceZones": [
            {"name": "inside", "type": "securityzone"}
        ],
        "destinationZones": [
            {"name": "outside", "type": "securityzone"}
        ],
        "sourceNetworks": [
            {"name": "source_address", "type": "networkobject"}
        ],
        "destinationNetworks": [
            {"name": "dest_address", "type": "networkobject"}
        ],
        "destinationPorts": [
            {"name": "service_name", "type": "tcpportobject"}
        ],
        "ruleAction": "PERMIT",
        "eventLogAction": "LOG_BOTH",
        "logFiles": false,
        "type": "accessrule"
    }

IMPORTANT NOTES:
    - FortiGate 'srcintf' and 'dstintf' map to FTD 'sourceZones' and 'destinationZones'
    - FortiGate action 'accept' -> FTD 'PERMIT'
    - FortiGate action 'deny' -> FTD 'DENY'
    - Special handling for 'any' and 'all' keywords
    - ruleId is assigned sequentially starting from 1
"""

# NOTE: This module is feature-frozen for compatibility.
# Implement new conversion behavior in Firewall_converter/converter_v2/core.

import re
from typing import Any


def sanitize_name(name: str) -> str:
    """
    Sanitize object names for FTD compatibility.
    
    FTD only allows alphanumeric characters and underscores in object names.
    This function replaces any other character with an underscore.
    
    Args:
        name: Original object name (may contain spaces, dashes, etc.)
        
    Returns:
        Sanitized name safe for FTD
    """
    # Convert to string in case it's not
    name = str(name)
    # Replace any non-alphanumeric character (except underscore) with underscore
    sanitized = re.sub(r'[^a-zA-Z0-9_]', '_', name)
    # Remove consecutive underscores
    sanitized = re.sub(r'_+', '_', sanitized)
    # Remove leading/trailing underscores
    sanitized = sanitized.strip('_')
    return sanitized


class PolicyConverter:
    """
    Converter class for transforming FortiGate firewall policies to FTD access rules.
    
    This class is responsible for:
    1. Reading the 'firewall_policy' section from FortiGate YAML
    2. Extracting policy information (source, dest, service, action)
    3. Mapping interfaces to security zones
    4. Mapping actions (accept/deny to PERMIT/DENY)
    5. Normalizing lists vs single values
    6. Converting to FTD's accessrule format
    """
    
    def __init__(self, fortigate_config: dict[str, Any],
                 split_services: set[str] | None = None,
                 service_name_mapping: dict[str, list[tuple[str, str]]] | None = None,
                 skipped_services: set[str] | None = None,
                 address_name_mapping: dict[str, str] | None = None,
                 address_group_members: dict[str, list[str]] | None = None,
                 address_groups: set[str] | None = None,
                 service_groups: set[str] | None = None,
                 interface_name_mapping: dict[str, str] | None = None):
        """
        Initialize the converter with FortiGate configuration data.
        
        Args:
            fortigate_config: Dictionary containing the complete parsed FortiGate YAML
                             Expected to have a 'firewall_policy' key
            split_services: (DEPRECATED) Set of service names that were split into TCP and UDP
            service_name_mapping: Dict mapping FortiGate service names to list of (FTD name, type) tuples
                                 Example: {"DNS": [("DNS_TCP", "tcpportobject"), ("DNS_UDP", "udpportobject")]}
            skipped_services: Set of service names that were skipped (ICMP, etc.)
            address_name_mapping: Dict mapping FortiGate address names to sanitized FTD names
            address_group_members: Dict mapping group names to their flattened member lists
            address_groups: Set of address group names (to set correct type in rules)
            service_groups: Set of service group names (to set correct type in rules)
            interface_name_mapping: Dict mapping FortiGate interface names to FTD names
        """
        # Store the entire FortiGate configuration
        self.fg_config = fortigate_config
        
        # DEPRECATED: Old way of tracking split services
        self.split_services = split_services or set()
        
        # NEW: Mapping of FortiGate service name -> list of (FTD name, type) tuples
        self.service_name_mapping = service_name_mapping or {}
        
        # Set of services that were skipped (ICMP, etc.)
        self.skipped_services = skipped_services or set()
        
        # Mapping of FortiGate address names to sanitized FTD names
        self.address_name_mapping = address_name_mapping or {}
        
        # Mapping of group names to their flattened member lists
        self.address_group_members = address_group_members or {}
        
        # Set of address group names (sanitized)
        self.address_groups = address_groups or set()
        
        # Set of service group names (sanitized)
        self.service_groups = service_groups or set()

        # Interface name mapping for zones
        self.interface_name_mapping = interface_name_mapping or {}
        
        # This will store the converted FTD access rules
        self.ftd_access_rules = []
        
        # Track statistics
        self.permit_count = 0
        self.deny_count = 0
    
    def convert(self) -> list[dict]:
        """
        Main conversion method - converts all FortiGate policies to FTD access rules.
        
        CONVERSION PROCESS:
        1. Extract the 'firewall_policy' list from FortiGate config
        2. Loop through each policy entry
        3. Extract the policy ID and properties
        4. Normalize all fields (convert single values to lists where needed)
        5. Map FortiGate action to FTD action
        6. Create FTD accessrule structure
        7. Assign sequential ruleId
        8. Return the complete list of converted rules
        
        Returns:
            List of dictionaries, each representing an FTD access rule
        """
        # ====================================================================
        # STEP 1: Extract firewall policies from FortiGate configuration
        # ====================================================================
        policies = self.fg_config.get('firewall_policy', [])
        
        if not policies:
            print("Warning: No firewall policies found in FortiGate configuration")
            print("  Expected key: 'firewall_policy'")
            return []
        
        # This list will accumulate all converted access rules
        access_rules = []
        
        # ruleId counter - FTD assigns sequential IDs to rules
        rule_id_counter = 1
        
        # ====================================================================
        # STEP 2: Process each FortiGate firewall policy
        # ====================================================================
        for policy_dict in policies:
            # ================================================================
            # STEP 2A: Extract the policy ID and properties
            # ================================================================
            # Each policy looks like: {161: {name: ..., action: ...}}
            # The policy ID is the key (e.g., 161)
            policy_id = list(policy_dict.keys())[0]
            properties = policy_dict[policy_id]
            
            # ================================================================
            # STEP 2B: Extract basic policy information
            # ================================================================
            policy_name_raw = properties.get('name', f'Policy_{policy_id}')
            policy_name = sanitize_name(policy_name_raw)
            action = properties.get('action', 'deny')
            
            # ================================================================
            # STEP 2C: Map FortiGate action to FTD action
            # ================================================================
            ftd_action = self._map_action(action)
            
            # Track statistics
            if ftd_action == 'PERMIT':
                self.permit_count += 1
            else:
                self.deny_count += 1
            
            # ================================================================
            # STEP 2D: Extract and normalize source/destination interfaces
            # ================================================================
            # FortiGate interfaces map to FTD security zones
            source_zones = self._normalize_to_list(properties.get('srcintf', []))
            dest_zones = self._normalize_to_list(properties.get('dstintf', []))
            
            # Convert to FTD zone format
            ftd_source_zones = self._create_zone_objects(source_zones)
            ftd_dest_zones = self._create_zone_objects(dest_zones)
            
            # ================================================================
            # STEP 2E: Extract and normalize source/destination addresses
            # ================================================================
            source_addrs = self._normalize_to_list(properties.get('srcaddr', []))
            dest_addrs = self._normalize_to_list(properties.get('dstaddr', []))
            
            # Convert to FTD network object format
            ftd_source_networks = self._create_network_objects(source_addrs)
            ftd_dest_networks = self._create_network_objects(dest_addrs)
            
            # ================================================================
            # STEP 2F: Extract and normalize services
            # ================================================================
            services = self._normalize_to_list(properties.get('service', []))
            
            # Expand services that were split into TCP and UDP
            expanded_services = self._expand_services(services)
            
            # Convert to FTD port object format
            ftd_dest_ports = self._create_port_objects(expanded_services)
            
            # ================================================================
            # STEP 2G: Create the FTD access rule structure
            # ================================================================
            ftd_rule = {
                "name": policy_name,
                "ruleId": rule_id_counter,
                "sourceZones": ftd_source_zones,
                "destinationZones": ftd_dest_zones,
                "sourceNetworks": ftd_source_networks,
                "destinationNetworks": ftd_dest_networks,
                "destinationPorts": ftd_dest_ports,
                "ruleAction": ftd_action,
                "eventLogAction": "LOG_BOTH",  # Can be customized
                "logFiles": False,
                "type": "accessrule"
            }
            
            # Add the converted rule to our result list
            access_rules.append(ftd_rule)
            
            # Increment rule ID for next rule
            rule_id_counter += 1
            
            # ================================================================
            # STEP 2H: Print conversion details for user feedback
            # ================================================================
            src_count = len(ftd_source_networks)
            dst_count = len(ftd_dest_networks)
            svc_count = len(ftd_dest_ports)
            print(f"  Converted: [{policy_id}] {policy_name} -> {ftd_action} "
                  f"(Src:{src_count} Dst:{dst_count} Svc:{svc_count})")
        
        # ====================================================================
        # STEP 3: Store results and return
        # ====================================================================
        self.ftd_access_rules = access_rules
        return access_rules
    
    def _map_action(self, fg_action: str) -> str:
        """
        Map FortiGate action to FTD action.
        
        FortiGate actions:
        - accept, allow -> FTD PERMIT
        - deny, reject -> FTD DENY
        
        Args:
            fg_action: FortiGate action string
            
        Returns:
            FTD action string ('PERMIT' or 'DENY')
        """
        action_lower = fg_action.lower()
        
        if action_lower in ['accept', 'allow']:
            return 'PERMIT'
        elif action_lower in ['deny', 'reject']:
            return 'DENY'
        else:
            # Default to DENY for safety
            print(f"    Warning: Unknown action '{fg_action}', defaulting to DENY")
            return 'DENY'
    
    def _normalize_to_list(self, value: Any) -> list[str]:
        """
        Normalize a value to always be a list.
        
        FortiGate can store values as:
        - Single string: "value"
        - List: ["value1", "value2"]
        - None/empty
        
        This method normalizes all to a list format.
        
        Args:
            value: The value to normalize (string, list, or None)
            
        Returns:
            List of strings
        """
        if value is None or value == '':
            return []
        elif isinstance(value, str):
            return [value]
        elif isinstance(value, list):
            return value
        else:
            return [str(value)]
    
    def _create_zone_objects(self, zone_names: list[str]) -> list[dict]:
        """
        Create FTD security zone references from FortiGate interface names.
        
        Maps FortiGate srcintf/dstintf values to the corresponding FTD security
        zone names. The zone names must match exactly what the interface converter
        created, otherwise the access rules will fail during FTD import.
        
        Lookup Strategy (in order):
            1. Direct lookup: interface_name_mapping[zone_name]
            2. String conversion: interface_name_mapping[str(zone_name)]
            3. Case variations: lowercase, original case
            4. VLAN suffix matching: check if zone_name is embedded in FTD name
            5. Sanitized lookup: sanitize and try again
            6. Fallback: use sanitized name and warn user
        
        Args:
            zone_names: List of FortiGate interface/zone names from policy
            
        Returns:
            List of FTD security zone reference dictionaries
        """
        zone_objects = []
        
        for zone_name in zone_names:
            # Skip 'any' - means no zone restriction in FTD
            if str(zone_name).lower() == 'any':
                continue
            
            # Convert to string (handles integer VLAN IDs from YAML)
            zone_name_str = str(zone_name)
            
            # Attempt lookup with multiple strategies for robustness
            ftd_zone_name = self._lookup_zone_name(zone_name_str)
            
            zone_obj = {
                "name": ftd_zone_name,
                "type": "securityzone"
            }
            zone_objects.append(zone_obj)
        
        return zone_objects
    
    def _lookup_zone_name(self, zone_name: str) -> str:
        """
        Look up the FTD security zone name for a FortiGate interface name.
        
        Tries multiple lookup strategies to handle various naming conventions
        used in FortiGate configurations (VLAN IDs, aliases, mixed case, etc.).
        
        Args:
            zone_name: FortiGate interface name (string)
            
        Returns:
            FTD security zone name (string)
        """
        # Strategy 1: Direct lookup (exact match)
        if zone_name in self.interface_name_mapping:
            return self.interface_name_mapping[zone_name]
        
        # Strategy 2: Lowercase lookup
        zone_name_lower = zone_name.lower()
        if zone_name_lower in self.interface_name_mapping:
            return self.interface_name_mapping[zone_name_lower]
        
        # Strategy 3: Check if any mapping value contains this as a suffix
        # Handles cases like "551" matching "l_slap_551"
        for fg_name, ftd_name in self.interface_name_mapping.items():
            if zone_name.isdigit() and ftd_name.endswith(f"_{zone_name}"):
                return ftd_name
            if ftd_name.endswith(f"_{zone_name_lower}"):
                return ftd_name
        
        # Strategy 4: Sanitize using existing function and try lookup
        sanitized = sanitize_name(zone_name).lower()
        if sanitized in self.interface_name_mapping:
            return self.interface_name_mapping[sanitized]
        
        # Strategy 5: Check if sanitized name exists as a value (is a valid zone)
        zone_values = set(self.interface_name_mapping.values())
        if sanitized in zone_values:
            return sanitized
        
        # Fallback: Use sanitized name but warn about potential mismatch
        print(f"    [WARNING] Interface '{zone_name}' not found in mapping, "
              f"using '{sanitized}' - verify zone exists")
        return sanitized
    
    def _create_network_objects(self, addr_names: list[str]) -> list[dict]:
        """
        Create FTD network object references from FortiGate address names.
        
        Args:
            addr_names: List of FortiGate address object names
            
        Returns:
            List of FTD network object reference dictionaries
        """
        network_objects = []
        
        for addr_name in addr_names:
            # Skip 'all' and 'any' as they mean no address restriction
            if addr_name.lower() in ['all', 'any']:
                continue
            
            # Sanitize the address name
            sanitized_name = sanitize_name(addr_name)
            
            # Check if this is a flattened group - if so, expand to individual members
            if sanitized_name in self.address_group_members:
                # This was a group that got flattened - add all individual members
                for member_name in self.address_group_members[sanitized_name]:
                    network_obj = {
                        "name": member_name,
                        "type": "networkobject"
                    }
                    network_objects.append(network_obj)
            else:
                # Check if we have a mapping for this name
                if sanitized_name in self.address_name_mapping:
                    ftd_name = self.address_name_mapping[sanitized_name]
                else:
                    ftd_name = sanitized_name
                
                # Determine type - is this a group or individual object?
                if sanitized_name in self.address_groups:
                    obj_type = "networkobjectgroup"
                else:
                    obj_type = "networkobject"
                
                network_obj = {
                    "name": ftd_name,
                    "type": obj_type
                }
                network_objects.append(network_obj)
        
        return network_objects
    
    def _expand_services(self, services: list[str]) -> list[tuple[str, str]]:
        """
        Expand services using the service_name_mapping.
        
        Looks up each service in the mapping to get the actual FTD object names
        and types. Filters out skipped services (ICMP, etc.).
        
        Args:
            services: List of FortiGate service names
            
        Returns:
            List of (name, type) tuples for FTD port objects
        """
        expanded = []
        
        for service in services:
            # Skip 'ALL' and 'any' as they mean no service restriction
            if service.upper() in ['ALL', 'ANY']:
                continue
            
            # Sanitize the service name
            sanitized_name = sanitize_name(service)
            
            # Skip if this service was skipped (ICMP, etc.)
            if sanitized_name in self.skipped_services:
                print(f"    Filtered out service: {service} (ICMP/non-port service)")
                continue
            
            # Check if this is a service GROUP
            if sanitized_name in self.service_groups:
                expanded.append((sanitized_name, "portobjectgroup"))
            # Check if this service is in our mapping (individual service)
            elif sanitized_name in self.service_name_mapping:
                # Get all FTD objects for this service (list of (name, type) tuples)
                ftd_objects = self.service_name_mapping[sanitized_name]
                expanded.extend(ftd_objects)
            elif service in self.split_services:
                # DEPRECATED: Old way - just add _TCP and _UDP suffixes
                expanded.append((f"{sanitized_name}_TCP", "tcpportobject"))
                expanded.append((f"{sanitized_name}_UDP", "udpportobject"))
            else:
                # Service not in mapping - use sanitized name, guess type from name
                if '_UDP' in sanitized_name:
                    expanded.append((sanitized_name, "udpportobject"))
                else:
                    expanded.append((sanitized_name, "tcpportobject"))
        
        return expanded
    
    def _create_port_objects(self, service_info: list[tuple[str, str]]) -> list[dict]:
        """
        Create FTD port object references from expanded service info.
        
        Args:
            service_info: List of (name, type) tuples from _expand_services
            
        Returns:
            List of FTD port object reference dictionaries
        """
        port_objects = []
        
        for name, obj_type in service_info:
            port_obj = {
                "name": name,
                "type": obj_type
            }
            port_objects.append(port_obj)
        
        return port_objects
    
    def set_split_services(self, split_services: set[str] = None, # pyright: ignore[reportArgumentType]
                           service_name_mapping: dict[str, list[tuple[str, str]]] = None, # pyright: ignore[reportArgumentType]
                           skipped_services: set[str] = None, # pyright: ignore[reportArgumentType]
                           address_name_mapping: dict[str, str] = None, # pyright: ignore[reportArgumentType]
                           address_group_members: dict[str, list[str]] = None, # pyright: ignore[reportArgumentType]
                           address_groups: set[str] = None, # pyright: ignore[reportArgumentType]
                           service_groups: set[str] = None, # pyright: ignore[reportArgumentType]
                           interface_name_mapping: dict[str, str] = None): # pyright: ignore[reportArgumentType]
        """
        Update the service and address mappings.
        
        This should be called by the main script after converting service and address objects,
        so the policy converter knows how to expand references.
        
        Args:
            split_services: (DEPRECATED) Set of service names that have both TCP and UDP versions
            service_name_mapping: Dict mapping FortiGate service names to list of (FTD name, type) tuples
            skipped_services: Set of service names that were skipped (ICMP, etc.)
            address_name_mapping: Dict mapping FortiGate address names to sanitized FTD names
            address_group_members: Dict mapping group names to their flattened member lists
            address_groups: Set of address group names (to set correct type in rules)
            service_groups: Set of service group names (to set correct type in rules)
        """
        if split_services is not None:
            self.split_services = split_services
        if service_name_mapping is not None:
            self.service_name_mapping = service_name_mapping
        if skipped_services is not None:
            self.skipped_services = skipped_services
        if address_name_mapping is not None:
            self.address_name_mapping = address_name_mapping
        if address_group_members is not None:
            self.address_group_members = address_group_members
        if address_groups is not None:
            self.address_groups = address_groups
        if service_groups is not None:
            self.service_groups = service_groups
        if interface_name_mapping is not None:
            self.interface_name_mapping = interface_name_mapping
    
    def get_statistics(self) -> dict[str, int]:
        """
        Get conversion statistics for reporting.
        
        Returns:
            Dictionary with counts of rules and actions
        """
        return {
            "total_rules": len(self.ftd_access_rules),
            "permit_rules": self.permit_count,
            "deny_rules": self.deny_count
        }


# =============================================================================
# TESTING CODE (for standalone testing of this module)
# =============================================================================

if __name__ == '__main__':
    """
    This code only runs when you execute this file directly.
    It's useful for testing the converter without running the main script.
    
    To test this module standalone:
        python policy_converter.py
    """
    
    # Sample FortiGate configuration for testing
    test_config = {
        'firewall_policy': [
            {
                161: {
                    'name': '3120_EAST_FW_TO_ALL',
                    'uuid': '11111111-2222-3333-8888-000000000013',
                    'srcintf': 'any',
                    'dstintf': 'any',
                    'action': 'accept',
                    'srcaddr': ['3120_EAST_MASTER', '3120_EAST_SLAVE'],
                    'dstaddr': 'all',
                    'schedule': 'always',
                    'service': 'ALL'
                }
            },
            {
                466: {
                    'name': 'BGP2',
                    'uuid': '11111111-2222-3333-8888-000000000013',
                    'srcintf': 'lock',
                    'dstintf': 'open',
                    'action': 'accept',
                    'srcaddr': 'Lock_add_2',
                    'dstaddr': 'open_less_1',
                    'schedule': 'always',
                    'service': 'ALL'
                }
            }
        ]
    }
    
    # Simulate that DNS and HTTPS were split
    split_services = {"DNS", "HTTPS"}
    
    # Create converter instance
    converter = PolicyConverter(test_config, split_services)
    
    # Run conversion
    print("Testing Policy Converter...")
    print("="*60)
    result = converter.convert()
    
    # Display results
    print("\nConversion Results:")
    print("="*60)
    import json
    print(json.dumps(result, indent=2))
    
    # Display statistics
    print("\nStatistics:")
    print("="*60)
    stats = converter.get_statistics()
    for key, value in stats.items():
        print(f"  {key}: {value}")