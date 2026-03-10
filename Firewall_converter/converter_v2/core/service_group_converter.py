#!/usr/bin/env python3
"""
FortiGate Service Group Converter Module
=========================================
This module handles the conversion of FortiGate service groups to 
Cisco FTD port object groups.

IMPORTANT CONSIDERATION:
    - When a FortiGate service group references a service that was split
      into TCP and UDP objects (like "DNS" -> "DNS_TCP" and "DNS_UDP"),
      the group must include BOTH the TCP and UDP versions
    - This module assumes all member names are provided as-is from FortiGate
    - The main script should handle resolving split services

WHAT THIS MODULE DOES:
    - Parses FortiGate 'firewall_service_group' section from YAML
    - Extracts group name and member services
    - Converts to FTD 'portobjectgroup' format
    - Handles both single members and lists of members

FORTIGATE YAML FORMAT:
    firewall_service_group:
        - GROUP_NAME:
            uuid: xxxxx
            member: ["HTTP", "HTTPS", "DNS"]  # List of service names
            color: 13  # Optional
        - ANOTHER_GROUP:
            member: "single_service"  # Single member (string, not list)

FTD JSON OUTPUT FORMAT:
    {
        "name": "Web_Access",
        "isSystemDefined": false,
        "objects": [
            {"name": "HTTP_TCP", "type": "tcpportobject"},
            {"name": "HTTPS_TCP", "type": "tcpportobject"},
            {"name": "DNS_TCP", "type": "tcpportobject"},
            {"name": "DNS_UDP", "type": "udpportobject"}
        ],
        "type": "portobjectgroup"
    }

NOTE ON MEMBER TYPES:
    - We don't know in advance if a member is TCP or UDP
    - We include the member name as-is from FortiGate
    - The type field is set generically (could be refined in post-processing)
"""

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
        Sanitized name with only alphanumeric characters and underscores
    """
    if name is None:
        return ""
    # Convert to string in case it's not
    name = str(name)
    # Replace any non-alphanumeric character (except underscore) with underscore
    sanitized = re.sub(r'[^a-zA-Z0-9_]', '_', name)
    # Remove consecutive underscores
    sanitized = re.sub(r'_+', '_', sanitized)
    # Remove leading/trailing underscores
    sanitized = sanitized.strip('_')
    return sanitized




class ServiceGroupConverter:
    """
    Converter class for transforming FortiGate service groups to FTD port groups.
    
    This class is responsible for:
    1. Reading the 'firewall_service_group' section from FortiGate YAML
    2. Extracting group names and their member services
    3. FLATTENING nested groups (FTD doesn't allow groups inside groups)
    4. Converting to FTD's portobjectgroup format
    5. Handling edge cases (empty groups, single vs multiple members)
    6. Expanding services that were split into multiple FTD objects
    """
    
    def __init__(self, fortigate_config: dict[str, Any],
                 split_services: set[str] | None = None,
                 service_name_mapping: dict[str, list[tuple[str, str]]] | None = None,
                 skipped_services: set[str] | None = None):
        """
        Initialize the converter with FortiGate configuration data.
        
        Args:
            fortigate_config: Dictionary containing the complete parsed FortiGate YAML
                             Expected to have a 'firewall_service_group' key
            split_services: (DEPRECATED) Set of service names that were split into TCP and UDP
            service_name_mapping: Dict mapping FortiGate service names to list of FTD object names
                                 Example: {"LR_CLUST": ["LR_CLUST_TCP_1", "LR_CLUST_TCP_2", "LR_CLUST_UDP_3"]}
            skipped_services: Set of service names that were skipped (ICMP, etc.) and should be
                            filtered out of groups
        """
        # Store the entire FortiGate configuration
        self.fg_config = fortigate_config
        
        # DEPRECATED: Old way of tracking split services (kept for backward compatibility)
        self.split_services = split_services or set()
        
        # NEW: Mapping of FortiGate service name -> list of FTD object names
        # This handles services split into multiple ports AND TCP/UDP splits
        self.service_name_mapping = service_name_mapping or {}
        
        # Set of services that were skipped (ICMP, etc.) - filter these from groups
        self.skipped_services = skipped_services or set()

        # This will store the converted FTD port groups
        self.ftd_port_groups = []
        
        # Build a lookup of group name -> member list for flattening nested groups
        self.group_members = {}
        self._flatten_cache: dict[str, list[str]] = {}
        self._cycle_warnings: set[str] = set()
        self._build_group_lookup()

    @staticmethod
    def _dedupe_preserve_order(items: list[str]) -> list[str]:
        seen: set[str] = set()
        result: list[str] = []
        for item in items:
            if item in seen:
                continue
            seen.add(item)
            result.append(item)
        return result
    
    def _build_group_lookup(self):
        """
        Build a lookup dictionary of group names to their members.
        This is used to flatten nested groups.
        """
        service_groups = self.fg_config.get('firewall_service_group', [])
        
        for group_dict in service_groups:
            group_name = list(group_dict.keys())[0]
            properties = group_dict[group_name]
            
            # Get members and normalize to list
            members_raw = properties.get('member', [])
            if isinstance(members_raw, str):
                members_list = [members_raw]
            elif isinstance(members_raw, list):
                members_list = members_raw
            else:
                members_list = []
            
            # Store with sanitized name
            self.group_members[sanitize_name(group_name)] = [sanitize_name(m) for m in members_list]
    
    def _is_group(self, name: str) -> bool:
        """
        Check if a name refers to a group (not an individual service object).
        
        Args:
            name: The sanitized object/group name to check
            
        Returns:
            True if the name is a group, False if it's an individual object
        """
        return name in self.group_members
    
    def _flatten_group(self, group_name: str, stack: set[str]) -> list[str]:
        """Return flattened members for a group with memoization."""
        if group_name in self._flatten_cache:
            return self._flatten_cache[group_name]

        if group_name in stack:
            if group_name not in self._cycle_warnings:
                print(f"    Warning: Circular reference detected for group '{group_name}', skipping")
                self._cycle_warnings.add(group_name)
            return []

        nested_stack = set(stack)
        nested_stack.add(group_name)
        flattened = self._flatten_members(self.group_members.get(group_name, []), nested_stack)
        flattened = self._dedupe_preserve_order(flattened)
        self._flatten_cache[group_name] = flattened
        return flattened

    def _flatten_members(self, members: list[str], visited: set = None) -> list[str]: # pyright: ignore[reportArgumentType]
        """
        Recursively flatten a list of members, expanding any nested groups.
        
        Args:
            members: List of member names (may include group names)
            visited: Set of already-visited group names (prevents infinite loops)
            
        Returns:
            List of individual object names (no groups)
        """
        stack = visited or set()
        
        flattened: list[str] = []
        
        for member in members:
            if self._is_group(member):
                flattened.extend(self._flatten_group(member, stack))
            else:
                # This is an individual object - add it
                flattened.append(member)

        return self._dedupe_preserve_order(flattened)
    
    def convert(self) -> list[dict]:
        """
        Main conversion method - converts all FortiGate service groups to FTD format.
        
        CONVERSION PROCESS:
        1. Extract the 'firewall_service_group' list from FortiGate config
        2. Loop through each group entry
        3. Extract the group name (the dictionary key)
        4. Extract the group properties (uuid, member, color, etc.)
        5. Normalize the 'member' field to always be a list
        6. Expand members that were split (add both _TCP and _UDP versions)
        7. Create FTD portobjectgroup structure
        8. Return the complete list of converted groups
        
        Returns:
            List of dictionaries, each representing an FTD port object group
        """
        # ====================================================================
        # STEP 1: Extract service groups from FortiGate configuration
        # ====================================================================
        service_groups = self.fg_config.get('firewall_service_group', [])
        
        if not service_groups:
            print("Warning: No service groups found in FortiGate configuration")
            print("  Expected key: 'firewall_service_group'")
            return []
        
        # This list will accumulate all converted groups
        port_groups = []
        
        # ====================================================================
        # STEP 2: Process each FortiGate service group
        # ====================================================================
        for group_dict in service_groups:
            # ================================================================
            # STEP 2A: Extract the group name
            # ================================================================
            group_name = list(group_dict.keys())[0]
            sanitized_group_name = sanitize_name(group_name)
            
            # ================================================================
            # STEP 2B: Extract the group properties
            # ================================================================
            properties = group_dict[group_name]
            
            # ================================================================
            # STEP 2C: Extract and normalize the member list
            # ================================================================
            members_raw = properties.get('member', [])
            
            # Normalize to list format
            if isinstance(members_raw, str):
                members_list = [sanitize_name(members_raw)]
            elif isinstance(members_raw, list):
                members_list = [sanitize_name(m) for m in members_raw]
            else:
                print(f"  Warning: Group '{group_name}' has unexpected member format")
                members_list = []
            
            # ================================================================
            # STEP 2D: FLATTEN nested groups
            # ================================================================
            # FTD does NOT allow groups inside groups, so we need to expand
            # any nested groups into their individual objects
            flattened_members = self._flatten_members(members_list)
            
            # ================================================================
            # STEP 2E: Filter out skipped services (ICMP, etc.)
            # ================================================================
            filtered_members = []
            for member_name in flattened_members:
                if member_name in self.skipped_services:
                    print(f"    Filtered out: {member_name} (ICMP/non-port service)")
                else:
                    filtered_members.append(member_name)

            # ================================================================
            # STEP 2F: Expand members that were split into multiple FTD objects
            # ================================================================
            # expanded_members now contains tuples of (name, type)
            expanded_members = []
            
            for member_name in filtered_members:
                # Check if this service was split into multiple FTD objects
                if member_name in self.service_name_mapping:
                    # Use the mapping to get all FTD objects (list of (name, type) tuples)
                    ftd_objects = self.service_name_mapping[member_name]
                    expanded_members.extend(ftd_objects)
                    if len(ftd_objects) > 1:
                        print(f"    Expanded: {member_name} -> {len(ftd_objects)} objects")
                elif member_name in self.split_services:
                    # Compatibility fallback: add _TCP and _UDP suffixes
                    expanded_members.append((f"{member_name}_TCP", "tcpportobject"))
                    expanded_members.append((f"{member_name}_UDP", "udpportobject"))
                    print(f"    Expanded (fallback): {member_name} -> {member_name}_TCP, {member_name}_UDP")
                else:
                    # This service was not in our mapping - might be a built-in FTD service
                    # Try to determine type from name, default to TCP
                    if '_UDP' in member_name:
                        expanded_members.append((member_name, "udpportobject"))
                    else:
                        expanded_members.append((member_name, "tcpportobject"))
            
            # ================================================================
            # STEP 2G: Convert members to FTD object format
            # ================================================================
            ftd_members = []
            for member_info in expanded_members:
                # Handle both tuple format (name, type) and compatibility string format
                if isinstance(member_info, tuple):
                    member_name, member_type = member_info
                else:
                    # Compatibility fallback - shouldn't happen but kept defensively
                    member_name = member_info
                    if '_TCP' in member_name:
                        member_type = "tcpportobject"
                    elif '_UDP' in member_name:
                        member_type = "udpportobject"
                    else:
                        member_type = "tcpportobject"
                
                member_obj = {
                    "name": member_name,
                    "type": member_type
                }
                ftd_members.append(member_obj)
            
            # ================================================================
            # STEP 2H: Create the FTD port group structure
            # ================================================================
            ftd_group = {
                "name": sanitized_group_name,
                "isSystemDefined": False,
                "objects": ftd_members,
                "type": "portobjectgroup"
            }
            
            # Add the converted group to our result list
            port_groups.append(ftd_group)
            
            # ================================================================
            # STEP 2I: Print conversion details for user feedback
            # ================================================================
            original_count = len(members_list)
            final_count = len(ftd_members)
            
            if group_name != sanitized_group_name:
                print(f"  Converted: {group_name} -> {sanitized_group_name} ({final_count} members)", end="")
            else:
                print(f"  Converted: {sanitized_group_name} ({final_count} members)", end="")
            
            if final_count != original_count:
                print(f" [flattened/expanded from {original_count} entries]")
            else:
                print()
        
        # ====================================================================
        # STEP 3: Store results and return
        # ====================================================================
        self.ftd_port_groups = port_groups
        return port_groups
    
    def set_split_services(self, split_services: set[str] | None = None,
                           service_name_mapping: dict[str, list[tuple[str, str]]] | None = None,
                           skipped_services: set[str] | None = None):

        """
        Update the service expansion information.
        
        This should be called by the main script after converting service objects,
        so the group converter knows which members need to be expanded.
        
        Args:
            split_services: (DEPRECATED) Set of service names that have both TCP and UDP versions
            service_name_mapping: Dict mapping FortiGate service names to list of
                (FTD object name, object type) tuples
            skipped_services: Set of service names that were skipped (ICMP, etc.) 
        """
        if split_services is not None:
            self.split_services = split_services
        if service_name_mapping is not None:
            self.service_name_mapping = service_name_mapping
        if skipped_services is not None:
            self.skipped_services = skipped_services
    
    def get_group_count(self) -> int:
        """
        Get the number of service groups that were converted.
        
        Returns:
            Integer count of converted groups
        """
        return len(self.ftd_port_groups)


# =============================================================================
# TESTING CODE (for standalone testing of this module)
# =============================================================================

if __name__ == '__main__':
    """
    This code only runs when you execute this file directly.
    It's useful for testing the converter without running the main script.
    
    To test this module standalone:
        python service_group_converter.py
    """
    
    # Sample FortiGate configuration for testing
    test_config = {
        'firewall_service_group': [
            {
                'Email Access': {
                    'uuid': '11111111-2222-3333-8888-000000000013',
                    'member': ["DNS", "IMAP", "IMAPS", "POP3", "POP3S", "SMTP"]
                }
            },
            {
                'Web Access': {
                    'uuid': '11111111-2222-3333-8888-000000000013',
                    'member': ["DNS", "HTTP", "HTTPS"]
                }
            },
            {
                'Windows AD': {
                    'uuid': '11111111-2222-3333-8888-000000000013',
                    'member': ["DNS", "Kerberos", "SAMBA", "SMB"]
                }
            }
        ]
    }
    
    # Simulate that DNS and HTTPS were split into TCP and UDP
    split_services = {"DNS", "HTTPS"}
    
    # Create converter instance
    converter = ServiceGroupConverter(test_config, split_services)
    
    # Run conversion
    print("Testing Service Group Converter...")
    print("="*60)
    result = converter.convert()
    
    # Display results
    print("\nConversion Results:")
    print("="*60)
    import json
    print(json.dumps(result, indent=2))
    print("\n" + "="*60)
    print(f"Total groups converted: {len(result)}")