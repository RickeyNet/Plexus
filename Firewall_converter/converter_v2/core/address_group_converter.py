#!/usr/bin/env python3
"""
FortiGate Address Group Converter Module
=========================================
This module handles the conversion of FortiGate address groups to 
Cisco FTD network object groups.

WHAT THIS MODULE DOES:
    - Parses FortiGate 'firewall_addrgrp' section from YAML
    - Extracts group name and member objects
    - Converts to FTD 'networkobjectgroup' format
    - Handles both single members and lists of members

FORTIGATE YAML FORMAT:
    firewall_addrgrp:
        - GROUP_NAME:
            uuid: xxxxx
            member: ["object1", "object2", "object3"]  # List of members
            color: 13  # Optional
        - ANOTHER_GROUP:
            member: "single_object"  # Single member (string, not list)

FTD JSON OUTPUT FORMAT:
    {
        "name": "GROUP_NAME",
        "isSystemDefined": false,
        "objects": [
            {"name": "object1", "type": "networkobject"},
            {"name": "object2", "type": "networkobject"}
        ],
        "type": "networkobjectgroup"
    }

IMPORTANT NOTES:
    - FortiGate 'member' can be either a STRING or a LIST
      Examples: member: "single_object" OR member: ["obj1", "obj2"]
    - We need to normalize this to always be a list for processing
    - FTD requires each member to be an object with 'name' and 'type' fields
    - The 'type' is always 'networkobject' for address group members
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




class AddressGroupConverter:
    """
    Converter class for transforming FortiGate address groups to FTD network groups.
    
    This class is responsible for:
    1. Reading the 'firewall_addrgrp' section from FortiGate YAML
    2. Extracting group names and their member objects
    3. FLATTENING nested groups (FTD doesn't allow groups inside groups)
    4. Converting to FTD's networkobjectgroup format
    5. Handling edge cases (empty groups, single vs multiple members)
    """
    
    def __init__(self, fortigate_config: dict[str, Any], address_object_names: set = None): # pyright: ignore[reportArgumentType]
        """
        Initialize the converter with FortiGate configuration data.
        
        Args:
            fortigate_config: Dictionary containing the complete parsed FortiGate YAML
                             Expected to have a 'firewall_addrgrp' key with group data
            address_object_names: Set of address object names (to distinguish objects from groups)
        """
        # Store the entire FortiGate configuration
        # We'll extract what we need from this in the convert() method
        self.fg_config = fortigate_config
        
        # Set of known address object names (not groups)
        self.address_object_names = address_object_names or set()
        
        # This will store the converted FTD network groups
        # Starts empty and gets populated by the convert() method
        self.ftd_network_groups = []
        
        # Build a lookup of group name -> member list for flattening nested groups
        self.group_members = {}
        self._build_group_lookup()
    
    def _build_group_lookup(self):
        """
        Build a lookup dictionary of group names to their members.
        This is used to flatten nested groups.
        """
        address_groups = self.fg_config.get('firewall_addrgrp', [])
        
        for group_dict in address_groups:
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
        Check if a name refers to a group (not an individual object).
        
        Args:
            name: The sanitized object/group name to check
            
        Returns:
            True if the name is a group, False if it's an individual object
        """
        return name in self.group_members
    
    def _flatten_members(self, members: list[str], visited: set = None) -> list[str]: # pyright: ignore[reportArgumentType]
        """
        Recursively flatten a list of members, expanding any nested groups.
        
        Args:
            members: List of member names (may include group names)
            visited: Set of already-visited group names (prevents infinite loops)
            
        Returns:
            List of individual object names (no groups)
        """
        if visited is None:
            visited = set()
        
        flattened = []
        
        for member in members:
            if self._is_group(member):
                # This member is a group - expand it
                if member in visited:
                    # Circular reference - skip to prevent infinite loop
                    print(f"    Warning: Circular reference detected for group '{member}', skipping")
                    continue
                
                # Mark as visited
                visited.add(member)
                
                # Get the group's members and recursively flatten
                nested_members = self.group_members.get(member, [])
                expanded = self._flatten_members(nested_members, visited)
                
                print(f"    Flattening nested group '{member}' -> {len(expanded)} objects")
                flattened.extend(expanded)
            else:
                # This is an individual object - add it
                flattened.append(member)
        
        # Remove duplicates while preserving order
        seen = set()
        unique_flattened = []
        for item in flattened:
            if item not in seen:
                seen.add(item)
                unique_flattened.append(item)
        
        return unique_flattened
    
    def convert(self) -> list[dict]:
        """
        Main conversion method - converts all FortiGate address groups to FTD format.
        
        CONVERSION PROCESS:
        1. Extract the 'firewall_addrgrp' list from FortiGate config
        2. Loop through each group entry
        3. Extract the group name (the dictionary key)
        4. Extract the group properties (uuid, member, color, etc.)
        5. Normalize the 'member' field to always be a list
        6. FLATTEN any nested groups (expand group members into individual objects)
        7. Create FTD networkobjectgroup structure
        8. Return the complete list of converted groups
        
        Returns:
            List of dictionaries, each representing an FTD network object group
        """
        # ====================================================================
        # STEP 1: Extract address groups from FortiGate configuration
        # ====================================================================
        address_groups = self.fg_config.get('firewall_addrgrp', [])
        
        if not address_groups:
            print("Warning: No address groups found in FortiGate configuration")
            print("  Expected key: 'firewall_addrgrp'")
            return []
        
        # This list will accumulate all converted groups
        network_groups = []
        
        # ====================================================================
        # STEP 2: Process each FortiGate address group
        # ====================================================================
        for group_dict in address_groups:
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
            # STEP 2E: Convert members to FTD object format
            # ================================================================
            ftd_members = []
            for member_name in flattened_members:
                member_obj = {
                    "name": member_name,
                    "type": "networkobject"
                }
                ftd_members.append(member_obj)
            
            # ================================================================
            # STEP 2F: Create the FTD network group structure
            # ================================================================
            ftd_group = {
                "name": sanitized_group_name,
                "isSystemDefined": False,
                "objects": ftd_members,
                "type": "networkobjectgroup"
            }
            
            # Add the converted group to our result list
            network_groups.append(ftd_group)
            
            # ================================================================
            # STEP 2G: Print conversion details for user feedback
            # ================================================================
            original_count = len(members_list)
            final_count = len(ftd_members)
            
            if group_name != sanitized_group_name:
                print(f"  Converted: {group_name} -> {sanitized_group_name} ({final_count} members)", end="")
            else:
                print(f"  Converted: {sanitized_group_name} ({final_count} members)", end="")
            
            if final_count != original_count:
                print(f" [flattened from {original_count} entries]")
            else:
                print()
        
        # ====================================================================
        # STEP 3: Return all converted groups
        # ====================================================================
        self.ftd_network_groups = network_groups
        return network_groups


# =============================================================================
# ADDITIONAL HELPER METHODS (if needed in the future)
# =============================================================================

    def _validate_group(self, group_name: str, properties: dict) -> bool:
        """
        Validate that a group has all required fields.
        This is an optional validation method that could be called before conversion.
        
        Args:
            group_name: Name of the group being validated
            properties: Dictionary of group properties
            
        Returns:
            True if valid, False otherwise
        """
        # Check if the group has members
        if 'member' not in properties:
            print(f"  Warning: Group '{group_name}' has no members")
            return False
        
        members = properties['member']
        
        # Check if members is empty
        if isinstance(members, list) and len(members) == 0:
            print(f"  Warning: Group '{group_name}' has empty member list")
            return False
        
        if isinstance(members, str) and members.strip() == '':
            print(f"  Warning: Group '{group_name}' has empty member string")
            return False
        
        return True
    
    def get_group_count(self) -> int:
        """
        Get the number of address groups that were converted.
        
        Returns:
            Integer count of converted groups
        """
        return len(self.ftd_network_groups)
    
    def get_member_count(self, group_name: str) -> int:
        """
        Get the number of members in a specific converted group.
        
        Args:
            group_name: Name of the group to check
            
        Returns:
            Integer count of members, or -1 if group not found
        """
        # Search through converted groups to find the matching name
        for group in self.ftd_network_groups:
            if group['name'] == group_name:
                return len(group['objects'])
        
        # Group not found
        return -1


# =============================================================================
# TESTING CODE (for standalone testing of this module)
# =============================================================================

if __name__ == '__main__':
    """
    This code only runs when you execute this file directly.
    It's useful for testing the converter without running the main script.
    
    To test this module standalone:
        python address_group_converter.py
    """
    
    # Sample FortiGate configuration for testing
    # Includes nested groups to test flattening
    test_config = {
        'firewall_addrgrp': [
            {
                'Blocked IPs': {
                    'uuid': '11111111-2222-3333-8888-000000000005',
                    'member': ["BadIP1", "BadIP2", "BadIP3"]
                }
            },
            {
                'Switches': {
                    'uuid': '11111111-2222-3333-8888-000000000006',
                    'member': ["Switch1", "Switch2", "Switch3"]
                }
            },
            {
                'Servers': {
                    'uuid': '11111111-2222-3333-8888-000000000007',
                    'member': ["Server1", "Server2"]
                }
            },
            {
                'All_Network_Devices': {
                    'uuid': '11111111-2222-3333-8888-000000000008',
                    # This group contains OTHER GROUPS - needs to be flattened!
                    'member': ["Switches", "Servers", "Firewall1"]
                }
            },
            {
                'Everything': {
                    'uuid': '11111111-2222-3333-8888-000000000009',
                    # This group contains a group that contains groups - deep nesting!
                    'member': ["All_Network_Devices", "Blocked IPs", "SingleServer"]
                }
            }
        ]
    }
    
    # Create converter instance
    converter = AddressGroupConverter(test_config)
    
    # Run conversion
    print("Testing Address Group Converter with Nested Groups...")
    print("="*60)
    result = converter.convert()
    
    # Display results
    print("\nConversion Results:")
    print("="*60)
    import json
    print(json.dumps(result, indent=2))
    print("\n" + "="*60)
    print(f"Total groups converted: {len(result)}")
    
    # Show flattening results
    print("\nFlattening Summary:")
    print("-"*60)
    for group in result:
        print(f"  {group['name']}: {len(group['objects'])} members")