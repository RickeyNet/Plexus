#!/usr/bin/env python3
"""
FortiGate Interface Converter Module
=====================================
This module handles the conversion of FortiGate interfaces to 
Cisco FTD interface configurations.

WHAT THIS MODULE DOES:
    - Parses FortiGate 'system_interface' section from YAML
    - Maps FortiGate ports to FTD hardware interfaces
    - Converts physical interfaces (generates PUT payloads)
    - Converts aggregate interfaces to EtherChannels
    - Converts switch interfaces to Bridge Groups
    - Converts VLAN interfaces to Subinterfaces
    - Ensures all interface names are lowercase (FTD requirement)

FORTIGATE INTERFACE TYPES:
    - type: physical → FTD physicalinterface (PUT to update)
    - type: aggregate → FTD etherchannelinterface (POST to create)
    - type: switch → FTD bridgegroupinterface (POST to create)
    - VLAN (has interface: and vlanid:) → FTD subinterface (POST to create)

FTD INTERFACE NAME RULES:
    - Must be lowercase
    - Only alphanumeric and underscores allowed
    - Cannot start with a number
"""

import re
from typing import Any

# =============================================================================
# FIREWALL MODEL DEFINITIONS
# =============================================================================
# Define supported FTD firewall models with their interface configurations

FTD_MODELS = {
    'ftd-1010': {
        'name': 'Cisco Firepower 1010',
        'total_ports': 8,
        'port_prefix': 'Ethernet1/',
        'ha_port': None,  # No dedicated HA port on 1010
        'management_port': 'Management1/1',
        'description': '8-port desktop firewall (Ethernet1/1 - Ethernet1/8)'
    },
    'ftd-1120': {
        'name': 'Cisco Firepower 1120',
        'total_ports': 12,
        'port_prefix': 'Ethernet1/',
        'ha_port': None,
        'management_port': 'Management1/1',
        'description': '12-port firewall (Ethernet1/1 - Ethernet1/12)'
    },
    'ftd-1140': {
        'name': 'Cisco Firepower 1140',
        'total_ports': 12,
        'port_prefix': 'Ethernet1/',
        'ha_port': None,
        'management_port': 'Management1/1',
        'description': '12-port firewall (Ethernet1/1 - Ethernet1/12)'
    },
    'ftd-2110': {
        'name': 'Cisco Firepower 2110',
        'total_ports': 12,
        'port_prefix': 'Ethernet1/',
        'ha_port': None,
        'management_port': 'Management1/1',
        'description': '12-port 1U firewall'
    },
    'ftd-2120': {
        'name': 'Cisco Firepower 2120',
        'total_ports': 12,
        'port_prefix': 'Ethernet1/',
        'ha_port': None,
        'management_port': 'Management1/1',
        'description': '12-port 1U firewall'
    },
    'ftd-2130': {
        'name': 'Cisco Firepower 2130',
        'total_ports': 16,
        'port_prefix': 'Ethernet1/',
        'ha_port': None,
        'management_port': 'Management1/1',
        'description': '16-port 1U firewall'
    },
    'ftd-2140': {
        'name': 'Cisco Firepower 2140',
        'total_ports': 16,
        'port_prefix': 'Ethernet1/',
        'ha_port': None,
        'management_port': 'Management1/1',
        'description': '16-port 1U firewall'
    },
    'ftd-3105': {
        'name': 'Cisco Secure Firewall 3105',
        'total_ports': 16,
        'port_prefix': 'Ethernet1/',
        'ha_port': 'Ethernet1/2',  # Typically port 2 for HA
        'management_port': 'Management1/1',
        'description': '16-port firewall (8 RJ45 + 8 SFP) with HA support'
    },
    'ftd-3110': {
        'name': 'Cisco Secure Firewall 3110',
        'total_ports': 16,
        'port_prefix': 'Ethernet1/',
        'ha_port': 'Ethernet1/2',
        'management_port': 'Management1/1',
        'description': '16-port firewall (8 RJ45 + 8 SFP) with HA'
    },
    'ftd-3120': {
        'name': 'Cisco Secure Firewall 3120',
        'total_ports': 16,
        'port_prefix': 'Ethernet1/',
        'ha_port': 'Ethernet1/2',
        'management_port': 'Management1/1',
        'description': '16-port firewall (8 RJ45 + 8 SFP) with HA'
    },
    'ftd-3130': {
        'name': 'Cisco Secure Firewall 3130',
        'total_ports': 24,
        'port_prefix': 'Ethernet1/',
        'ha_port': 'Ethernet1/2',
        'management_port': 'Management1/1',
        'description': '24-port firewall with HA'
    },
    'ftd-3140': {
        'name': 'Cisco Secure Firewall 3140',
        'total_ports': 24,
        'port_prefix': 'Ethernet1/',
        'ha_port': 'Ethernet1/2',
        'management_port': 'Management1/1',
        'description': '24-port firewall with HA'
    },
    'ftd-4215': {
        'name': 'Cisco Secure Firewall 4215',
        'total_ports': 24,
        'port_prefix': 'Ethernet1/',
        'ha_port': 'Ethernet1/2',
        'management_port': 'Management1/1',
        'description': '24-port enterprise firewall with HA'
    }
}

def get_supported_models() -> list:
    """Return list of supported firewall model names."""
    return sorted(FTD_MODELS.keys())

def print_supported_models():
    """Print a table of supported firewall models."""
    print("\nSupported FTD Firewall Models:")
    print("=" * 70)
    print(f"{'Model':<15} {'Name':<30} {'Ports':<8} {'HA Port':<12}")
    print("-" * 70)
    for model_id, info in sorted(FTD_MODELS.items()):
        ha = info['ha_port'] if info['ha_port'] else 'None'
        print(f"{model_id:<15} {info['name']:<30} {info['total_ports']:<8} {ha:<12}")
    print("=" * 70)


def sanitize_interface_name(name: str) -> str:
    """
    Sanitize interface names for FTD compatibility.
    
    FTD interface names must be:
    - Lowercase
    - Alphanumeric and underscores only
    - Cannot start with a number
    
    Args:
        name: Original interface name
        
    Returns:
        Sanitized lowercase name
    """
    if name is None:
        return ""
    
    # Convert to string and lowercase
    name = str(name).lower()
    
    # Replace any non-alphanumeric character (except underscore) with underscore
    sanitized = re.sub(r'[^a-z0-9_]', '_', name)
    
    # Remove consecutive underscores
    sanitized = re.sub(r'_+', '_', sanitized)
    
    # Remove leading/trailing underscores
    sanitized = sanitized.strip('_')
    
    return sanitized


class InterfaceConverter:
    """
    Converter class for transforming FortiGate interfaces to FTD format.
    
    Supports multiple FTD firewall models with automatic port mapping.
    Use set_target_model() to configure for a specific firewall.
    """
    
    def __init__(self, fortigate_config: dict[str, Any], target_model: str = 'ftd-3120', custom_ha_port: str = None): # pyright: ignore[reportArgumentType]
        """
        Initialize the converter with FortiGate configuration data.
        
        Args:
            fortigate_config: Dictionary containing the complete parsed FortiGate YAML
                            Expected to have a 'system_interface' key
            target_model: Target FTD firewall model (e.g., 'ftd-1010', 'ftd-3120')
                        Use get_supported_models() to see available models
            custom_ha_port: Optional custom HA port (e.g., 'Ethernet1/5'). 
                        If None, uses the model's default HA port.
                        Must match format: 'Ethernet1/X' where X is a valid port number.
        """
        self.fg_config = fortigate_config
    
        # Set target model (this also sets up port mapping)
        self.target_model = None
        self.model_info = None
        self.total_ports = 16  # Default
        self.ha_port = None
        self.custom_ha_port = custom_ha_port  # NEW: Store custom HA port preference
        self.skip_ftd_ports = set()
        
        # Port mapping - will be built dynamically
        self.port_mapping = {}
        
        # Set the target model (this builds the port mapping)
        self.set_target_model(target_model)
        
        # Store converted interfaces
        self.physical_interfaces = []      # PUT requests
        self.subinterfaces = []            # POST requests
        self.etherchannels = []            # POST requests
        self.bridge_groups = []            # POST requests
        self.security_zones = []           # POST requests - zones for firewall policies
        
        # Interface name mapping: FortiGate name -> FTD name (for routes/policies)
        self.interface_name_mapping = {}
        
        # Track used subinterface names to avoid duplicates
        self.used_subinterface_names = set()
        
        # Track created security zone names to avoid duplicates
        self.created_zone_names = set()
        
        # Track bridge group membership: hardware_name -> bridge_group_name
        # Used to assign physical interfaces to bridge group zones instead of individual zones
        self.bridge_group_members = {}
        
        # Track statistics
        self.stats = {
            'physical_updated': 0,
            'subinterfaces_created': 0,
            'etherchannels_created': 0,
            'bridge_groups_created': 0,
            'security_zones_created': 0,
            'skipped': 0
        }
    
    def set_target_model(self, model: str):
        """
        Set the target FTD firewall model.
        
        This configures the available ports and HA port based on the model.
        Interfaces are assigned starting from the LAST port and working down.
        
        Args:
            model: Model identifier (e.g., 'ftd-1010', 'ftd-3120')
        
        Raises:
            ValueError: If model is not supported
            ValueError: If custom_ha_port is invalid for this model
        """
        if model not in FTD_MODELS:
            raise ValueError(f"Unsupported model: {model}. Use get_supported_models() to see available models.")
        
        self.target_model = model
        self.model_info = FTD_MODELS[model]
        self.total_ports = self.model_info['total_ports']
        
        # NEW: Use custom HA port if specified, otherwise use model default
        if self.custom_ha_port:
            # Validate custom HA port format and availability
            self._validate_custom_ha_port(self.custom_ha_port) # pyright: ignore[reportAttributeAccessIssue]
            self.ha_port = self.custom_ha_port
        else:
            self.ha_port = self.model_info['ha_port']
        
        # Build skip set for reserved ports
        self.skip_ftd_ports = set()
        
        # HA port is reserved and cannot be used for data interfaces
        if self.ha_port:
            self.skip_ftd_ports.add(self.ha_port)
        
        # Clear existing mapping
        self.port_mapping = {}
        
        # Build available ports list (starting from LAST port, going DOWN)
        # This allows adding interfaces from the end
        self.available_ftd_ports = []
        for i in range(self.total_ports, 0, -1):
            port = f"Ethernet1/{i}"
            if port not in self.skip_ftd_ports:
                self.available_ftd_ports.append(port)
        
        # Track assigned ports
        self.assigned_ftd_ports = set(self.skip_ftd_ports)
        
        print(f"  Target model: {self.model_info['name']}")
        print(f"  Available ports: Ethernet1/1 - Ethernet1/{self.total_ports}")
        if self.ha_port:
            print(f"  HA port (skipped): {self.ha_port}")
        print(f"  Port assignment order: Starting from Ethernet1/{self.total_ports} down to Ethernet1/1")
    
    def _validate_custom_ha_port(self, ha_port: str):
        """
        Validate that the custom HA port is valid for the target model.
        
        Args:
            ha_port: Custom HA port string (e.g., 'Ethernet1/5')
        
        Raises:
            ValueError: If the HA port format is invalid or port number exceeds model capacity
        
        Notes:
            - HA port must match format: 'Ethernet1/X' where X is 1-24
            - Port number must not exceed the model's total_ports
            - Management ports cannot be used as HA ports
        """
        import re
        
        # Validate format: Ethernet1/X
        match = re.match(r'^Ethernet1/(\d+)$', ha_port)
        if not match:
            raise ValueError(
                f"Invalid HA port format: '{ha_port}'. "
                f"Must be 'Ethernet1/X' where X is a port number (e.g., 'Ethernet1/5')"
            )
        
        # Extract port number
        port_num = int(match.group(1))
        
        # Validate port number is within model's range
        if port_num < 1 or port_num > self.total_ports:
            raise ValueError(
                f"Invalid HA port: '{ha_port}'. "
                f"Model '{self.target_model}' only has ports 1-{self.total_ports}. "
                f"Specify a port between Ethernet1/1 and Ethernet1/{self.total_ports}."
            )
    
        # Warn if using port 1 (often used for management/uplink)
        if port_num == 1:
            print("\nWARNING: Using Ethernet1/1 as HA port. This is typically the first data port.")
            print("         Ensure this doesn't conflict with your network design.\n")

    def set_port_mapping(self, mapping: dict[str, str]):
        """
        Set explicit port mapping for specific interfaces.
        
        Use this to override automatic assignment for specific interfaces.
        
        Args:
            mapping: Dict of FortiGate port name -> FTD hardware name
        """
        for fg_port, ftd_port in mapping.items():
            # Validate the FTD port is within range for this model
            try:
                port_num = int(ftd_port.split('/')[-1])
                if port_num > self.total_ports:
                    print(f"  Warning: {ftd_port} exceeds available ports for {self.target_model} (max: Ethernet1/{self.total_ports})")
                    continue
            except:
                pass
            
            self.port_mapping[fg_port] = ftd_port
            self.assigned_ftd_ports.add(ftd_port)
            
            # Remove from available list if present
            if ftd_port in self.available_ftd_ports:
                self.available_ftd_ports.remove(ftd_port)
    
    def set_skip_ports(self, ports: set[str]):
        """
        Set additional FTD ports to skip.
        
        Args:
            ports: Set of FTD hardware names to skip
        """
        self.skip_ftd_ports.update(ports)
        self.assigned_ftd_ports.update(ports)
        
        # Remove from available list
        self.available_ftd_ports = [p for p in self.available_ftd_ports if p not in ports]
    
    def _get_ftd_hardware_name(self, fg_port: str) -> str | None:
        """
        Get the FTD hardware name for a FortiGate port.
        
        Args:
            fg_port: FortiGate port name (e.g., 'port1', 'x1')
            
        Returns:
            FTD hardware name (e.g., 'Ethernet1/1') or None if not available
        """
        # Check explicit mapping first
        if fg_port in self.port_mapping:
            return self.port_mapping[fg_port]
        
        # Auto-assign from available ports
        if self.available_ftd_ports:
            ftd_port = self.available_ftd_ports.pop(0)
            self.port_mapping[fg_port] = ftd_port
            self.assigned_ftd_ports.add(ftd_port)
            return ftd_port
        
        # No ports available
        return None
    
    def _netmask_to_cidr(self, netmask: str) -> int:
        """Convert subnet mask to CIDR prefix length."""
        try:
            octets = netmask.split('.')
            binary_str = ''.join(bin(int(octet))[2:].zfill(8) for octet in octets)
            return binary_str.count('1')
        except:
            return 24  # Default
    
    def convert(self) -> dict[str, list[dict]]:
        """
        Main conversion method - converts all FortiGate interfaces to FTD format.
        
        PORT ASSIGNMENT PRIORITY (for limited-port firewalls):
        1. EtherChannels - Need physical member ports
        2. Bridge Groups - Need physical member ports  
        3. Physical interfaces WITH subinterfaces - Can carry multiple VLANs
        4. Standalone physical interfaces - Only if ports available
        
        This priority ensures maximum utilization of limited ports.
        
        Returns:
            Dictionary with keys:
            - 'physical_interfaces': List of PUT payloads for physical interfaces
            - 'subinterfaces': List of POST payloads for subinterfaces
            - 'etherchannels': List of POST payloads for etherchannels
            - 'bridge_groups': List of POST payloads for bridge groups
        """
        interfaces = self.fg_config.get('system_interface', [])
        
        # Get switch interfaces (bridge groups) from separate section
        switch_interfaces = self.fg_config.get('system_switch-interface', [])
        
        if not interfaces:
            print("Warning: No interfaces found in FortiGate configuration")
            print("  Expected key: 'system_interface'")
            return {
                'physical_interfaces': [],
                'subinterfaces': [],
                'etherchannels': [],
                'bridge_groups': []
            }
        
        if switch_interfaces:
            print(f"  Found {len(switch_interfaces)} switch interfaces (bridge groups)")
        
        # ====================================================================
        # PHASE 1: Categorize all interfaces by type
        # ====================================================================
        physical_ports = []
        aggregate_ports = []  # EtherChannels
        switch_ports = []     # Bridge Groups (from system_switch-interface)
        vlan_interfaces = []  # Subinterfaces
        
        # Process system_switch-interface section for bridge groups
        for switch_dict in switch_interfaces:
            switch_name = list(switch_dict.keys())[0]
            switch_props = switch_dict[switch_name]
            
            if isinstance(switch_props, dict):
                switch_ports.append((switch_name, switch_props))
        
        # Process system_interface section
        skipped_special = []
        for intf_dict in interfaces:
            intf_name = list(intf_dict.keys())[0]
            properties = intf_dict[intf_name]
            
            # Skip non-dict entries
            if not isinstance(properties, dict):
                continue
            
            intf_type = properties.get('type', 'physical')

            # ----------------------------------------------------------------
            # Skip non-data interfaces that should never map to FTD data ports
            # ----------------------------------------------------------------
            # Virtual wire interfaces:
            #   FortiGate CLI uses "vwl-peer" (hyphen); YAML preserves hyphens verbatim.
            #   Some export tools convert to underscore, so check both.
            if (intf_type in ('vwl', 'vwl-zone')
                    or 'vwl-peer' in properties
                    or 'vwl_peer' in properties):
                skipped_special.append((intf_name, 'virtual-wire'))
                continue
            # HA-dedicated interfaces:
            #   FortiGate CLI: "set role ha"  →  YAML key: "role", value: "ha"
            if intf_type == 'ha' or properties.get('role') == 'ha':
                skipped_special.append((intf_name, 'ha'))
                continue
            # Management-dedicated interfaces:
            #   FortiGate CLI: "set dedicated-to management"  →  YAML key: "dedicated-to"
            #   Some export tools normalise hyphens to underscores, check both.
            dedicated = properties.get('dedicated-to') or properties.get('dedicated_to') or ''
            if str(dedicated).lower() in ('management', 'mgmt'):
                skipped_special.append((intf_name, 'management'))
                continue
            # Name-pattern fallback for interfaces that carry no distinguishing fields
            # in the YAML (e.g. some export formats strip extra attributes).
            #   FortiGate 500E defaults: mgmt1, ha1, vwl1, vwl2
            _lname = str(intf_name).lower()
            if (_lname in ('mgmt', 'mgmt1', 'mgmt2')
                    or _lname.startswith('ha') and _lname[2:].isdigit()
                    or _lname.startswith('vwl') and _lname[3:].isdigit()):
                reason = ('management' if _lname.startswith('mgmt')
                          else 'ha' if _lname.startswith('ha')
                          else 'virtual-wire')
                skipped_special.append((intf_name, reason))
                continue
            # ----------------------------------------------------------------
            
            # Check if this is a VLAN interface (has 'interface' and 'vlanid')
            if 'interface' in properties and 'vlanid' in properties:
                vlan_interfaces.append((intf_name, properties))
            elif intf_type == 'aggregate':
                aggregate_ports.append((intf_name, properties))
            elif intf_type == 'physical':
                physical_ports.append((intf_name, properties))
            # Skip tunnel, loopback, etc.

        # ====================================================================
        # PHASE 2: Identify which physical interfaces have subinterfaces
        # ====================================================================
        # These get priority because they can carry multiple VLANs
        parent_interfaces = set()
        for vlan_name, vlan_props in vlan_interfaces:
            parent = vlan_props.get('interface', '')
            if parent:
                parent_interfaces.add(parent)
        
        # ====================================================================
        # PHASE 2B: Identify EtherChannel and Bridge Group members
        # ====================================================================
        # These interfaces should NOT be processed as standalone physical interfaces
        # because they will be configured as members of their parent interface
        etherchannel_members = set()
        for _, props in aggregate_ports:
            members = props.get('member', [])
            if isinstance(members, str):
                members = [members]
            for member in members:
                etherchannel_members.add(member)
        
        # Combined set of all member interfaces (should not be processed standalone)
        member_interfaces = etherchannel_members
        
        # Separate physical ports into those with and without subinterfaces
        # Also exclude interfaces that are members of EtherChannels
        physical_with_subs = [(n, p) for n, p in physical_ports 
                              if n in parent_interfaces and n not in member_interfaces]
        physical_standalone = [(n, p) for n, p in physical_ports 
                               if n not in parent_interfaces and n not in member_interfaces]
        
        # ====================================================================
        # PHASE 3: Check available ports and warn if insufficient
        # ====================================================================
        # Count ports needed (rough estimate)
        etherch_member_count = 0
        for _, props in aggregate_ports:
            members = props.get('member', [])
            if isinstance(members, str):
                etherch_member_count += 1
            else:
                etherch_member_count += len(members)
        
        bridge_member_count = 0
        for _, props in switch_ports:
            members = props.get('member', [])
            if isinstance(members, str):
                bridge_member_count += 1
            else:
                bridge_member_count += len(members)
        
        total_needed = (etherch_member_count + bridge_member_count + 
                       len(physical_with_subs) + len(physical_standalone))
        available = len(self.available_ftd_ports)
        
        print(f"\n  Port Analysis for {self.model_info['name']}:") # pyright: ignore[reportOptionalSubscript]
        print(f"    Available FTD ports: {available}")
        print("    FortiGate interfaces to convert:")
        print(f"      - EtherChannel members: {etherch_member_count}")
        print(f"      - Bridge Group members: {bridge_member_count}")
        print(f"      - Physical with subinterfaces: {len(physical_with_subs)}")
        print(f"      - Standalone physical: {len(physical_standalone)}")
        if member_interfaces:
            print(f"      - Excluded (EC members): {len(member_interfaces)} ({', '.join(sorted(member_interfaces))})")
        if skipped_special:
            by_reason = {}
            for name, reason in skipped_special:
                by_reason.setdefault(reason, []).append(name)
            parts = [f"{len(v)} {k}" for k, v in by_reason.items()]
            print(f"      - Skipped (non-data): {len(skipped_special)} ({', '.join(parts)})")
        print(f"    Total ports needed: {total_needed}")
        
        if total_needed > available:
            print(f"\n  [WARNING] Not enough ports! Need {total_needed}, have {available}")
            print("  [INFO] Using priority-based assignment:")
            print("         1. EtherChannels (aggregate traffic)")
            print("         2. Bridge Groups (switch ports)")
            print("         3. Interfaces with subinterfaces (carry VLANs)")
            print("         4. Standalone interfaces (if ports remain)")
        
        # ====================================================================
        # PHASE 4: Convert in PRIORITY ORDER
        # ====================================================================
        
        # PRIORITY 1: Convert aggregate interfaces (EtherChannels)
        # These need member ports, so do first
        print("\n  [Priority 1] Converting Aggregate Interfaces (EtherChannels)...")
        for fg_name, properties in aggregate_ports:
            self._convert_aggregate_interface(fg_name, properties)
        
        # PRIORITY 2: Convert switch interfaces (Bridge Groups)
        # These also need member ports
        print("\n  [Priority 2] Converting Switch Interfaces (Bridge Groups)...")
        for fg_name, properties in switch_ports:
            self._convert_switch_interface(fg_name, properties)
        
        # PRIORITY 3: Convert physical interfaces THAT HAVE SUBINTERFACES
        # These are valuable because one port can carry multiple VLANs
        print("\n  [Priority 3] Converting Physical Interfaces with Subinterfaces...")
        for fg_name, properties in physical_with_subs:
            self._convert_physical_interface(fg_name, properties)
        
        # PRIORITY 4: Convert standalone physical interfaces
        # Only if we have ports left
        print("\n  [Priority 4] Converting Standalone Physical Interfaces...")
        remaining_ports = len(self.available_ftd_ports)
        if remaining_ports == 0 and len(physical_standalone) > 0:
            print(f"    [WARNING] No ports remaining for {len(physical_standalone)} standalone interfaces")
            for fg_name, _ in physical_standalone:
                print(f"      Skipped: {fg_name} (no ports available)")
                self.stats['skipped'] += 1
        else:
            for fg_name, properties in physical_standalone:
                if len(self.available_ftd_ports) == 0:
                    print(f"    Skipped: {fg_name} (no ports available)")
                    self.stats['skipped'] += 1
                else:
                    self._convert_physical_interface(fg_name, properties)
        
        # PHASE 5: Convert VLAN interfaces (Subinterfaces)
        # These don't need additional ports - they use parent interfaces
        print("\n  [Phase 5] Converting VLAN Interfaces (Subinterfaces)...")
        for fg_name, properties in vlan_interfaces:
            self._convert_vlan_interface(fg_name, properties)
        
        # PHASE 6: Generate Security Zones for all converted interfaces
        # FTD requires security zones for firewall policies
        print("\n  [Phase 6] Generating Security Zones...")
        self._generate_security_zones()
        
        # Print final port allocation summary
        print("\n  Port Allocation Summary:")
        print(f"    Ports used: {len(self.assigned_ftd_ports) - len(self.skip_ftd_ports)}")
        print(f"    Ports remaining: {len(self.available_ftd_ports)}")
        print(f"    Security zones created: {len(self.security_zones)}")
        
        return {
            'physical_interfaces': self.physical_interfaces,
            'subinterfaces': self.subinterfaces,
            'etherchannels': self.etherchannels,
            'bridge_groups': self.bridge_groups,
            'security_zones': self.security_zones
        }
    
    def _generate_security_zones(self):
        """
        Generate security zones for all converted interfaces.
        
        FTD requires security zones for firewall policies. Each interface
        that will be used in access rules needs a corresponding security zone.
        
        Zone naming convention:
            - Uses the FTD interface name as the zone name
            - This allows firewall policies to reference zones by interface name
        
        FTD Security Zone API format:
            {
                "name": "zone_name",
                "description": "Auto-generated zone for interface",
                "mode": "ROUTED",
                "interfaces": [
                    {"name": "interface_name", "type": "physicalinterface"}
                ],
                "type": "securityzone"
            }
        """
        # Collect all unique interface names that need zones
        interfaces_needing_zones = []
        
        # Physical interfaces
        # NOTE: If a physical interface is a bridge group member, use the bridge
        # group name as the zone name instead of the physical interface name
        for intf in self.physical_interfaces:
            intf_name = intf.get('name', '')
            hardware_name = intf.get('hardwareName', '')
            
            # Check if this interface is a bridge group member
            bridge_group_name = self.bridge_group_members.get(hardware_name)
            
            if bridge_group_name:
                # Use bridge group name as zone name for member interfaces
                zone_name = bridge_group_name
            else:
                # Use interface name for standalone physical interfaces
                zone_name = intf_name
            
            if zone_name and zone_name not in self.created_zone_names:
                interfaces_needing_zones.append({
                    'name': intf_name,
                    'hardwareName': hardware_name,
                    'type': 'physicalinterface',
                    'zone_name': zone_name  # Store the zone name to use
                })
        
        # Subinterfaces
        for intf in self.subinterfaces:
            intf_name = intf.get('name', '')
            hardware_name = intf.get('hardwareName', '')
            if intf_name and intf_name not in self.created_zone_names:
                interfaces_needing_zones.append({
                    'name': intf_name,
                    'hardwareName': hardware_name,
                    'type': 'subinterface',
                    'zone_name': intf_name  # Zone name matches interface name
                })
        
        # EtherChannels
        for intf in self.etherchannels:
            intf_name = intf.get('name', '')
            hardware_name = intf.get('hardwareName', '')
            if intf_name and intf_name not in self.created_zone_names:
                interfaces_needing_zones.append({
                    'name': intf_name,
                    'hardwareName': hardware_name,
                    'type': 'etherchannelinterface',
                    'zone_name': intf_name  # Zone name matches interface name
                })
        
        # Bridge Groups - SKIP adding to security zones
        # In FTD, bridge group member physical interfaces are added to the zone,
        # NOT the BVI interface itself. The member interfaces above are already
        # assigned to use the bridge group name as their zone name.
        # 
        # FTD Security Zone behavior:
        #   - Physical interfaces that are bridge group members -> added to zone
        #   - The BVI (bridgegroupinterface) itself -> NOT added to zone
        
       # Create security zones for each interface
        # Group interfaces by zone name to support multiple interfaces per zone
        zone_interfaces = {}  # zone_name -> list of interface info dicts
        zone_hardware_seen = {}  # zone_name -> set of hardwareNames already added
        
        for intf_info in interfaces_needing_zones:
            # Use explicit zone_name if provided, otherwise use interface name
            zone_name = intf_info.get('zone_name', intf_info['name'])
            hardware_name = intf_info['hardwareName']
            
            if zone_name not in zone_interfaces:
                zone_interfaces[zone_name] = []
                zone_hardware_seen[zone_name] = set()
            
            # Skip if this hardware interface was already added to this zone
            if hardware_name in zone_hardware_seen[zone_name]:
                continue
            
            zone_interfaces[zone_name].append({
                'name': intf_info['name'],
                'hardwareName': hardware_name,
                'type': intf_info['type']
            })
            zone_hardware_seen[zone_name].add(hardware_name)
        
        # Create security zones
        for zone_name, interfaces in zone_interfaces.items():
            # Skip if zone already created
            if zone_name in self.created_zone_names:
                continue
            
            # Build interface list for zone description
            hardware_names = [intf['hardwareName'] for intf in interfaces]
            desc_interfaces = ', '.join(hardware_names) if len(hardware_names) <= 3 else f"{hardware_names[0]} + {len(hardware_names)-1} more"
            
            # Build security zone payload
            security_zone = {
                "name": zone_name,
                "description": f"Auto-generated zone for interface(s) {desc_interfaces}",
                "mode": "ROUTED",
                "interfaces": interfaces,
                "type": "securityzone"
            }
            
            self.security_zones.append(security_zone)
            self.created_zone_names.add(zone_name)
            self.stats['security_zones_created'] += 1
            
            if len(interfaces) > 1:
                print(f"    Created zone: {zone_name} (interfaces: {', '.join(hardware_names)})")
            else:
                print(f"    Created zone: {zone_name} (interface: {interfaces[0]['hardwareName']})")

    def _convert_physical_interface(self, fg_name: str, properties: dict):
        """Convert a FortiGate physical interface to FTD format."""
        
        # Skip certain interfaces
        if fg_name in ['ha', 'mgmt', 'modem', 'naf.root', 'l2t.root', 'ssl.root']:
            print(f"    Skipped: {fg_name} (system/virtual interface)")
            self.stats['skipped'] += 1
            return
        
        # Skip interfaces that start with s, vw (special FortiGate ports)
        if fg_name.startswith('s') and len(fg_name) <= 2:
            print(f"    Skipped: {fg_name} (special port - no FTD equivalent)")
            self.stats['skipped'] += 1
            return
        if fg_name.startswith('vw'):
            print(f"    Skipped: {fg_name} (virtual wire port)")
            self.stats['skipped'] += 1
            return
        
        # Get FTD hardware name
        ftd_hardware = self._get_ftd_hardware_name(fg_name)
        if not ftd_hardware:
            print(f"    Skipped: {fg_name} (no available FTD port)")
            self.stats['skipped'] += 1
            return
        
        # Check if this FTD port should be skipped
        if ftd_hardware in self.skip_ftd_ports:
            print(f"    Skipped: {fg_name} -> {ftd_hardware} (reserved port)")
            self.stats['skipped'] += 1
            return
        
       # Get interface name (use alias if available, otherwise port name)
        alias = properties.get('alias', fg_name)
        ftd_name = sanitize_interface_name(alias)
        
        # Reserved names that conflict with FTD built-in interfaces
        # These names cannot be used for user interfaces
        reserved_names = {
            'management',
            'diagnostic',
            'inside',
            'outside'
        }
        
        # If name matches a reserved name, append hardware port number
        if ftd_name.lower() in reserved_names:
            original_reserved = ftd_name
            # Extract port number from hardware name (e.g., "Ethernet1/5" -> "5")
            port_num = ftd_hardware.split('/')[-1] if '/' in ftd_hardware else '1'
            ftd_name = f"{ftd_name}_port{port_num}"
            print(f"      Note: '{original_reserved}' is reserved, renamed to '{ftd_name}'")
        
        # Get description
        description = properties.get('description', alias)
        
        # Store the mapping
        self.interface_name_mapping[fg_name] = ftd_name
        self.interface_name_mapping[alias] = ftd_name
        
        # Build FTD physical interface payload (for PUT)
        ftd_interface = {
            "name": ftd_name,
            "hardwareName": ftd_hardware,
            "description": description,
            "enabled": properties.get('status', 'up') != 'down',
            "mode": "ROUTED",
            "type": "physicalinterface"
        }
        
        # Add IP address if present
        ip_config = properties.get('ip')
        if ip_config and isinstance(ip_config, list) and len(ip_config) >= 2:
            ip_addr = str(ip_config[0])
            netmask = str(ip_config[1])
            
            # Skip if IP is 0.0.0.0
            if ip_addr != '0.0.0.0':
                ftd_interface["ipv4"] = {
                    "ipType": "STATIC",
                    "defaultRouteUsingDHCP": False,
                    "ipAddress": {
                        "ipAddress": ip_addr,
                        "netmask": netmask,
                        "type": "haipv4address"
                    },
                    "dhcp": False,
                    "addressNull": False,
                    "type": "interfaceipv4"
                }
        
        # Add MTU if overridden (cap at 9000 - FTD maximum)
        if properties.get('mtu-override') == 'enable':
            mtu = properties.get('mtu', 1500)
            if mtu > 9000:
                mtu = 9000
            ftd_interface["mtu"] = mtu
        
        self.physical_interfaces.append(ftd_interface)
        self.stats['physical_updated'] += 1
        
        print(f"    Converted: {fg_name} -> {ftd_name} ({ftd_hardware})")
    
    def _convert_aggregate_interface(self, fg_name: str, properties: dict):
        """Convert a FortiGate aggregate interface to FTD EtherChannel."""
        
        # Get interface name
        alias = properties.get('alias', fg_name)
        ftd_name = sanitize_interface_name(alias)
        
        # Store the mapping
        self.interface_name_mapping[fg_name] = ftd_name
        self.interface_name_mapping[alias] = ftd_name
        
        # Get member interfaces
        members = properties.get('member', [])
        if isinstance(members, str):
            members = [members]
        
        # Map member names to FTD hardware names
        # AND create physical interface entries for each member
        # so they get set to routed mode before EtherChannel creation
        ftd_members = []
        for member in members:
            ftd_hardware = self._get_ftd_hardware_name(member)
            if ftd_hardware:
                ftd_members.append({
                    "hardwareName": ftd_hardware,
                    "type": "physicalinterface"
                })
                
                # Create a physical interface entry for this member
                # This ensures it gets imported and set to routed mode
                # BEFORE the EtherChannel is created
                # 
                # IMPORTANT: EtherChannel members require specific settings:
                #   - speedType: DETECT_SFP (for SFP) or AUTO
                #   - fecMode: AUTO
                #   - autoNegotiation: True (enabled)
                #   - duplexType: FULL
                #   - name: '' (empty - no name allowed for EC members)
                member_interface = {
                    "name": '',  # No name - required for EtherChannel membership
                    "hardwareName": ftd_hardware,
                    "description": f"EtherChannel {fg_name} member",
                    "enabled": True,
                    "mode": "ROUTED",
                    "duplexType": "FULL",
                    "autoNegotiation": True,
                    "type": "physicalinterface"
                }
                
                # Only add if not already in the list
                existing_hardware = [p.get('hardwareName') for p in self.physical_interfaces]
                if ftd_hardware not in existing_hardware:
                    self.physical_interfaces.append(member_interface)
                    print(f"      Added member interface: {member} -> {ftd_hardware} (routed mode, EC-ready)")
        
        if not ftd_members:
            print(f"    Skipped: {fg_name} (no valid member interfaces)")
            self.stats['skipped'] += 1
            return
        
        # Determine EtherChannel ID (extract from existing or assign new)
        # For simplicity, use 1 for first etherchannel, 2 for second, etc.
        etherchannel_id = len(self.etherchannels) + 1
        
        # Build FTD EtherChannel payload
        ftd_interface = {
            "name": ftd_name,
            "hardwareName": f"Port-channel{etherchannel_id}",
            "description": properties.get('description', alias),
            "enabled": properties.get('status', 'up') != 'down',
            "mode": "ROUTED",
            "etherChannelID": etherchannel_id,
            "memberInterfaces": ftd_members,
            "lacpMode": "ACTIVE",
            "type": "etherchannelinterface"
        }
        
        # Add MTU if overridden (cap at 9000 - FTD maximum)
        if properties.get('mtu-override') == 'enable':
            mtu = properties.get('mtu', 1500)
            if mtu > 9000:
                mtu = 9000
            ftd_interface["mtu"] = mtu
        
        self.etherchannels.append(ftd_interface)
        self.stats['etherchannels_created'] += 1
        
        member_str = ', '.join([m['hardwareName'] for m in ftd_members])
        print(f"    Converted: {fg_name} -> {ftd_name} (Port-channel{etherchannel_id}) members: [{member_str}]")
    
    def _convert_switch_interface(self, fg_name: str, properties: dict):
        """Convert a FortiGate switch interface to FTD Bridge Group."""
        
        # Get interface name
        ftd_name = sanitize_interface_name(fg_name)
        
        # Store the mapping
        self.interface_name_mapping[fg_name] = ftd_name
        
        # Get member interfaces from system_switch-interface properties
        # FortiGate can store as: "port5" or "port5 port6" or ["port5", "port6"]
        members_raw = properties.get('member', [])
        if isinstance(members_raw, str):
            # Could be space-separated: "port5 port6"
            members = members_raw.split()
        elif isinstance(members_raw, list):
            members = members_raw
        else:
            members = []
        
        # Map member names to FTD hardware names
        # AND create physical interface entries for each member
        ftd_members = []
        for member in members:
            ftd_hardware = self._get_ftd_hardware_name(member)
            if ftd_hardware:
                ftd_members.append({
                    "hardwareName": ftd_hardware,
                    "type": "physicalinterface"
                })
                
                # Create a physical interface entry for this member
                # This ensures it gets imported and prepped for bridge group
                # Get the name from the physical port's alias in system_interface
                member_props = self._get_interface_properties(member)
                member_alias = member_props.get('alias', member) if member_props else member
                member_name = sanitize_interface_name(member_alias)

                member_interface = {
                    "name": member_name,
                    "hardwareName": ftd_hardware,
                    "description": member_props.get('description', f"Bridge Group {fg_name} member") if member_props else f"Bridge Group {fg_name} member",
                    "enabled": True,
                    "mode": "ROUTED",
                    "type": "physicalinterface"
                }
                
                # Only add if not already in the list
                existing_hardware = [p.get('hardwareName') for p in self.physical_interfaces]
                if ftd_hardware not in existing_hardware:
                    self.physical_interfaces.append(member_interface)
                    print(f"      Added member interface: {member} -> {ftd_hardware}")
                
                # Track this physical interface as a bridge group member
                # so its security zone is named after the bridge group
                self.bridge_group_members[ftd_hardware] = ftd_name
        
        if not ftd_members:
            print(f"    Skipped: {fg_name} (no valid member interfaces)")
            self.stats['skipped'] += 1
            return
        
        # Bridge Group ID
        bridge_group_id = len(self.bridge_groups) + 1
        
        # Look up IP and MTU from system_interface section
        # The switch interface name (fg_name) should have a corresponding entry
        switch_intf_props = self._get_interface_properties(fg_name)
        
        # Build FTD Bridge Group payload
        ftd_interface = {
            "name": ftd_name,
            "bridgeGroupId": bridge_group_id,
            "description": properties.get('description', fg_name),
            "enabled": True,
            "selectedInterfaces": ftd_members,
            "type": "bridgegroupinterface"
        }
        
        # Add IP address if present (from system_interface lookup)
        ip_config = switch_intf_props.get('ip') if switch_intf_props else None
        if ip_config and isinstance(ip_config, list) and len(ip_config) >= 2:
            ip_addr = str(ip_config[0])
            netmask = str(ip_config[1])
            
            if ip_addr != '0.0.0.0':
                ftd_interface["ipv4"] = {
                    "ipType": "STATIC",
                    "defaultRouteUsingDHCP": False,
                    "ipAddress": {
                        "ipAddress": ip_addr,
                        "netmask": netmask,
                        "type": "haipv4address"
                    },
                    "dhcp": False,
                    "addressNull": False,
                    "type": "interfaceipv4"
                }
        
        # Add MTU if overridden (cap at 9000 - FTD maximum)
        mtu_override = switch_intf_props.get('mtu-override') if switch_intf_props else None
        if mtu_override == 'enable':
            mtu = switch_intf_props.get('mtu', 1500)
            if mtu > 9000:
                mtu = 9000
            ftd_interface["mtu"] = mtu
        
        self.bridge_groups.append(ftd_interface)
        self.stats['bridge_groups_created'] += 1
        
        member_str = ', '.join([m['hardwareName'] for m in ftd_members])
        print(f"    Converted: {fg_name} -> {ftd_name} (BVI{bridge_group_id}) members: [{member_str}]")

    def _get_interface_properties(self, intf_name: str) -> dict:
        """
        Look up interface properties from system_interface section.
        
        Args:
            intf_name: Interface name to look up
            
        Returns:
            Properties dictionary or empty dict if not found
        """
        interfaces = self.fg_config.get('system_interface', [])
        
        for intf_dict in interfaces:
            name = list(intf_dict.keys())[0]
            if name == intf_name:
                return intf_dict[name]
        
        return {}
    
    def _convert_vlan_interface(self, fg_name: str, properties: dict):
        """
        Convert a FortiGate VLAN interface to FTD Subinterface.
        
        The FTD subinterface name combines both the alias and the original
        FortiGate interface name for clarity and uniqueness.
        
        Args:
            fg_name: FortiGate interface name (e.g., '551')
            properties: Interface properties from YAML config
        """
        # Get parent interface and VLAN ID
        parent_fg_name = properties.get('interface')
        vlan_id = properties.get('vlanid')
        
        if not parent_fg_name or not vlan_id:
            print(f"    Skipped: {fg_name} (missing parent interface or VLAN ID)")
            self.stats['skipped'] += 1
            return
        
        # Build FTD name from both alias and fg_name for clarity
        # Example: alias="L-slap", fg_name="551" -> "l_slap_551"
        alias = properties.get('alias', '')
        
        if alias and alias != fg_name:
            # Combine alias and fg_name: "alias_fgname"
            combined_name = f"{alias}_{fg_name}"
        else:
            # No alias or alias equals fg_name, just use fg_name
            combined_name = fg_name
        
        ftd_name = sanitize_interface_name(combined_name)
        
        # Reserved names that conflict with FTD built-in interfaces
        # These names cannot be used for subinterfaces
        reserved_names = {
            'management',
            'diagnostic',
            'inside',
            'outside'
        }
        
        # If name matches a reserved name, append a suffix
        if ftd_name.lower() in reserved_names:
            original_reserved = ftd_name
            ftd_name = f"{ftd_name}_vlan{vlan_id}"
            print(f"      Note: '{original_reserved}' is reserved, renamed to '{ftd_name}'")
        
        # Check for duplicate names and make unique if needed
        original_name = ftd_name
        counter = 2
        while ftd_name in self.used_subinterface_names:
            ftd_name = f"{original_name}_{counter}"
            counter += 1
        
        # Track this name as used
        self.used_subinterface_names.add(ftd_name)
        
        # Store the mapping for both fg_name and alias (if different)
        self.interface_name_mapping[fg_name] = ftd_name
        if alias and alias != fg_name:
            self.interface_name_mapping[alias] = ftd_name
        
        # Determine parent FTD interface
        # Could be physical or etherchannel
        parent_ftd_name = self.interface_name_mapping.get(parent_fg_name)
        
        # Build set of FortiGate aggregate interface names for efficient lookup
        # This includes the original FortiGate name that maps to each etherchannel
        etherchannel_fg_names = set()
        for ec in self.etherchannels:
            ec_ftd_name = ec.get('name', '')
            # Find all FortiGate names that map to this etherchannel's FTD name
            for fg_name_key, ftd_name_val in self.interface_name_mapping.items():
                if ftd_name_val == ec_ftd_name:
                    etherchannel_fg_names.add(fg_name_key)
        
        # Determine hardware name based on parent type
        if parent_fg_name in etherchannel_fg_names:
            # Parent is an etherchannel - find its hardware name
            for ec in self.etherchannels:
                if parent_ftd_name == ec.get('name'):
                    parent_hardware = ec.get('hardwareName', 'Port-channel1')
                    break
            else:
                parent_hardware = 'Port-channel1'  # Default fallback
        else:
            # Parent is a physical interface
            parent_hardware = self.port_mapping.get(parent_fg_name, "Ethernet1/1")
        
        hardware_name = f"{parent_hardware}.{vlan_id}"
        
        # Build FTD Subinterface payload
        ftd_interface = {
            "name": ftd_name,
            "hardwareName": hardware_name,
            "description": properties.get('description', alias),
            "enabled": properties.get('status', 'up') != 'down',
            "mode": "ROUTED",
            "subIntfId": int(vlan_id),
            "vlanId": int(vlan_id),
            "type": "subinterface"
        }
        
        # Add IP address if present
        ip_config = properties.get('ip')
        if ip_config and isinstance(ip_config, list) and len(ip_config) >= 2:
            ip_addr = str(ip_config[0])
            netmask = str(ip_config[1])
            
            if ip_addr != '0.0.0.0':
                ftd_interface["ipv4"] = {
                    "ipType": "STATIC",
                    "defaultRouteUsingDHCP": False,
                    "ipAddress": {
                        "ipAddress": ip_addr,
                        "netmask": netmask,
                        "type": "haipv4address"
                    },
                    "dhcp": False,
                    "addressNull": False,
                    "type": "interfaceipv4"
                }
        
        # Add MTU if overridden (cap at 9000 - FTD maximum)
        if properties.get('mtu-override') == 'enable':
            mtu = properties.get('mtu', 1500)
            if mtu > 9000:
                mtu = 9000
            ftd_interface["mtu"] = mtu
        
        self.subinterfaces.append(ftd_interface)
        self.stats['subinterfaces_created'] += 1
        
        if ftd_name != original_name:
            print(f"    Converted: {fg_name} -> {ftd_name} ({hardware_name}) VLAN {vlan_id} [renamed from {original_name}]")
        else:
            print(f"    Converted: {fg_name} -> {ftd_name} ({hardware_name}) VLAN {vlan_id}")
    
    def get_interface_mapping(self) -> dict[str, str]:
        """
        Get the mapping of FortiGate interface names to FTD interface names.
        
        This is used by route and policy converters to update interface references.
        
        Returns:
            Dict mapping FortiGate names to FTD names
        """
        return self.interface_name_mapping.copy()
    
    def get_statistics(self) -> dict[str, int]:
        """Get conversion statistics."""
        return self.stats.copy()


# =============================================================================
# TESTING CODE
# =============================================================================

if __name__ == '__main__':
    """Test the interface converter."""
    
    # Sample FortiGate configuration
    test_config = {
        'system_interface': [
            {
                'port2': {
                    'vdom': 'root',
                    'ip': ['10.0.0.6', '255.255.255.252'],
                    'type': 'physical',
                    'alias': 'IP-KVM',
                    'description': 'Connection to KVM'
                }
            },
            {
                'port6': {
                    'vdom': 'root',
                    'ip': ['10.0.0.10', '255.255.255.252'],
                    'type': 'physical',
                    'alias': 'NTP'
                }
            },
            {
                'ether_trunk': {
                    'vdom': 'root',
                    'type': 'aggregate',
                    'member': ['x1', 'x2'],
                    'alias': 'rt',
                    'mtu-override': 'enable',
                    'mtu': 9216
                }
            },
            {
                'whitebox': {
                    'vdom': 'root',
                    'ip': ['10.10.255.1', '255.255.255.0'],
                    'type': 'switch',
                    'description': 'Bridge Group'
                }
            },
            {
                '551': {
                    'vdom': 'root',
                    'ip': ['10.1.70.1', '255.255.255.0'],
                    'alias': 'L-slap',
                    'interface': 'ether_trunk',
                    'vlanid': 551
                }
            }
        ]
    }
    
    converter = InterfaceConverter(test_config)
    
    print("Testing Interface Converter...")
    print("="*60)
    result = converter.convert()
    
    print("\n" + "="*60)
    print("Results:")
    print("="*60)
    
    import json
    
    print("\nPhysical Interfaces (PUT):")
    print(json.dumps(result['physical_interfaces'], indent=2))
    
    print("\nEtherChannels (POST):")
    print(json.dumps(result['etherchannels'], indent=2))
    
    print("\nBridge Groups (POST):")
    print(json.dumps(result['bridge_groups'], indent=2))
    
    print("\nSubinterfaces (POST):")
    print(json.dumps(result['subinterfaces'], indent=2))
    
    print("\nInterface Name Mapping:")
    print(json.dumps(converter.get_interface_mapping(), indent=2))
    
    print("\nStatistics:")
    print(json.dumps(converter.get_statistics(), indent=2))