#!/usr/bin/env python3
"""
FortiGate Service Port Object Converter Module
===============================================
This module handles the conversion of FortiGate service custom objects to 
Cisco FTD port objects (TCP and UDP).

CRITICAL RULES FOR CISCO FTD:
    1. TCP and UDP must be in SEPARATE objects
    2. Each object can only have ONE port or ONE port range
    3. Multiple ports/ranges must be split into separate objects

WHAT THIS MODULE DOES:
    - Parses FortiGate 'firewall_service_custom' section from YAML
    - Extracts service objects (TCP ports, UDP ports, or both)
    - Splits services with both TCP and UDP into separate objects
    - Splits multiple ports/ranges into separate objects (with _1, _2, etc. suffixes)
    - Converts to FTD 'tcpportobject' and 'udpportobject' formats

FORTIGATE YAML FORMAT:
    firewall_service_custom:
        - SERVICE_NAME:
            uuid: xxxxx
            tcp-portrange: 80  # Single port
            tcp-portrange: 80-443  # Port range
            tcp-portrange: [80, 443, 8080]  # Multiple ports (list)
            tcp-portrange: [80-443, 8080-8090]  # Multiple ranges (list)

CONVERSION EXAMPLES:
    FortiGate: LR_CLUST with tcp-portrange: [8300-8301, 8500-8501, 8086]
    
    FTD Output:
        LR_CLUST_TCP_1: port 8300-8301
        LR_CLUST_TCP_2: port 8500-8501
        LR_CLUST_TCP_3: port 8086

FTD JSON OUTPUT FORMAT:
    {
        "name": "LR_CLUST_TCP_1",
        "isSystemDefined": false,
        "port": "8300-8301",
        "type": "tcpportobject"
    }
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

# FTD System-Defined Services - these names are reserved and cannot be used
# If a FortiGate service has the same name, we'll add "_Custom" suffix
FTD_BUILTIN_UDP_SERVICES = {
    'DNS': '53',           # DNS over UDP
    'NFSD_UDP': '2049',
    'NTP_UDP': '123',
    'RADIUS': '1645',
    'RIP': '520',
    'SIP': '5060',
    'SNMP': '161',
    'SYSLOG': '514',
    'TFTP': '69',
}

FTD_BUILTIN_TCP_SERVICES = {
    'AOL': '5190',
    'Bittorrent': '6881-6889',
    'DNS': '53',           # DNS over TCP
    'FTP': '21',
    'HTTP': '80',
    'HTTPS': '443',
    'IMAP': '143',
    'LDAP': '389',
    'NFSD_TCP': '2049',
    'NTP_TCP': '123',
    'POP_2': '109',
    'POP_3': '110',
    'SMTP': '25',
    'SMTPS': '465',
    'SSH': '22',
    'TELNET': '23',
}

# Combined set of all built-in service names (sanitized)
FTD_BUILTIN_SERVICES = set()
for name in FTD_BUILTIN_UDP_SERVICES.keys():
    FTD_BUILTIN_SERVICES.add(sanitize_name(name))
for name in FTD_BUILTIN_TCP_SERVICES.keys():
    FTD_BUILTIN_SERVICES.add(sanitize_name(name))

class ServiceConverter:
    """
    Converter class for transforming FortiGate service objects to FTD port objects.
    
    This class is responsible for:
    1. Reading the 'firewall_service_custom' section from FortiGate YAML
    2. Identifying TCP and UDP port ranges
    3. Splitting services with both TCP and UDP into separate objects
    4. Splitting multiple ports/ranges into separate objects
    5. Formatting ports for FTD API compatibility
    6. Handling special protocols (IP, ICMP, etc.)
    """
    
    def __init__(self, fortigate_config: dict[str, Any]):
        """
        Initialize the converter with FortiGate configuration data.
        
        Args:
            fortigate_config: Dictionary containing the complete parsed FortiGate YAML
                             Expected to have a 'firewall_service_custom' key
        """
        # Store the entire FortiGate configuration
        self.fg_config = fortigate_config
        
        # This will store the converted FTD port objects
        # Both TCP and UDP objects will be stored here
        self.ftd_port_objects = []
        
        # Track statistics for reporting
        self.tcp_count = 0
        self.udp_count = 0
        self.split_count = 0  # Services that were split into TCP and UDP
        self.multi_port_split_count = 0  # Services split due to multiple ports
        self.skipped_count = 0  # Services that couldn't be converted
        self.icmp_skipped_count = 0 # ICMP/non-port services skipped

        # Mapping of FortiGate service name -> list of FTD object names created
        # Used by ServiceGroupConverter to expand group members correctly
        self.service_name_mapping = {}
        # Set of service names that were skipped (ICMP, etc.)
        # Used by ServiceGroupConverter to filter these out of groups
        self.skipped_services = set()
    
    def _parse_port_list(self, port_value: Any) -> list[str]:
        """
        Parse FortiGate port value into a list of individual ports/ranges.
        
        FortiGate can specify ports as:
        - Single int: 80
        - Single string: "80" or "80-443"
        - Colon-separated string: "80:443:8080" or "80-90:443-445"
        - List: [80, 443, 8080] or ["80-90", "443-445"]
        - List of mixed: [8300-8301, 8500-8501, 8086]
        
        Args:
            port_value: The port value from FortiGate config
            
        Returns:
            List of individual port strings (each suitable for one FTD object)
        """
        if port_value is None:
            return []
        
        ports = []
        
        # Case 1: It's a list
        if isinstance(port_value, list):
            for item in port_value:
                # Each item could be an int, a string with a single port/range,
                # or a string with colon-separated ports
                item_str = str(item)
                if ':' in item_str:
                    # Split colon-separated values
                    ports.extend(item_str.split(':'))
                else:
                    ports.append(item_str)
        
        # Case 2: It's a string (possibly colon-separated)
        elif isinstance(port_value, str):
            if ':' in port_value:
                ports = port_value.split(':')
            else:
                ports = [port_value]
        
        # Case 3: It's a single integer
        elif isinstance(port_value, int):
            ports = [str(port_value)]
        
        # Case 4: Something else - convert to string
        else:
            ports = [str(port_value)]
        
        # Clean up each port (strip whitespace)
        ports = [p.strip() for p in ports if p.strip()]
        
        return ports
    
    def convert(self) -> list[dict]:
        """
        Main conversion method - converts all FortiGate services to FTD port objects.
        
        CONVERSION PROCESS:
        1. Extract the 'firewall_service_custom' list from FortiGate config
        2. Loop through each service entry
        3. Extract the service name and properties
        4. Parse TCP and UDP port lists
        5. Create separate FTD port objects for EACH port/range
        6. Handle special protocols (IP, ICMP) - skip them
        7. Return the complete list of converted port objects
        
        Returns:
            List of dictionaries, each representing an FTD port object
        """
        # ====================================================================
        # STEP 1: Extract service objects from FortiGate configuration
        # ====================================================================
        services = self.fg_config.get('firewall_service_custom', [])
        
        if not services:
            print("Warning: No service objects found in FortiGate configuration")
            print("  Expected key: 'firewall_service_custom'")
            return []
        
        # This list will accumulate all converted port objects
        port_objects = []
        
        # ====================================================================
        # STEP 2: Process each FortiGate service object
        # ====================================================================
        for service_dict in services:
            # ================================================================
            # STEP 2A: Extract the service name and properties
            # ================================================================
            service_name = list(service_dict.keys())[0]
            properties = service_dict[service_name]
            sanitized_name = sanitize_name(service_name)
            
            # ================================================================
            # STEP 2B: Check the protocol type
            # ================================================================
            protocol = properties.get('protocol', '').upper()
            
            # List of protocols to skip (not port-based services)
            skip_protocols = ['IP', 'ICMP', 'ICMP6', 'ICMPV6', 'IPIP', 'GRE', 'ESP', 'AH']
            
            if protocol in skip_protocols:
                print(f"  Skipped: {service_name} (Protocol: {protocol} - not a port-based service)")
                self.icmp_skipped_count += 1
                self.skipped_services.add(sanitized_name)
                continue
            
            # Also check for ICMP-specific fields (some FortiGate configs use these)
            if 'icmptype' in properties or 'icmpcode' in properties:
                print(f"  Skipped: {service_name} (ICMP service - not supported in FTD port objects)")
                self.icmp_skipped_count += 1
                self.skipped_services.add(sanitized_name)
                continue
            
            # Check if protocol-number field indicates ICMP (protocol 1) or ICMPv6 (protocol 58)
            protocol_number = properties.get('protocol-number', None)
            if protocol_number in [1, 58, '1', '58']:
                print(f"  Skipped: {service_name} (ICMP protocol number {protocol_number})")
                self.icmp_skipped_count += 1
                self.skipped_services.add(sanitized_name)
                continue
            
            # ================================================================
            # STEP 2C: Parse TCP and UDP port lists
            # ================================================================
            tcp_ports = self._parse_port_list(properties.get('tcp-portrange', None))
            udp_ports = self._parse_port_list(properties.get('udp-portrange', None))
            
            # ================================================================
            # STEP 2D: Create FTD port objects
            # ================================================================
            has_tcp = len(tcp_ports) > 0
            has_udp = len(udp_ports) > 0
            
            if not has_tcp and not has_udp:
                print(f"  Skipped: {service_name} (No TCP or UDP ports defined)")
                self.skipped_count += 1
                self.skipped_services.add(sanitized_name)
                continue
            
            # Track if this service was split
            total_objects = len(tcp_ports) + len(udp_ports)
            needs_numbering = total_objects > 1
            
            if has_tcp and has_udp:
                self.split_count += 1
            
            if total_objects > 1:
                self.multi_port_split_count += 1
            
            # Counter for object numbering - separate counters for TCP and UDP
            tcp_counter = 1
            udp_counter = 1
            
            # Track FTD objects for this service: list of (name, type) tuples
            ftd_object_info = []
            
            # Create TCP objects
            for port in tcp_ports:
                # Determine the object name
                if len(tcp_ports) > 1:
                    # Multiple TCP ports - number them
                    obj_name = f"{sanitized_name}_TCP_{tcp_counter}"
                elif has_udp:
                    # Has both TCP and UDP but only one TCP
                    obj_name = f"{sanitized_name}_TCP"
                else:
                    # Only TCP, single port - use base name
                    obj_name = sanitized_name
                
                # Check if this name conflicts with FTD built-in services
                if obj_name in FTD_BUILTIN_SERVICES:
                    original_name = obj_name
                    obj_name = f"{obj_name}_Custom"
                    print(f"    Renamed: {original_name} -> {obj_name} (conflicts with FTD built-in)")

                obj_type = "tcpportobject"
                port_obj = {
                    "name": obj_name,
                    "isSystemDefined": False,
                    "port": str(port),
                    "type": obj_type
                }
                port_objects.append(port_obj)
                ftd_object_info.append((obj_name, obj_type))
                self.tcp_count += 1
                tcp_counter += 1
            
            # Create UDP objects
            for port in udp_ports:
                # Determine the object name
                if len(udp_ports) > 1:
                    # Multiple UDP ports - number them
                    obj_name = f"{sanitized_name}_UDP_{udp_counter}"
                elif has_tcp:
                    # Has both TCP and UDP but only one UDP
                    obj_name = f"{sanitized_name}_UDP"
                else:
                    # Only UDP, single port - use base name
                    obj_name = sanitized_name
                
                # Check if this name conflicts with FTD built-in services
                if obj_name in FTD_BUILTIN_SERVICES:
                    original_name = obj_name
                    obj_name = f"{obj_name}_Custom"
                    print(f"    Renamed: {original_name} -> {obj_name} (conflicts with FTD built-in)")

                obj_type = "udpportobject"
                port_obj = {
                    "name": obj_name,
                    "isSystemDefined": False,
                    "port": str(port),
                    "type": obj_type
                }
                port_objects.append(port_obj)
                ftd_object_info.append((obj_name, obj_type))
                self.udp_count += 1
                udp_counter += 1
            
            # Store the mapping of FortiGate name -> FTD names
            self.service_name_mapping[sanitized_name] = ftd_object_info
            
            # ================================================================
            # STEP 2E: Print conversion details
            # ================================================================
            if total_objects == 1:
                proto = "TCP" if has_tcp else "UDP"
                port = tcp_ports[0] if has_tcp else udp_ports[0]
                if service_name != sanitized_name:
                    print(f"  Converted: {service_name} -> {sanitized_name} [{proto} port {port}]")
                else:
                    print(f"  Converted: {sanitized_name} [{proto} port {port}]")
            else:
                print(f"  Converted: {service_name} -> {total_objects} objects:", end="")
                if has_tcp:
                    print(f" {len(tcp_ports)} TCP", end="")
                if has_udp:
                    print(f" {len(udp_ports)} UDP", end="")
                print()
                # Print details for each object
                for port_obj in port_objects[-total_objects:]:
                    print(f"    -> {port_obj['name']}: {port_obj['port']}")
        
        # ====================================================================
        # STEP 3: Store results and return
        # ====================================================================
        self.ftd_port_objects = port_objects
        return port_objects
    
    def get_statistics(self) -> dict[str, int]:
        """
        Get conversion statistics for reporting.
        
        Returns:
            Dictionary with counts of TCP, UDP, split, and skipped services
        """
        return {
            "total_objects": len(self.ftd_port_objects),
            "tcp_objects": self.tcp_count,
            "udp_objects": self.udp_count,
            "split_services": self.split_count,  # Services with both TCP and UDP
            "multi_port_services": self.multi_port_split_count,  # Services with multiple ports
            "skipped_services": self.skipped_count,  # Services with no ports defined
            "icmp_skipped": self.icmp_skipped_count  # ICMP and other non-port protocols
        }
    
    def get_service_name_mapping(self) -> dict[str, list[tuple[str, str]]]:
        """
        Get a mapping of original FortiGate service names to FTD object names.
        
        This is used by the ServiceGroupConverter to expand group members
        to the correct FTD object names.
        
        Returns:
            Dict mapping FortiGate service name -> list of (FTD object name, object type)
            Example: {"DNS": [("DNS_TCP", "tcpportobject"), ("DNS_UDP", "udpportobject")]}
        """
        return self.service_name_mapping
    
    def get_skipped_services(self) -> set[str]:
        """
        Get the set of service names that were skipped (ICMP, etc.).
        
        This is used by the ServiceGroupConverter to filter these
        services out of groups.
        
        Returns:
            Set of sanitized service names that were skipped
        """
        return self.skipped_services


# =============================================================================
# TESTING CODE (for standalone testing of this module)
# =============================================================================

if __name__ == '__main__':
    """
    This code only runs when you execute this file directly.
    It's useful for testing the converter without running the main script.
    
    To test this module standalone:
        python service_converter.py
    """
    
    # Sample FortiGate configuration for testing
    # Including the LR_CLUST example with multiple ports
    test_config = {
        'firewall_service_custom': [
            {
                'ALL': {
                    'uuid': '11111111-2222-3333-8888-000000000014',
                    'category': 'General',
                    'protocol': 'IP',
                    'color': 1
                }
            },
            {
                'HTTP': {
                    'uuid': '11111111-2222-3333-8888-000000000013',
                    'category': 'Web Access',
                    'color': 13,
                    'tcp-portrange': 80
                }
            },
            {
                'DNS': {
                    'uuid': '11111111-2222-3333-8888-000000000013',
                    'category': 'Network Services',
                    'color': 13,
                    'tcp-portrange': 53,
                    'udp-portrange': 53
                }
            },
            {
                'LR_CLUST': {
                    'uuid': '11111111-2222-3333-8888-000000000015',
                    'color': 1,
                    'tcp-portrange': ['8300-8301', '8500-8501', '13100-13202', '8086', '8110-8112', '14502-14503', '9200-9400'],
                    'udp-portrange': '8300-8301'
                }
            },
            {
                'Multi_Port_Service': {
                    'uuid': '11111111-2222-3333-8888-000000000016',
                    'tcp-portrange': [80, 443, 8080]
                }
            }
        ]
    }
    
    # Create converter instance
    converter = ServiceConverter(test_config)
    
    # Run conversion
    print("Testing Service Converter with Multiple Ports...")
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