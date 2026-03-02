#!/usr/bin/env python3
"""
FortiGate Static Route Converter Module
========================================
This module handles the conversion of FortiGate static routes to 
Cisco FTD static route entries.

WHAT THIS MODULE DOES:
    - Parses FortiGate 'router_static' section from YAML
    - Extracts route information (destination, gateway, interface, metric)
    - Converts destination subnet to network object reference
    - Converts gateway IP to network object reference
    - Maps FortiGate device/interface to FTD interface reference
    - Handles blackhole routes (routes with no gateway)
    - Converts to FTD 'staticrouteentry' format

FORTIGATE YAML FORMAT:
    router_static:
        - ROUTE_ID:
            dst: [10.0.20.0, 255.255.255.0]  # Destination network
            gateway: 10.0.222.18             # Gateway IP (optional)
            distance: 1                       # Metric/distance (optional)
            device: "port2"                  # Interface name (optional)
            comment: "Description"           # Optional comment
            blackhole: enable                # Blackhole route (optional)
            vrf: 0                           # VRF (optional)

FTD JSON OUTPUT FORMAT:
    {
        "name": "Route_Name",
        "iface": {
            "name": "interface_name",
            "type": "physicalinterface"
        },
        "networks": [
            {"name": "destination_network", "type": "networkobject"}
        ],
        "gateway": {
            "name": "gateway_ip",
            "type": "networkobject"
        },
        "metricValue": 1,
        "ipType": "IPv4",
        "type": "staticrouteentry"
    }

IMPORTANT NOTES:
    - FortiGate 'dst' (destination) becomes FTD 'networks' array
    - FortiGate 'gateway' becomes FTD 'gateway' object reference
    - FortiGate 'device' becomes FTD 'iface' reference
    - FortiGate 'distance' becomes FTD 'metricValue'
    - Blackhole routes are skipped (or handled specially)
    - Default routes (0.0.0.0/0) are converted to "any-ipv4" reference
"""

import json
import re
from typing import Dict, List, Any, Optional

def sanitize_name(name: str) -> str:
    """
    Sanitize object names for FTD compatibility.
    
    FTD does not allow spaces in object names. This function replaces
    spaces with underscores to ensure compatibility.
    
    Args:
        name: Original object name (may contain spaces)
        
    Returns:
        Sanitized name with spaces replaced by underscores
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




class RouteConverter:
    """
    Converter class for transforming FortiGate static routes to FTD route entries.
    
    This class is responsible for:
    1. Reading the 'router_static' section from FortiGate YAML
    2. Extracting route information (destination, gateway, interface, metric)
    3. Converting IP addresses to network object references
    4. Mapping FortiGate interfaces to FTD interfaces
    5. Converting to FTD's staticrouteentry format
    6. Handling special cases (blackhole routes, default routes)
    """
    
    def __init__(
    self,
    fortigate_config: Dict[str, Any],
    network_objects: Optional[List[Dict]] = None,
    address_objects_json_path: Optional[str] = None,
    interface_name_mapping: Optional[Dict[str, str]] = None,
    converted_interfaces: Optional[Dict[str, List[Dict]]] = None,
    debug: bool = False
    ):

        """
        Initialize the converter with FortiGate configuration data.
        
        Args:
            fortigate_config: Dictionary containing the complete parsed FortiGate YAML
                             Expected to have a 'router_static' key with route data
            network_objects: List of already-converted FTD network objects
                           Used to match route destinations/gateways to existing objects
            interface_name_mapping: Dict mapping FortiGate interface names to FTD interface names
            converted_interfaces: Dict containing converted interface lists
                                 Keys: 'physical_interfaces', 'subinterfaces', 'etherchannels', 'bridge_groups'
            debug: Enable debug output
        """
        # Store the entire FortiGate configuration
        self.fg_config = fortigate_config
        
        # Store/load the list of network objects (address objects) for lookup
        # Priority:
        #   1) Explicit network_objects list passed in (already loaded by caller)
        #   2) JSON file path provided (load objects from disk)
        #   3) Empty list (no matching possible; routes will generate missing objects)
        if network_objects:
            self.network_objects = network_objects
        elif address_objects_json_path:
            self.network_objects = self._load_network_objects_from_json(address_objects_json_path)
        else:
            self.network_objects = []

        # Store interface name mapping
        self.interface_name_mapping = interface_name_mapping or {}
        
        # Store debug flag
        self.debug = debug
        
        # Store converted interfaces
        self.converted_interfaces = converted_interfaces or {}

        # Track any objects we auto-generate so the caller can export them
        # This list accumulates objects from _ensure_network_object_with_value()
        # and _ensure_network_object_for_value() for export by fortigate_converter.py
        self.generated_network_objects: List[Dict] = []
        
        # Build lookup dictionaries
        # Name -> full network object (for routes)
        self.name_to_network_object = {}
        self._build_network_object_lookup()
        
        # IP/CIDR -> network object name
        self.ip_to_network_object_name = {}
        self._build_ip_to_network_object_lookup()
        
        # Interface name -> full interface object
        self.name_to_interface_object = {}
        self._build_interface_object_lookup()
        
        # IP/network -> interface name (for determining which interface a network/gateway is on)
        self.ip_to_interface_name = {}
        self._build_ip_to_interface_name_lookup()
        
        # This will store the converted FTD static routes
        self.ftd_static_routes = []
        
        # Track routes that need network objects created
        self.missing_network_objects = []

        # The interface object currently being processed in convert()
        self._current_route_interface_obj: Optional[Dict] = None

        
        # Track statistics
        self.converted_count = 0
        self.blackhole_count = 0
        self.skipped_count = 0
        self.unmatched_count = 0  # Track routes with no matching address object

    def _build_network_object_lookup(self):
        """Build lookup from network object name to full object."""
        for obj in self.network_objects:
            name = obj.get('name')
            if name:
                self.name_to_network_object[name] = obj

    def _ensure_host_object_for_ip(self, ip: str, name_prefix: str) -> Dict:
        """
        Ensure a host network object exists for the given IP.

        FortiGate allows next-hop gateway IPs without an address object. FTD route modeling
        in this project uses networkobject references, so we auto-create minimal host objects
        when missing.

        Args:
            ip: IPv4 address string
            name_prefix: Prefix for generated object names (e.g., "Gateway", "Host")

        Returns:
            A networkobject dict with 'name' and 'type' keys suitable for route references.
        """
        ip = str(ip).strip()
        if not ip:
            # Defensive fallback
            return {"name": f"{name_prefix}_UNKNOWN", "type": "networkobject"}

        # If an object already exists for this IP, reuse it
        existing_name = self.ip_to_network_object_name.get(ip) or self.ip_to_network_object_name.get(f"{ip}/32")
        if existing_name:
            return {"name": existing_name, "type": "networkobject"}

        # Create a minimal host object
        safe_ip = ip.replace(".", "_").replace(":", "_")
        obj_name = f"{name_prefix}_{safe_ip}"
        new_obj = {
            "name": obj_name,
            "description": f"Auto-created for static route next-hop {ip}",
            "type": "networkobject",
            "subType": "HOST",
            "value": ip
        }


        # Persist into local stores so subsequent routes can reuse it
        self.network_objects.append(new_obj)
        self.generated_network_objects.append(new_obj)

        # Update lookup for both 'ip' and 'ip/32'
        self.ip_to_network_object_name[ip] = obj_name
        self.ip_to_network_object_name[f"{ip}/32"] = obj_name

        if self.debug:
            print(f"    [DEBUG] Auto-created host object: {obj_name} -> {ip}")

        return {"name": obj_name, "type": "networkobject"}
    
    def _infer_subtype_from_value(self, value: str) -> str:
        """
        Infer the FTD networkobject subType from a value string.

        Rules (aligned with address_converter output semantics):
            - "IP1-IP2" => RANGE
            - "IP/CIDR" => HOST if /32, else NETWORK
            - "IP"      => HOST

        Args:
            value: Network object value (e.g., "10.0.0.1", "10.0.0.0/24", "10.0.0.1-10.0.0.10")

        Returns:
            "HOST", "NETWORK", or "RANGE"
        """
        v = str(value).strip()
        if "-" in v:
            return "RANGE"
        if "/" in v:
            try:
                prefix = v.split("/", 1)[1].strip()
                return "HOST" if prefix == "32" else "NETWORK"
            except Exception:
                return "NETWORK"
        return "HOST"
    
    def _build_ip_to_network_object_lookup(self):
        """
        Build lookup from IP/CIDR to network object name.

        Why this exists:
            - Converted address objects may represent:
            * networks as "10.0.20.0/24"
            * hosts as "10.0.0.5" (no "/32")  <-- address_converter does this intentionally【turn16:14†address_converter.py†L15-L22】
            - Route gateway matching often checks "IP/32" first【turn16:2†route_converter.py†L29-L40】

        This function normalizes keys so lookups succeed regardless of representation.
        """
        for obj in self.network_objects:
            name = obj.get('name', '')
            value = obj.get('value', '')

            if not value or not name:
                continue

            # Normalize whitespace just in case
            value = str(value).strip()

            # Store the raw value as-is
            self.ip_to_network_object_name[value] = name

            if '/' in value:
                ip_only, prefix = value.split('/', 1)
                ip_only = ip_only.strip()

                # Allow lookup by base IP as well
                if ip_only and ip_only not in self.ip_to_network_object_name:
                    self.ip_to_network_object_name[ip_only] = name

                # If this object is explicitly a /32, also store IP/32 key
                if prefix.strip() == '32':
                    ip32 = f"{ip_only}/32"
                    if ip32 not in self.ip_to_network_object_name:
                        self.ip_to_network_object_name[ip32] = name
            else:
                # Host object emitted by address_converter: add /32 alias for gateway matching
                ip32 = f"{value}/32"
                if ip32 not in self.ip_to_network_object_name:
                    self.ip_to_network_object_name[ip32] = name

    def _ensure_network_object_with_value(self, name: str, value: str, sub_type: str, description: str = "") -> Dict:
        """
        Ensure a network object exists with the specified name/value/subType.

        This is used when FortiGate provides a raw gateway IP and no address object exists.
        We must create an object that FTD routes can reference.

        Performance characteristics:
            - O(1) lookups against local dict caches
            - Minimal writes (only when missing)

        Args:
            name: Desired object name (e.g., "Gateway_10_10_10_2")
            value: Desired value (e.g., "10.10.10.2/30" or "10.10.10.2/32")
            sub_type: "HOST", "NETWORK", or "RANGE"
            description: Optional description string

        Returns:
            A reference dict {"name": <name>, "type": "networkobject"} suitable for route JSON.
        """
        name = str(name).strip()
        value = str(value).strip()
        sub_type = str(sub_type).strip().upper()

        # 1) If an object with this name already exists, reuse it.
        existing = self.name_to_network_object.get(name)
        if existing:
            return {"name": existing.get("name", name), "type": "networkobject"}

        # 2) If an object exists for this value, reuse it (avoid duplicates by value).
        existing_name = self.ip_to_network_object_name.get(value)
        if existing_name and existing_name in self.name_to_network_object:
            return {"name": existing_name, "type": "networkobject"}

        # 3) Create new object (track it for export + later imports)
        new_obj = {
            "name": name,
            "description": description,
            "type": "networkobject",
            "subType": sub_type,
            "value": value
        }

        # Track for later export/merge in fortigate_converter.py
        # Add to both lists: missing_network_objects for backward compatibility
        # and generated_network_objects for the main export mechanism
        self.missing_network_objects.append(new_obj)
        self.generated_network_objects.append(new_obj)

        # Update in-memory caches so subsequent lookups succeed in the same run
        self.name_to_network_object[name] = new_obj
        self.ip_to_network_object_name[value] = name

        # Add useful aliases for host formats (helps gateway matching)
        # If value is "ip/prefix", also map "ip" and "ip/32" when appropriate.
        if "/" in value and "-" not in value:
            ip_only, prefix = value.split("/", 1)
            ip_only = ip_only.strip()
            prefix = prefix.strip()
            if ip_only:
                self.ip_to_network_object_name.setdefault(ip_only, name)
                if prefix == "32":
                    self.ip_to_network_object_name.setdefault(f"{ip_only}/32", name)

        return {"name": name, "type": "networkobject"}


    def _ensure_network_object_for_value(self, value: str, name_prefix: str) -> Dict:
        """
        Ensure a networkobject exists for a given value string (CIDR/host/range).
        Used for destinations when FortiGate references raw values without address objects.

        Args:
            value: e.g. "10.0.0.0/24", "10.0.0.1", "10.0.0.1-10.0.0.10"
            name_prefix: e.g. "RouteNet"

        Returns:
            Reference dict: {"name": <obj_name>, "type": "networkobject"}
        """
        v = str(value).strip()
        if not v:
            return {"name": f"{name_prefix}_UNKNOWN", "type": "networkobject"}

        # Reuse existing object if present
        existing_name = self.ip_to_network_object_name.get(v)
        if existing_name:
            return {"name": existing_name, "type": "networkobject"}

        safe = v.replace(".", "_").replace(":", "_").replace("/", "_").replace("-", "_")
        obj_name = f"{name_prefix}_{safe}"
        sub_type = self._infer_subtype_from_value(v)

        new_obj = {
            "name": obj_name,
            "description": f"Auto-created for static route destination {v}",
            "type": "networkobject",
            "subType": sub_type,
            "value": v
        }

        self.network_objects.append(new_obj)
        self.generated_network_objects.append(new_obj)

        # Populate lookup for raw value
        self.ip_to_network_object_name[v] = obj_name

        # If it's a host value without /32, also add /32 alias (helps gateway-like lookups)
        if sub_type == "HOST" and "/" not in v and "-" not in v:
            self.ip_to_network_object_name[f"{v}/32"] = obj_name

        return {"name": obj_name, "type": "networkobject"}

    
    def _load_network_objects_from_json(self, filename: str) -> List[Dict]:
        """
        Load converted address objects (network objects) from a JSON file.

        The conversion pipeline produces a JSON list of objects like:
            {"name": "...", "value": "...", "type": "networkobject"}

        This loader is intentionally strict and fast:
            - Returns [] on failure and prints a warning
            - Ensures the result is a list of dicts

        Args:
            filename: Path to the converted address objects JSON file.

        Returns:
            List of address/network object dictionaries.
        """
        try:
            with open(filename, "r", encoding="utf-8") as f:
                data = json.load(f)

            if not isinstance(data, list):
                print(f"[WARN] Address objects JSON is not a list: {filename}")
                return []

            # Filter to dicts only (defensive)
            return [o for o in data if isinstance(o, dict)]

        except FileNotFoundError:
            print(f"[WARN] Address objects JSON file not found: {filename}")
            return []
        except json.JSONDecodeError as e:
            print(f"[WARN] Invalid JSON in address objects file: {filename} ({e})")
            return []
        except OSError as e:
            print(f"[WARN] Could not read address objects file: {filename} ({e})")
            return []


    def _build_interface_object_lookup(self):
        """Build lookup from interface name to full interface object."""
        for interface_type in ['physical_interfaces', 'subinterfaces', 'etherchannels', 'bridge_groups']:
            interfaces = self.converted_interfaces.get(interface_type, [])
            
            for intf in interfaces:
                name = intf.get('name', '')
                if name:
                    self.name_to_interface_object[name] = intf


    def _build_ip_to_interface_name_lookup(self):
        """Build lookup from IP/network to interface name."""
        for interface_type in ['physical_interfaces', 'subinterfaces', 'etherchannels', 'bridge_groups']:
            interfaces = self.converted_interfaces.get(interface_type, [])
            
            for intf in interfaces:
                intf_name = intf.get('name', '')
                if not intf_name:
                    continue
                
                # Extract IPv4 address if present
                ipv4_config = intf.get('ipv4')
                if ipv4_config and isinstance(ipv4_config, dict):
                    ip_address_obj = ipv4_config.get('ipAddress', {})
                    
                    if isinstance(ip_address_obj, dict):
                        ip_addr = ip_address_obj.get('ipAddress')
                        netmask = ip_address_obj.get('netmask')
                        
                        if ip_addr and netmask:
                            # Calculate network address and CIDR
                            cidr = self._netmask_to_cidr(netmask)
                            network_addr = self._calculate_network_address(ip_addr, netmask)
                            network_cidr = f"{network_addr}/{cidr}"
                            
                            # Store mappings
                            self.ip_to_interface_name[ip_addr] = intf_name
                            self.ip_to_interface_name[f"{ip_addr}/32"] = intf_name
                            self.ip_to_interface_name[network_cidr] = intf_name
                            self.ip_to_interface_name[network_addr] = intf_name
    
    def _calculate_network_address(self, ip_addr: str, netmask: str) -> str:
        """Calculate the network address given an IP and netmask."""
        try:
            ip_octets = [int(o) for o in ip_addr.split('.')]
            mask_octets = [int(o) for o in netmask.split('.')]
            network_octets = [ip_octets[i] & mask_octets[i] for i in range(4)]
            return '.'.join(str(o) for o in network_octets)
        except Exception:
            return ip_addr
        

    def _get_network_object_for_destination(self, dst: List) -> Optional[Dict]:
        """
        Get the full network object for a route destination.

        FortiGate static routes may specify destinations directly as IP+netmask
        without requiring a named address object. FTD route modeling in this
        project uses networkobject references, so we must resolve (or create)
        a matching object.

        Args:
            dst: List containing [IP_address, netmask]

        Returns:
            Full network object dict copy if it exists, otherwise a reference dict
            {"name": ..., "type": "networkobject"} for a newly generated object.
        """
        if not dst or len(dst) < 2:
            return None

        ip_addr = str(dst[0]).strip()
        netmask = str(dst[1]).strip()
        cidr = self._netmask_to_cidr(netmask)

        # Default route
        if ip_addr == "0.0.0.0" and cidr == 0:
            return {"name": "any-ipv4", "type": "networkobject"}

        # Calculate the actual network address for the destination
        network_addr = self._calculate_network_address(ip_addr, netmask)
        network_cidr = f"{network_addr}/{cidr}"

        # 1) Match by normalized CIDR (preferred)
        obj_name = self.ip_to_network_object_name.get(network_cidr)
        if obj_name:
            obj = self.name_to_network_object.get(obj_name)
            if obj:
                return obj.copy()

        # 2) Match by network base address only
        obj_name = self.ip_to_network_object_name.get(network_addr)
        if obj_name:
            obj = self.name_to_network_object.get(obj_name)
            if obj:
                return obj.copy()

        # 3) Last resort: match by raw ip_addr (some object values might be host style)
        obj_name = self.ip_to_network_object_name.get(ip_addr)
        if obj_name:
            obj = self.name_to_network_object.get(obj_name)
            if obj:
                return obj.copy()

        if self.debug:
            print(f"    [DEBUG] Destination lookup miss for: dst={ip_addr} mask={netmask} -> {network_cidr}")

        # 4) Not found: auto-create an object that represents the destination.
        self.unmatched_count += 1

        # If /32, treat as HOST; otherwise treat as NETWORK
        if cidr == 32:
            generated_name = f"Host_{ip_addr.replace('.', '_').replace(':', '_')}"
            value = ip_addr  # keep host form consistent with address_converter
            sub_type = "HOST"
            description = f"Auto-created for static route destination host {ip_addr}"
        else:
            generated_name = f"RouteNet_{network_addr.replace('.', '_')}_{cidr}"
            value = network_cidr
            sub_type = "NETWORK"
            description = f"Auto-created for static route destination {network_cidr}"

        return self._ensure_network_object_with_value(
            name=generated_name,
            value=value,
            sub_type=sub_type,
            description=description
        )

    
    def _get_network_object_for_gateway(self, gateway_ip: str) -> Optional[Dict]:
        """
        Get the full network object for a gateway IP.

        Behavior:
            1) Try to resolve an existing object by gateway_ip or gateway_ip/32
            2) If not found, auto-create a HOST object for the gateway IP
            3) Return a reference dict suitable for insertion into the static route payload

        IMPORTANT: Gateways are always HOST addresses (a specific next-hop IP),
        not networks. FTD requires HOST objects to have just the IP address
        without CIDR notation, or with /32. Using a non-/32 CIDR with a host IP
        (e.g., 15.0.252.18/30) will fail because 15.0.252.18 is not the network
        address for that subnet.

        Args:
            gateway_ip: Gateway IP address as string

        Returns:
            Full network object dict copy if it exists, otherwise a reference dict
            {"name": ..., "type": "networkobject"} for a newly generated object.
        """
        # Normalize gateway formatting from FortiGate YAML (defensive)
        gateway_ip = str(gateway_ip).strip()

        # Try with /32 CIDR notation first
        gateway_cidr = f"{gateway_ip}/32"
        if gateway_cidr in self.ip_to_network_object_name:
            obj_name = self.ip_to_network_object_name[gateway_cidr]
            obj = self.name_to_network_object.get(obj_name)
            if obj:
                return obj.copy()

        # Try without CIDR
        if gateway_ip in self.ip_to_network_object_name:
            obj_name = self.ip_to_network_object_name[gateway_ip]
            obj = self.name_to_network_object.get(obj_name)
            if obj:
                return obj.copy()

        if self.debug:
            print(f"    [DEBUG] Gateway lookup miss for: '{gateway_ip}'")
            print(f"    [DEBUG] Tried keys: '{gateway_ip}/32' and '{gateway_ip}'")
            if self._current_route_interface_obj:
                print(f"    [DEBUG] Current interface object: {self._current_route_interface_obj.get('name', 'unknown')}")

        # No existing object found: create a HOST object for this gateway IP
        self.unmatched_count += 1

        # Use a deterministic name; keep "Gateway_" prefix to make these easy to audit later
        generated_name = f"Gateway_{gateway_ip.replace('.', '_').replace(':', '_')}"

        # IMPORTANT: Gateways are always HOST objects with just the IP address.
        # Do NOT use CIDR notation like /30 with a host IP - FTD will reject it
        # because the IP (e.g., 15.0.252.18) is not the network address (15.0.252.16)
        # for that subnet. HOST objects should use plain IP or IP/32.
        gateway_value = gateway_ip  # Plain IP for HOST objects
        sub_type = "HOST"

        if self.debug:
            print(f"    [DEBUG] Creating gateway HOST object: name={generated_name}, value={gateway_value}")

        # Create (or reuse) an object with the computed value
        return self._ensure_network_object_with_value(
            name=generated_name,
            value=gateway_value,
            sub_type=sub_type,
            description=f"Auto-created HOST for static route next-hop {gateway_ip}"
        )


    
    def _get_interface_object(self, interface_name: str) -> Optional[Dict]:
        """
        Get the full interface object by name.
        
        Args:
            interface_name: FTD interface name
            
        Returns:
            Full interface object dict, or None
        """
        return self.name_to_interface_object.get(interface_name)
    
    
    def convert(self) -> List[Dict]:
        """
        Main conversion method - converts all FortiGate static routes to FTD format.
        
        CONVERSION PROCESS:
        1. Extract the 'router_static' list from FortiGate config
        2. Loop through each route entry
        3. Extract the route ID and properties
        4. Check if it's a blackhole route (skip or handle specially)
        5. Extract destination network and convert to CIDR
        6. Extract gateway IP
        7. Extract interface name
        8. Extract metric/distance
        9. Create FTD staticrouteentry structure
        10. Return the complete list of converted routes
        
        Returns:
            List of dictionaries, each representing an FTD static route entry
        """
        # ====================================================================
        # STEP 1: Extract static routes from FortiGate configuration
        # ====================================================================
        routes = self.fg_config.get('router_static', [])
        
        if not routes:
            print("Warning: No static routes found in FortiGate configuration")
            print("  Expected key: 'router_static'")
            return []
        
        # This list will accumulate all converted routes
        static_routes = []
        
        # ====================================================================
        # STEP 2: Process each FortiGate static route
        # ====================================================================
        for route_dict in routes:
            # ================================================================
            # STEP 2A: Extract the route ID and properties
            # ================================================================
            # Each route looks like: {64: {dst: ..., gateway: ...}}
            # The route ID is the key (e.g., 64)
            route_id = list(route_dict.keys())[0]
            properties = route_dict[route_id]
            
            # ================================================================
            # STEP 2B: Check if this is a blackhole route
            # ================================================================
            # Blackhole routes drop traffic - they may not be needed in FTD
            if properties.get('blackhole') == 'enable':
                self.blackhole_count += 1
                print(f"  Skipped: Route [{route_id}] - Blackhole route")
                continue
            
            # ================================================================
            # STEP 2C: Extract destination network
            # ================================================================
            dst = properties.get('dst', [])
            if not dst or len(dst) < 2:
                print(f"  Skipped: Route [{route_id}] - No destination specified")
                self.skipped_count += 1
                continue
            
            # Convert destination to CIDR format
            dst_network = self._format_destination(dst)
            
            # ================================================================
            # STEP 2D: Get destination network object
            # ================================================================
            dst_network_obj = self._get_network_object_for_destination(dst)
            if not dst_network_obj:
                print(f"  Skipped: Route [{route_id}] - Could not resolve destination network object")
                self.skipped_count += 1
                continue
            
            # ================================================================
            # STEP 2E: Extract interface/device and get interface object
            # ================================================================
            # NOTE: Interface must be resolved BEFORE gateway so that auto-created
            # gateway objects can inherit the correct subnet prefix from the interface
            fg_interface_name = properties.get('device', 'unknown')
            
            # Map FortiGate interface name to FTD interface name
            if fg_interface_name in self.interface_name_mapping:
                ftd_interface_name = self.interface_name_mapping[fg_interface_name]
            else:
                ftd_interface_name = self.interface_name_mapping.get(
                    fg_interface_name, 
                    fg_interface_name.lower().replace('-', '_')
                )
            
            # Get the full interface object
            interface_obj = self._get_interface_object(ftd_interface_name) # type: ignore
            if not interface_obj:
                print(f"  Warning: Route [{route_id}] - Could not find interface object for {ftd_interface_name}")
                print(f"           Using basic interface reference")
                # Create basic interface reference as fallback
                interface_obj = {
                    "name": ftd_interface_name,
                    "type": "physicalinterface"
                }
            # Save the resolved interface object for gateway object synthesis
            # (used when FortiGate has a raw gateway IP with no address object)
            self._current_route_interface_obj = interface_obj
            
            # ================================================================
            # STEP 2F: Extract gateway and get network object
            # ================================================================
            gateway_ip = properties.get('gateway', None)
            if not gateway_ip:
                print(f"  Skipped: Route [{route_id}] - No gateway specified")
                self.skipped_count += 1
                continue
            
            gateway_obj = self._get_network_object_for_gateway(gateway_ip)
            if not gateway_obj:
                print(f"  Skipped: Route [{route_id}] - Could not resolve gateway network object")
                self.skipped_count += 1
                continue

            
            # ================================================================
            # STEP 2G: Extract metric/distance
            # ================================================================
            metric = properties.get('distance', 1)
            
            # ================================================================
            # STEP 2H: Extract comment for route name
            # ================================================================
            comment = properties.get('comment', '')
            if comment:
                route_name = sanitize_name(comment)
            else:
                dst_obj_name = dst_network_obj.get('name', 'unknown')
                route_name = f"Route_{route_id}_{sanitize_name(dst_obj_name)}"
            
            # ================================================================
            # STEP 2I: Create the FTD static route entry structure
            # ================================================================
            ftd_route = {
                "name": route_name,
                "iface": {
                    "name": interface_obj.get('name', ftd_interface_name),
                    "hardwareName": interface_obj.get('hardwareName', ''),
                    "type": interface_obj.get('type', 'physicalinterface')
                },
                "networks": [
                    {
                        "name": dst_network_obj.get('name', dst_network_obj),
                        "type": "networkobject"
                    }
                ],
                "gateway": {
                    "name": gateway_obj.get('name', gateway_obj),
                    "type": "networkobject"
                },
                "metricValue": metric,
                "ipType": "IPv4",
                "type": "staticrouteentry"
            }
            
            # Add the converted route to our result list
            static_routes.append(ftd_route)
            self.converted_count += 1
            
            # ================================================================
            # STEP 2J: Print conversion details for user feedback
            # ================================================================
            dst_obj_name = dst_network_obj.get('name', 'unknown')
            gateway_obj_name = gateway_obj.get('name', 'unknown')
            interface_obj_name = interface_obj.get('name', 'unknown')
            
            print(f"  Converted: [{route_id}] {route_name}")
            print(f"    Destination: {dst_obj_name} ({dst_network})")
            print(f"    Gateway: {gateway_obj_name}")
            print(f"    Interface: {interface_obj_name}")
            print(f"    Metric: {metric}")
        
        # ====================================================================
        # STEP 3: Store results and return
        # ====================================================================
        self.ftd_static_routes = static_routes
        return static_routes
    
    def _format_destination(self, dst: List) -> str:
        """
        Convert FortiGate destination format to CIDR notation.
        
        FortiGate format: [IP, NETMASK]
        FTD format: IP/CIDR
        
        Args:
            dst: List containing [IP_address, netmask]
            
        Returns:
            String in CIDR format (e.g., "10.0.20.0/24")
        """
        if len(dst) < 2:
            return ""
        
        ip_addr = str(dst[0])
        netmask = str(dst[1])
        
        # Convert netmask to CIDR notation
        cidr = self._netmask_to_cidr(netmask)
        
        return f"{ip_addr}/{cidr}"
    
    def _netmask_to_cidr(self, netmask: str) -> int:
        """
        Convert subnet mask to CIDR prefix length.
        
        This is the same method used in the address converter.
        
        Args:
            netmask: Subnet mask in dotted decimal format (e.g., "255.255.255.0")
            
        Returns:
            Integer representing CIDR prefix length (e.g., 24)
        """
        try:
            # Split the netmask into individual octets
            octets = netmask.split('.')
            
            # Convert each octet to binary and concatenate
            binary_str = ''
            for octet in octets:
                # Convert to binary and pad to 8 bits
                binary_octet = bin(int(octet))[2:].zfill(8)
                binary_str += binary_octet
            
            # Count the number of '1' bits
            cidr_prefix = binary_str.count('1')
            
            return cidr_prefix
            
        except Exception as e:
            # If conversion fails, default to /32
            print(f"    Warning: Could not convert netmask '{netmask}' to CIDR")
            return 32
        
    def _get_interface_ipv4_prefix(self, interface_obj: Dict) -> Optional[int]:
        """
        Extract the IPv4 prefix length for a converted interface object.

        The interface converter emits:
            intf["ipv4"]["ipAddress"]["netmask"] = "255.255.255.252" (example)【turn25:10†interface_converter.py†L6-L14】

        Args:
            interface_obj: Converted interface dictionary.

        Returns:
            CIDR prefix length (e.g., 30) or None if not available.
        """
        ipv4 = interface_obj.get("ipv4")
        if not isinstance(ipv4, dict):
            return None

        ip_addr_obj = ipv4.get("ipAddress")
        if not isinstance(ip_addr_obj, dict):
            return None

        netmask = ip_addr_obj.get("netmask")
        if not netmask:
            return None

        return self._netmask_to_cidr(str(netmask))

    
    def _create_network_name(self, dst: List) -> str:
        """
        Find the interface name for the destination network.
        
        This method looks up the destination IP/network to find which interface
        it's configured on, then returns that interface name.
        
        This allows FTD routes to reference interface names as the network object.
        
        Args:
            dst: List containing [IP_address, netmask]
            
        Returns:
            String name of the interface where this network exists, or a generated name if no match
        """
        if len(dst) < 2:
            return "Unknown_Network"
        
        ip_addr = str(dst[0])
        netmask = str(dst[1])
        cidr = self._netmask_to_cidr(netmask)
        
        # Check if this is a default route (0.0.0.0/0)
        if ip_addr == "0.0.0.0" and cidr == 0:
            return "any-ipv4"
        
        # Calculate network address
        network_addr = self._calculate_network_address(ip_addr, netmask)
        network_cidr = f"{network_addr}/{cidr}"
        
        if self.debug:
            print(f"\n    [DEBUG] Looking up network: {network_cidr}")
        
        # Try to find the interface by network CIDR
        if network_cidr in self.ip_to_interface: # pyright: ignore[reportAttributeAccessIssue]
            result = self.ip_to_interface[network_cidr] # pyright: ignore[reportAttributeAccessIssue]
            if self.debug:
                print(f"    [DEBUG] Found interface by network CIDR: {result}")
            return result
        
        # Try to find by network address only
        if network_addr in self.ip_to_interface: # pyright: ignore[reportAttributeAccessIssue]
            result = self.ip_to_interface[network_addr] # pyright: ignore[reportAttributeAccessIssue]
            if self.debug:
                print(f"    [DEBUG] Found interface by network address: {result}")
            return result
        
        # Try to find by IP address (in case it's a host route)
        if ip_addr in self.ip_to_interface: # pyright: ignore[reportAttributeAccessIssue]
            result = self.ip_to_interface[ip_addr] # pyright: ignore[reportAttributeAccessIssue]
            if self.debug:
                print(f"    [DEBUG] Found interface by IP address: {result}")
            return result
        
        if self.debug:
            print(f"    [DEBUG] No interface found, trying address objects...")
        
        # FALLBACK: Try legacy address object lookup
        cidr_notation = f"{ip_addr}/{cidr}"
        
        # Try to find the address object by exact CIDR match
        if cidr_notation in self.ip_to_name: # pyright: ignore[reportAttributeAccessIssue]
            result = self.ip_to_name[cidr_notation] # pyright: ignore[reportAttributeAccessIssue]
            if self.debug:
                print(f"    [DEBUG] Found address object by CIDR: {result}")
            return result
        
        # Try to find by IP only (for host addresses)
        if ip_addr in self.ip_to_name: # pyright: ignore[reportAttributeAccessIssue]
            result = self.ip_to_name[ip_addr] # pyright: ignore[reportAttributeAccessIssue]
            if self.debug:
                print(f"    [DEBUG] Found address object by IP: {result}")
            return result
        
        # No match found - generate a name and warn the user
        self.unmatched_count += 1
        generated_name = f"Net_{ip_addr.replace('.', '_')}_{cidr}"
        print(f"    Warning: No interface or address object found for {cidr_notation}, using generated name: {generated_name}")
        
        return generated_name
    
    def _create_gateway_name(self, gateway_ip: str, properties: Dict) -> str:
        """
        Find the interface name for the gateway IP.
        
        This method looks up the gateway IP to find which interface network
        it belongs to, then returns that interface name.
        
        This allows FTD routes to reference interface names as the gateway object.
        
        Args:
            gateway_ip: Gateway IP address as string
            properties: Route properties dictionary (for comment field)
            
        Returns:
            String name of the interface where this gateway exists, or a generated name if no match
        """
        if self.debug:
            print(f"\n    [DEBUG] Looking up gateway: {gateway_ip}")
        
        # Try to find the interface by gateway IP
        # The gateway is typically an IP address on a directly connected network
        
        # First try exact IP match
        if gateway_ip in self.ip_to_interface: # pyright: ignore[reportAttributeAccessIssue]
            result = self.ip_to_interface[gateway_ip] # pyright: ignore[reportAttributeAccessIssue]
            if self.debug:
                print(f"    [DEBUG] Found interface by IP: {result}")
            return result
        
        # Try with /32 CIDR notation
        gateway_cidr = f"{gateway_ip}/32"
        if gateway_cidr in self.ip_to_interface: # pyright: ignore[reportAttributeAccessIssue]
            result = self.ip_to_interface[gateway_cidr] # pyright: ignore[reportAttributeAccessIssue]
            if self.debug:
                print(f"    [DEBUG] Found interface by CIDR: {result}")
            return result
        
        if self.debug:
            print(f"    [DEBUG] No interface found, trying address objects...")
        
        # FALLBACK: Try legacy address object lookup
        if gateway_cidr in self.ip_to_name: # pyright: ignore[reportAttributeAccessIssue]
            result = self.ip_to_name[gateway_cidr] # pyright: ignore[reportAttributeAccessIssue]
            if self.debug:
                print(f"    [DEBUG] Found address object by CIDR: {result}")
            return result
        
        if gateway_ip in self.ip_to_name: # pyright: ignore[reportAttributeAccessIssue]
            result = self.ip_to_name[gateway_ip] # pyright: ignore[reportAttributeAccessIssue]
            if self.debug:
                print(f"    [DEBUG] Found address object by IP: {result}")
            return result
        
        # No match found - generate a name and warn the user
        self.unmatched_count += 1
        generated_name = f"Gateway_{gateway_ip.replace('.', '_')}"
        print(f"    Warning: No interface or address object found for gateway {gateway_ip}, using generated name: {generated_name}")
        
        return generated_name
    
    def get_statistics(self) -> Dict[str, int]:
        """
        Get conversion statistics for reporting.
        
        Returns:
            Dictionary with counts of converted, blackhole, and skipped routes
        """
        return {
            "total_routes": len(self.ftd_static_routes),
            "converted": self.converted_count,
            "blackhole_skipped": self.blackhole_count,
            "other_skipped": self.skipped_count,
            "unmatched_objects": self.unmatched_count
        }
    

    def get_missing_network_objects(self) -> List[Dict]:
        """
        Get list of network objects that need to be created for routes.
        
        Returns:
            List of network object dictionaries that should be created
        """
        return self.missing_network_objects


# =============================================================================
# TESTING CODE (for standalone testing of this module)
# =============================================================================

if __name__ == '__main__':
    """
    This code only runs when you execute this file directly.
    It's useful for testing the converter without running the main script.
    
    To test this module standalone:
        python route_converter.py
    """
    
    # Sample FortiGate configuration for testing
    test_config = {
        'router_static': [
            {
                64: {
                    'dst': ['10.0.20.0', '255.255.255.0'],
                    'gateway': '10.0.222.18',
                    'distance': 1,
                    'device': 'port2',
                    'comment': 'P5 Bear'
                }
            },
            {
                88: {
                    'dst': ['10.0.0.0', '255.252.0.0'],
                    'blackhole': 'enable',
                    'vrf': 0
                }
            },
            {
                118: {
                    'dst': ['10.0.22.0', '255.255.255.0'],
                    'gateway': '15.0.2.130',
                    'device': '20_Bull'
                }
            },
            {
                122: {
                    'dst': ['10.0.0.0', '255.0.0.0'],
                    'blackhole': 'enable',
                    'vrf': 0
                }
            }
        ]
    }
    
    # Create converter instance
    converter = RouteConverter(test_config)
    
    # Run conversion
    print("Testing Route Converter...")
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