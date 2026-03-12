#!/usr/bin/env python3
"""
Cisco FTD FDM API Importer
===========================
This script imports converted FortiGate configurations into Cisco FTD
using the Firewall Device Manager (FDM) API.

REQUIREMENTS:
    - Python 3.6 or higher
    - requests library (install with: pip install requests)
    - urllib3 library (install with: pip install urllib3)

SUPPORTED FTD VERSIONS:
    - FTD 7.4.x with FDM (tested on 7.4.2.4-9)
    - Local management via FDM

WHAT THIS SCRIPT DOES:
    1. Authenticates to FTD FDM API
    2. Imports address objects
    3. Imports address groups
    4. Imports port objects
    5. Imports port groups
    6. Imports static routes
    7. Imports access rules
    8. Deploys the configuration changes
    9. Provides detailed progress and error reporting

HOW TO RUN:
    python ftd_api_importer.py --host 192.168.1.1 --username admin --password YourPassword

IMPORTANT NOTES:
    - SSL certificate verification is disabled by default (self-signed certs)
    - Always test on a non-production firewall first
    - Back up your FTD configuration before running
    - The script uses the /api/fdm/latest/ endpoint
    - Objects are imported in the correct dependency order
"""

import argparse
import getpass
import json
import sys
import threading
import time

import requests
import urllib3

try:
    from .concurrency_utils import is_transient_error, run_thread_pool, run_with_retry
except ImportError:
    from concurrency_utils import is_transient_error, run_thread_pool, run_with_retry


# Disable SSL warnings for self-signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


MAX_IMPORT_WORKERS = 32
DEFAULT_STAGE_WORKERS = {
    "address_objects": 6,
    "service_objects": 6,
    "subinterfaces": 4,
}
DEFAULT_STAGE_RETRY_ATTEMPTS = {
    "address_objects": 4,
    "service_objects": 4,
    "subinterfaces": 6,
}
DEFAULT_STAGE_RETRY_BACKOFF = {
    "address_objects": 0.3,
    "service_objects": 0.3,
    "subinterfaces": 0.75,
}
DEFAULT_RETRY_JITTER_MAX = 0.25


def _bounded_workers(value: int | None, stage: str) -> int:
    requested = value if value is not None else DEFAULT_STAGE_WORKERS.get(stage, 1)
    workers = max(1, int(requested))
    if workers > MAX_IMPORT_WORKERS:
        print(f"[WARN] Capping {stage} workers from {workers} to {MAX_IMPORT_WORKERS}")
        return MAX_IMPORT_WORKERS
    return workers


def _resolve_stage_attempts(stage: str, stage_value: int | None, global_value: int | None) -> int:
    if stage_value is not None:
        return max(1, int(stage_value))
    if global_value is not None:
        return max(1, int(global_value))
    return DEFAULT_STAGE_RETRY_ATTEMPTS.get(stage, 3)


def _resolve_stage_backoff(stage: str, stage_value: float | None, global_value: float | None) -> float:
    if stage_value is not None:
        return max(0.0, float(stage_value))
    if global_value is not None:
        return max(0.0, float(global_value))
    return DEFAULT_STAGE_RETRY_BACKOFF.get(stage, 0.3)


class FTDAPIClient:
    """
    Client for interacting with Cisco FTD Firewall Device Manager (FDM) API.
    
    This class handles:
    - Authentication and token management
    - CRUD operations for network objects, services, routes, and policies
    - Deployment of configuration changes
    - Error handling and retry logic
    """
    
    def __init__(self, host: str, username: str, password: str, verify_ssl: bool = False):
        """
        Initialize the FTD API client.
        
        Args:
            host: FTD management IP address or hostname
            username: FDM username (typically 'admin')
            password: FDM password
            verify_ssl: Whether to verify SSL certificates (False for self-signed)
            debug: Enable debug output
        """
        self.host = host
        self.username = username
        self.password = password
        self.verify_ssl = verify_ssl
        self.debug = False  # Will be set by caller if needed
        self._stats_lock = threading.Lock()
        
        # Base URL for FDM API
        self.base_url = f"https://{host}/api/fdm/latest"
        
        # Session for maintaining connection
        self.session = requests.Session()
        self.session.verify = verify_ssl
        
        # Authentication token (obtained after login)
        self.access_token = None
        self.refresh_token = None
        
        # =================================================================
        # REFERENCE CACHES - Prefetch and cache name->id mappings
        # =================================================================
        # These caches store FTD object references to avoid repeated API calls
        # Format: hardware_name -> {id, type, name, .full object}
        self._physical_interface_cache = {}      # Ethernet1/1 -> {id: xxx, .}
        self._etherchannel_cache = {}            # Port-channel1 -> {id: xxx, .}
        self._bridge_group_cache = {}            # BVI/BridgeGroup name -> {id: xxx, .}  (NO hardwareName)
        self._missing_physical_interface_cache = set()  # parent hardware names not found
        self._missing_etherchannel_cache = set()        # parent hardware names not found
        self._security_zone_cache = {}           # zone_name -> {id: xxx, .}
        self._network_object_cache = {}          # object_name -> {id: xxx, .}
        self._caches_populated = False

        
        # Track statistics
        self.stats = {
            "address_objects_created": 0,
            "address_objects_failed": 0,
            "address_objects_skipped": 0,
            "address_groups_created": 0,
            "address_groups_failed": 0,
            "address_groups_skipped": 0,
            "port_objects_created": 0,
            "port_objects_failed": 0,
            "port_objects_skipped": 0,
            "port_groups_created": 0,
            "port_groups_failed": 0,
            "port_groups_skipped": 0,
            "security_zones_created": 0,
            "security_zones_failed": 0,
            "security_zones_skipped": 0,
            "routes_created": 0,
            "routes_failed": 0,
            "routes_skipped": 0,
            "rules_created": 0,
            "rules_failed": 0,
            "rules_skipped": 0,
            "physical_interfaces_updated": 0,
            "physical_interfaces_failed": 0,
            "physical_interfaces_skipped": 0,
            "subinterfaces_created": 0,
            "subinterfaces_failed": 0,
            "subinterfaces_skipped": 0,
            "etherchannels_created": 0,
            "etherchannels_failed": 0,
            "etherchannels_skipped": 0,
            "bridge_groups_created": 0,
            "bridge_groups_failed": 0,
            "bridge_groups_skipped": 0
        }

    def record_stat(self, key: str) -> None:
        """Thread-safe increment for statistics counters."""
        with self._stats_lock:
            self.stats[key] += 1
    
    # =========================================================================
    # REFERENCE CACHING METHODS
    # =========================================================================

    def _fetch_paginated_items(self, endpoint: str, limit: int = 200, timeout: int = 30) -> list[dict]:
        """Fetch all paginated items from an FDM endpoint."""
        items: list[dict] = []
        offset = 0

        while True:
            response = self.session.get(
                endpoint,
                params={"offset": offset, "limit": limit},
                timeout=timeout,
            )
            if response.status_code != 200:
                print(f"    Warning: Failed to fetch {endpoint} (HTTP {response.status_code})")
                break

            data = response.json()
            page_items = data.get("items", [])
            if not page_items:
                break

            items.extend(page_items)
            paging = data.get("paging", {})
            if not paging.get("next"):
                break

            offset += limit

        return items
    
    def prefetch_interface_cache(self, force_refresh: bool = False):
        """
        Prefetch and cache all physical interfaces and etherchannels.
        
        This should be called ONCE before importing subinterfaces to avoid
        repeated API calls for parent interface lookups.
        """
        if self._caches_populated and not force_refresh:
            return

        if force_refresh:
            self._physical_interface_cache.clear()
            self._etherchannel_cache.clear()
            self._bridge_group_cache.clear()
            self._missing_physical_interface_cache.clear()
            self._missing_etherchannel_cache.clear()
        
        print("  Prefetching interface references...")
        
        # Fetch all physical interfaces
        endpoint = f"{self.base_url}/devices/default/interfaces"
        try:
            interfaces = self._fetch_paginated_items(endpoint, limit=200, timeout=30)
            for intf in interfaces:
                hardware_name = intf.get('hardwareName', '')
                if hardware_name:
                    self._physical_interface_cache[hardware_name] = intf
            print(f"    Cached {len(self._physical_interface_cache)} physical interfaces")
        except Exception as e:
            print(f"    Warning: Failed to cache physical interfaces: {e}")
        
        # Fetch all etherchannels
        endpoint = f"{self.base_url}/devices/default/etherchannelinterfaces"
        try:
            etherchannels = self._fetch_paginated_items(endpoint, limit=200, timeout=30)
            for ec in etherchannels:
                hardware_name = ec.get('hardwareName', '')
                if hardware_name:
                    self._etherchannel_cache[hardware_name] = ec
            print(f"    Cached {len(self._etherchannel_cache)} etherchannels")
        except Exception as e:
            print(f"    Warning: Failed to cache etherchannels: {e}")

        # Fetch all bridge-group interfaces (these often do NOT have hardwareName)
        endpoint = f"{self.base_url}/devices/default/bridgegroupinterfaces"
        try:
            bgs = self._fetch_paginated_items(endpoint, limit=200, timeout=30)
            for bg in bgs:
                bg_name = (bg.get("name") or "").strip()
                if bg_name:
                    self._bridge_group_cache[bg_name] = bg
            print(f"    Cached {len(self._bridge_group_cache)} bridge groups")
        except Exception as e:
            print(f"    Warning: Failed to cache bridge groups: {e}")

        self._caches_populated = True


    def prefetch_network_object_cache(self):
        """
        Prefetch and cache all network objects.
        
        This should be called ONCE before importing routes to avoid
        repeated API calls for network object lookups. Handles pagination
        to fetch all objects regardless of count.
        """
        if self._network_object_cache:
            # Already populated
            return
        
        print("  Prefetching network object references...")
        
        endpoint = f"{self.base_url}/object/networks"
        offset = 0
        limit = 200  # Fetch 200 at a time
        total_fetched = 0
        
        try:
            while True:
                params = {
                    "offset": offset,
                    "limit": limit
                }
                response = self.session.get(endpoint, params=params, timeout=60)
                
                if response.status_code != 200:
                    print(f"    Warning: Failed to fetch network objects (HTTP {response.status_code})")
                    break
                
                data = response.json()
                items = data.get("items", [])
                
                # Cache each object by name
                for obj in items:
                    obj_name = obj.get('name', '')
                    if obj_name:
                        self._network_object_cache[obj_name] = obj
                
                total_fetched += len(items)
                
                # Check if there are more pages
                paging = data.get('paging', {})
                total_count = paging.get('count', total_fetched)
                
                # If we've fetched all items or this page was empty, stop
                if len(items) == 0 or total_fetched >= total_count:
                    break
                
                # Move to next page
                offset += limit
            
            print(f"    Cached {len(self._network_object_cache)} network objects")
            
        except Exception as e:
            print(f"    Warning: Failed to cache network objects: {e}")
    
    def get_cached_physical_interface(self, hardware_name: str) -> tuple[bool, dict | None]:
        """
        Get a physical interface from cache (or fetch if not cached).
        
        Args:
            hardware_name: FTD hardware name (e.g., 'Ethernet1/1')
            
        Returns:
            Tuple of (found: bool, interface_dict or error_message)
        """
        # Check cache first
        if hardware_name in self._physical_interface_cache:
            return True, self._physical_interface_cache[hardware_name]

        # Negative cache to avoid repeated full scans for missing parents.
        if hardware_name in self._missing_physical_interface_cache:
            return False, f"Interface {hardware_name} not found"  # pyright: ignore[reportReturnType]
        
        # Not in cache - do a direct lookup and cache it
        success, result = self.get_physical_interface(hardware_name)
        if success and isinstance(result, dict):
            self._physical_interface_cache[hardware_name] = result
            self._missing_physical_interface_cache.discard(hardware_name)
        else:
            self._missing_physical_interface_cache.add(hardware_name)
        return success, result
    
    def get_cached_etherchannel(self, hardware_name: str) -> tuple[bool, dict | None]:
        """
        Get an etherchannel from cache (or fetch if not cached).
        
        Args:
            hardware_name: FTD hardware name (e.g., 'Port-channel1')
            
        Returns:
            Tuple of (found: bool, etherchannel_dict or error_message)
        """
        # Check cache first
        if hardware_name in self._etherchannel_cache:
            return True, self._etherchannel_cache[hardware_name]

        # Negative cache to avoid repeated full scans for missing parents.
        if hardware_name in self._missing_etherchannel_cache:
            return False, f"EtherChannel {hardware_name} not found"  # pyright: ignore[reportReturnType]
        
        # Not in cache - do a direct lookup and cache it
        success, result = self._get_etherchannel_by_hardware(hardware_name)
        if success and isinstance(result, dict):
            self._etherchannel_cache[hardware_name] = result
            self._missing_etherchannel_cache.discard(hardware_name)
        else:
            self._missing_etherchannel_cache.add(hardware_name)
        return success, result
    
    def populate_physical_interface_cache(self):
        """
        Fetch all existing physical interfaces and cache them by hardwareName for quick lookup.
        Caching behavior:
        - Only caches objects where type == 'physicalinterface'
        - Keyed by hardwareName (e.g., 'Ethernet1/1')
        - Overwrites any prior cache contents

        Returns:
            None
        """
        print("  Fetching existing physical interfaces from FTD for update detection...")
        endpoint = f"{self.base_url}/devices/default/interfaces"

        self._physical_interface_cache.clear()

        offset = 0
        limit = 200  # higher limit = fewer round-trips; safe for typical interface counts

        try:
            while True:
                params = {"offset": offset, "limit": limit}
                response = self.session.get(endpoint, params=params, timeout=30)

                if response.status_code != 200:
                    print(f"[WARN] Could not fetch interfaces list: {response.status_code}")
                    print(f"       {response.text}")
                    return

                data = response.json()
                items = data.get("items", [])
                if not items:
                    break

                for intf in items:
                    # Only keep physical interfaces in this cache
                    if intf.get("type") != "physicalinterface":
                        continue

                    hw = intf.get("hardwareName")
                    if hw:
                        self._physical_interface_cache[hw] = intf

                paging = data.get("paging", {})
                if not paging.get("next"):
                    break

                offset += limit

            print(f"    Cached {len(self._physical_interface_cache)} existing physical interfaces")
        except Exception as e:
            print(f"[WARN] Exception while fetching physical interfaces: {e}")
    
    def clear_caches(self):
        """Clear all reference caches."""
        self._physical_interface_cache.clear()
        self._etherchannel_cache.clear()
        self._missing_physical_interface_cache.clear()
        self._missing_etherchannel_cache.clear()
        self._security_zone_cache.clear()
        self._network_object_cache.clear()
        self._caches_populated = False
    
    def authenticate(self) -> bool:
        """
        Authenticate to the FTD FDM API and obtain access tokens.
        
        The FDM API uses OAuth 2.0 token-based authentication.
        After successful authentication, tokens are stored for subsequent requests.
        
        Returns:
            True if authentication successful, False otherwise
        """
        print(f"\n{'='*60}")
        print(f"Authenticating to FTD at {self.host}")
        print(f"{'='*60}")
        
        # Authentication endpoint
        auth_url = f"{self.base_url}/fdm/token"
        
        # OAuth 2.0 grant type for password-based authentication
        payload = {
            "grant_type": "password",
            "username": self.username,
            "password": self.password
        }
        
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json"
        }
        
        try:
            response = self.session.post(
                auth_url,
                json=payload,
                headers=headers,
                timeout=30
            )
            
            if response.status_code == 200:
                tokens = response.json()
                self.access_token = tokens.get("access_token")
                self.refresh_token = tokens.get("refresh_token")
                
                # Set the authorization header for all future requests
                self.session.headers.update({
                    "Authorization": f"Bearer {self.access_token}",
                    "Content-Type": "application/json",
                    "Accept": "application/json"
                })
                
                print("Authentication successful")
                return True
            else:
                print(f"FAIL Authentication failed: {response.status_code}")
                print(f"  Response: {response.text}")
                return False
                
        except requests.exceptions.RequestException as e:
            print(f"FAIL Connection error: {e}")
            return False
    
    def create_network_object(self, obj: dict, track_stats: bool = True) -> tuple[bool, str | None]:
        """
        Create a network object (address object) in FTD.
        
        Args:
            obj: Dictionary containing network object data
            
        Returns:
            Tuple of (success: bool, object_id: str or error message)
        """
        endpoint = f"{self.base_url}/object/networks"
        
        try:
            response = self.session.post(endpoint, json=obj, timeout=30)
            
            if response.status_code in [200, 201]:
                created_obj = response.json()
                if track_stats:
                    self.record_stat("address_objects_created")
                return True, created_obj.get("id")
            elif response.status_code == 422:
                # 422 Unprocessable Entity - usually means object already exists
                error_data = response.json()
                error_msg = error_data.get('error', {}).get('messages', [{}])[0].get('description', 'Unknown error')
                
                # Check if it's a duplicate/already exists error
                if 'already exists' in error_msg.lower() or 'duplicate' in error_msg.lower():
                    if track_stats:
                        self.record_stat("address_objects_skipped")
                    return True, f"SKIPPED: {error_msg}"  # Return True to indicate it's not a failure
                else:
                    if track_stats:
                        self.record_stat("address_objects_failed")
                    return False, error_msg
            else:
                if track_stats:
                    self.record_stat("address_objects_failed")
                error_msg = response.text
                return False, error_msg
                
        except requests.exceptions.RequestException as e:
            if track_stats:
                self.record_stat("address_objects_failed")
            return False, str(e)
    
    def create_network_group(self, group: dict, track_stats: bool = True) -> tuple[bool, str | None]:
        """
        Create a network object group (address group) in FTD.
        
        Args:
            group: Dictionary containing network group data
            
        Returns:
            Tuple of (success: bool, object_id: str or error message)
        """
        endpoint = f"{self.base_url}/object/networkgroups"
        
        try:
            response = self.session.post(endpoint, json=group, timeout=30)
            
            if response.status_code in [200, 201]:
                created_obj = response.json()
                if track_stats:
                    self.record_stat("address_groups_created")
                return True, created_obj.get("id")
            elif response.status_code == 422:
                error_data = response.json()
                error_msg = error_data.get('error', {}).get('messages', [{}])[0].get('description', 'Unknown error')
                
                if 'already exists' in error_msg.lower() or 'duplicate' in error_msg.lower():
                    if track_stats:
                        self.record_stat("address_groups_skipped")
                    return True, f"SKIPPED: {error_msg}"
                else:
                    if track_stats:
                        self.record_stat("address_groups_failed")
                    return False, error_msg
            else:
                if track_stats:
                    self.record_stat("address_groups_failed")
                error_msg = response.text
                return False, error_msg
                
        except requests.exceptions.RequestException as e:
            if track_stats:
                self.record_stat("address_groups_failed")
            return False, str(e)
    
    def create_port_object(self, obj: dict, track_stats: bool = True) -> tuple[bool, str | None]:
        """
        Create a port object (service object) in FTD.
        
        Args:
            obj: Dictionary containing port object data
            
        Returns:
            Tuple of (success: bool, object_id: str or error message)
        """
        # Determine the correct endpoint based on protocol type
        obj_type = obj.get("type", "tcpportobject")
        
        if obj_type == "tcpportobject":
            endpoint = f"{self.base_url}/object/tcpports"
        elif obj_type == "udpportobject":
            endpoint = f"{self.base_url}/object/udpports"
        else:
            self.stats["port_objects_failed"] += 1
            return False, f"Unknown port type: {obj_type}"
        
        try:
            response = self.session.post(endpoint, json=obj, timeout=30)
            
            if response.status_code in [200, 201]:
                created_obj = response.json()
                if track_stats:
                    self.record_stat("port_objects_created")
                return True, created_obj.get("id")
            elif response.status_code == 422:
                error_data = response.json()
                error_msg = error_data.get('error', {}).get('messages', [{}])[0].get('description', 'Unknown error')
                
                if 'already exists' in error_msg.lower() or 'duplicate' in error_msg.lower():
                    if track_stats:
                        self.record_stat("port_objects_skipped")
                    return True, f"SKIPPED: {error_msg}"
                else:
                    if track_stats:
                        self.record_stat("port_objects_failed")
                    return False, error_msg
            else:
                if track_stats:
                    self.record_stat("port_objects_failed")
                error_msg = response.text
                return False, error_msg
                
        except requests.exceptions.RequestException as e:
            if track_stats:
                self.record_stat("port_objects_failed")
            return False, str(e)
    
    def create_port_group(self, group: dict, track_stats: bool = True) -> tuple[bool, str | None]:
        """
        Create a port object group (service group) in FTD.
        
        Args:
            group: Dictionary containing port group data
            
        Returns:
            Tuple of (success: bool, object_id: str or error message)
        """
        endpoint = f"{self.base_url}/object/portgroups"
        
        try:
            response = self.session.post(endpoint, json=group, timeout=30)
            
            if response.status_code in [200, 201]:
                created_obj = response.json()
                if track_stats:
                    self.record_stat("port_groups_created")
                return True, created_obj.get("id")
            elif response.status_code == 422:
                error_data = response.json()
                error_msg = error_data.get('error', {}).get('messages', [{}])[0].get('description', 'Unknown error')
                
                if 'already exists' in error_msg.lower() or 'duplicate' in error_msg.lower():
                    if track_stats:
                        self.record_stat("port_groups_skipped")
                    return True, f"SKIPPED: {error_msg}"
                else:
                    if track_stats:
                        self.record_stat("port_groups_failed")
                    return False, error_msg
            else:
                if track_stats:
                    self.record_stat("port_groups_failed")
                error_msg = response.text
                return False, error_msg
                
        except requests.exceptions.RequestException as e:
            if track_stats:
                self.record_stat("port_groups_failed")
            return False, str(e)
        
    def resolve_route_references(self, route: dict) -> tuple[bool, dict]:
        """
        Resolve all object references in a route to include IDs and versions.
        
        Routes reference network objects, interfaces, etc. by name, but the API
        requires full object references with id and version fields.
        
        Args:
            route: Route dictionary with minimal object references
            
        Returns:
            Tuple of (success: bool, resolved route dict or error message)
        """
        resolved_route = route.copy()
        
        # Resolve interface reference
        if "iface" in route and isinstance(route["iface"], dict):
            iface_ref = route["iface"]
            hardware_name = iface_ref.get("hardwareName")
            iface_name = iface_ref.get("name")
            iface_type = iface_ref.get("type")

            intf_obj = None

            if hardware_name:
                # Look up interface by hardware name (fast path)
                success, intf_obj = self.get_interface_by_hardware_name(hardware_name)
                if not (success and intf_obj):
                    return False, f"Could not resolve interface by hardwareName: {hardware_name}"  # pyright: ignore[reportReturnType]
            else:
                # Fallback: resolve by logical name (needed for bridgegroupinterface, etc.)
                success, intf_obj = self.get_interface_by_name(str(iface_name or ""), iface_type=str(iface_type or ""))
                if not (success and intf_obj):
                    return False, f"Could not resolve interface by name: {iface_name}"  # pyright: ignore[reportReturnType]

            # Hard validation: if id is missing, FDM will throw "UUID null"
            intf_id = intf_obj.get("id")
            if not intf_id:
                return False, f"Resolved interface has no id (would become UUID null): {intf_obj.get('name')}"  # pyright: ignore[reportReturnType]

            # Use minimal reference with id and version
            resolved_route["iface"] = {
                "version": intf_obj.get("version"),
                "name": intf_obj.get("name"),
                "hardwareName": intf_obj.get("hardwareName"),
                "id": intf_id,
                "type": intf_obj.get("type"),
            }

        
        # Resolve network object references in networks array
        if 'networks' in route:
            resolved_networks = []
            for net_ref in route['networks']:
                net_name = net_ref.get('name')
                
                # Special case: any-ipv4 is a built-in object
                if net_name == 'any-ipv4':
                    success, net_obj = self.get_network_object_by_name('any-ipv4')
                    if success and net_obj:
                        resolved_networks.append({
                            "version": net_obj.get('version'),
                            "name": net_obj.get('name'),
                            "id": net_obj.get('id'),
                            "type": "networkobject"
                        })
                    else:
                        return False, "Could not resolve built-in object: any-ipv4" # pyright: ignore[reportReturnType]
                else:
                    success, net_obj = self.get_network_object_by_name(net_name)
                    if success and net_obj:
                        resolved_networks.append({
                            "version": net_obj.get('version'),
                            "name": net_obj.get('name'),
                            "id": net_obj.get('id'),
                            "type": "networkobject"
                        })
                    else:
                        return False, f"Could not resolve network object: {net_name}" # pyright: ignore[reportReturnType]
            
            resolved_route['networks'] = resolved_networks
        
        # Resolve gateway network object reference
        if 'gateway' in route:
            gw_ref = route['gateway']
            gw_name = gw_ref.get('name')
            
            success, gw_obj = self.get_network_object_by_name(gw_name)
            if success and gw_obj:
                resolved_route['gateway'] = {
                    "version": gw_obj.get('version'),
                    "name": gw_obj.get('name'),
                    "id": gw_obj.get('id'),
                    "type": "networkobject"
                }
            else:
                return False, f"Could not resolve gateway object: {gw_name}" # pyright: ignore[reportReturnType]
        
        return True, resolved_route
    
    def get_default_virtual_router_id(self) -> tuple[bool, str | None]:
        """Get the ID of the default virtual router (Global)."""
        if hasattr(self, '_default_vr_id') and self._default_vr_id:
            return True, self._default_vr_id
        
        endpoint = f"{self.base_url}/devices/default/routing/virtualrouters"
        
        try:
            response = self.session.get(endpoint, timeout=30)
            if response.status_code == 200:
                data = response.json()
                items = data.get('items', [])
                
                for vr in items:
                    vr_name = vr.get('name', '').lower()
                    if vr_name in ['global', 'default', 'global-vr']:
                        self._default_vr_id = vr.get('id')
                        return True, self._default_vr_id
                
                if items:
                    self._default_vr_id = items[0].get('id')
                    return True, self._default_vr_id
                
                return False, "No virtual routers found"
            else:
                return False, f"API error: {response.status_code}"
        except Exception as e:
            return False, str(e)

    def create_static_route(self, route: dict) -> tuple[bool, str | None]:
        """
        Create a static route in FTD.
        
        Args:
            route: Dictionary containing static route data (with minimal object references)
            
        Returns:
            Tuple of (success: bool, object_id: str or error message)
        """
        success, vr_id = self.get_default_virtual_router_id()
        if not success:
            self.stats["routes_failed"] += 1
            return False, f"Failed to get virtual router ID: {vr_id}"
        # Resolve all object references to include IDs and versions
        success, resolved_route = self.resolve_route_references(route)
        if not success:
            self.stats["routes_failed"] += 1
            return False, f"Failed to resolve references: {resolved_route}"
        
        endpoint = f"{self.base_url}/devices/default/routing/virtualrouters/{vr_id}/staticrouteentries"
        
        try:
            response = self.session.post(endpoint, json=resolved_route, timeout=30)
            
            if response.status_code in [200, 201]:
                created_obj = response.json()
                self.stats["routes_created"] += 1
                return True, created_obj.get("id")
            elif response.status_code == 422:
                error_data = response.json()
                error_msg = error_data.get('error', {}).get('messages', [{}])[0].get('description', 'Unknown error')
                
                if 'already exists' in error_msg.lower() or 'duplicate' in error_msg.lower():
                    self.stats["routes_skipped"] += 1
                    return True, f"SKIPPED: {error_msg}"
                else:
                    self.stats["routes_failed"] += 1
                    return False, error_msg
            else:
                self.stats["routes_failed"] += 1
                error_msg = response.text
                return False, error_msg
                
        except requests.exceptions.RequestException as e:
            self.stats["routes_failed"] += 1
            return False, str(e)
    
    def create_access_rule(self, rule: dict) -> tuple[bool, str | None]:
        """
        Create an access rule (firewall policy) in FTD.
        
        Args:
            rule: Dictionary containing access rule data
            
        Returns:
            Tuple of (success: bool, object_id: str or error message)
        """
        endpoint = f"{self.base_url}/policy/accesspolicies/default/accessrules"
        
        try:
            response = self.session.post(endpoint, json=rule, timeout=30)
            
            if response.status_code in [200, 201]:
                created_obj = response.json()
                self.stats["rules_created"] += 1
                return True, created_obj.get("id")
            elif response.status_code == 422:
                error_data = response.json()
                error_msg = error_data.get('error', {}).get('messages', [{}])[0].get('description', 'Unknown error')
                
                if 'already exists' in error_msg.lower() or 'duplicate' in error_msg.lower():
                    self.stats["rules_skipped"] += 1
                    return True, f"SKIPPED: {error_msg}"
                else:
                    self.stats["rules_failed"] += 1
                    return False, error_msg
            else:
                self.stats["rules_failed"] += 1
                error_msg = response.text
                return False, error_msg
                
        except requests.exceptions.RequestException as e:
            self.stats["rules_failed"] += 1
            return False, str(e)
    
    def get_interface_by_name(self, name: str, iface_type: str | None = None) -> tuple[bool, dict | None]:
        """
        Resolve an interface by *logical name* when hardwareName is not available.

        This is primarily needed for interface types like bridgegroupinterface, where FDM objects
        may not include a hardwareName, but routes still require a valid interface UUID (id).

        Args:
            name: Interface logical name (e.g., "Bull_uplink", "BVI10", etc.)
            iface_type: Optional expected interface type (e.g., "bridgegroupinterface")

        Returns:
            Tuple of (success: bool, interface dict or error message)
        """
        search = (name or "").strip()
        if not search:
            return False, "Empty interface name"  # pyright: ignore[reportReturnType]

        # Ensure caches are populated
        self.prefetch_interface_cache()

        # 1) If explicitly bridge-group, check bridge-group cache first
        if iface_type == "bridgegroupinterface":
            bg = self._bridge_group_cache.get(search)
            if bg:
                return True, bg
            return False, f"Bridge-group interface {search} not found"  # pyright: ignore[reportReturnType]

        # 2) Check physical/etherchannel caches by *name* (not hardwareName)
        for d in (self._physical_interface_cache, self._etherchannel_cache):
            for obj in d.values():
                if (obj.get("name") or "").strip() == search:
                    return True, obj

        # 3) Check bridge-group cache by name as a fallback
        bg = self._bridge_group_cache.get(search)
        if bg:
            return True, bg

        return False, f"Interface {search} not found"  # pyright: ignore[reportReturnType]


    def get_physical_interface(self, hardware_name: str) -> tuple[bool, dict | None]:
        """
        Get a physical interface by hardware name to retrieve its ID.
        
        Args:
            hardware_name: Hardware name (e.g., 'Ethernet1/1')
            
        Returns:
            Tuple of (success: bool, interface dict or error message)
        """
        endpoint = f"{self.base_url}/devices/default/interfaces"
        
        # Normalize the hardware name for comparison (case-insensitive)
        search_name = hardware_name.lower().strip()
        
        try:
            # Use pagination to get all interfaces
            all_interfaces = []
            offset = 0
            limit = 100
            
            while True:
                params = {"offset": offset, "limit": limit}
                response = self.session.get(endpoint, params=params, timeout=30)
                
                if response.status_code == 200:
                    data = response.json()
                    interfaces = data.get('items', [])
                    
                    if not interfaces:
                        break
                    
                    all_interfaces.extend(interfaces)
                    
                    # Check pagination
                    paging = data.get('paging', {})
                    if not paging.get('next'):
                        break
                    
                    offset += limit
                else:
                    return False, f"HTTP {response.status_code}: {response.text}" # pyright: ignore[reportReturnType]
            
            # Search for the interface (case-insensitive)
            for intf in all_interfaces:
                intf_hardware = intf.get('hardwareName', '').lower().strip()
                if intf_hardware == search_name:
                    return True, intf
            
            # Interface not found - this might be because it's disabled/unconfigured
            return False, f"Interface {hardware_name} not found (may be disabled or not present on this device)" # pyright: ignore[reportReturnType]
                
        except requests.exceptions.RequestException as e:
            return False, str(e) # pyright: ignore[reportReturnType]
        
    def get_interface_by_hardware_name(self, hardware_name: str) -> tuple[bool, dict | None]:
        """
        Get any interface (physical, subinterface, etherchannel, bridge group) by hardware name.
        
        Args:
            hardware_name: Hardware name (e.g., 'Ethernet1/1', 'Port-channel1.100')
            
        Returns:
            Tuple of (success: bool, interface dict or error message)
        """
        # Try physical interfaces cache first
        if hardware_name in self._physical_interface_cache:
            return True, self._physical_interface_cache[hardware_name]
        
        # Try etherchannel cache
        if hardware_name in self._etherchannel_cache:
            return True, self._etherchannel_cache[hardware_name]
        
        # Check if this looks like a subinterface (contains a dot like "Port-channel1.108")
        is_subinterface = '.' in hardware_name
        
        # Try all physical interfaces endpoint first
        endpoint = f"{self.base_url}/devices/default/interfaces"
        
        try:
            response = self.session.get(endpoint, params={"limit": 200}, timeout=30)
            if response.status_code == 200:
                data = response.json()
                items = data.get('items', [])
                
                for intf in items:
                    if intf.get('hardwareName') == hardware_name:
                        # Cache it for future lookups
                        self._physical_interface_cache[hardware_name] = intf
                        return True, intf
            
            # If it's a subinterface, search subinterfaces under physical interfaces
            if is_subinterface:
                # Extract parent hardware name (e.g., "Port-channel1" from "Port-channel1.108")
                parent_hw_name = hardware_name.split('.')[0]
                
                # First check if parent is an etherchannel
                ec_endpoint = f"{self.base_url}/devices/default/etherchannelinterfaces"
                response = self.session.get(ec_endpoint, params={"limit": 100}, timeout=30)
                if response.status_code == 200:
                    data = response.json()
                    etherchannels = data.get('items', [])
                    
                    for ec in etherchannels:
                        if ec.get('hardwareName') == parent_hw_name:
                            # Found parent etherchannel, now get its subinterfaces
                            parent_id = ec.get('id')
                            sub_endpoint = f"{self.base_url}/devices/default/etherchannelinterfaces/{parent_id}/subinterfaces"
                            sub_response = self.session.get(sub_endpoint, params={"limit": 100}, timeout=30)
                            
                            if sub_response.status_code == 200:
                                sub_data = sub_response.json()
                                subinterfaces = sub_data.get('items', [])
                                
                                for sub in subinterfaces:
                                    if sub.get('hardwareName') == hardware_name:
                                        return True, sub
                
                # Check if parent is a physical interface
                for intf in items:
                    if intf.get('hardwareName') == parent_hw_name:
                        # Found parent physical interface, now get its subinterfaces
                        parent_id = intf.get('id')
                        sub_endpoint = f"{self.base_url}/devices/default/interfaces/{parent_id}/subinterfaces"
                        sub_response = self.session.get(sub_endpoint, params={"limit": 100}, timeout=30)
                        
                        if sub_response.status_code == 200:
                            sub_data = sub_response.json()
                            subinterfaces = sub_data.get('items', [])
                            
                            for sub in subinterfaces:
                                if sub.get('hardwareName') == hardware_name:
                                    return True, sub
            
            # Also try etherchannels endpoint
            ec_endpoint = f"{self.base_url}/devices/default/etherchannelinterfaces"
            response = self.session.get(ec_endpoint, params={"limit": 100}, timeout=30)
            if response.status_code == 200:
                data = response.json()
                items = data.get('items', [])
                
                for intf in items:
                    if intf.get('hardwareName') == hardware_name:
                        self._etherchannel_cache[hardware_name] = intf
                        return True, intf
            
            return False, f"Interface not found: {hardware_name}"  # type: ignore
        except Exception as e:
            return False, str(e)  # type: ignore
    
    def _apply_model_specific_media_defaults(self, existing_intf: dict, update_payload: dict,) -> None:
        """
        Apply platform/model-specific media defaults for copper (non-SFP) interfaces.

        Why:
            Some platforms (notably 3100-series like FTD 3120) do not accept speedType='AUTO'
            on copper ports the same way smaller platforms (e.g., 1010) do. Instead they expect:
                - explicit speedType (HUNDRED/THOUSAND, etc.)
                - auto-negotiation enabled

        This helper makes the behavior deterministic and keeps the branching localized.

        Args:
            existing_intf: The current interface object fetched from FDM (source of truth)
            update_payload: The PUT payload being assembled (mutated in place)

        Returns:
            None
        """
        model = str(getattr(self, "appliance_model", "generic")).lower().strip()

        # Treat DETECT_SFP / SFP_DETECT as SFP - we don't override those here.
        speed = str(existing_intf.get("speedType", "")).upper()
        if speed in {"DETECT_SFP", "SFP_DETECT"}:
            return

        # Define platform families for model-specific behavior
        # 1000-series: Do NOT support autoNeg field (must be null/omitted)
        # 2000-series: Support AUTO speed, autoNeg may vary
        # 3100-series: Require explicit speed + autoNeg enabled
        ftd_1000_series = {"ftd-1010", "1010", "ftd1010", 
                          "ftd-1120", "1120", "ftd1120",
                          "ftd-1140", "1140", "ftd1140"}
        ftd_2000_series = {"ftd-2110", "2110", "ftd2110",
                          "ftd-2120", "2120", "ftd2120",
                          "ftd-2130", "2130", "ftd2130",
                          "ftd-2140", "2140", "ftd2140"}
        ftd_3100_series = {"ftd-3105", "3105", "ftd3105",
                          "ftd-3110", "3110", "ftd3110",
                          "ftd-3120", "3120", "ftd3120",
                          "ftd-3130", "3130", "ftd3130",
                          "ftd-3140", "3140", "ftd3140",
                          "ftd-4215", "4215", "ftd4215"}

        if model in ftd_1000_series:
            # 1000-series: autoNeg field must be null/omitted
            # Remove autoNeg fields if present (they cause API errors)
            update_payload.pop("autoNeg", None)
            update_payload.pop("autoNegotiation", None)
            # Use AUTO speed and duplex
            update_payload["speedType"] = "AUTO"
            update_payload["duplexType"] = "AUTO"
            
        elif model in ftd_3100_series:
            # 3100-series: Require explicit speed + autoNeg enabled
            update_payload["autoNegotiation"] = True
            update_payload["autoNeg"] = True
            # Keep existing explicit speed if present, otherwise default to THOUSAND
            explicit_ok = {"TEN", "HUNDRED", "THOUSAND", "TEN_THOUSAND"}
            if speed in explicit_ok:
                update_payload["speedType"] = speed
            else:
                update_payload["speedType"] = "THOUSAND"
            update_payload["duplexType"] = "AUTO"
            
        else:
            # Default behavior for 2000-series and unknown platforms
            # Use AUTO speed and duplex, set autoNeg if platform supports it
            update_payload["speedType"] = "AUTO"
            update_payload["duplexType"] = "AUTO"
            # Try setting autoNeg - some platforms may ignore it
            update_payload["autoNegotiation"] = True

    def update_physical_interface(self, intf: dict) -> tuple[bool, str | None]:
        """
        Update a physical interface in FTD (PUT request).
        
        Physical interfaces already exist in FTD - we update them with
        name, description, IP address, etc.
        
        IMPORTANT: This method handles:
        - Converting switchport mode to routed mode (required for L3 config)
        - Preserving existing hardware settings (speed, duplex, FEC, auto-negotiation)
        
        Args:
            intf: Dictionary containing physical interface data
            
        Returns:
            Tuple of (success: bool, object_id: str or error message)
        """
        hardware_name = intf.get('hardwareName')
        
        # First, get the existing interface to retrieve its ID and version
        success, existing = self.get_physical_interface(hardware_name) # pyright: ignore[reportArgumentType]
        if not success:
            # Interface not found - skip it instead of failing
            self.stats["physical_interfaces_skipped"] += 1
            return True, f"SKIPPED: {existing}"
        
        # Merge our updates with the existing interface
        intf_id = existing.get('id') # pyright: ignore[reportOptionalMemberAccess]
        intf_version = existing.get('version') # pyright: ignore[reportOptionalMemberAccess]
        intf_type = existing.get('type', 'physicalinterface') # pyright: ignore[reportOptionalMemberAccess]
        
        # Check if interface is in switchport mode
        current_mode = existing.get('mode', None) # pyright: ignore[reportOptionalMemberAccess]
        is_switchport = current_mode == 'SWITCHPORT' or existing.get('switchPortMode') is not None # pyright: ignore[reportOptionalMemberAccess]
        
        # If interface is a switchport and we want to configure it as routed,
        # we need to change it to routed mode first
        if is_switchport:
            if self.debug:
                print(f"\n      [DEBUG] Interface {hardware_name} switchport details:")
                print(f"              Mode: {current_mode}")
                print(f"              SwitchPortMode: {existing.get('switchPortMode')}") # type: ignore
                print(f"              Has VLAN config: {existing.get('vlanId') is not None}") # type: ignore
            
            print(f"\n      [INFO] {hardware_name} is in switchport mode, converting to routed mode...", end=" ")
            
            convert_success, convert_msg = self._convert_switchport_to_routed(existing) # pyright: ignore[reportArgumentType]
            if not convert_success:
                self.stats["physical_interfaces_failed"] += 1
                if self.debug:
                    print(f"\n      [DEBUG] Conversion failure details: {convert_msg}")
                return False, f"Failed to convert from switchport: {convert_msg}"
            
            print("[OK]")
            
            # Re-fetch the interface after mode change to get updated version
            success, existing = self.get_physical_interface(hardware_name) # pyright: ignore[reportArgumentType]
            if not success:
                self.stats["physical_interfaces_failed"] += 1
                return False, f"Failed to re-fetch interface after mode change: {existing}"
            
            intf_id = existing.get('id') # pyright: ignore[reportOptionalMemberAccess]
        
        # Start with the existing interface configuration
        # This preserves ALL existing settings including hardware config
        update_payload = existing.copy() # pyright: ignore[reportOptionalMemberAccess]
        
        # Only update the fields we want to change (logical config)
        # Name - only update if we have a name to set
        if intf.get('name'):
            update_payload['name'] = intf['name']
        
        # Description - only update if provided
        if 'description' in intf:
            update_payload['description'] = intf.get('description', '')
        
        # Enabled - only update if explicitly provided
        if 'enabled' in intf:
            update_payload['enabled'] = intf['enabled']
        
        # Update IPv4 if provided
        if 'ipv4' in intf and intf['ipv4'] is not None:
            update_payload['ipv4'] = intf['ipv4']
        
        # Update MTU if provided (cap at 9000 - FTD maximum for most interfaces)
        if 'mtu' in intf and intf['mtu'] is not None:
            mtu_value = intf['mtu']
            if mtu_value > 9000:
                mtu_value = 9000
            update_payload['mtu'] = mtu_value
        
        # Ensure mode is set to ROUTED for L3 interfaces
        # (This should already be set after conversion, but ensure it)
        if 'ipv4' in intf and intf['ipv4'] is not None:
            update_payload['mode'] = 'ROUTED'
        
        # Get current interface speed type to determine if SFP or copper
        current_speed = existing.get("speedType", "AUTO")  # pyright: ignore[reportOptionalMemberAccess]
        is_sfp_port = current_speed in {"DETECT_SFP", "SFP_DETECT"}
        
        # Get appliance model for platform-specific behavior
        model = str(getattr(self, "appliance_model", "generic")).lower().strip()
        ftd_1000_series = {"ftd-1010", "1010", "ftd1010", 
                          "ftd-1120", "1120", "ftd1120",
                          "ftd-1140", "1140", "ftd1140"}
        ftd_3100_series = {"ftd-3105", "3105", "ftd3105",
                          "ftd-3110", "3110", "ftd3110",
                          "ftd-3120", "3120", "ftd3120",
                          "ftd-3130", "3130", "ftd3130",
                          "ftd-3140", "3140", "ftd3140",
                          "ftd-4215", "4215", "ftd4215"}
        
        # Handle speed/duplex/autoNeg settings based on port type and platform
        # CRITICAL: SFP ports must preserve SFP_DETECT speed - never override!
        if is_sfp_port:
            # SFP interface - preserve existing speed, use FULL duplex
            update_payload["speedType"] = current_speed
            update_payload["duplexType"] = "FULL"
            if 'fecMode' in existing:  # pyright: ignore[reportOperatorIssue]
                update_payload["fecMode"] = "AUTO"
            # Only set autoNeg for platforms that support it
            if model not in ftd_1000_series:
                update_payload["autoNegotiation"] = True
                update_payload["autoNeg"] = True
            else:
                update_payload.pop("autoNeg", None)
                update_payload.pop("autoNegotiation", None)
        else:
            # Copper interface - apply platform-specific defaults
            # Only apply converter's duplex/autoNeg if NOT on a platform that needs special handling
            if model in ftd_3100_series:
                # 3100-series copper: preserve existing speed, use FULL duplex
                explicit_ok = {'TEN', 'HUNDRED', 'THOUSAND', 'TEN_THOUSAND'}
                if current_speed in explicit_ok:
                    update_payload['speedType'] = current_speed
                else:
                    update_payload['speedType'] = 'THOUSAND'
                update_payload['duplexType'] = 'FULL'
                update_payload['autoNegotiation'] = True
                update_payload['autoNeg'] = True
            elif model in ftd_1000_series:
                # 1000-series copper: AUTO speed, no autoNeg field
                update_payload['speedType'] = 'AUTO'
                update_payload['duplexType'] = 'AUTO'
                update_payload.pop("autoNeg", None)
                update_payload.pop("autoNegotiation", None)
            else:
                # Default/2000-series: use converter settings or AUTO
                if 'duplexType' in intf:
                    update_payload['duplexType'] = intf['duplexType']
                if 'autoNegotiation' in intf:
                    update_payload['autoNegotiation'] = intf['autoNegotiation']
        
        # If this is an EtherChannel member prep (name is empty string), 
        # ensure name is cleared
        if intf.get('name') == '':
            update_payload['name'] = ''

        # EtherChannel member prep: CTS/SGT must be disabled on members.
        disable_cts_sgt_settings(update_payload)

        
        # Remove switchport-specific fields if present (they're not valid in routed mode)
        switchport_fields = ['switchPortMode', 'switchPortConfig', 'nativeVlan', 
                            'allowedVlans', 'voiceVlan', 'spanningTreePortfast']
        for field in switchport_fields:
            update_payload.pop(field, None)
        
        endpoint = f"{self.base_url}/devices/default/interfaces/{intf_id}"
        
        try:
            response = self.session.put(endpoint, json=update_payload, timeout=30)
            
            if response.status_code in [200, 201]:
                updated_obj = response.json()
                self.stats["physical_interfaces_updated"] += 1
                return True, updated_obj.get("id")
            elif response.status_code == 422:
                error_data = response.json()
                error_msg = error_data.get('error', {}).get('messages', [{}])[0].get('description', 'Unknown error')
                self.stats["physical_interfaces_failed"] += 1
                return False, error_msg
            else:
                self.stats["physical_interfaces_failed"] += 1
                error_msg = response.text
                return False, error_msg
                
        except requests.exceptions.RequestException as e:
            self.stats["physical_interfaces_failed"] += 1
            return False, str(e)
    
    def _convert_switchport_to_routed(self, intf: dict) -> tuple[bool, str]:
        """
        Convert a physical interface from switchport mode to routed mode.
        
        This is required before configuring L3 settings (IP address, etc.)
        on an interface that is in switchport mode by default.
        
        Args:
            intf: The existing interface configuration from FTD
            
        Returns:
            Tuple of (success: bool, error_message: str)
        """
        intf_id = intf.get('id')
        
        if not intf_id:
            return False, "Interface has no ID"
        
        # Build a minimal payload to change the mode
        # We need to preserve required fields but change mode to ROUTED
        convert_payload = intf.copy()
        
        # Set mode to ROUTED
        convert_payload['mode'] = 'ROUTED'
        
        # Remove ALL switchport-specific fields that conflict with ROUTED mode
        # This list must be comprehensive to avoid 422 validation errors
        switchport_fields = [
            'switchPortMode',       # Access/trunk mode
            'switchPortConfig',     # Switchport configuration object
            'nativeVlan',           # Native VLAN (trunk only)
            'allowedVlans',         # Allowed VLAN list
            'voiceVlan',            # Voice VLAN
            'spanningTreePortfast', # STP portfast
            'stpGuardType',         # STP guard (root/loop/bpdu)
            'stpPathCost',          # STP path cost
            'stpPortPriority',      # STP port priority
            'vlanId'                # VLAN assignment for switchport
        ]
        for field in switchport_fields:
            convert_payload.pop(field, None)
        
        # Clear any VLAN-related config
        convert_payload.pop('vlanId', None)
        
        endpoint = f"{self.base_url}/devices/default/interfaces/{intf_id}"
        
        try:
            response = self.session.put(endpoint, json=convert_payload, timeout=30)
            
            if response.status_code in [200, 201]:
                return True, ""
            elif response.status_code == 422:
                try:
                    error_data = response.json()
                    error_msg = error_data.get('error', {}).get('messages', [{}])[0].get('description', 'Unknown error')
                    return False, error_msg
                except:
                    return False, f"HTTP 422: {response.text[:200]}"
            else:
                return False, f"HTTP {response.status_code}: {response.text[:200]}"
                
        except requests.exceptions.RequestException as e:
            return False, str(e)
    
    def create_subinterface(self, intf: dict) -> tuple[bool, str | None]:
        """
        Create a subinterface (VLAN interface) in FTD.
        
        Subinterfaces in FTD require a reference to their parent interface.
        The parent can be a physical interface or an etherchannel.
        
        Endpoints:
        - Physical interface parent: POST /devices/default/interfaces/{parentId}/subinterfaces
        - EtherChannel parent: POST /devices/default/etherchannelinterfaces/{parentId}/subinterfaces
        
        Args:
            intf: Dictionary containing subinterface data
            
        Returns:
            Tuple of (success: bool, object_id: str or error message)
        """
        # Extract parent interface info from hardware name
        # Hardware name format: "Ethernet1/1.100" or "Port-channel1.100"
        hardware_name = intf.get('hardwareName', '')
        
        if '.' not in hardware_name:
            self.stats["subinterfaces_failed"] += 1
            return False, f"Invalid hardwareName format: {hardware_name} (expected parent.vlanid)"
        
        parent_hardware, vlan_str = hardware_name.rsplit('.', 1)
        
        try:
            vlan_id = int(vlan_str)
        except ValueError:
            self.stats["subinterfaces_failed"] += 1
            return False, f"Invalid VLAN ID: {vlan_str}"
        
        # We need to find the parent interface ID
        # Check if parent is an etherchannel (Port-channel) or physical interface
        # Based on hardware name pattern
        parent_is_etherchannel = parent_hardware.lower().startswith('port-channel')
        
        if self.debug:
            print("\n      [DEBUG] Parent interface lookup:")
            print(f"              Hardware name: {parent_hardware}")
            print(f"              Type: {'EtherChannel' if parent_is_etherchannel else 'Physical'}")
        
        # USE CACHED LOOKUPS for performance
        if parent_is_etherchannel:
            # Try to find it as an etherchannel (from cache)
            success, parent_intf = self.get_cached_etherchannel(parent_hardware)
            if self.debug and not success:
                print("              Result: EtherChannel not found in cache")
        else:
            # Try to find it as a physical interface (from cache)
            success, parent_intf = self.get_cached_physical_interface(parent_hardware)
            if self.debug and not success:
                print("              Result: Physical interface not found in cache")
        
        if not success:
            # Parent interface not found - skip
            self.stats["subinterfaces_skipped"] += 1
            if self.debug:
                print("              Skipping subinterface creation (parent not available)")
            return True, f"SKIPPED: Parent interface {parent_hardware} not found"
        
        if self.debug:
            print(f"              Found: {parent_intf.get('name')} (ID: {parent_intf.get('id')})") # type: ignore
        
        parent_id = parent_intf.get('id') # pyright: ignore[reportOptionalMemberAccess]
        parent_type = parent_intf.get('type', 'physicalinterface') # pyright: ignore[reportOptionalMemberAccess]
        
        # Get interface name - ensure it's valid
        subintf_name = intf.get('name', '')
        if not subintf_name:
            subintf_name = f"vlan{vlan_id}"
        
        # Get MTU (cap at 9000 - FTD maximum)
        mtu_value = intf.get('mtu', 1500)
        if mtu_value > 9000:
            mtu_value = 9000
        
        # Build the subinterface payload - FTD FDM API format
        subintf_payload = {
            "name": subintf_name,
            "subIntfId": vlan_id,
            "vlanId": vlan_id,
            "type": "subinterface",
            "enabled": intf.get('enabled', True),
            "managementOnly": False,
            "mtu": mtu_value,
            "parentInterface": {
                "id": parent_id,
                "type": parent_type
            }
        }
        
        # Add description if provided
        if intf.get('description'):
            subintf_payload['description'] = str(intf['description'])
        
        # Add IPv4 if provided
        if intf.get('ipv4'):
            ipv4_data = intf['ipv4']
            ip_address_obj = ipv4_data.get('ipAddress', {})
            
            ip_addr = None
            netmask = None
            
            if isinstance(ip_address_obj, dict):
                ip_addr = ip_address_obj.get('ipAddress')
                netmask = ip_address_obj.get('netmask')
            
            if ip_addr and netmask:
                subintf_payload['ipv4'] = {
                    "ipType": "STATIC",
                    "defaultRouteUsingDHCP": False,
                    "ipAddress": {
                        "ipAddress": ip_addr,
                        "netmask": netmask,
                        "type": "haipv4address"
                    },
                    "type": "interfaceipv4"
                }
        
        # Print debug info
        if self.debug:
            print(f"\n      [DEBUG] Subinterface payload: {subintf_payload}")
        
        # DIFFERENT ENDPOINTS for physical vs etherchannel parents
        if parent_is_etherchannel:
            # EtherChannel parent: /devices/default/etherchannelinterfaces/{parentId}/subinterfaces
            endpoint = f"{self.base_url}/devices/default/etherchannelinterfaces/{parent_id}/subinterfaces"
        else:
            # Physical interface parent: /devices/default/interfaces/{parentId}/subinterfaces
            endpoint = f"{self.base_url}/devices/default/interfaces/{parent_id}/subinterfaces"
        
        if self.debug:
            print(f"      [DEBUG] Endpoint: {endpoint}")
            print(f"      [DEBUG] Parent type: {'EtherChannel' if parent_is_etherchannel else 'Physical'}")
        
        try:
            response = self.session.post(endpoint, json=subintf_payload, timeout=30)
            
            if response.status_code in [200, 201]:
                created_obj = response.json()
                self.stats["subinterfaces_created"] += 1
                return True, created_obj.get("id")
            elif response.status_code == 422:
                try:
                    error_data = response.json()
                    error_messages = error_data.get('error', {}).get('messages', [])
                    if error_messages:
                        error_msg = error_messages[0].get('description', '')
                    else:
                        error_msg = str(error_data)
                    
                    if 'already exists' in error_msg.lower() or 'duplicate' in error_msg.lower():
                        self.stats["subinterfaces_skipped"] += 1
                        return True, f"SKIPPED: {error_msg}"
                    
                    self.stats["subinterfaces_failed"] += 1
                    return False, f"422: {error_msg}"
                except Exception:
                    self.stats["subinterfaces_failed"] += 1
                    return False, f"422: {response.text[:300]}"
            else:
                self.stats["subinterfaces_failed"] += 1
                return False, f"HTTP {response.status_code}: {response.text[:300]}"
                
        except requests.exceptions.RequestException as e:
            self.stats["subinterfaces_failed"] += 1
            return False, str(e)
    
    def _get_etherchannel_by_hardware(self, hardware_name: str) -> tuple[bool, dict | None]:
        """
        Get an etherchannel interface by hardware name.
        
        Args:
            hardware_name: Hardware name (e.g., 'Port-channel1')
            
        Returns:
            Tuple of (success: bool, interface dict or error message)
        """
        endpoint = f"{self.base_url}/devices/default/etherchannelinterfaces"
        search_name = hardware_name.lower().strip()
        
        try:
            response = self.session.get(endpoint, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                interfaces = data.get('items', [])
                
                for intf in interfaces:
                    intf_hardware = intf.get('hardwareName', '').lower().strip()
                    if intf_hardware == search_name:
                        return True, intf
                
                return False, f"EtherChannel {hardware_name} not found" # pyright: ignore[reportReturnType]
            else:
                return False, f"HTTP {response.status_code}" # pyright: ignore[reportReturnType]
                
        except requests.exceptions.RequestException as e:
            return False, str(e) # pyright: ignore[reportReturnType]
    
    def create_etherchannel(self, intf: dict) -> tuple[bool, str | None]:
        """
        Create an EtherChannel (port-channel) interface in FTD.
        
        Args:
            intf: Dictionary containing etherchannel data
            
        Returns:
            Tuple of (success: bool, object_id: str or error message)
        """
        endpoint = f"{self.base_url}/devices/default/etherchannelinterfaces"
        
        # Cap MTU at 9000 if present
        if 'mtu' in intf and intf['mtu'] is not None:
            if intf['mtu'] > 9000:
                intf['mtu'] = 9000
        
        # For etherchannels, we need to resolve member interface IDs
        # Also get the speedType from the first member interface
        member_speed_type = None
        is_sfp_member = False
        if 'memberInterfaces' in intf:
            resolved_members = []
            for member in intf['memberInterfaces']:
                hardware_name = member.get('hardwareName')
                success, existing = self.get_physical_interface(hardware_name)
                if success:
                    resolved_members.append({
                        "id": existing.get('id'), # pyright: ignore[reportOptionalMemberAccess]
                        "type": "physicalinterface"
                    })
                    # Get speedType from first member interface
                    if member_speed_type is None:
                        member_speed_type = existing.get('speedType') # pyright: ignore[reportOptionalMemberAccess]
                        if member_speed_type in {'DETECT_SFP', 'SFP_DETECT'}:
                            is_sfp_member = True
                else:
                    print(f"    Warning: Could not resolve member {hardware_name}")
            intf['memberInterfaces'] = resolved_members
        
        # Get appliance model for platform-specific behavior
        model = str(getattr(self, "appliance_model", "generic")).lower().strip()
        ftd_1000_series = {"ftd-1010", "1010", "ftd1010", 
                          "ftd-1120", "1120", "ftd1120",
                          "ftd-1140", "1140", "ftd1140"}
        ftd_3100_series = {"ftd-3105", "3105", "ftd3105",
                          "ftd-3110", "3110", "ftd3110",
                          "ftd-3120", "3120", "ftd3120",
                          "ftd-3130", "3130", "ftd3130",
                          "ftd-3140", "3140", "ftd3140",
                          "ftd-4215", "4215", "ftd4215"}
        
        # Set speedType and duplexType based on member interfaces and platform
        # CRITICAL: Use correct field names (speedType, duplexType) NOT (speed, duplex)
        if is_sfp_member:
            # SFP members - use SFP_DETECT speed
            intf['speedType'] = member_speed_type  # Preserve SFP_DETECT
            intf['duplexType'] = 'FULL'
            if model not in ftd_1000_series:
                intf['autoNeg'] = True
        elif model in ftd_3100_series:
            # 3100-series: Cannot use AUTO speed, use explicit speed
            explicit_ok = {'TEN', 'HUNDRED', 'THOUSAND', 'TEN_THOUSAND'}
            if member_speed_type in explicit_ok:
                intf['speedType'] = member_speed_type
            else:
                intf['speedType'] = 'TEN_THOUSAND'  # Default for 3100-series
            intf['duplexType'] = 'FULL'
            intf['autoNeg'] = True
        elif model in ftd_1000_series:
            # 1000-series: Support AUTO speed, no autoNeg field
            intf['speedType'] = 'AUTO'
            intf['duplexType'] = 'AUTO'
            # Don't set autoNeg - not supported
        else:
            # Default/2000-series: use AUTO or member speed
            if member_speed_type and member_speed_type != 'AUTO':
                intf['speedType'] = member_speed_type
            else:
                intf['speedType'] = 'AUTO'
            intf['duplexType'] = 'AUTO'
            intf['autoNeg'] = True
        
        # Remove old incorrect field names if present
        intf.pop('speed', None)
        intf.pop('duplex', None)
        
        try:
            response = self.session.post(endpoint, json=intf, timeout=30)
            
            if response.status_code in [200, 201]:
                created_obj = response.json()
                self.stats["etherchannels_created"] += 1
                return True, created_obj.get("id")
            elif response.status_code == 422:
                error_data = response.json()
                error_msg = error_data.get('error', {}).get('messages', [{}])[0].get('description', 'Unknown error')
                
                if 'already exists' in error_msg.lower() or 'duplicate' in error_msg.lower():
                    self.stats["etherchannels_skipped"] += 1
                    return True, f"SKIPPED: {error_msg}"
                else:
                    self.stats["etherchannels_failed"] += 1
                    return False, error_msg
            else:
                self.stats["etherchannels_failed"] += 1
                error_msg = response.text
                return False, error_msg
                
        except requests.exceptions.RequestException as e:
            self.stats["etherchannels_failed"] += 1
            return False, str(e)
    
    def create_bridge_group(self, intf: dict) -> tuple[bool, str | None]:
        """
        Create a Bridge Group interface in FTD.
        
        Bridge groups require member interfaces to be:
        1. In ROUTED mode (FTD automatically manages bridge membership)
        2. Referenced by ID (not hardware name)
        
        Args:
            intf: Dictionary containing bridge group data
            
        Returns:
            Tuple of (success: bool, object_id: str or error message)
        """
        endpoint = f"{self.base_url}/devices/default/bridgegroupinterfaces"
        
        # Cap MTU at 9000 if present
        if 'mtu' in intf and intf['mtu'] is not None:
            if intf['mtu'] > 9000:
                intf['mtu'] = 9000
        
        # CRITICAL: Resolve member interface IDs
        # The converter provides hardware names, but the API requires IDs
        # Bridge groups use "selectedInterfaces" field (not "memberInterfaces")
        if 'selectedInterfaces' in intf:
            resolved_members = []
            for member in intf['selectedInterfaces']:
                hardware_name = member.get('hardwareName')
                
                # Look up the physical interface by hardware name
                success, existing = self.get_physical_interface(hardware_name)
                if success:
                    # Add the member with ID reference
                    # Note: Member should be in ROUTED mode - FTD will manage bridge membership
                    resolved_members.append({
                        "id": existing.get('id'), # pyright: ignore[reportOptionalMemberAccess]
                        "type": "physicalinterface"
                    })
                    
                    if self.debug:
                        current_mode = existing.get('mode') # pyright: ignore[reportOptionalMemberAccess]
                        print(f"\n      [DEBUG] Resolved member: {hardware_name} -> ID {existing.get('id')} (mode: {current_mode})") # pyright: ignore[reportOptionalMemberAccess]
                else:
                    # Member interface not found - this is a problem
                    print(f"\n      [WARNING] Could not resolve member {hardware_name}")
                    if self.debug:
                        print(f"                Error: {existing}")
            
            # Update the interface config with resolved member IDs
            # Use "selectedInterfaces" for bridge groups (API requirement)
            intf['selectedInterfaces'] = resolved_members
            
            if not resolved_members:
                self.stats["bridge_groups_failed"] += 1
                return False, "No valid member interfaces found (all members failed to resolve)"
        
        if self.debug:
            print("\n      [DEBUG] Bridge group payload:")
            print(f"                Name: {intf.get('name')}")
            print(f"                Members: {len(intf.get('selectedInterfaces', []))}")
        
        try:
            response = self.session.post(endpoint, json=intf, timeout=30)
            
            if response.status_code in [200, 201]:
                created_obj = response.json()
                self.stats["bridge_groups_created"] += 1
                return True, created_obj.get("id")
            elif response.status_code == 422:
                error_data = response.json()
                error_msg = error_data.get('error', {}).get('messages', [{}])[0].get('description', 'Unknown error')
                
                if 'already exists' in error_msg.lower() or 'duplicate' in error_msg.lower():
                    self.stats["bridge_groups_skipped"] += 1
                    return True, f"SKIPPED: {error_msg}"
                else:
                    self.stats["bridge_groups_failed"] += 1
                    return False, error_msg
            else:
                self.stats["bridge_groups_failed"] += 1
                error_msg = response.text
                return False, error_msg
                
        except requests.exceptions.RequestException as e:
            self.stats["bridge_groups_failed"] += 1
            return False, str(e)
        
    def create_security_zone(self, zone: dict) -> tuple[bool, str | None]:
        """
        Create a security zone in FTD.
        
        Security zones are required for firewall policies. Each interface
        used in access rules must be assigned to a security zone.
        
        Args:
            zone: Dictionary containing security zone data
            
        Returns:
            Tuple of (success: bool, object_id: str or error message)
        """
        endpoint = f"{self.base_url}/object/securityzones"
        
        # Build the zone payload - resolve interface references
        zone_payload = {
            "name": zone.get("name"),
            "description": zone.get("description", ""),
            "mode": zone.get("mode", "ROUTED"),
            "type": "securityzone"
        }
        
        # Resolve interface references if present
        if "interfaces" in zone and zone["interfaces"]:
            resolved_interfaces = []
            for intf_ref in zone["interfaces"]:
                intf_name = intf_ref.get("name")
                hardware_name = intf_ref.get("hardwareName")
                intf_type = intf_ref.get("type", "physicalinterface")
                
                # Try to get the interface ID from FTD
                if hardware_name:
                    success, intf_obj = self.get_interface_by_hardware_name(hardware_name)
                    if success and intf_obj:
                        resolved_interfaces.append({
                            "id": intf_obj.get("id"),
                            "name": intf_obj.get("name"),
                            "hardwareName": intf_obj.get("hardwareName"),
                            "type": intf_obj.get("type", intf_type)
                        })
                    else:
                        if self.debug:
                            print(f"\n      [DEBUG] Interface not found: {hardware_name}")
            
            if resolved_interfaces:
                zone_payload["interfaces"] = resolved_interfaces
        
        if self.debug:
            print("\n      [DEBUG] Creating security zone:")
            print(f"              Name: {zone_payload.get('name')}")
            print(f"              Interfaces: {len(zone_payload.get('interfaces', []))}")
        
        try:
            response = self.session.post(endpoint, json=zone_payload, timeout=30)
            
            if response.status_code in [200, 201]:
                created_obj = response.json()
                self.stats["security_zones_created"] += 1
                return True, created_obj.get("id")
            elif response.status_code == 422:
                error_data = response.json()
                error_msg = error_data.get('error', {}).get('messages', [{}])[0].get('description', 'Unknown error')
                
                if 'already exists' in error_msg.lower() or 'duplicate' in error_msg.lower():
                    self.stats["security_zones_skipped"] += 1
                    return True, f"SKIPPED: {error_msg}"
                else:
                    self.stats["security_zones_failed"] += 1
                    return False, error_msg
            else:
                self.stats["security_zones_failed"] += 1
                error_msg = response.text
                return False, error_msg
                
        except requests.exceptions.RequestException as e:
            self.stats["security_zones_failed"] += 1
            return False, str(e)

    def get_network_object_by_name(self, name: str) -> tuple[bool, dict | None]:
        """
        Get a network object by name to retrieve its ID and version.
        
        This method first checks the local cache, then uses the FTD API's 
        filter parameter for efficient lookup, with fallback to paginated 
        search if filtering is not supported.
        
        Args:
            name: Network object name
            
        Returns:
            Tuple of (success: bool, network object dict or error message)
        """
        # Check cache first (fastest path)
        if name in self._network_object_cache:
            return True, self._network_object_cache[name]
        
        endpoint = f"{self.base_url}/object/networks"
        
        try:
            # First, try using the filter parameter for efficient lookup
            # FTD API supports filter=name:ObjectName syntax
            filter_params = {
                "filter": f"name:{name}",
                "limit": 10
            }
            response = self.session.get(endpoint, params=filter_params, timeout=30)
            if response.status_code == 200:
                data = response.json()
                items = data.get('items', [])
                
                for obj in items:
                    if obj.get('name') == name:
                        # Cache for future lookups
                        self._network_object_cache[name] = obj
                        return True, obj
            
            # If filter didn't work or didn't find it, do a paginated search
            # This handles cases where the filter syntax isn't supported
            offset = 0
            limit = 100  # Fetch 100 at a time for efficiency
            
            while True:
                params = {
                    "offset": offset,
                    "limit": limit
                }
                response = self.session.get(endpoint, params=params, timeout=30)
                
                if response.status_code != 200:
                    return False, f"API error: {response.status_code}"  # type: ignore
                
                data = response.json()
                items = data.get('items', [])
                
                # Search through this page of results
                for obj in items:
                    if obj.get('name') == name:
                        # Cache for future lookups
                        self._network_object_cache[name] = obj
                        return True, obj
                
                # Check if there are more pages
                paging = data.get('paging', {})
                total_count = paging.get('count', len(items))
                
                # If we've fetched all items or this page was empty, stop
                if len(items) == 0 or offset + len(items) >= total_count:
                    break
                
                # Move to next page
                offset += limit
            
            return False, f"Network object not found: {name}"  # type: ignore
            
        except Exception as e:
            return False, str(e)  # type: ignore
    
    def deploy_changes(self) -> bool:
        """
        Deploy pending configuration changes to the FTD device.
        
        After creating/modifying objects, changes must be deployed
        for them to take effect on the firewall.
        
        Returns:
            True if deployment initiated successfully, False otherwise
        """
        print(f"\n{'='*60}")
        print("Deploying configuration changes...")
        print(f"{'='*60}")
        
        endpoint = f"{self.base_url}/operational/deploy"
        
        try:
            response = self.session.post(endpoint, json={}, timeout=30)
            
            if response.status_code in [200, 201, 202]:
                print("  Deployment initiated successfully")
                print("  Note: Deployment may take several minutes to complete")
                print("  Check FDM web interface for deployment status")
                return True
            else:
                print(f"FAIL Deployment failed: {response.status_code}")
                print(f"  Response: {response.text}")
                return False
                
        except requests.exceptions.RequestException as e:
            print(f"FAIL Deployment error: {e}")
            return False
    
    def print_statistics(self):
        """
        Print a summary of import statistics.
        """
        print(f"\n{'='*60}")
        print("IMPORT STATISTICS")
        print(f"{'='*60}")
        print("\nPhysical Interfaces:")
        print(f"  Updated: {self.stats['physical_interfaces_updated']}")
        print(f"  Skipped: {self.stats['physical_interfaces_skipped']}")
        print(f"  Failed:  {self.stats['physical_interfaces_failed']}")
        print("\nEtherChannels:")
        print(f"  Created: {self.stats['etherchannels_created']}")
        print(f"  Skipped: {self.stats['etherchannels_skipped']} (already exist)")
        print(f"  Failed:  {self.stats['etherchannels_failed']}")
        print("\nBridge Groups:")
        print(f"  Created: {self.stats['bridge_groups_created']}")
        print(f"  Skipped: {self.stats['bridge_groups_skipped']} (already exist)")
        print(f"  Failed:  {self.stats['bridge_groups_failed']}")
        print("\nSubinterfaces:")
        print(f"  Created: {self.stats['subinterfaces_created']}")
        print(f"  Skipped: {self.stats['subinterfaces_skipped']} (already exist)")
        print(f"  Failed:  {self.stats['subinterfaces_failed']}")
        print("\nSecurity Zones:")
        print(f"  Created: {self.stats['security_zones_created']}")
        print(f"  Skipped: {self.stats['security_zones_skipped']} (already exist)")
        print(f"  Failed:  {self.stats['security_zones_failed']}")
        print("\nAddress Objects:")
        print(f"  Created: {self.stats['address_objects_created']}")
        print(f"  Skipped: {self.stats['address_objects_skipped']} (already exist)")
        print(f"  Failed:  {self.stats['address_objects_failed']}")
        print("\nAddress Groups:")
        print(f"  Created: {self.stats['address_groups_created']}")
        print(f"  Skipped: {self.stats['address_groups_skipped']} (already exist)")
        print(f"  Failed:  {self.stats['address_groups_failed']}")
        print("\nPort Objects:")
        print(f"  Created: {self.stats['port_objects_created']}")
        print(f"  Skipped: {self.stats['port_objects_skipped']} (already exist)")
        print(f"  Failed:  {self.stats['port_objects_failed']}")
        print("\nPort Groups:")
        print(f"  Created: {self.stats['port_groups_created']}")
        print(f"  Skipped: {self.stats['port_groups_skipped']} (already exist)")
        print(f"  Failed:  {self.stats['port_groups_failed']}")
        print("\nStatic Routes:")
        print(f"  Created: {self.stats['routes_created']}")
        print(f"  Skipped: {self.stats['routes_skipped']} (already exist)")
        print(f"  Failed:  {self.stats['routes_failed']}")
        print("\nAccess Rules:")
        print(f"  Created: {self.stats['rules_created']}")
        print(f"  Skipped: {self.stats['rules_skipped']} (already exist)")
        print(f"  Failed:  {self.stats['rules_failed']}")
        print(f"\n{'='*60}")


def load_json_file(filename: str) -> list[dict] | None:
    """
    Load a JSON file containing configuration objects.
    
    Args:
        filename: Path to the JSON file
        
    Returns:
        List of objects from the file, or None if error
    """
    try:
        with open(filename) as f:
            data = json.load(f)
            return data
    except FileNotFoundError:
        print(f"FAIL File not found: {filename}")
        return None
    except json.JSONDecodeError as e:
        print(f"FAIL Invalid JSON in {filename}: {e}")
        return None
    
def load_metadata_file(path: str) -> dict:
    """
    Load conversion metadata emitted by converter_v2/fortigate_converter_v2.py.

    Args:
        path: Path to metadata JSON file

    Returns:
        Dict (empty on failure)
    """
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def auto_discover_metadata(base_name: str) -> dict:
    """
    Auto-discover metadata file based on the --base argument.
    
    Checks for {base}_metadata.json in the current directory.
    This eliminates the need to manually specify --metadata-file
    when using standard naming conventions.
    
    Args:
        base_name: Base name from --base argument (e.g., 'ftd_config')
        
    Returns:
        Metadata dict if found, empty dict otherwise
    """
    import os
    
    # Build expected metadata filename
    metadata_path = f"{base_name}_metadata.json"
    
    # Check if file exists
    if os.path.isfile(metadata_path):
        print(f"[INFO] Auto-discovered metadata file: {metadata_path}")
        return load_metadata_file(metadata_path)
    
    return {}

    

def physical_interface_matches_json_config(current: dict, desired_json: dict) -> bool:
    """
    Determine whether the *current* FTD interface configuration already matches the
    *desired* JSON configuration produced by the converter.

    Important design choice:
        - We only compare keys that are present in desired_json (the converter output).
          This prevents false diffs when the converter intentionally omits fields.
        - We normalize common API differences (None vs "", missing ipv4/ipv6 vs None).

    Args:
        current: Interface object retrieved from FTD (GET/cache)
        desired_json: Interface object from converted JSON file

    Returns:
        True if no update is required, False otherwise.
    """
    # Keys we allow the converter to manage for physical interfaces
    managed_keys = (
        "name",
        "description",
        "mtu",
        "enabled",
        "managementOnly",
        "mode",
        "monitorInterface",
    )

    def _norm_scalar(v):
        # Normalize empty strings vs None (FDM sometimes flips these)
        if v == "":
            return None
        return v

    # Compare only fields actually present in JSON
    for key in managed_keys:
        if key in desired_json:
            if _norm_scalar(current.get(key)) != _norm_scalar(desired_json.get(key)):
                return False

    # Compare ipv4/ipv6 blocks only if present in JSON
    for ip_key in ("ipv4", "ipv6"):
        if ip_key in desired_json:
            cur_block = current.get(ip_key)
            des_block = desired_json.get(ip_key)

            # Normalize missing vs None
            if cur_block == {}:
                cur_block = None
            if des_block == {}:
                des_block = None

            if cur_block != des_block:
                return False

    return True


def is_cts_sgt_enabled(interface_obj: dict) -> bool:
    """Best-effort detection of CTS/SGT enablement on an interface object."""
    bool_enable_keys = (
        "ctsEnabled",
        "trustSecEnabled",
        "securityGroupTagging",
        "sgtEnabled",
        "enableCts",
        "ctsManual",
    )

    for key in bool_enable_keys:
        if interface_obj.get(key) is True:
            return True

    # Common nested blocks returned by FDM APIs.
    cts_block = interface_obj.get("cts")
    if isinstance(cts_block, dict):
        if cts_block.get("enabled") is True:
            return True
        mode = str(cts_block.get("mode", "")).upper()
        if mode in {"ENABLED", "INLINE", "MANUAL"}:
            return True

    # Any explicit tag assignment implies SGT is active.
    tag_value = interface_obj.get("securityGroupTag")
    if tag_value not in (None, "", 0, "0"):
        return True

    return False


def disable_cts_sgt_settings(interface_payload: dict) -> None:
    """Mutate payload to disable CTS/SGT so interfaces can join EtherChannels."""
    # Boolean toggles if present.
    for key in (
        "ctsEnabled",
        "trustSecEnabled",
        "securityGroupTagging",
        "sgtEnabled",
        "enableCts",
        "ctsManual",
    ):
        if key in interface_payload:
            interface_payload[key] = False

    # Explicit tag assignments should be cleared.
    for key in (
        "securityGroupTag",
        "securityGroupTagId",
        "sgt",
        "ctsTag",
    ):
        if key in interface_payload:
            interface_payload.pop(key, None)

    # Normalize nested CTS object if present.
    cts_block = interface_payload.get("cts")
    if isinstance(cts_block, dict):
        cts_block["enabled"] = False
        if "mode" in cts_block:
            cts_block["mode"] = "DISABLED"
        for key in ("securityGroupTag", "securityGroupTagId", "sgt", "ctsTag"):
            cts_block.pop(key, None)


def import_address_objects(
    client: FTDAPIClient,
    filename: str,
    max_workers: int = 1,
    max_attempts: int = 4,
    retry_backoff: float = 0.3,
    retry_jitter_max: float = DEFAULT_RETRY_JITTER_MAX,
) -> bool:
    """
    Import address objects from JSON file to FTD.
    
    Args:
        client: Authenticated FTD API client
        filename: Path to address objects JSON file
        
    Returns:
        True if all imports successful, False if any failed
    """
    print(f"\n{'-'*60}")
    print(f"Importing Address Objects from {filename}")
    print(f"{'-'*60}")
    
    objects = load_json_file(filename)
    if objects is None:
        return False
    
    if not objects:
        print("  No objects to import")
        return True
    
    total = len(objects)
    print_lock = threading.Lock()
    failure_flag = [False]

    def worker(idx: int, obj: dict) -> None:
        name = obj.get("name", "Unknown")
        success, result = run_with_retry(
            operation=lambda: client.create_network_object(obj, track_stats=False),
            should_retry=is_transient_error,
            max_attempts=max_attempts,
            initial_backoff=retry_backoff,
            jitter_max=retry_jitter_max,
        )
        if success:
            if isinstance(result, str) and str(result).startswith("SKIPPED"):
                client.record_stat("address_objects_skipped")
                line = f"  [{idx+1}/{total}] Creating: {name}... SKIP"
            else:
                client.record_stat("address_objects_created")
                line = f"  [{idx+1}/{total}] Creating: {name}... OK"
            with print_lock:
                print(line)
            return

        client.record_stat("address_objects_failed")
        line = f"  [{idx+1}/{total}] Creating: {name}... FAIL {result}"
        with print_lock:
            print(line)
        failure_flag[0] = True
        return

    run_thread_pool(objects, max_workers=max_workers, worker=worker)

    return not failure_flag[0]


def import_address_groups(client: FTDAPIClient, filename: str) -> bool:
    """
    Import address groups from JSON file to FTD.

    Args:
        client: Authenticated FTD API client
        filename: Path to address groups JSON file

    Returns:
        True if all imports successful, False if any failed
    """
    print(f"\n{'-'*60}")
    print(f"Importing Address Groups from {filename}")
    print(f"{'-'*60}")

    groups = load_json_file(filename)
    if groups is None:
        return False

    if not groups:
        print("  No groups to import")
        return True

    all_success = True
    for i, group in enumerate(groups, 1):
        name = group.get("name", "Unknown")

        # Clean the group object - ensure member objects only have name and type
        cleaned_group = clean_group_object(group)

        print(f"  [{i}/{len(groups)}] Creating: {name}...", end=" ")

        success, result = client.create_network_group(cleaned_group)
        if success:
            print("[Success!]")
        else:
            print(f"[FAIL {result}]")
            all_success = False

        time.sleep(0.2)

    return all_success


def clean_group_object(group: dict) -> dict:
    """
    Clean a group object to ensure member references only have name and type.

    FTD groups reference member objects by name only. Remove any UUIDs, IDs,
    versions, or other fields that might cause "cannot find entity" errors.

    Args:
        group: Group object dictionary

    Returns:
        Cleaned group object
    """
    cleaned = group.copy()

    # Clean the member objects in the "objects" array
    if "objects" in cleaned and isinstance(cleaned["objects"], list):
        cleaned_members = []
        for member in cleaned["objects"]:
            if isinstance(member, dict):
                # Keep ONLY name and type - remove everything else
                cleaned_member = {
                    "name": member.get("name"),
                    "type": member.get("type", "networkobject")
                }
                cleaned_members.append(cleaned_member)
            else:
                # If member is just a string, convert to proper format
                cleaned_members.append({
                    "name": str(member),
                    "type": "networkobject"
                })

        cleaned["objects"] = cleaned_members

    # Remove any UUID, id, or version fields from the group itself that came from FortiGate
    cleaned.pop("uuid", None)
    cleaned.pop("id", None)
    cleaned.pop("version", None)

    return cleaned


def import_service_objects(
    client: FTDAPIClient,
    filename: str,
    max_workers: int = 1,
    max_attempts: int = 4,
    retry_backoff: float = 0.3,
    retry_jitter_max: float = DEFAULT_RETRY_JITTER_MAX,
) -> bool:
    """
    Import service port objects from JSON file to FTD.

    Args:
        client: Authenticated FTD API client
        filename: Path to service objects JSON file

    Returns:
        True if all imports successful, False if any failed
    """
    print(f"\n{'-'*60}")
    print(f"Importing Service Objects from {filename}")
    print(f"{'-'*60}")

    objects = load_json_file(filename)
    if objects is None:
        return False

    if not objects:
        print("  No objects to import")
        return True

    total = len(objects)
    print_lock = threading.Lock()
    failure_flag = [False]

    def worker(idx: int, obj: dict) -> None:
        name = obj.get("name", "Unknown")
        obj_type = obj.get("type", "")
        success, result = run_with_retry(
            operation=lambda: client.create_port_object(obj, track_stats=False),
            should_retry=is_transient_error,
            max_attempts=max_attempts,
            initial_backoff=retry_backoff,
            jitter_max=retry_jitter_max,
        )
        if success:
            if isinstance(result, str) and str(result).startswith("SKIPPED"):
                client.record_stat("port_objects_skipped")
                line = f"  [{idx+1}/{total}] Creating: {name} ({obj_type})... SKIP"
            else:
                client.record_stat("port_objects_created")
                line = f"  [{idx+1}/{total}] Creating: {name} ({obj_type})... OK"
            with print_lock:
                print(line)
            return

        client.record_stat("port_objects_failed")
        line = f"  [{idx+1}/{total}] Creating: {name} ({obj_type})... FAIL {result}"
        with print_lock:
            print(line)
        failure_flag[0] = True
        return

    run_thread_pool(objects, max_workers=max_workers, worker=worker)

    return not failure_flag[0]


def import_service_groups(client: FTDAPIClient, filename: str) -> bool:
    """
    Import service port groups from JSON file to FTD.
    
    Args:
        client: Authenticated FTD API client
        filename: Path to service groups JSON file
        
    Returns:
        True if all imports successful, False if any failed
    """
    print(f"\n{'-'*60}")
    print(f"Importing Service Groups from {filename}")
    print(f"{'-'*60}")
    
    groups = load_json_file(filename)
    if groups is None:
        return False
    
    if not groups:
        print("  No groups to import")
        return True
    
    all_success = True
    for i, group in enumerate(groups, 1):
        name = group.get("name", "Unknown")
        
        # Clean the group object - ensure member objects only have name and type
        cleaned_group = clean_group_object(group)
        
        print(f"  [{i}/{len(groups)}] Creating: {name}...", end=" ")
        
        success, result = client.create_port_group(cleaned_group)
        if success:
            print("[Success!]")
        else:
            print(f"[FAIL {result}]")
            all_success = False
        
        time.sleep(0.2)
    
    return all_success


def import_physical_interfaces(client: FTDAPIClient, filename: str) -> bool:
    """
    Update existing physical interfaces using PUT if they exist on the device.
    Physical interfaces cannot be created via POST - they are pre-provisioned.
    This function uses the pre-populated _physical_interface_cache to detect existing interfaces,
    merges converted settings (name, description, IP, MTU, etc.) onto the real interface object,
    and sends a PUT request.
    
    NOTE: Interfaces not found on the FTD (wrong model, disabled ports, etc.) will be skipped.
    NOTE: Hardware settings (speed, duplex, FEC, auto-neg) are preserved.
    
    Args:
        client: Authenticated FTD API client
        filename: Path to physical interfaces JSON file
        
    Returns:
        True if all attempted updates were successful (skips don't count as failure)
    """
    print(f"\n{'-'*60}")
    print(f"Updating Physical Interfaces from {filename}")
    print(f"{'-'*60}")
    print("  - Physical Interfaces")
    print("  NOTE: Auto-negotiation=ENABLED, Duplex=FULL will be set")
    print("  NOTE: Interfaces not found on FTD will be skipped")
    
    interfaces = load_json_file(filename)
    if interfaces is None:
        return False
    
    if not interfaces:
        print("  No physical interfaces to update")
        return True
    
    # Cache physical interfaces once so we can do fast update detection by hardwareName
    client.populate_physical_interface_cache()
    
    all_success = True
    skipped_count = 0
    updated_count = 0
    failed_count = 0
    
    for i, intf in enumerate(interfaces, 1):
        name = intf.get("name", "")  # Empty string if not provided
        hardware = intf.get("hardwareName", "Unknown")
        
        # Display name - show hardware if name is empty
        display_name = name if name else f"<{hardware}>"
        print(f"  [{i}/{len(interfaces)}] Processing: {display_name} ({hardware})...", end=" ")

        if not hardware or hardware not in client._physical_interface_cache:
            print("[SKIP] (not present on this FTD model)")
            skipped_count += 1
            client.stats["physical_interfaces_skipped"] += 1
            continue

        # Get the original interface from cache
        original = client._physical_interface_cache[hardware]

        # Check if the interface already matches the desired JSON config.
        # Even when config matches, force update when CTS/SGT is enabled so
        # EtherChannel member validation does not fail later.
        if physical_interface_matches_json_config(original, intf) and not is_cts_sgt_enabled(original):
            print("[OK] No changes needed.")
            skipped_count += 1
            client.stats["physical_interfaces_skipped"] += 1
            continue

        # Use the client's update_physical_interface method
        # This method properly handles:
        # - Switchport to routed mode conversion
        # - Removal of switchport-specific fields
        # - Version management
        # - Error handling
        success, result = client.update_physical_interface(intf)
        
        if success:
            if "SKIPPED" in str(result):
                print(f"[SKIP] {result}")
                skipped_count += 1
            else:
                # Update successful
                print("[Success!]")
                updated_count += 1
        else:
            # Update failed
            print(f"[FAIL] {result}")
            if client.debug:
                print(f"       Error details: {result}")
            failed_count += 1
            all_success = False

        time.sleep(0.2)
    
    # Print summary
    print(f"\n  Summary: {updated_count} updated, {skipped_count} skipped (not present or no changes needed), {failed_count} failed")
    
    return all_success


def import_etherchannels(client: FTDAPIClient, filename: str) -> bool:
    """
    Import EtherChannel interfaces from JSON file to FTD.
    
    Args:
        client: Authenticated FTD API client
        filename: Path to etherchannels JSON file
        
    Returns:
        True if all imports successful, False if any failed
    """
    print(f"\n{'-'*60}")
    print(f"Creating EtherChannels from {filename}")
    print(f"{'-'*60}")
    print("  - EtherChannels")
    interfaces = load_json_file(filename)
    if interfaces is None:
        return False
    
    if not interfaces:
        print("  No etherchannels to create")
        return True
    
    all_success = True
    for i, intf in enumerate(interfaces, 1):
        name = intf.get("name", "Unknown")
        hardware = intf.get("hardwareName", "Unknown")
        print(f"  [{i}/{len(interfaces)}] Creating: {name} ({hardware})...", end=" ")
        
        success, result = client.create_etherchannel(intf)
        if success:
            if "SKIPPED" in str(result):
                if "already exists" in str(result).lower():
                    print("SKIP (already exists)")
                else:
                    print(f"SKIP ({result.split('SKIPPED:')[-1].strip()[:50]})") # pyright: ignore[reportOptionalMemberAccess]
            else:
                print("OK")
        else:
            print(f"FAIL {result}")
            all_success = False
        
        time.sleep(0.2)
    
    return all_success


def import_bridge_groups(client: FTDAPIClient, filename: str) -> bool:
    """
    Import Bridge Group interfaces from JSON file to FTD.
    
    Args:
        client: Authenticated FTD API client
        filename: Path to bridge groups JSON file
        
    Returns:
        True if all imports successful, False if any failed
    """
    print(f"\n{'-'*60}")
    print(f"Creating Bridge Groups from {filename}")
    print(f"{'-'*60}")
    print("  - Bridge Groups")

    interfaces = load_json_file(filename)
    if interfaces is None:
        return False
    
    if not interfaces:
        print("  No bridge groups to create")
        return True
    
    all_success = True
    for i, intf in enumerate(interfaces, 1):
        name = intf.get("name", "Unknown")
        print(f"  [{i}/{len(interfaces)}] Creating: {name}...", end=" ")
        
        success, result = client.create_bridge_group(intf)
        if success:
            if "SKIPPED" in str(result):
                if "already exists" in str(result).lower():
                    print("SKIP (already exists)")
                else:
                    print(f"SKIP ({result.split('SKIPPED:')[-1].strip()[:50]})") # pyright: ignore[reportOptionalMemberAccess]
            else:
                print("OK")
        else:
            print(f"FAIL {result}")
            all_success = False
        
        time.sleep(0.2)
    
    return all_success


def import_subinterfaces(
    client: FTDAPIClient,
    filename: str,
    parent_type_filter: str | None = None,
    max_workers: int = 4,
    max_attempts: int = 3,
    retry_backoff: float = 0.2,
    retry_jitter_max: float = DEFAULT_RETRY_JITTER_MAX,
) -> bool:
    """
    Import subinterfaces (VLANs) from JSON file to FTD.
    
    This function can filter subinterfaces by parent type to support
    two-phase import:
    - Phase 1: Import subinterfaces on physical interfaces (before EtherChannels)
    - Phase 2: Import subinterfaces on EtherChannels (after EtherChannels created)
    
    Args:
        client: Authenticated FTD API client
        filename: Path to subinterfaces JSON file
        parent_type_filter: Optional filter - 'physical' or 'etherchannel' or None for all
        
    Returns:
        True if all imports successful, False if any failed
    """
    # Determine header based on filter
    if parent_type_filter == 'physical':
        print("  - Subinterfaces (two-phase import)")
        print("    Phase 1: Physical interface parents")
        header = f"Creating Subinterfaces (Physical Interface Parents) from {filename}"
    elif parent_type_filter == 'etherchannel':
        print("    Phase 2: EtherChannel parents")
        header = f"Creating Subinterfaces (EtherChannel Parents) from {filename}"
    else:
        header = f"Creating Subinterfaces from {filename}"
    
    print(f"\n{'-'*60}")
    print(header)
    print(f"{'-'*60}")
    interfaces = load_json_file(filename)
    if interfaces is None:
        return False
    
    if not interfaces:
        print("  No subinterfaces to create")
        return True
    
    # Filter interfaces based on parent type if requested
    filtered_interfaces = []
    skipped_count = 0
    
    for intf in interfaces:
        hardware_name = intf.get('hardwareName', '')
        
        # Extract parent hardware name
        if '.' in hardware_name:
            parent_hardware = hardware_name.rsplit('.', 1)[0]
            parent_is_etherchannel = parent_hardware.lower().startswith('port-channel')
            
            # Apply filter if specified
            if parent_type_filter == 'physical' and not parent_is_etherchannel:
                filtered_interfaces.append(intf)
            elif parent_type_filter == 'etherchannel' and parent_is_etherchannel:
                filtered_interfaces.append(intf)
            elif parent_type_filter is None:
                filtered_interfaces.append(intf)
            else:
                skipped_count += 1
        else:
            # Invalid format - include it to let create_subinterface handle the error
            filtered_interfaces.append(intf)
    
    if skipped_count > 0:
        print(f"  Filtered out {skipped_count} subinterfaces (wrong parent type for this phase)")
    
    if not filtered_interfaces:
        print("  No subinterfaces match filter criteria")
        return True

    # Warm/refresh caches once per phase so parent lookups stay in-memory.
    # Force refresh for EtherChannel phase because those parents are created
    # earlier in the same run and won't exist in stale caches.
    client.prefetch_interface_cache(force_refresh=(parent_type_filter == 'etherchannel'))

    # Prime parent lookups once per unique parent to avoid repeated fallback
    # scans for each subinterface when a cache entry is missing.
    unique_parents = set()
    for intf in filtered_interfaces:
        hardware_name = str(intf.get('hardwareName', ''))
        if '.' in hardware_name:
            unique_parents.add(hardware_name.rsplit('.', 1)[0])
    for parent_hardware in unique_parents:
        if parent_hardware.lower().startswith('port-channel'):
            client.get_cached_etherchannel(parent_hardware)
        else:
            client.get_cached_physical_interface(parent_hardware)
    
    total = len(filtered_interfaces)

    # FDM commonly returns HTTP 423 lockTimeout when writing many
    # EtherChannel subinterfaces in parallel. Serialize that phase by default.
    effective_workers = max_workers
    effective_attempts = max_attempts
    effective_backoff = retry_backoff
    if parent_type_filter == 'etherchannel':
        effective_workers = 1
        effective_attempts = max(max_attempts, 6)
        effective_backoff = max(retry_backoff, 0.75)

    print(f"  Processing {total} subinterfaces with up to {effective_workers} workers...")

    print_lock = threading.Lock()
    count_lock = threading.Lock()
    failed_flag = [False]
    created_count = 0
    skipped_api_count = 0
    failed_count = 0

    def worker(idx: int, intf: dict) -> None:
        nonlocal created_count, skipped_api_count, failed_count
        name = intf.get("name", "Unknown")
        hardware = intf.get("hardwareName", "Unknown")

        success, result = run_with_retry(
            operation=lambda: client.create_subinterface(intf),
            should_retry=is_transient_error,
            max_attempts=effective_attempts,
            initial_backoff=effective_backoff,
            jitter_max=retry_jitter_max,
        )

        if success:
            if "SKIPPED" in str(result):
                if "already exists" in str(result).lower():
                    line = f"  [{idx+1}/{total}] Creating: {name} ({hardware})... SKIP (already exists)"
                else:
                    reason = str(result).split("SKIPPED:")[-1].strip()[:50]
                    line = f"  [{idx+1}/{total}] Creating: {name} ({hardware})... SKIP ({reason})"
                with count_lock:
                    skipped_api_count += 1
            else:
                line = f"  [{idx+1}/{total}] Creating: {name} ({hardware})... OK"
                with count_lock:
                    created_count += 1
            with print_lock:
                print(line)
            return

        line = f"  [{idx+1}/{total}] Creating: {name} ({hardware})... FAIL {result}"
        with count_lock:
            failed_count += 1
            failed_flag[0] = True
        with print_lock:
            print(line)

    run_thread_pool(filtered_interfaces, max_workers=effective_workers, worker=worker)
    
    # Print summary
    print(f"\n  Summary: {created_count} created, {skipped_api_count} skipped, {failed_count} failed")
    
    return not failed_flag[0]

def import_security_zones(client: FTDAPIClient, filename: str) -> bool:
    """
    Import security zones from JSON file to FTD.
    
    Args:
        client: Authenticated FTD API client
        filename: Path to security zones JSON file
        
    Returns:
        True if all imports successful, False if any failed
    """
    print(f"\n{'-'*60}")
    print(f"Importing Security Zones from {filename}")
    print(f"{'-'*60}")
    
    zones = load_json_file(filename)
    if zones is None:
        return False
    
    if not zones:
        print("  No security zones to import")
        return True
    
    all_success = True
    for i, zone in enumerate(zones, 1):
        name = zone.get("name", "Unknown")
        print(f"  [{i}/{len(zones)}] Creating zone: {name}...", end=" ")
        
        success, result = client.create_security_zone(zone)
        if success:
            if isinstance(result, str) and result.startswith("SKIPPED"):
                print("[SKIPPED]")
            else:
                print("[OK]")
        else:
            print(f"[FAIL {result}]")
            all_success = False
        
        time.sleep(0.2)
    
    return all_success

def import_static_routes(client: FTDAPIClient, filename: str) -> bool:
    """
    Import static routes from JSON file to FTD.
    
    Args:
        client: Authenticated FTD API client
        filename: Path to static routes JSON file
        
    Returns:
        True if all imports successful, False if any failed
    """
    print(f"\n{'-'*60}")
    print(f"Importing Static Routes from {filename}")
    print(f"{'-'*60}")
    
    routes = load_json_file(filename)
    if routes is None:
        return False
    
    if not routes:
        print("  No routes to import")
        return True
    
    # Prefetch interfaces AND network objects for faster lookups.
    # Interfaces are required to resolve route iface UUIDs (id) and avoid "UUID null" errors.
    client.prefetch_interface_cache()
    client.prefetch_network_object_cache()

    
    all_success = True
    for i, route in enumerate(routes, 1):
        name = route.get("name", "Unknown")
        print(f"  [{i}/{len(routes)}] Creating: {name}...", end=" ")
        
        success, result = client.create_static_route(route)
        if success:
            print("[OK]")
        else:
            print(f"[FAIL {result}]")
            all_success = False
        
        time.sleep(0.2)
    
    return all_success

def import_access_rules(client: FTDAPIClient, filename: str) -> bool:
    """
    Import access rules from JSON file to FTD.
    
    Args:
        client: Authenticated FTD API client
        filename: Path to access rules JSON file
        
    Returns:
        True if all imports successful, False if any failed
    """
    print(f"\n{'-'*60}")
    print(f"Importing Access Rules from {filename}")
    print(f"{'-'*60}")
    
    rules = load_json_file(filename)
    if rules is None:
        return False
    
    if not rules:
        print("  No rules to import")
        return True
    
    all_success = True
    for i, rule in enumerate(rules, 1):
        name = rule.get("name", "Unknown")
        action = rule.get("ruleAction", "")
        print(f"  [{i}/{len(rules)}] Creating: {name} ({action})...", end=" ")
        
        success, result = client.create_access_rule(rule)
        if success:
            print("[Success!]")
        else:
            print(f"[FAIL {result}]")
            all_success = False
        
        time.sleep(0.2)
    
    return all_success


def main():
    """
    Main function that orchestrates the import process.
    """
    parser = argparse.ArgumentParser(
        description='Import FortiGate converted configurations to Cisco FTD via FDM API',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Import everything (all files)
  python ftd_api_importer.py --host 192.168.1.1 --username admin --password MyPass123
  
  # Import only address objects
  python ftd_api_importer.py --host 192.168.1.1 -u admin --only-address-objects
  
  # Import only service objects and groups
  python ftd_api_importer.py --host 192.168.1.1 -u admin --only-service-objects --only-service-groups
  
  # Import a specific file
  python ftd_api_importer.py --host 192.168.1.1 -u admin --file my_addresses.json --type address-objects
  
  # Import and deploy
  python ftd_api_importer.py --host 192.168.1.1 -u admin --only-routes --deploy
        """
    )
    
    parser.add_argument('--host', required=True,
                       help='FTD management IP address or hostname')
    parser.add_argument('-u', '--username', required=True,
                       help='FDM username (typically "admin")')
    parser.add_argument('-p', '--password',
                       help='FDM password (will prompt if not provided)')
    parser.add_argument('--base', default='ftd_config',
                       help='Base name of converted JSON files (default: ftd_config)')
    parser.add_argument('--deploy', action='store_true',
                       help='Automatically deploy changes after import')
    parser.add_argument('--skip-verify', action='store_true', default=True,
                       help='Skip SSL certificate verification (default: True)')
    parser.add_argument('--debug', action='store_true',
                       help='Enable debug output (shows API payloads)')
    parser.add_argument("--metadata-file", default="",
                       help="Path to *_metadata.json generated by converter_v2/fortigate_converter_v2.py (used for model-specific behavior).",)
    parser.add_argument('--workers', type=int, default=6,
                       help='Global worker override for object/subinterface imports (default: 6, max: 32)')
    parser.add_argument('--workers-address-objects', type=int, default=None,
                       help='Workers for address object imports (default: stage/global setting)')
    parser.add_argument('--workers-service-objects', type=int, default=None,
                       help='Workers for service object imports (default: stage/global setting)')
    parser.add_argument('--workers-subinterfaces', type=int, default=None,
                       help='Workers for subinterface imports (default: stage/global setting)')

    parser.add_argument('--retry-attempts', type=int, default=None,
                       help='Global retry attempts override (default: stage-specific)')
    parser.add_argument('--retry-attempts-address-objects', type=int, default=None,
                       help='Retry attempts for address object imports')
    parser.add_argument('--retry-attempts-service-objects', type=int, default=None,
                       help='Retry attempts for service object imports')
    parser.add_argument('--retry-attempts-subinterfaces', type=int, default=None,
                       help='Retry attempts for subinterface imports')

    parser.add_argument('--retry-backoff', type=float, default=None,
                       help='Global initial retry backoff seconds override (default: stage-specific)')
    parser.add_argument('--retry-backoff-address-objects', type=float, default=None,
                       help='Initial retry backoff seconds for address object imports')
    parser.add_argument('--retry-backoff-service-objects', type=float, default=None,
                       help='Initial retry backoff seconds for service object imports')
    parser.add_argument('--retry-backoff-subinterfaces', type=float, default=None,
                       help='Initial retry backoff seconds for subinterface imports')
    parser.add_argument('--retry-jitter-max', type=float, default=DEFAULT_RETRY_JITTER_MAX,
                       help='Maximum random jitter added to retry backoff (default: 0.25)')

    
    # Selective import options - allows importing only specific object types
    parser.add_argument('--only-physical-interfaces', action='store_true',
                       help='Update only physical interfaces')
    parser.add_argument('--only-etherchannels', action='store_true',
                       help='Create only etherchannels')
    parser.add_argument('--only-bridge-groups', action='store_true',
                       help='Create only bridge groups')
    parser.add_argument('--only-subinterfaces', action='store_true',
                       help='Create only subinterfaces')
    parser.add_argument('--only-security-zones', action='store_true',
                       help='Create only security zones')
    parser.add_argument('--only-address-objects', action='store_true',
                       help='Import only address objects')
    parser.add_argument('--only-address-groups', action='store_true',
                       help='Import only address groups')
    parser.add_argument('--only-service-objects', action='store_true',
                       help='Import only service objects')
    parser.add_argument('--only-service-groups', action='store_true',
                       help='Import only service groups')
    parser.add_argument('--only-routes', action='store_true',
                       help='Import only static routes')
    parser.add_argument('--only-rules', action='store_true',
                       help='Import only access rules')
    
    # Alternative: specify a single file directly
    parser.add_argument('--file', 
                       help='Import a specific JSON file (overrides --base and --only flags)')
    parser.add_argument('--type',
                       choices=['address-objects', 'address-groups', 'service-objects', 
                               'service-groups', 'routes', 'rules', 'security-zones',
                               'physical-interfaces', 'etherchannels', 'bridge-groups', 'subinterfaces'],
                       help='Type of objects in the file (required with --file)')
    
    args = parser.parse_args()
    
    # Validate --file requires --type
    if args.file and not args.type:
        parser.error("--file requires --type to be specified")
    
    # Prompt for password if not provided
    if not args.password:
        args.password = getpass.getpass(f"Enter password for {args.username}: ")
    
    # Create API client
    client = FTDAPIClient(
        host=args.host,
        username=args.username,
        password=args.password,
        verify_ssl=not args.skip_verify
    )

    stage_workers = {
        "address_objects": _bounded_workers(args.workers_address_objects or args.workers, "address_objects"),
        "service_objects": _bounded_workers(args.workers_service_objects or args.workers, "service_objects"),
        "subinterfaces": _bounded_workers(args.workers_subinterfaces or args.workers, "subinterfaces"),
    }
    stage_attempts = {
        "address_objects": _resolve_stage_attempts("address_objects", args.retry_attempts_address_objects, args.retry_attempts),
        "service_objects": _resolve_stage_attempts("service_objects", args.retry_attempts_service_objects, args.retry_attempts),
        "subinterfaces": _resolve_stage_attempts("subinterfaces", args.retry_attempts_subinterfaces, args.retry_attempts),
    }
    stage_backoff = {
        "address_objects": _resolve_stage_backoff("address_objects", args.retry_backoff_address_objects, args.retry_backoff),
        "service_objects": _resolve_stage_backoff("service_objects", args.retry_backoff_service_objects, args.retry_backoff),
        "subinterfaces": _resolve_stage_backoff("subinterfaces", args.retry_backoff_subinterfaces, args.retry_backoff),
    }
    retry_jitter_max = max(0.0, float(args.retry_jitter_max))

    # Track per-phase timings for simple performance comparisons
    phase_timings = []

    def record_phase(label: str, func, *func_args, **func_kwargs):
        """Run a phase, time it, and capture success for summary output."""
        start = time.perf_counter()
        result = func(*func_args, **func_kwargs)
        duration = time.perf_counter() - start
        success = True if result is None else bool(result)
        phase_timings.append({"label": label, "seconds": duration, "success": success})
        return result
    
    # Load metadata: explicit file takes priority, then auto-discover from --base
    metadata = {}
    if args.metadata_file:
        metadata = load_metadata_file(args.metadata_file)
    else:
        # Auto-discover metadata based on --base argument
        metadata = auto_discover_metadata(args.base)
    
    # Store model hint on the client for downstream logic
    target_model = str(metadata.get("target_model", "generic")).lower().strip()
    client.appliance_model = target_model # pyright: ignore[reportAttributeAccessIssue]
    
    if target_model and target_model != "generic":
        print(f"[INFO] Target firewall model: {target_model}")

    # Set debug mode if requested
    if args.debug:
        client.debug = True
        print("[DEBUG MODE ENABLED]")
    
    # Authenticate
    if not client.authenticate():
        print("\nFAIL Authentication failed. Exiting.")
        return 1
    
    # Populate required caches before importing interfaces
    client.populate_physical_interface_cache()
    
    # Determine what to import
    print(f"\n{'='*60}")
    print("Starting Import Process")
    print(f"{'='*60}")
    
    # Check if specific file is provided
    if args.file:
        print(f"\nImporting single file: {args.file}")
        print(f"Object type: {args.type}")
        
        # Import based on type
        if args.type == 'physical-interfaces':
            record_phase("Physical Interfaces", import_physical_interfaces, client, args.file)
        elif args.type == 'etherchannels':
            record_phase("EtherChannels", import_etherchannels, client, args.file)
        elif args.type == 'bridge-groups':
            record_phase("Bridge Groups", import_bridge_groups, client, args.file)
        elif args.type == 'subinterfaces':
            # Import subinterfaces in two phases for correct parent dependency order
            print("\nPhase 1: Subinterfaces on Physical Interfaces")
            record_phase(
                "Subinterfaces (physical parents)",
                import_subinterfaces,
                client,
                args.file,
                parent_type_filter='physical',
                max_workers=stage_workers["subinterfaces"],
                max_attempts=stage_attempts["subinterfaces"],
                retry_backoff=stage_backoff["subinterfaces"],
                retry_jitter_max=retry_jitter_max,
            )
            print("\nPhase 2: Subinterfaces on EtherChannels")
            record_phase(
                "Subinterfaces (etherchannel parents)",
                import_subinterfaces,
                client,
                args.file,
                parent_type_filter='etherchannel',
                max_workers=stage_workers["subinterfaces"],
                max_attempts=stage_attempts["subinterfaces"],
                retry_backoff=stage_backoff["subinterfaces"],
                retry_jitter_max=retry_jitter_max,
            )
        elif args.type == 'security-zones':
            record_phase("Security Zones", import_security_zones, client, args.file)
        elif args.type == 'address-objects':
            record_phase(
                "Address Objects",
                import_address_objects,
                client,
                args.file,
                stage_workers["address_objects"],
                stage_attempts["address_objects"],
                stage_backoff["address_objects"],
                retry_jitter_max,
            )
        elif args.type == 'address-groups':
            record_phase("Address Groups", import_address_groups, client, args.file)
        elif args.type == 'service-objects':
            record_phase(
                "Service Objects",
                import_service_objects,
                client,
                args.file,
                stage_workers["service_objects"],
                stage_attempts["service_objects"],
                stage_backoff["service_objects"],
                retry_jitter_max,
            )
        elif args.type == 'service-groups':
            record_phase("Service Groups", import_service_groups, client, args.file)
        elif args.type == 'routes':
            record_phase("Static Routes", import_static_routes, client, args.file)
        elif args.type == 'rules':
            record_phase("Access Rules", import_access_rules, client, args.file)
    
    # Check if any --only flags are set
    elif any([args.only_physical_interfaces, args.only_etherchannels,
              args.only_bridge_groups, args.only_subinterfaces,
              args.only_security_zones,
              args.only_address_objects, args.only_address_groups, 
              args.only_service_objects, args.only_service_groups,
              args.only_routes, args.only_rules]):
        
        print("\nSelective Import Mode:")
        imported_any = False
        
        if args.only_physical_interfaces:
            record_phase("Physical Interfaces", import_physical_interfaces, client, f"{args.base}_physical_interfaces.json")
            imported_any = True
        
        if args.only_etherchannels:
            record_phase("EtherChannels", import_etherchannels, client, f"{args.base}_etherchannels.json")
            imported_any = True
        
        if args.only_bridge_groups:
            record_phase("Bridge Groups", import_bridge_groups, client, f"{args.base}_bridge_groups.json")
            imported_any = True
        
        if args.only_subinterfaces:
            record_phase(
                "Subinterfaces (physical parents)",
                import_subinterfaces,
                client,
                f"{args.base}_subinterfaces.json",
                parent_type_filter='physical',
                max_workers=stage_workers["subinterfaces"],
                max_attempts=stage_attempts["subinterfaces"],
                retry_backoff=stage_backoff["subinterfaces"],
                retry_jitter_max=retry_jitter_max,
            )
            record_phase(
                "Subinterfaces (etherchannel parents)",
                import_subinterfaces,
                client,
                f"{args.base}_subinterfaces.json",
                parent_type_filter='etherchannel',
                max_workers=stage_workers["subinterfaces"],
                max_attempts=stage_attempts["subinterfaces"],
                retry_backoff=stage_backoff["subinterfaces"],
                retry_jitter_max=retry_jitter_max,
            )
            imported_any = True
        
        if args.only_security_zones:
            print("  - Security Zones")
            record_phase("Security Zones", import_security_zones, client, f"{args.base}_security_zones.json")
            imported_any = True

        if args.only_address_objects:
            print("  - Address Objects")
            record_phase(
                "Address Objects",
                import_address_objects,
                client,
                f"{args.base}_address_objects.json",
                stage_workers["address_objects"],
                stage_attempts["address_objects"],
                stage_backoff["address_objects"],
                retry_jitter_max,
            )
            imported_any = True
        
        if args.only_address_groups:
            print("  - Address Groups")
            record_phase("Address Groups", import_address_groups, client, f"{args.base}_address_groups.json")
            imported_any = True
        
        if args.only_service_objects:
            print("  - Service Objects")
            record_phase(
                "Service Objects",
                import_service_objects,
                client,
                f"{args.base}_service_objects.json",
                stage_workers["service_objects"],
                stage_attempts["service_objects"],
                stage_backoff["service_objects"],
                retry_jitter_max,
            )
            imported_any = True
        
        if args.only_service_groups:
            print("  - Service Groups")
            record_phase("Service Groups", import_service_groups, client, f"{args.base}_service_groups.json")
            imported_any = True
        
        if args.only_routes:
            print("  - Static Routes")
            record_phase("Static Routes", import_static_routes, client, f"{args.base}_static_routes.json")
            imported_any = True
        
        if args.only_rules:
            print("  - Access Rules")
            record_phase("Access Rules", import_access_rules, client, f"{args.base}_access_rules.json")
            imported_any = True
        
        if not imported_any:
            print("\nFAIL No import flags specified. Nothing to import.")
            return 1
    # Default: Import everything in order
    else:
        print("\nFull Import Mode - All objects in order:")
        print("  1. Physical Interfaces (update)")
        print("  2. Subinterfaces on Physical Interfaces (create)")
        print("  3. EtherChannels (create)")
        print("  4. Subinterfaces on EtherChannels (create)")
        print("  5. Bridge Groups (create)")
        print("  6. Security Zones (create)")
        print("  7. Address Objects")
        print("  8. Address Groups")
        print("  9. Service Objects")
        print("  10. Service Groups")
        print("  11. Static Routes")
        print("  12. Access Rules")
        
        # Step 1: Update physical interfaces
        record_phase("Physical Interfaces", import_physical_interfaces, client, f"{args.base}_physical_interfaces.json")
        
        # Step 2: Create subinterfaces on physical interfaces BEFORE adding them to EtherChannels
        record_phase(
            "Subinterfaces (physical parents)",
            import_subinterfaces,
            client,
            f"{args.base}_subinterfaces.json",
            parent_type_filter='physical',
            max_workers=stage_workers["subinterfaces"],
            max_attempts=stage_attempts["subinterfaces"],
            retry_backoff=stage_backoff["subinterfaces"],
            retry_jitter_max=retry_jitter_max,
        )
        
        # Step 3: Create etherchannels (this may add physical interfaces as members)
        record_phase("EtherChannels", import_etherchannels, client, f"{args.base}_etherchannels.json")
        
        # Step 4: Create subinterfaces on EtherChannels AFTER they are created
        record_phase(
            "Subinterfaces (etherchannel parents)",
            import_subinterfaces,
            client,
            f"{args.base}_subinterfaces.json",
            parent_type_filter='etherchannel',
            max_workers=stage_workers["subinterfaces"],
            max_attempts=stage_attempts["subinterfaces"],
            retry_backoff=stage_backoff["subinterfaces"],
            retry_jitter_max=retry_jitter_max,
        )
        
        # Step 5: Create bridge groups
        record_phase("Bridge Groups", import_bridge_groups, client, f"{args.base}_bridge_groups.json")
        
        # Step 6: Create security zones (required for access rules)
        record_phase("Security Zones", import_security_zones, client, f"{args.base}_security_zones.json")

        # Step 5: Import address objects
        record_phase(
            "Address Objects",
            import_address_objects,
            client,
            f"{args.base}_address_objects.json",
            stage_workers["address_objects"],
            stage_attempts["address_objects"],
            stage_backoff["address_objects"],
            retry_jitter_max,
        )
        
        # Step 6: Import address groups
        record_phase("Address Groups", import_address_groups, client, f"{args.base}_address_groups.json")
        
        # Step 7: Import service objects
        record_phase(
            "Service Objects",
            import_service_objects,
            client,
            f"{args.base}_service_objects.json",
            stage_workers["service_objects"],
            stage_attempts["service_objects"],
            stage_backoff["service_objects"],
            retry_jitter_max,
        )
        
        # Step 8: Import service groups
        record_phase("Service Groups", import_service_groups, client, f"{args.base}_service_groups.json")
        
        # Step 9: Import static routes
        record_phase("Static Routes", import_static_routes, client, f"{args.base}_static_routes.json")
        
        # Step 10: Import access rules
        record_phase("Access Rules", import_access_rules, client, f"{args.base}_access_rules.json")

    if phase_timings:
        print(f"\n{'='*60}")
        print("TIMING SUMMARY (seconds)")
        print(f"{'='*60}")
        total_seconds = 0.0
        for entry in phase_timings:
            total_seconds += entry["seconds"]
            status = "OK" if entry["success"] else "FAIL"
            print(f"{entry['label']:<35}{entry['seconds']:.2f}s [{status}]")
        print("-"*60)
        print(f"{'Total':<35}{total_seconds:.2f}s")
    
    # Print statistics
    client.print_statistics()
    
    # Deploy changes if requested
    if args.deploy:
        client.deploy_changes()
    else:
        print(f"\n{'='*60}")
        print("Import complete. Changes are pending deployment.")
        print("To deploy, either:")
        print("  1. Run this script again with --deploy flag")
        print("  2. Deploy manually from the FDM web interface")
        print(f"{'='*60}")
    
    return 0


if __name__ == '__main__':
    sys.exit(main())