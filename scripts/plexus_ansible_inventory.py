#!/usr/bin/env python3
"""
plexus_ansible_inventory.py — Ansible dynamic inventory script for Plexus.

Usage:
  # List all hosts and groups:
  ansible-inventory -i plexus_ansible_inventory.py --list

  # Get variables for a single host:
  ansible-inventory -i plexus_ansible_inventory.py --host myswitch01

  # Use with ansible-playbook:
  ansible-playbook -i plexus_ansible_inventory.py site.yml

Environment variables:
  PLEXUS_URL        Base URL of the Plexus server (default: http://localhost:8000)
  PLEXUS_API_TOKEN  API token for authentication (required)
  PLEXUS_GROUP      Optional — filter inventory to a single Plexus group
  PLEXUS_DEVICE_TYPE     Optional — filter by device_type (e.g. cisco_ios)
  PLEXUS_DEVICE_CATEGORY Optional — filter by device_category (e.g. router, switch)
  PLEXUS_VERIFY_SSL      Set to "false" to disable TLS verification (default: true)
"""

import argparse
import json
import os
import sys
import urllib.error
import urllib.request
import ssl


def _build_url(base: str, host: str | None = None) -> str:
    """Build the Plexus ansible inventory API URL."""
    base = base.rstrip("/")
    if host:
        return f"{base}/api/ansible/inventory/host/{urllib.request.quote(host, safe='')}"

    params: list[str] = []
    group = os.environ.get("PLEXUS_GROUP")
    device_type = os.environ.get("PLEXUS_DEVICE_TYPE")
    device_category = os.environ.get("PLEXUS_DEVICE_CATEGORY")
    if group:
        params.append(f"group={urllib.request.quote(group, safe='')}")
    if device_type:
        params.append(f"device_type={urllib.request.quote(device_type, safe='')}")
    if device_category:
        params.append(f"device_category={urllib.request.quote(device_category, safe='')}")

    url = f"{base}/api/ansible/inventory"
    if params:
        url += "?" + "&".join(params)
    return url


def _fetch(url: str, token: str, verify_ssl: bool = True) -> dict:
    """Fetch JSON from the Plexus API."""
    req = urllib.request.Request(url)
    req.add_header("X-Api-Token", token)
    req.add_header("Accept", "application/json")

    context = None
    if not verify_ssl:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

    try:
        with urllib.request.urlopen(req, context=context) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as exc:
        print(f"Error: Plexus API returned HTTP {exc.code}", file=sys.stderr)
        sys.exit(1)
    except urllib.error.URLError as exc:
        print(f"Error: Could not connect to Plexus at {url}: {exc.reason}", file=sys.stderr)
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description="Ansible dynamic inventory script for Plexus",
    )
    parser.add_argument("--list", action="store_true", help="List all groups and hosts")
    parser.add_argument("--host", type=str, help="Get variables for a specific host")
    args = parser.parse_args()

    base_url = os.environ.get("PLEXUS_URL", "http://localhost:8000")
    token = os.environ.get("PLEXUS_API_TOKEN")
    if not token:
        print("Error: PLEXUS_API_TOKEN environment variable is required", file=sys.stderr)
        sys.exit(1)

    verify_ssl = os.environ.get("PLEXUS_VERIFY_SSL", "true").lower() not in ("false", "0", "no")

    if args.host:
        url = _build_url(base_url, host=args.host)
        data = _fetch(url, token, verify_ssl)
        print(json.dumps(data, indent=2))
    elif args.list:
        url = _build_url(base_url)
        data = _fetch(url, token, verify_ssl)
        print(json.dumps(data, indent=2))
    else:
        # Default to --list per Ansible convention
        url = _build_url(base_url)
        data = _fetch(url, token, verify_ssl)
        print(json.dumps(data, indent=2))


if __name__ == "__main__":
    main()
