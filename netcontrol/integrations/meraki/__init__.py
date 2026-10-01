"""Cisco Meraki Dashboard API integration - topology collection and export.

Pipeline (each stage is a separate module so it can be tested in isolation):

  ``client``     - rate-limited, paginating Dashboard API v1 client (read-only)
  ``collector``  - walks one organization and returns the raw API payloads
  ``normalize``  - turns raw payloads into a positioned node/edge snapshot
  ``enrich``     - attaches Plexus inventory data (SNMP/SSH-collected) to nodes
  ``html_export``- renders a snapshot as one self-contained interactive HTML file
"""
