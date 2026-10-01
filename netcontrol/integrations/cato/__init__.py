"""Cato Networks API integration - SASE topology collection.

A Cato account goes through the same pipeline as a Meraki organization and
produces the same snapshot format, so everything downstream of the snapshot
(merge into the Topology graph, node details, deep search, subnet index for
path mode, HTML export) is shared with ``netcontrol.integrations.meraki``:

  ``client``     - paced GraphQL client for the Cato API (read-only queries)
  ``collector``  - reads the account snapshot, remote users and site ranges
  ``normalize``  - turns the raw payloads into a positioned node/edge snapshot
  ``sample``     - demo account for previewing the map without an API key
"""
