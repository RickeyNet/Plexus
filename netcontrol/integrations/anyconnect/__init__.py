"""Cisco AnyConnect (Secure Client) remote access VPN - topology collection.

AnyConnect terminates on Cisco Secure Firewall Threat Defense (FTD) devices
that a Firewall Management Center (FMC) manages. One FMC is registered like a
Cato account (``provider`` "anyconnect") and goes through the same pipeline,
producing the same snapshot format, so everything downstream of the snapshot
(merge into the Topology graph, node details, deep search, subnet index for
path mode, HTML export) is shared with ``netcontrol.integrations.meraki``:

  ``client``     - paced REST client for the FMC API (token auth, GET only)
  ``collector``  - reads device records, remote access VPN policies,
                   connection profiles, address pools, interfaces, sessions
  ``normalize``  - turns the raw payloads into a positioned node/edge snapshot
  ``sample``     - demo FMC for previewing the map without credentials
"""
