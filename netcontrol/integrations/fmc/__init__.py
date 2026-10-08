"""Cisco Secure Firewall Management Center (FMC) - topology collection.

One FMC is registered like a Cato account (``provider`` "fmc"; entries
stored as "anyconnect" by earlier releases are read as "fmc") and goes
through the same pipeline, producing the same snapshot format, so
everything downstream of the snapshot (merge into the Topology graph, node
details, deep search, subnet index for Path Mode and IPAM, HTML export,
software versions) is shared with ``netcontrol.integrations.meraki``.

The FMC is read-only and read whole: every managed FTD, HA pairs and
clusters, interfaces and connected subnets, static and dynamic routing,
NAT, access control and prefilter policies, site-to-site VPN topologies,
network objects and zones, health, pending deployments, and the remote
access VPN side (AnyConnect / Secure Client headends and their users):

  ``client``     - paced REST client for the FMC API (token auth, GET only)
  ``collector``  - reads every resource above, best-effort past the device list
  ``normalize``  - turns the raw payloads into a positioned node/edge snapshot
  ``sample``     - demo FMC for previewing the map without credentials
"""
