"""Palo Alto Networks Panorama - topology collection.

One Panorama is registered like a Cisco FMC (``provider`` "panorama") and
goes through the same pipeline, producing the same snapshot format, so
everything downstream of the snapshot (merge into the Topology graph, node
details, deep search, subnet index for Path Mode and IPAM, HTML export,
software versions, the hop-by-hop path tracer) is shared with
``netcontrol.integrations.meraki``.

The Panorama is read-only, over its XML API: every managed firewall and HA
pair, the device group hierarchy with its address and service objects, the
security and NAT rules each firewall inherits (shared, its device group and
the ancestors), the network configuration of the templates and template
stacks (interfaces, zones, virtual routers, static routes, BGP, OSPF, IKE
gateways, IPsec tunnels, GlobalProtect gateways) and, through Panorama, the
operational state of each connected firewall (interfaces, routing table,
BGP peers, IPsec tunnel state, HA state, GlobalProtect users):

  ``client``      - paced XML API client (API key in a header, read-only)
  ``collector``   - reads every part above, best-effort past the device list
  ``normalize``   - turns the raw payloads into a positioned node/edge snapshot
  ``forwarding``  - the forwarding block of each firewall, for the path tracer
  ``sample``      - demo Panorama for previewing the map without credentials
"""
