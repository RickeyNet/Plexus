"""OPNsense firewall - topology collection (read-only, phase 1).

One OPNsense firewall is registered like an Appgate SDP collective
(``provider`` "opnsense"): the entry's address is the firewall's web GUI,
its secret the ``<API key>:<API secret>`` of an API user. It goes through
the same pipeline, producing the same snapshot format, so everything
downstream of the snapshot (merge into the Topology graph, node details,
deep search, subnet index for Path Mode and IPAM, HTML export, availability
tracking of gateways and tunnels, software versions) is shared with
``netcontrol.integrations.meraki``.

The firewall is read over its REST API: system information and firmware
status, interfaces and their addresses, gateways with their monitor state,
the routing table, IPsec, WireGuard and OpenVPN tunnel state, the built-in
security audit of the installed packages, and ``config.xml`` (stored as a
configuration backup of the matching inventory host, never in the snapshot):

  ``client``      - paced API client (HTTP Basic: API key and secret)
  ``collector``   - reads every part above, best-effort call by call
  ``normalize``   - turns the raw payloads into a positioned node/edge snapshot
  ``sample``      - demo firewall for previewing the map without credentials

Rules, NAT and the path tracer's forwarding model of the firewall are not
part of phase 1.
"""
