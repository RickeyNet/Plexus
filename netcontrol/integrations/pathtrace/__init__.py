"""Path tracing: how a flow between two addresses crosses every device on the map.

Path Mode asks this package which policies, ACLs, security groups, NAT rules
and routes a flow meets at each device between a source and a destination,
in the order each device applies them, for the request and for the replies.

The data comes from the ``forwarding`` block each integration's normaliser
puts on the nodes that forward traffic (Meraki appliances, L3 switches and
non-Meraki VPN peers, the FTDs of a Cisco FMC, the firewalls of a Palo
Alto Panorama, Cato Sockets, PoPs and the Cato Cloud; see ``netcontrol.integrations.meraki.forwarding`` for the
schema), and, for inventory hosts, from the block ``inventory`` builds out
of what Plexus already stores (interfaces and the SSH route table capture).

Anything a source does not collect is reported as unknown, never as allowed.
"""
