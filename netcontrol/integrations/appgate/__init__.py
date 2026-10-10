"""Appgate SDP (zero trust network access) - topology collection.

One Appgate collective is registered like a Palo Alto Panorama (``provider``
"appgate"): the entry's address is the admin interface of a Controller, its
secret the password of an admin user that signs in with the identity
provider named in ``org_id``. It goes through the same pipeline, producing
the same snapshot format, so everything downstream of the snapshot (merge
into the Topology graph, node details, deep search, subnet index for Path
Mode and IPAM, HTML export, software versions, the hop-by-hop path tracer)
is shared with ``netcontrol.integrations.meraki``.

The collective is read-only, over the Controller's admin REST API: every
appliance (Controllers, Gateways, Portals, LogServers, Connectors) with its
health, every site with its network subnets and name resolution, the
policies, entitlements, conditions and ringfence rules, the IP pools and
identity providers, the users connected with the Appgate Client and, per
user, the entitlements each Gateway grants them:

  ``client``      - paced admin API client (bearer token, peer version negotiated)
  ``collector``   - reads every part above, best-effort past appliances and sites
  ``normalize``   - turns the raw payloads into a positioned node/edge snapshot
  ``forwarding``  - the forwarding block of each appliance and user, for the path tracer
  ``sample``      - demo collective for previewing the map without credentials
"""
