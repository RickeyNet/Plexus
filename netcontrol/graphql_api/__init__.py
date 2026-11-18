"""Read-only GraphQL API over inventory, IPAM and the other object models
(``/api/graphql``).

``schema`` holds the inventory and IPAM types and the root ``Query``,
``models`` the other object models (locations, device model, circuits,
DCIM, virtualization, routing, lifecycle), ``common`` their shared
helpers, ``context`` the per-request access checks and batched readers,
``limits`` the depth, alias, cost and introspection limits
checked before a query runs, ``settings`` the ``graphql_api`` admin setting.
The HTTP routes are in ``netcontrol.routes.graphql``. See docs/graphql-api.md.
"""
