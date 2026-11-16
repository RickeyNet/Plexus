"""Read-only GraphQL API over inventory and IPAM (``/api/graphql``).

``schema`` holds the types, ``context`` the per-request access checks and
batched readers, ``limits`` the depth, alias, cost and introspection limits
checked before a query runs, ``settings`` the ``graphql_api`` admin setting.
The HTTP routes are in ``netcontrol.routes.graphql``. See docs/graphql-api.md.
"""
