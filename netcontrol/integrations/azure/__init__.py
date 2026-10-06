"""Azure in the Topology map.

Azure subscriptions are Cloud Visibility accounts (``/api/cloud/accounts``,
``provider`` "azure"): Cloud Visibility discovers them and stores the result
as cloud resources and connections. This package reshapes what the Azure
Network API returns into those records (``collect``), turns a stored
discovery into a topology snapshot in the Meraki snapshot format
(``normalize``), decides whether Azure routes and network security groups
carry a flow (``reachability``) and bundles a demo subscription
(``sample``). No Azure SDK import lives here; the Cloud Visibility collector
fetches the API models and passes them in.
"""
