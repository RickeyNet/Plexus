"""Google Cloud (GCP) in the Topology map.

GCP projects are Cloud Visibility accounts (``/api/cloud/accounts``,
``provider`` "gcp"): Cloud Visibility discovers them and stores the result
as cloud resources and connections. This package reshapes what the Compute
Engine API returns into those records (``collect``), turns a stored
discovery into a topology snapshot in the Meraki snapshot format
(``normalize``), decides whether GCP routes and VPC firewall rules carry a
flow (``reachability``) and bundles a demo project (``sample``). No Google
SDK import lives here; the Cloud Visibility collector fetches the API
responses and passes them in.
"""
