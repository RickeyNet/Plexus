"""AWS in the Topology map.

AWS accounts are owned by Cloud Visibility (``/api/cloud/accounts``), which
discovers them and stores the result as cloud resources and connections.
This package adds the detail the map needs to that discovery (``collect``)
and turns the stored result into a topology snapshot (``normalize``), the
same format the Meraki and Cato integrations produce. No AWS SDK import
lives here; ``collect`` only reshapes items the Cloud Visibility collector
already fetched.
"""
