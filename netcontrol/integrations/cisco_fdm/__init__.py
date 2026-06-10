"""Cisco FTD on-box (Firepower Device Manager) REST API integration.

``client.FdmClient`` owns one OAuth2 session per FTD and exposes the
read-only operational/monitoring resources Plexus consumes.  Higher
layers (the metrics collector, config-export, compliance) build on it.
"""

from netcontrol.integrations.cisco_fdm.client import FdmApiError, FdmClient

__all__ = ["FdmClient", "FdmApiError"]
