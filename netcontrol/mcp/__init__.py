"""Read-only AI access to Plexus data over the Model Context Protocol.

Served at ``/mcp`` (see ``server.py``). An AI client authenticates with a
token an admin created (``auth.py``); every tool call goes through one
dispatcher (``dispatch.py``) that checks access, masks secrets
(``redact.py``), caps the result and writes an audit event. There are no
write tools and nothing here contacts a device or a vendor API.
"""
