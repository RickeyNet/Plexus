"""ChatOps: Plexus commands from Slack, Webex and Microsoft Teams.

- ``signatures``: request signature checks per platform, with replay guards.
- ``replies``: the platform-neutral reply and its Slack, Webex and Teams forms.
- ``commands``: the command catalogue; handlers reuse the MCP query tools.
- ``dispatcher``: parse, map the chat user to a Plexus user, check
  permission, run, log and audit.
- ``bots``: stored bot settings and their secrets.
- ``adapters``: inbound payload parsing and outbound replies per platform.
- ``notify``: alert notifications with an Acknowledge button.

See docs/chatops.md.
"""
