# Writing a New Playbook

1. Create a file in `playbooks/`, e.g. `playbooks/my_script.py`
2. Subclass `BasePlaybook` and decorate with `@register_playbook`
3. Implement `async def run()` as an async generator yielding `LogEvent`s

```python
from runner import BasePlaybook, LogEvent, register_playbook


@register_playbook
class MyScript(BasePlaybook):
    filename = "my_script.py"
    display_name = "My Automation Script"
    description = "Does something useful"
    tags = ["example"]
    requires_template = False

    async def run(self, hosts, credentials, template_commands=None, dry_run=True):
        yield self.log_info(f"Starting on {len(hosts)} hosts")

        async def run_host(host):
            ip = host["ip_address"]
            yield self.log_info(f"Processing {ip}", host=ip)

            # Your automation logic here
            # Use credentials["username"], credentials["password"]
            # Use template_commands if requires_template = True

            yield self.log_success(f"Finished processing {ip}", host=ip)

        async for event in self.run_hosts_concurrently(hosts, run_host):
            yield event

        yield self.log_success("All done.")
```

4. Restart the server - playbooks auto-register on import
5. Register it in the DB via API:
```bash
curl -X POST http://localhost:8080/api/playbooks \
  -H "Content-Type: application/json" \
  -d '{"name": "My Script", "filename": "my_script.py", "description": "...", "tags": ["example"]}'
```

## Simulation Mode

When Netmiko is not installed, playbooks that support it (like VLAN 1
Remediation) automatically run in simulation mode with realistic fake
output. This is useful for frontend development and demos.
