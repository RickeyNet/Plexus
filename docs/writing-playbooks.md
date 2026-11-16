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

## Run inputs and dry run

A playbook can declare the typed inputs its launch dialog asks for, in code,
as `parameters_schema`. The types and attributes are listed in
[Running jobs](jobs.md#run-inputs); the server checks every value before the
job is queued. A schema saved on the task in the UI overrides the code one.

```python
@register_playbook
class SetDescription(BasePlaybook):
    filename = "set_description.py"
    display_name = "Set Interface Description"
    description = "Sets one interface description"
    tags = ["example"]

    parameters_schema = [
        {"name": "interface", "type": "string", "label": "Interface", "required": True,
         "regex": "[A-Za-z]+[0-9/.]+"},
        {"name": "text", "type": "string", "label": "Description", "max": 200},
        {"name": "peer", "type": "ip", "label": "Peer address"},
        {"name": "target", "type": "host", "label": "Device"},
    ]

    async def run(self, hosts, credentials, template_commands=None, dry_run=True):
        commands = [f"interface {self.inputs['interface']}", f"description {self.inputs.get('text', '')}"]
        if dry_run:
            for cmd in commands:
                yield self.log_info(f"[DRY-RUN] Would apply: {cmd}")
            return
        ...  # push the commands
```

Inside `run()`:

- `self.inputs` (also `self.parameters`) holds the validated values: numbers
  as `int`, yes/no as `bool`, lists as lists, a host as
  `{id, hostname, ip_address, device_type}`, a group as `{id, name}`, and a
  secret as its decrypted value. Secret values are removed from the job log.
- `dry_run` (also `self.dry_run`) is `True` unless the user chose **Run and
  commit**. A dry run must not change any device: read and print what would
  change, but do not call `send_config_set` or `save_config`.
- A playbook that cannot preview sets `supports_dry_run = False` on the
  class. The launch dialog then offers only **Run and commit**, behind a
  confirmation, and the server refuses a dry run of it.

The built-in playbooks that change devices (**Enable NetFlow Export**,
**SNMPv3 Configurator**, **Template Configurator**, **VLAN 1 Remediation**)
all honour `dry_run`; **NTP Compliance Check** only reads.
`tests/test_job_inputs.py` checks that none of them writes in a dry run.

Ansible playbooks receive the inputs as extra vars (`{{ vlan_id }}`) and run
with `--check --diff` in a dry run.

## Simulation Mode

When Netmiko is not installed, playbooks that support it (like VLAN 1
Remediation) automatically run in simulation mode with realistic fake
output. This is useful for frontend development and demos.
