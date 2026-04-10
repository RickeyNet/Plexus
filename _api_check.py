import re

api_file = r'C:\Users\18652\code\Plexus\netcontrol\static\js\api.js'
with open(api_file, 'r', encoding='utf-8') as f:
    content = f.read()

# Find all compliance-related exports
compliance_funcs = []
for m in re.finditer(r'export\s+(?:async\s+)?function\s+(\w*[Cc]ompliance\w*|loadBuiltin\w*|remediate\w*)', content):
    compliance_funcs.append(m.group(1))

# Also search for compliance in function names
for m in re.finditer(r'export\s+(?:async\s+)?function\s+(\w+)', content):
    name = m.group(1)
    if 'ompliance' in name.lower() or 'remediat' in name.lower() or 'builtin' in name.lower():
        if name not in compliance_funcs:
            compliance_funcs.append(name)

# Now find what the compliance module calls on api.*
comp_file = r'C:\Users\18652\code\Plexus\netcontrol\static\js\modules\compliance.js'
with open(comp_file, 'r', encoding='utf-8') as f:
    comp_content = f.read()

api_calls = set(re.findall(r'api\.(\w+)', comp_content))

with open(r'C:\Users\18652\code\Plexus\_api_check_output.txt', 'w', encoding='utf-8') as f:
    f.write("=== Compliance API functions exported from api.js ===\n")
    for fn in sorted(compliance_funcs):
        f.write(f"  {fn}\n")
    f.write(f"\n=== api.* calls in compliance.js ===\n")
    for call in sorted(api_calls):
        f.write(f"  api.{call}\n")
    f.write(f"\n=== Missing from api.js (called but not exported) ===\n")
    api_exports = set(re.findall(r'export\s+(?:async\s+)?function\s+(\w+)', content))
    for call in sorted(api_calls):
        if call not in api_exports:
            f.write(f"  ❌ api.{call}\n")
    if not any(call not in api_exports for call in api_calls):
        f.write("  (none — all calls have matching exports)\n")

print("Done")
