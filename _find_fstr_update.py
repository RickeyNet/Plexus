import re
with open(r'C:\Users\18652\code\Plexus\routes\database.py', 'r', encoding='utf-8') as f:
    lines = f.readlines()

with open(r'C:\Users\18652\code\Plexus\_fstr_update_results.txt', 'w', encoding='utf-8') as out:
    for i, line in enumerate(lines, 1):
        if 'f"UPDATE' in line or "f'UPDATE" in line:
            out.write(f"L{i}: {line.rstrip()}\n")
        elif "join(sets)" in line or "join(fields)" in line or "join(updates" in line:
            if "UPDATE" in lines[max(0,i-4):i+1].__repr__():
                out.write(f"L{i}: {line.rstrip()}\n")

print("Done")
