"""Check brace/bracket balance in app.js, stripping strings and comments."""

with open('netcontrol/static/js/app.js', encoding='utf-8') as f:
    content = f.read()

# State machine to strip strings and comments
result = []
i = 0
n = len(content)
while i < n:
    c = content[i]
    # Single-line comment
    if c == '/' and i + 1 < n and content[i + 1] == '/':
        while i < n and content[i] != '\n':
            i += 1
        continue
    # Multi-line comment
    if c == '/' and i + 1 < n and content[i + 1] == '*':
        i += 2
        while i + 1 < n and not (content[i] == '*' and content[i + 1] == '/'):
            i += 1
        i += 2
        continue
    # String literals
    if c in ('"', "'", '`'):
        quote = c
        i += 1
        while i < n and content[i] != quote:
            if content[i] == '\\':
                i += 1  # skip escaped char
            i += 1
        i += 1  # skip closing quote
        continue
    result.append(c)
    i += 1

cleaned = ''.join(result)
lines = cleaned.split('\n')

braces = cleaned.count('{') - cleaned.count('}')
brackets = cleaned.count('[') - cleaned.count(']')
parens = cleaned.count('(') - cleaned.count(')')
print(f'braces={braces:+d} brackets={brackets:+d} parens={parens:+d}')

if braces == 0 and brackets == 0 and parens == 0:
    print('All balanced!')
else:
    # Find which chunks are off
    if braces != 0:
        for s in range(0, len(lines), 100):
            e = min(s + 100, len(lines))
            b = sum(line.count('{') - line.count('}') for line in lines[s:e])
            if b != 0:
                print(f'  Brace L{s+1}-{e}: {b:+d}')
    if brackets != 0:
        for s in range(0, len(lines), 100):
            e = min(s + 100, len(lines))
            b = sum(line.count('[') - line.count(']') for line in lines[s:e])
            if b != 0:
                print(f'  Bracket L{s+1}-{e}: {b:+d}')
