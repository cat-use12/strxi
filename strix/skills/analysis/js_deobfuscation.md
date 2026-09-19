---
name: js_deobfuscation
description: JavaScript deobfuscation techniques — eval chains, array substitution, packer patterns, AST manipulation, Node.js sandbox tricks
---

# JavaScript Deobfuscation

## Quick Identification

```bash
# File signature
head -5 malware.js
wc -c malware.js   # tiny file = likely packed; huge = array-sub obfuscation

# Common patterns:
# 1. eval(function(p,a,c,k,e,...) → JsFuck / Dean Edwards packer
# 2. var _0x1234=['a','b','c']; → array substitution (obfuscator.io)
# 3. eval(atob("..."))          → base64 encoded
# 4. (function(){ ... })()      → IIFE wrapper
# 5. \x41\x42\x43               → hex encoded strings
```

## Layer 1: Base64 / atob

```javascript
// Pattern: eval(atob("base64string"))
// Fix: replace eval with console.log
const code = atob("base64string");
console.log(code);

// Multi-layer: eval(atob(atob("...")))
const inner = atob(atob("doubly_encoded"));
console.log(inner);
```

```python
import base64
data = "base64string"
print(base64.b64decode(data).decode())
```

## Layer 2: Dean Edwards Packer

```
eval(function(p,a,c,k,e,d){...}('payload',36,N,['array','of','words']...))
```

**Tools:**
- Online: [de4js](https://lelinhtinh.github.io/de4js/) → select "P,A,C,K,E,D"
- Manual: the function substitutes string fragments back — output is readable JS

## Layer 3: Array Substitution (obfuscator.io style)

```javascript
// Pattern:
var _0x1a2b = ['log', 'hello', 'world'];
var _0x3c4d = function(_0x5e6f, _0x7a8b) {
    return _0x1a2b[_0x5e6f];
};
console[_0x3c4d(0)](_0x3c4d(1) + ' ' + _0x3c4d(2));
// → console.log('hello world')
```

**Deobfuscate:**

```python
import re

# Extract the array
code = open("obf.js").read()
arr_match = re.search(r'var _0x\w+ ?= ?\[([^\]]+)\]', code)
if arr_match:
    items = arr_match.group(1)
    strings = re.findall(r"'([^']*)'", items)
    print("Array:", strings)

# Replace all _0xXXXX(N) calls with the actual string
def replace_array_calls(code, arr):
    def replacer(m):
        idx = int(m.group(1))
        return f"'{arr[idx]}'" if idx < len(arr) else m.group(0)
    return re.sub(r'_0x\w+\((\d+)\)', replacer, code)

deobfuscated = replace_array_calls(code, strings)
print(deobfuscated[:2000])
```

## Layer 4: Hex Encoded Strings

```python
import re

code = open("obf.js").read()
# \x41\x42 style
unhexed = re.sub(r'\\x([0-9a-fA-F]{2})', lambda m: chr(int(m.group(1), 16)), code)
# A style
unhexed = re.sub(r'\\u([0-9a-fA-F]{4})', lambda m: chr(int(m.group(1), 16)), unhexed)
print(unhexed[:2000])
```

## Runtime Deobfuscation (Node.js Sandbox)

The most reliable method: let the code deobfuscate itself, intercept the result.

```javascript
// sandbox.js — intercept eval and Function constructor
const vm = require('vm');
const fs = require('fs');

let code = fs.readFileSync('malware.js', 'utf8');

// Override eval to capture output
const sandbox = {
    eval: function(s) {
        console.log('[EVAL INTERCEPTED]');
        console.log(s.slice(0, 5000));
        // DO NOT execute: return undefined
    },
    Function: function(...args) {
        const body = args[args.length - 1];
        console.log('[FUNCTION INTERCEPTED]');
        console.log(body.slice(0, 5000));
        return function() {};
    },
    console: console,
    require: require,
    // Stub out dangerous globals:
    fetch: () => Promise.resolve({json: () => ({}), text: () => ''}),
    XMLHttpRequest: class { open(){} send(){} },
    WebSocket: class { constructor(url){ console.log('[WS]', url); } },
    setTimeout: (fn, t) => { fn(); },
    setInterval: () => {},
};

vm.runInNewContext(code, sandbox, { timeout: 5000 });
```

```bash
node sandbox.js 2>&1 | head -200
```

## Synchrony (Modern Deobfuscator)

```bash
# Best for obfuscator.io output
npx synchrony deobfuscate malware.js -o clean.js

# Options:
npx synchrony deobfuscate malware.js --target node --output clean.js
```

## AST-Based Deobfuscation

```javascript
// Use Babel to transform the AST
// npm install @babel/core @babel/parser @babel/traverse @babel/generator

const parser = require('@babel/parser');
const traverse = require('@babel/traverse').default;
const generate = require('@babel/generator').default;
const fs = require('fs');

const code = fs.readFileSync('obf.js', 'utf8');
const ast = parser.parse(code);

// Example: inline string array
const strings = [];
traverse(ast, {
    VariableDeclarator(path) {
        if (path.node.id.name.startsWith('_0x') && 
            path.node.init.type === 'ArrayExpression') {
            path.node.init.elements.forEach((el, i) => {
                if (el.type === 'StringLiteral') strings[i] = el.value;
            });
        }
    },
    CallExpression(path) {
        // Replace _0x1234(5) with strings[5]
        if (path.node.callee.name && path.node.callee.name.startsWith('_0x')) {
            const idx = path.node.arguments[0]?.value;
            if (typeof idx === 'number' && strings[idx]) {
                path.replaceWith({type: 'StringLiteral', value: strings[idx]});
            }
        }
    }
});

const output = generate(ast, {}, code);
fs.writeFileSync('deobf_ast.js', output.code);
```

## Custom Obfuscator Reversal (6000+ entry lookup table)

When an obfuscator generates a massive function lookup table (unique to the tool):

```python
import re

code = open("obf.js").read()

# Extract the lookup table (dict-like structure at top of file)
# Pattern: {"funcA": "console.log", "funcB": "document.write", ...}
table_match = re.search(r'\{(\s*"[^"]+"\s*:\s*"[^"]+"\s*,?\s*){100,}\}', code)
if table_match:
    raw = table_match.group(0)
    entries = re.findall(r'"([^"]+)"\s*:\s*"([^"]+)"', raw)
    lookup = dict(entries)
    print(f"Found {len(lookup)} entries")
    
    # Replace all obf names with real names
    for obf, real in lookup.items():
        code = code.replace(f'"{obf}"', f'"{real}"')
        code = code.replace(f"'{obf}'", f"'{real}'")
    
    open("deobf_lookup.js", "w").write(code)
```

## IOC Extraction from JS Malware

```python
import re

code = open("malware.js").read()

# After deobfuscation, find C2 indicators
patterns = {
    'urls':      r'https?://[^\s\'"<>]+',
    'ws':        r'wss?://[^\s\'"<>]+',
    'ips':       r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?::\d{2,5})?\b',
    'bot_token': r'\d{9,10}:AA[A-Za-z0-9_-]{35}',
    'eval_args': r'eval\(([^)]{1,200})\)',
    'base64':    r'[A-Za-z0-9+/]{50,}={0,2}',
}

for name, pattern in patterns.items():
    matches = list(set(re.findall(pattern, code)))
    if matches:
        print(f"\n=== {name} ===")
        for m in matches[:10]:
            print(" ", m)
```

## Beautify + Final Cleanup

```bash
# After deobfuscation, beautify for readability
npm install -g prettier
prettier --parser babel deobf.js > final_clean.js

# or: js-beautify
js-beautify deobf.js -o final_clean.js --indent-size 2

# Rename _0x variables with meaningful names (manual + grep):
grep -n "_0x[a-f0-9]\{4,6\}" final_clean.js | head -20
# Then use sed or editor to rename based on context
```
