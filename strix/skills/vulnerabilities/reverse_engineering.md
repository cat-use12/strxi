---
name: reverse_engineering
description: Static and dynamic reverse engineering — Ghidra, radare2, strings, anti-debug bypass, binary analysis, unpacking
---

# Reverse Engineering

## Quick Triage

```bash
# File type and basic info
file ./binary
strings ./binary | grep -i "flag\|key\|password\|http\|192\.\|token\|secret"
strings -n 8 ./binary | head -100   # longer strings only

# Dependencies
ldd ./binary
readelf -d ./binary | grep NEEDED

# Import/export table
nm -D ./binary 2>/dev/null
objdump -T ./binary 2>/dev/null

# Entropy (high = packed/encrypted)
binwalk -E ./binary
# or: python3 -c "
# import math, collections
# data = open('./binary','rb').read()
# freq = collections.Counter(data)
# ent = -sum(c/len(data)*math.log2(c/len(data)) for c in freq.values())
# print(f'Entropy: {ent:.2f}/8.0')
# "

# Packing detection
strings ./binary | grep -i "upx\|UPX0\|packed"
upx -t ./binary
```

## Static Analysis

### Ghidra

```bash
# Headless analysis
ghidra_headless /tmp/ghidra_proj MyProj -import ./binary -postScript PrintTree.java
# GUI:
ghidraRun
# Import binary → analyze → CodeBrowser
# Key windows: Functions list, Decompiler, Symbol Tree, References

# Useful Ghidra scripts (Script Manager):
# - FindStrings.java: find all strings
# - RecoverClassesFromRTTI.java: C++ class recovery
```

### radare2

```bash
r2 ./binary        # open
r2 -A ./binary     # open + analyze all (slow on big binaries)
r2 -d ./binary     # open in debug mode

# Inside r2:
aaa                # analyze all
afl                # list all functions
pdf @ main         # disassemble main
pdf @ sym.win      # disassemble 'win' function
s main             # seek to main
VV                 # visual graph mode (q to quit)
iz                 # strings in data section
iE                 # exports
iI                 # binary info (arch, bits, pic, canary, nx)
/x 90909090        # search for bytes (NOP sled)
```

### objdump / readelf

```bash
objdump -d ./binary | less                    # full disassembly
objdump -d ./binary | grep -A10 "<main>"      # main function
objdump -M intel -d ./binary                  # Intel syntax
readelf -a ./binary                           # all ELF info
readelf -l ./binary                           # program headers (segments)
readelf -S ./binary                           # section headers
```

## Dynamic Analysis

### GDB + GEF/pwndbg

```bash
gdb ./binary
# Basic commands:
run                          # start
run arg1 arg2                # with args
break main                   # breakpoint at main
break *0x401234              # breakpoint at address
info breakpoints             # list breakpoints
continue                     # continue after break
next / n                     # step over
step / s                     # step into
nexti / ni                   # next instruction
stepi / si                   # step into instruction
info registers               # all registers
print $rax                   # print register
x/20gx $rsp                  # examine 20 qwords at rsp
x/s 0x402000                 # examine as string
disas main                   # disassemble function
set $rip = 0x401234          # change instruction pointer
set *0x602010 = 0x41414141   # write to memory
watch *0x602010              # watchpoint on memory

# GEF specific:
pattern create 200           # generate cyclic pattern
pattern offset $rip          # find offset from crash
checksec                     # binary protections
vmmap                        # memory map
telescope $rsp               # inspect stack
```

### ltrace / strace

```bash
ltrace ./binary              # library calls (strcmp, malloc, etc.)
ltrace -s 200 ./binary       # show strings up to 200 chars
strace ./binary              # system calls
strace -e trace=open,read,write ./binary  # filter syscalls
strace -f ./binary           # follow forks
```

## Anti-Debug / Anti-Analysis Bypass

### ptrace detection

```bash
# In GDB:
catch syscall ptrace
run
# When ptrace called:
set $rax = 0    # fake success return
continue
```

```python
# Frida: bypass ptrace anti-debug
import frida
script = """
var ptrace = Module.findExportByName(null, 'ptrace');
Interceptor.attach(ptrace, {
    onLeave: function(retval) {
        retval.replace(0);  // always return 0 (success)
    }
});
"""
```

### Timing checks

```bash
# Binary checks time diff to detect single-stepping
# In GDB: set a breakpoint before the check, skip the check
set $rip = <address_after_check>
continue
```

### String obfuscation (XOR / base64 / custom)

```python
# Find XOR key by known plaintext
ciphertext = bytes.fromhex("1a2b3c4d...")
known_plain = b"http"
key = bytes(a ^ b for a, b in zip(ciphertext[:4], known_plain))
print("key:", key)

# Decrypt full string
decrypted = bytes(b ^ key[i % len(key)] for i, b in enumerate(ciphertext))
print(decrypted)
```

## Unpacking

```bash
# UPX
upx -d ./packed -o ./unpacked

# Manual unpacking (OEP finding):
# 1. Run binary in GDB
# 2. Set hardware watchpoint on ESP/RSP (write)
#    watch -l *$rsp
# 3. Run until OEP (Original Entry Point)
# 4. Dump memory: generate-core-file → extract from core

# procfs dump (Linux, running process):
cat /proc/<pid>/maps | grep r-xp
dd if=/proc/<pid>/mem bs=1 skip=<start_addr> count=<size> of=dump.bin
```

## Windows PE Analysis

```bash
# Wine + tools
wine ./binary.exe
file ./binary.exe
strings ./binary.exe | grep -i "http\|reg\|cmd\|powershell"

# PE analysis (Linux tools):
pefile pip install pefile
python3 -c "
import pefile
pe = pefile.PE('./binary.exe')
for entry in pe.DIRECTORY_ENTRY_IMPORT:
    print(entry.dll.decode())
    for imp in entry.imports:
        print('  ' + (imp.name.decode() if imp.name else str(imp.ordinal)))
"

# pestudio (Windows) / pe-bear (cross-platform)
```

## Useful One-Liners

```bash
# Find all function calls to a specific lib func
objdump -d ./binary | grep -B5 "call.*puts\|call.*system\|call.*execve"

# Find ROP gadgets
ROPgadget --binary ./binary --rop | grep "pop rdi"
ropper -f ./binary --search "pop rdi"

# Detect self-modifying code
strace -e trace=mprotect ./binary  # mprotect(PROT_EXEC) = SMC

# Find crypto constants (AES S-box, etc.)
binwalk --raw="\x63\x7c\x77\x7b" ./binary  # AES S-box start

# Check for hardcoded IPs/URLs
strings ./binary | grep -Eo "(https?://[^\"' ]+|[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+:[0-9]+)"
```
