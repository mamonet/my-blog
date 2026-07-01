---
title: "Android Obfuscation Analysis: ProGuard, R8, and Native Code Protection"
description: "Techniques for analyzing obfuscated Android applications including ProGuard/R8 deobfuscation, control flow flattening reversal, string decryption, and native library unpacking."
pubDate: 2025-02-25
author: "Mamone Tarsia"
tags: ["reverse-engineering", "android", "obfuscation", "deobfuscation"]
draft: false
---

## Introduction

Android obfuscation techniques aim to hinder reverse engineering by renaming symbols, encrypting strings, flattening control flow, and packing native libraries. Understanding deobfuscation methods is essential for security analysis and malware research.

## ProGuard/R8 Obfuscation

### Symbol Renaming

```java
// Original code
package com.example.banking;

public class AccountManager {
    private String accountNumber;
    private double balance;

    public void transfer(String recipient, double amount) {
        if (balance >= amount) {
            balance -= amount;
            sendTransaction(recipient, amount);
        }
    }
}

// After ProGuard
package a.b.c;

public class a {
    private String a;
    private double b;

    public void a(String a, double b) {
        if (this.b >= b) {
            this.b -= b;
            b(a, b);
        }
    }
}
```

### Deobfuscation with Mapping File

```
# mapping.txt (ProGuard output)
com.example.banking.AccountManager -> a.b.c.a:
    java.lang.String accountNumber -> a
    double balance -> b
    void transfer(java.lang.String,double) -> a
    void sendTransaction(java.lang.String,double) -> b
```

**Apply mapping**:

```python
#!/usr/bin/env python3
"""
Apply ProGuard mapping to decompiled code
"""
import re

def parse_mapping(mapping_file):
    """Parse ProGuard mapping file"""
    mappings = {}

    with open(mapping_file, 'r') as f:
        current_class = None

        for line in f:
            line = line.strip()

            if ' -> ' in line and ':' in line:
                # Class mapping
                original, obfuscated = line.split(' -> ')
                obfuscated = obfuscated.rstrip(':')
                current_class = obfuscated
                mappings[obfuscated] = {'name': original, 'members': {}}

            elif current_class and ' -> ' in line:
                # Member mapping
                parts = line.split(' -> ')
                member_sig = parts[0].strip()
                obfuscated_name = parts[1]

                # Parse signature
                if '(' in member_sig:
                    # Method
                    ret_type, rest = member_sig.split(' ', 1)
                    method_name = rest.split('(')[0]
                    mappings[current_class]['members'][obfuscated_name] = method_name
                else:
                    # Field
                    field_type, field_name = member_sig.rsplit(' ', 1)
                    mappings[current_class]['members'][obfuscated_name] = field_name

    return mappings

def deobfuscate_code(code, mappings):
    """Apply mappings to decompiled code"""

    # Replace class names
    for obf_class, info in mappings.items():
        orig_class = info['name']
        code = re.sub(rf'\\b{re.escape(obf_class)}\\b', orig_class, code)

        # Replace member names
        for obf_member, orig_member in info['members'].items():
            code = re.sub(rf'\\b{re.escape(obf_member)}\\b', orig_member, code)

    return code

if __name__ == '__main__':
    mappings = parse_mapping('mapping.txt')
    decompiled = open('decompiled.java').read()
    deobfuscated = deobfuscate_code(decompiled, mappings)
    print(deobfuscated)
```

## String Encryption

### Encrypted Strings Pattern

```java
// Obfuscated code with encrypted strings
public class a {
    public void a() {
        String s1 = b.a("Gur dhvpx oebja sbk");  // ROT13 encrypted
        String s2 = c.a(new byte[]{0x48, 0x65, 0x6c, 0x6c, 0x6f});  // Hex encoded
        String s3 = d.a("SGVsbG8gV29ybGQ=");  // Base64
    }
}
```

### Automated Decryption

```python
#!/usr/bin/env python3
"""
Decrypt Android string obfuscation
"""
import re
import base64

def decrypt_rot13(encrypted):
    """ROT13 decryption"""
    decrypted = ""
    for char in encrypted:
        if 'a' <= char <= 'z':
            decrypted += chr((ord(char) - ord('a') + 13) % 26 + ord('a'))
        elif 'A' <= char <= 'Z':
            decrypted += chr((ord(char) - ord('A') + 13) % 26 + ord('A'))
        else:
            decrypted += char
    return decrypted

def decrypt_base64(encrypted):
    """Base64 decryption"""
    return base64.b64decode(encrypted).decode('utf-8')

def decrypt_hex_array(hex_string):
    """Hex byte array decryption"""
    # Parse: new byte[]{0x48, 0x65, ...}
    hex_values = re.findall(r'0x([0-9a-fA-F]{2})', hex_string)
    return ''.join(chr(int(h, 16)) for h in hex_values)

def deobfuscate_strings(code):
    """Find and decrypt all encrypted strings"""

    # Pattern: b.a("...")
    for match in re.finditer(r'b\.a\("([^"]+)"\)', code):
        encrypted = match.group(1)
        decrypted = decrypt_rot13(encrypted)
        print(f"ROT13: {encrypted} -> {decrypted}")
        code = code.replace(match.group(0), f'"{decrypted}"')

    # Pattern: c.a(new byte[]{...})
    for match in re.finditer(r'c\.a\(new byte\[\]\{([^}]+)\}\)', code):
        hex_str = match.group(1)
        decrypted = decrypt_hex_array(hex_str)
        print(f"HEX: {hex_str} -> {decrypted}")
        code = code.replace(match.group(0), f'"{decrypted}"')

    # Pattern: d.a("...")
    for match in re.finditer(r'd\.a\("([^"]+)"\)', code):
        encrypted = match.group(1)
        decrypted = decrypt_base64(encrypted)
        print(f"BASE64: {encrypted} -> {decrypted}")
        code = code.replace(match.group(0), f'"{decrypted}"')

    return code

if __name__ == '__main__':
    obfuscated = open('obfuscated.java').read()
    deobfuscated = deobfuscate_strings(obfuscated)
    print(deobfuscated)
```

## Control Flow Flattening

### Flattened Code Pattern

```java
// Original code
public int calculate(int x) {
    int result = x * 2;
    if (result > 10) {
        result += 5;
    } else {
        result -= 3;
    }
    return result;
}

// After control flow flattening
public int calculate(int x) {
    int state = 0;
    int result = 0;

    while (true) {
        switch (state) {
            case 0:
                result = x * 2;
                state = 1;
                break;

            case 1:
                if (result > 10) {
                    state = 2;
                } else {
                    state = 3;
                }
                break;

            case 2:
                result += 5;
                state = 4;
                break;

            case 3:
                result -= 3;
                state = 4;
                break;

            case 4:
                return result;
        }
    }
}
```

### Deflattening Technique

```python
#!/usr/bin/env python3
"""
Deflatten control flow obfuscation
"""
import re

def extract_state_machine(code):
    """Parse flattened control flow"""
    states = {}

    # Find switch cases
    for match in re.finditer(r'case (\d+):\s*(.*?)(?:break;|return)', code, re.DOTALL):
        state_num = int(match.group(1))
        state_code = match.group(2).strip()
        states[state_num] = state_code

    return states

def build_cfg(states):
    """Build control flow graph"""
    cfg = {}

    for state_num, code in states.items():
        # Find next state assignment
        next_match = re.search(r'state = (\d+)', code)

        if next_match:
            next_state = int(next_match.group(1))
            cfg[state_num] = {'code': code, 'next': next_state}
        else:
            cfg[state_num] = {'code': code, 'next': None}

    return cfg

def reconstruct_linear_code(cfg, start_state=0):
    """Reconstruct linear code from CFG"""
    reconstructed = []
    current = start_state
    visited = set()

    while current is not None and current not in visited:
        visited.add(current)
        node = cfg[current]

        # Clean up code (remove state assignment)
        clean_code = re.sub(r'state = \d+;', '', node['code']).strip()
        reconstructed.append(clean_code)

        current = node['next']

    return '\\n'.join(reconstructed)

if __name__ == '__main__':
    flattened_code = open('flattened.java').read()
    states = extract_state_machine(flattened_code)
    cfg = build_cfg(states)
    linear = reconstruct_linear_code(cfg)
    print(linear)
```

## Native Library Packing

### Packed Library Detection

```bash
# Check for packing indicators
file libnative.so
# libnative.so: ELF 64-bit LSB shared object, ARM aarch64

# Check sections
readelf -S libnative.so | grep -E "(PACK|UPX|encrypt)"

# Entropy analysis (high entropy = likely packed/encrypted)
python3 -c "
import sys
import math
from collections import Counter

data = open('libnative.so', 'rb').read()
entropy = -sum(count/len(data) * math.log2(count/len(data))
               for count in Counter(data).values())
print(f'Entropy: {entropy:.2f} bits/byte')
# >7.5 bits/byte suggests encryption/packing
"
```

### Dynamic Unpacking

```javascript
// Frida script: dump_unpacked.js
'use strict';

const moduleName = "libnative.so";

// Hook dlopen to catch unpacking
Interceptor.attach(Module.findExportByName(null, "dlopen"), {
    onEnter: function(args) {
        const path = args[0].readCString();
        console.log(`[*] dlopen: ${path}`);
    },

    onLeave: function(retval) {
        if (!retval.isNull()) {
            const module = Process.findModuleByAddress(retval);
            console.log(`[*] Loaded: ${module.name} at ${module.base}`);

            // Dump unpacked library
            const size = module.size;
            const buffer = module.base.readByteArray(size);

            const file = new File(`/sdcard/${module.name}.unpacked`, 'wb');
            file.write(buffer);
            file.close();

            console.log(`[+] Dumped to /sdcard/${module.name}.unpacked`);
        }
    }
});

// Alternative: Hook mmap for runtime decryption
Interceptor.attach(Module.findExportByName(null, "mmap"), {
    onLeave: function(retval) {
        if (!retval.isNull()) {
            // Check if mapped region looks like ELF
            const magic = retval.readByteArray(4);
            const elf_magic = [0x7f, 0x45, 0x4c, 0x46];  // \x7fELF

            if (magic && magic[0] === elf_magic[0] &&
                magic[1] === elf_magic[1] &&
                magic[2] === elf_magic[2] &&
                magic[3] === elf_magic[3]) {

                console.log(`[!] ELF mapped at ${retval}`);

                // Dump decrypted code
                const dump_size = 0x100000;  // 1MB
                const buffer = retval.readByteArray(dump_size);

                const file = new File('/sdcard/decrypted_elf.so', 'wb');
                file.write(buffer);
                file.close();

                console.log('[+] Dumped decrypted ELF');
            }
        }
    }
});
```

## Conclusion

Android obfuscation analysis requires systematic approaches to reverse symbol renaming, decrypt strings, deflatten control flow, and unpack native libraries. Combining static analysis tools (ProGuard mappings, entropy analysis) with dynamic instrumentation (Frida runtime dumping) enables comprehensive deobfuscation.

## References

1. Google (2023). "R8 Code Shrinker"
2. ProGuard (2023). "ProGuard Manual"
3. Tigress (2023). "Control Flow Obfuscation"
4. Quarkslab (2020). "Android Native Library Unpacking"
