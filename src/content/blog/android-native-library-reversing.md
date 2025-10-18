---
title: "Android Native Library Reverse Engineering: ARM Assembly to C++ Reconstruction"
description: "Advanced techniques for reversing Android native libraries, including ARM/ARM64 disassembly, JNI bridge analysis, C++ name demangling, vtable reconstruction, and automated decompilation workflows."
pubDate: 2025-07-02
author: "Mamoun Tarsha-Kurdi"
tags: ["reverse-engineering", "android", "arm", "jni"]
draft: false
---

## Introduction

Android native libraries (JNI) contain performance-critical code often implementing cryptography, DRM, and proprietary algorithms. Reversing these ARM/ARM64 binaries requires understanding JNI conventions, ARM calling standards, and C++ ABI internals.

## ARM Architecture Fundamentals

### ARM64 Registers and Calling Convention

```
General Purpose Registers:
x0-x7   : Function arguments / return values
x8      : Indirect result location
x9-x15  : Temporary registers
x16-x17 : Intra-procedure-call scratch registers
x18     : Platform register
x19-x28 : Callee-saved registers
x29     : Frame pointer (FP)
x30     : Link register (LR)
sp      : Stack pointer
pc      : Program counter
```

**Calling convention**:
```asm
; Function: int add(int a, int b, int c, int d)
;
; Parameters:
; w0 = a (32-bit)
; w1 = b
; w2 = c
; w3 = d
;
; Return value in w0

add_function:
    add w0, w0, w1  ; a + b
    add w0, w0, w2  ; + c
    add w0, w0, w3  ; + d
    ret             ; Return to caller (LR)
```

### ARM64 Instruction Set

Common instructions in native libraries:

```asm
; Load/Store
ldr x0, [x1]          ; Load 64-bit from [x1] into x0
ldr w0, [x1, #4]      ; Load 32-bit from [x1+4]
str x0, [x1]          ; Store x0 to [x1]
stp x29, x30, [sp, #-16]!  ; Store pair (push FP, LR)
ldp x29, x30, [sp], #16    ; Load pair (pop FP, LR)

; Arithmetic
add x0, x1, x2        ; x0 = x1 + x2
sub x0, x1, #0x10     ; x0 = x1 - 16
mul x0, x1, x2        ; x0 = x1 * x2

; Logic
and x0, x1, x2        ; x0 = x1 & x2
orr x0, x1, x2        ; x0 = x1 | x2
eor x0, x1, x2        ; x0 = x1 ^ x2

; Branches
b label               ; Unconditional branch
bl function           ; Branch with link (call)
ret                   ; Return (br x30)
cbz x0, label         ; Compare and branch if zero
cbnz x0, label        ; Compare and branch if not zero

; Comparisons
cmp x0, x1            ; Compare (sets flags)
b.eq label            ; Branch if equal
b.ne label            ; Branch if not equal
b.lt label            ; Branch if less than
b.gt label            ; Branch if greater than
```

## JNI Function Analysis

### JNI Naming Convention

```
Java_<package>_<class>_<method>

Example:
Java package: com.example.crypto
Class: NativeCrypto
Method: decrypt

JNI function: Java_com_example_crypto_NativeCrypto_decrypt
```

### JNI Function Signatures

```c
// Basic JNI function
JNIEXPORT jstring JNICALL
Java_com_example_Crypto_encrypt(
    JNIEnv* env,        // x0: JNI environment
    jobject thiz,       // x1: 'this' object
    jstring input       // x2: String parameter
);

// Static JNI function
JNIEXPORT jint JNICALL
Java_com_example_Crypto_initialize(
    JNIEnv* env,        // x0
    jclass clazz        // x1: Class object (not 'this')
);

// Multiple parameters
JNIEXPORT jbyteArray JNICALL
Java_com_example_Crypto_process(
    JNIEnv* env,        // x0
    jobject thiz,       // x1
    jbyteArray data,    // x2
    jint length,        // x3
    jint mode           // x4
);
```

### Reversing JNI Functions in Ghidra

```c
// Ghidra decompilation of JNI function
undefined8 Java_com_example_Crypto_decrypt(long env, long thiz, long encrypted) {
    long decrypted;
    int len;
    byte* enc_buf;
    byte* dec_buf;

    // GetByteArrayLength (offset 171 in JNINativeInterface)
    len = *(code**)(*(long*)env + 0x558)(env, encrypted);

    // GetByteArrayElements (offset 183)
    enc_buf = *(code**)(*(long*)env + 0x5b8)(env, encrypted, (long*)0x0);

    // Allocate output buffer
    dec_buf = (byte*)malloc(len);

    // Decrypt (custom algorithm)
    for (int i = 0; i < len; i++) {
        dec_buf[i] = enc_buf[i] ^ 0xAA;  // Simple XOR
    }

    // ReleaseByteArrayElements (offset 184)
    *(code**)(*(long*)env + 0x5c0)(env, encrypted, enc_buf, 0);

    // NewByteArray (offset 175)
    decrypted = *(code**)(*(long*)env + 0x578)(env, len);

    // SetByteArrayRegion (offset 186)
    *(code**)(*(long*)env + 0x5d0)(env, decrypted, 0, len, dec_buf);

    free(dec_buf);
    return decrypted;
}
```

### JNIEnv Function Table

```c
// JNINativeInterface structure (partial)
struct JNINativeInterface {
    void* reserved0;
    // ... (many entries)

    // Array operations
    jsize (*GetArrayLength)(JNIEnv*, jarray);         // Offset 171
    jobjectArray (*NewObjectArray)(JNIEnv*, jsize, jclass, jobject);  // 172
    jobject (*GetObjectArrayElement)(JNIEnv*, jobjectArray, jsize);   // 173

    // Byte array
    jbyteArray (*NewByteArray)(JNIEnv*, jsize);       // 175
    // ... other primitive arrays

    // Get primitive array elements
    jboolean* (*GetBooleanArrayElements)(JNIEnv*, jbooleanArray, jboolean*);  // 179
    jbyte* (*GetByteArrayElements)(JNIEnv*, jbyteArray, jboolean*);           // 183

    // Release primitive array elements
    void (*ReleaseBooleanArrayElements)(JNIEnv*, jbooleanArray, jboolean*, jint);  // 180
    void (*ReleaseByteArrayElements)(JNIEnv*, jbyteArray, jbyte*, jint);            // 184
};

// Calculate offset
// GetByteArrayElements is at index 183
// Offset = 183 * sizeof(void*) = 183 * 8 = 0x5B8
```

## C++ ABI Reverse Engineering

### Name Demangling

```bash
# Mangled names in shared library
nm -D libnative.so | grep "_Z"
000000000001234 T _ZN7Example6Crypto7decryptERKNSt6stringE

# Demangle
c++filt _ZN7Example6Crypto7decryptERKNSt6stringE
# Output: Example::Crypto::decrypt(std::string const&)
```

### Vtable Reconstruction

```c
// C++ class with virtual methods
class Crypto {
public:
    virtual ~Crypto();
    virtual int encrypt(const char* data, int len);
    virtual int decrypt(const char* data, int len);
private:
    uint8_t key[16];
};

// Disassembly shows vtable
/*
.data:0000000000010000 vtable_Crypto:
.data:0000000000010000   dq offset _ZN6CryptoD1Ev  ; destructor
.data:0000000000010008   dq offset _ZN6CryptoD0Ev  ; deleting destructor
.data:0000000000010010   dq offset _ZN6Crypto7encryptEPKci  ; encrypt
.data:0000000000010018   dq offset _ZN6Crypto7decryptEPKci  ; decrypt
*/

// Ghidra struct
struct Crypto_vtable {
    void (*destructor)(Crypto*);
    void (*deleting_destructor)(Crypto*);
    int (*encrypt)(Crypto*, const char*, int);
    int (*decrypt)(Crypto*, const char*, int);
};

struct Crypto {
    Crypto_vtable* vtable;  // Offset 0
    uint8_t key[16];        // Offset 8
};
```

### Virtual Function Call Analysis

```asm
; C++ code: obj->decrypt(data, len)
;
; Disassembly:
ldr x8, [x0]              ; Load vtable pointer from object
ldr x9, [x8, #0x18]       ; Load decrypt function pointer (offset 0x18)
blr x9                    ; Call decrypt

; Reconstruct:
; 1. x0 = this pointer (Crypto object)
; 2. vtable at offset 0
; 3. decrypt() at vtable offset 0x18 (3rd virtual function)
```

## Static Analysis Workflow

### IDA Pro Analysis

```python
# IDA Python script: analyze_jni.py
import idaapi
import idc
import idautils

def find_jni_functions():
    """Find all JNI functions in binary"""
    jni_funcs = []

    for func_ea in idautils.Functions():
        func_name = idc.get_func_name(func_ea)

        if func_name.startswith("Java_"):
            jni_funcs.append((func_ea, func_name))

    return jni_funcs

def parse_jni_name(jni_name):
    """Parse JNI function name"""
    # Java_com_example_Class_method
    parts = jni_name.replace("Java_", "").split("_")

    package = ".".join(parts[:-2])
    class_name = parts[-2]
    method = parts[-1]

    return {
        'package': package,
        'class': class_name,
        'method': method
    }

def analyze_jni_function(func_ea):
    """Analyze JNI function parameters"""
    func = idaapi.get_func(func_ea)

    # ARM64: Parameters in x0-x7
    # x0 = JNIEnv*
    # x1 = jobject/jclass
    # x2+ = actual parameters

    print(f"[*] Analyzing {idc.get_func_name(func_ea)}")

    # Find JNI API calls
    for head in idautils.Heads(func.start_ea, func.end_ea):
        if idc.print_insn_mnem(head) == "BLR":
            # Indirect call (likely JNI function)
            print(f"  JNI call at {hex(head)}")

if __name__ == "__main__":
    jni_funcs = find_jni_functions()

    for ea, name in jni_funcs:
        info = parse_jni_name(name)
        print(f"\n{info['package']}.{info['class']}.{info['method']}()")
        analyze_jni_function(ea)
```

### Ghidra Scripting

```java
// Ghidra script: JNI_Analyzer.java
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;

public class JNI_Analyzer extends GhidraScript {
    @Override
    public void run() throws Exception {
        SymbolTable symTable = currentProgram.getSymbolTable();

        for (Symbol sym : symTable.getAllSymbols(true)) {
            String name = sym.getName();

            if (name.startsWith("Java_")) {
                analyzeJNIFunction(sym.getAddress(), name);
            }
        }
    }

    private void analyzeJNIFunction(Address addr, String name) {
        println("\\n[*] " + name);

        Function func = getFunctionAt(addr);
        if (func == null) {
            println("  Not a function");
            return;
        }

        // Set function signature
        // JNIEXPORT <type> JNICALL name(JNIEnv*, jobject, ...)
        String signature = "undefined8 " + name + "(long env, long thiz)";
        println("  Signature: " + signature);

        // TODO: Parse parameters from Java signature
    }
}
```

## Dynamic Analysis Techniques

### Frida Hooking

```javascript
// Hook JNI function
'use strict';

const moduleName = "libnative.so";
const jniFunc = "Java_com_example_Crypto_decrypt";

const addr = Module.findExportByName(moduleName, jniFunc);
console.log(`[*] ${jniFunc} at ${addr}`);

Interceptor.attach(addr, {
    onEnter: function(args) {
        // args[0] = JNIEnv*
        // args[1] = jobject thiz
        // args[2] = jbyteArray encrypted

        const env = args[0];
        const encrypted = args[2];

        // Get array length
        const GetArrayLength = new NativeFunction(
            env.add(171 * Process.pointerSize).readPointer(),
            'int', ['pointer', 'pointer']
        );
        const len = GetArrayLength(env, encrypted);

        // Get array elements
        const GetByteArrayElements = new NativeFunction(
            env.add(183 * Process.pointerSize).readPointer(),
            'pointer', ['pointer', 'pointer', 'pointer']
        );
        const buf = GetByteArrayElements(env, encrypted, NULL);

        console.log("[*] Encrypted data:");
        console.log(hexdump(buf, { length: len }));

        // Save for onLeave
        this.env = env;
        this.len = len;
    },

    onLeave: function(retval) {
        // retval = jbyteArray (decrypted)

        const GetByteArrayElements = new NativeFunction(
            this.env.add(183 * Process.pointerSize).readPointer(),
            'pointer', ['pointer', 'pointer', 'pointer']
        );
        const buf = GetByteArrayElements(this.env, retval, NULL);

        console.log("[*] Decrypted data:");
        console.log(hexdump(buf, { length: this.len }));
    }
});
```

## Automated Reconstruction

### Decompiler Output Cleanup

```python
#!/usr/bin/env python3
"""
Clean up Ghidra decompiler output for readability
"""
import re

def cleanup_ghidra_code(code):
    """Transform Ghidra output to readable C"""

    # Replace undefined types
    code = re.sub(r'undefined8', 'uint64_t', code)
    code = re.sub(r'undefined4', 'uint32_t', code)
    code = re.sub(r'undefined', 'uint8_t', code)

    # Replace JNI function table accesses
    jni_functions = {
        '0x558': 'GetByteArrayLength',
        '0x5b8': 'GetByteArrayElements',
        '0x5c0': 'ReleaseByteArrayElements',
        '0x578': 'NewByteArray',
        '0x5d0': 'SetByteArrayRegion',
    }

    for offset, name in jni_functions.items():
        pattern = rf'\*\(code\*\*\)\(\*\(long\*\)env \+ {offset}\)'
        code = re.sub(pattern, name, code)

    # Clean up casts
    code = re.sub(r'\(long\*\)0x0', 'NULL', code)

    return code

if __name__ == '__main__':
    ghidra_output = open('decompiled.c').read()
    cleaned = cleanup_ghidra_code(ghidra_output)
    print(cleaned)
```

## Conclusion

Android native library reverse engineering combines ARM architecture knowledge, JNI internals understanding, and C++ ABI familiarity. Systematic analysis using IDA/Ghidra for static analysis and Frida for dynamic instrumentation enables reconstruction of proprietary algorithms and discovery of vulnerabilities in compiled code.

## References

1. ARM (2022). "ARM Architecture Reference Manual"
2. Oracle (2023). "Java Native Interface Specification"
3. Itanium (2023). "Itanium C++ ABI"
4. Google (2023). "Android NDK Documentation"
