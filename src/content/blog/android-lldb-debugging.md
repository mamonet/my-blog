---
title: "Android Native Debugging with LLDB: From JNI Analysis to Exploit Development"
description: "Advanced Android native debugging techniques using LLDB, including remote debugging setup, JNI function analysis, memory inspection, breakpoint strategies, and exploit development workflows for ARM/ARM64 binaries."
pubDate: 2025-01-17
author: "Mamone Tarsia"
tags: ["reverse-engineering", "android", "debugging", "exploitation"]
draft: false
---

## Introduction

Android native code debugging requires specialized tools and techniques for ARM/ARM64 architectures. LLDB (LLVM Debugger) provides powerful capabilities for analyzing JNI functions, inspecting memory, and developing exploits for Android native vulnerabilities.

## LLDB Setup for Android

### Installing LLDB

```bash
# LLDB comes with Android NDK
export ANDROID_NDK=/path/to/android-ndk-r25c
export PATH=$ANDROID_NDK/toolchains/llvm/prebuilt/linux-x86_64/bin:$PATH

# Verify installation
lldb --version
# lldb version 14.0.6

# Android-specific lldb-server
ls $ANDROID_NDK/toolchains/llvm/prebuilt/linux-x86_64/lib64/clang/14.0.6/lib/linux/
# lldb-server-arm64.so
# lldb-server-armv7.so
```

### Remote Debugging Setup

```bash
# Push lldb-server to device
adb push $ANDROID_NDK/prebuilt/android-arm64/lldb-server/lldb-server /data/local/tmp/

# Start lldb-server on device
adb shell "chmod +x /data/local/tmp/lldb-server"
adb shell "/data/local/tmp/lldb-server platform --listen '*:1234' --server"

# Forward port to host
adb forward tcp:1234 tcp:1234

# Connect from host
lldb
(lldb) platform select remote-android
(lldb) platform connect connect://localhost:1234
  Platform: remote-android
 Connected: yes
```

### Attaching to Process

```bash
# Method 1: Attach to running process
(lldb) process attach --name com.example.app

# Method 2: Attach by PID
adb shell ps | grep com.example.app
# Get PID: 12345
(lldb) process attach --pid 12345

# Method 3: Launch and attach
(lldb) process launch --stop-at-entry -- /data/app/com.example.app/lib/arm64/libnative.so
```

## JNI Function Analysis

### Locating JNI Functions

```bash
# List loaded modules
(lldb) image list
[  0] /system/bin/app_process64
[  1] /system/lib64/libc.so
[  2] /data/app/com.example.app/lib/arm64/libnative.so

# Find JNI exports
(lldb) image lookup --regex --name "Java_" libnative.so
2 matches found in /data/app/com.example.app/lib/arm64/libnative.so:
        Address: libnative.so[0x0000000000001234] (libnative.so.PT_LOAD[0]..text + 4660)
        Summary: libnative.so`Java_com_example_Native_processData
        Address: libnative.so[0x0000000000005678] (libnative.so.PT_LOAD[0]..text + 22136)
        Summary: libnative.so`Java_com_example_Native_decrypt

# Set breakpoint on JNI function
(lldb) b Java_com_example_Native_processData
Breakpoint 1: where = libnative.so`Java_com_example_Native_processData, address = 0x00007a12345678
```

### Inspecting JNI Parameters

```c
// JNI function signature:
// JNIEXPORT jint JNICALL Java_com_example_Native_processData
//   (JNIEnv *env, jobject thiz, jbyteArray data, jint len);
//
// ARM64 calling convention:
// x0 = JNIEnv* env
// x1 = jobject thiz
// x2 = jbyteArray data
// x3 = jint len
```

**LLDB inspection**:

```
(lldb) b Java_com_example_Native_processData
Breakpoint hit

# Examine registers
(lldb) register read x0 x1 x2 x3
x0 = 0x00007a00000100  # JNIEnv*
x1 = 0x00007a00000200  # jobject
x2 = 0x00007a00000300  # jbyteArray
x3 = 0x0000000000000040  # len = 64

# Dereference JNIEnv to access JNI function table
(lldb) memory read --size 8 --count 1 $x0
0x7a00000100: 0x00007a12340000  # JNINativeInterface*

# Access GetByteArrayElements (offset 183)
(lldb) memory read --size 8 --format x 0x00007a12340000+183*8
0x7a123405b8: 0x00007a99887766

# Call JNI function to get array data
(lldb) expr void* (*GetByteArrayElements)(void*, void*, void*) = (void*(*)(void*,void*,void*))0x00007a99887766
(lldb) expr void* buf = GetByteArrayElements((void*)$x0, (void*)$x2, NULL)
(lldb) memory read --size 1 --count 64 buf
0x7b00001000: 41 42 43 44 45 46 47 48  ABCDEFGH
0x7b00001008: 49 4a 4b 4c 4d 4e 4f 50  IJKLMNOP
```

### JNI Function Hooking

```
# Set breakpoint and modify parameters
(lldb) b Java_com_example_Native_processData
(lldb) breakpoint command add 1
> expr $x3 = 0x1000  # Modify len parameter
> continue
> DONE

# Now function receives modified length
```

## Memory Inspection

### Reading Memory Regions

```
# Read as hex
(lldb) memory read --size 4 --format x --count 16 0x7a00000000
0x7a00000000: 0x464c457f 0x00010101 0x00000000 0x00000000
0x7a00000010: 0x00030003 0x00000001 0x00001234 0x00000000

# Read as instructions (disassemble)
(lldb) disassemble --start-address 0x7a12345678 --count 10
libnative.so`Java_com_example_Native_processData:
0x7a12345678:  stp    x29, x30, [sp, #-0x30]!
0x7a1234567c:  mov    x29, sp
0x7a12345680:  stp    x20, x19, [sp, #0x10]
0x7a12345684:  stp    x22, x21, [sp, #0x20]
0x7a12345688:  mov    x19, x0
0x7a1234568c:  mov    x20, x1
0x7a12345690:  mov    x21, x2
0x7a12345694:  mov    w22, w3

# Read as string
(lldb) memory read --format s 0x7a00010000
0x7a00010000: "Hello from native code"

# Search memory
(lldb) memory find --string "password" 0x7a00000000 0x7a10000000
data found at location: 0x7a00005678
```

### Writing Memory

```
# Write integer
(lldb) memory write 0x7a00001000 0x41424344
(lldb) memory read --size 4 --format x 0x7a00001000
0x7a00001000: 0x41424344

# Write bytes
(lldb) memory write 0x7a00001000 --infile /tmp/shellcode.bin

# Modify instruction (NOP out call)
(lldb) disassemble --start-address $pc --count 1
0x7a12345690:  bl     0x7a12340000  ; dangerous_function
(lldb) memory write $pc 0x1f2003d5  # NOP instruction (ARM64)
```

## Breakpoint Strategies

### Conditional Breakpoints

```
# Break only when specific condition is met
(lldb) b Java_com_example_Native_processData
(lldb) breakpoint modify 1 --condition "$x3 > 0x100"

# Break when accessing specific memory
(lldb) watchpoint set expression -- 0x7a00001000
(lldb) watchpoint modify 1 --condition "*(int*)0x7a00001000 == 0x41424344"
```

### Hardware Breakpoints

```
# Set hardware breakpoint (limited to 4 on ARM)
(lldb) breakpoint set --hardware --name vulnerable_function

# Hardware watchpoint (memory access)
(lldb) watchpoint set expression -- 0x7a00001000
(lldb) watchpoint modify 1 --watch read  # Break on read
(lldb) watchpoint modify 1 --watch write # Break on write
(lldb) watchpoint modify 1 --watch read_write  # Break on both
```

### Function Entry/Exit Hooks

```python
# LLDB Python script: log_calls.py
import lldb

def log_function_calls(debugger, command, result, internal_dict):
    target = debugger.GetSelectedTarget()
    process = target.GetProcess()

    # Set breakpoint on function
    bp = target.BreakpointCreateByName("Java_com_example_Native_processData")

    def breakpoint_callback(frame, bp_loc, dict):
        thread = frame.GetThread()
        process = thread.GetProcess()

        # Log parameters
        x0 = frame.FindRegister("x0").GetValueAsUnsigned()
        x1 = frame.FindRegister("x1").GetValueAsUnsigned()
        x2 = frame.FindRegister("x2").GetValueAsUnsigned()
        x3 = frame.FindRegister("x3").GetValueAsUnsigned()

        print(f"[*] processData called: env={hex(x0)}, thiz={hex(x1)}, data={hex(x2)}, len={x3}")

        return False  # Continue execution

    bp.SetScriptCallbackFunction("log_calls.breakpoint_callback")

# Load script in LLDB
# (lldb) command script import /path/to/log_calls.py
# (lldb) command script add -f log_calls.log_function_calls log_calls
```

## Stack and Heap Analysis

### Stack Trace

```
# Print backtrace
(lldb) bt
* thread #1, name = 'com.example.app', stop reason = breakpoint 1.1
  * frame #0: 0x00007a12345678 libnative.so`Java_com_example_Native_processData
    frame #1: 0x00007a99887766 libart.so`art_quick_generic_jni_trampoline
    frame #2: 0x00007a99889000 libart.so`art::Method::Invoke
    frame #3: 0x00007a9988a000 libart.so`art::JNI::CallIntMethodV
    frame #4: 0x00007a00001234 base.odex`com.example.Native.processData

# Select frame
(lldb) frame select 0

# Print local variables
(lldb) frame variable
(JNIEnv *) env = 0x00007a00000100
(jobject) thiz = 0x00007a00000200
(jbyteArray) data = 0x00007a00000300
(jint) len = 64

# Disassemble current function
(lldb) disassemble --frame
```

### Heap Inspection

```
# Find heap allocations
(lldb) image lookup --type "malloc"
(lldb) b malloc
(lldb) breakpoint command add 1
> bt
> register read x0  # Allocation size
> continue
> DONE

# Track allocation
(lldb) expr void* ptr = malloc(256)
(lldb) memory read $ptr

# Detect heap corruption
(lldb) watchpoint set expression -- $ptr
# If watchpoint triggers unexpectedly → heap corruption
```

## Exploit Development Workflow

### Vulnerability Analysis

```c
// Vulnerable function (simplified)
JNIEXPORT jint JNICALL
Java_com_example_Native_processData(JNIEnv* env, jobject thiz, jbyteArray data, jint len) {
    char buffer[256];

    jbyte* input = (*env)->GetByteArrayElements(env, data, NULL);

    // VULNERABLE: No length check
    memcpy(buffer, input, len);  // Stack overflow if len > 256

    (*env)->ReleaseByteArrayElements(env, data, input, 0);

    return process(buffer);
}
```

**LLDB analysis**:

```
# Set breakpoint before memcpy
(lldb) b 0x7a12345690  # Address of memcpy call

# Examine stack layout
(lldb) register read sp x29
sp = 0x007ffff000
x29 = 0x007ffff030  # Frame pointer

# Calculate buffer offset
(lldb) p/d (long)$x29 - (long)$sp
32  # Buffer starts at sp + 32

# Trigger overflow
(lldb) expr $x3 = 0x300  # Set len = 768 (overflow)
(lldb) continue

# Check for crash
Thread 1 stopped
* thread #1, name = 'com.example.app', stop reason = EXC_BAD_ACCESS (code=1, address=0x4141414141414141)
    frame #0: 0x4141414141414141
(lldb) bt
* thread #1, stop reason = EXC_BAD_ACCESS
  * frame #0: 0x4141414141414141

# RIP control achieved!
```

### ROP Gadget Hunting

```python
# Find ROP gadgets in loaded libraries
import lldb

def find_gadgets(debugger, command, result, internal_dict):
    target = debugger.GetSelectedTarget()
    module = target.FindModule(lldb.SBFileSpec("libnative.so"))

    text_section = module.FindSection(".text")
    start = text_section.GetLoadAddress(target)
    size = text_section.GetByteSize()

    # Search for gadgets
    gadgets = {
        "pop {r0, pc}": b"\x00\x80\xbd\xe8",  # ARM32
        "pop {x0, x30}; ret": b"\xfd\x7b\xc1\xa8\xc0\x03\x5f\xd6",  # ARM64
    }

    process = target.GetProcess()
    error = lldb.SBError()

    for name, pattern in gadgets.items():
        for offset in range(0, size - len(pattern)):
            addr = start + offset
            data = process.ReadMemory(addr, len(pattern), error)

            if data == pattern:
                print(f"[+] Found gadget '{name}' at {hex(addr)}")

# (lldb) command script import /path/to/find_gadgets.py
# (lldb) find_gadgets
```

### Shellcode Testing

```
# Allocate executable memory
(lldb) expr void* (*mmap_ptr)(void*, size_t, int, int, int, off_t) = (void*(*)(void*,size_t,int,int,int,off_t))dlsym((void*)-2, "mmap")
(lldb) expr void* shellcode_mem = mmap_ptr(NULL, 0x1000, 7, 0x22, -1, 0)  # PROT_READ|WRITE|EXEC

# Write shellcode
(lldb) memory write shellcode_mem --infile /tmp/shellcode.bin

# Execute shellcode
(lldb) expr ((void(*)())shellcode_mem)()

# Or set PC to shellcode
(lldb) register write pc shellcode_mem
(lldb) continue
```

## Frida + LLDB Integration

### Combining Tools

```javascript
// frida_lldb_bridge.js
'use strict';

// Frida script to help LLDB
const moduleName = "libnative.so";
const funcName = "Java_com_example_Native_processData";

const baseAddr = Module.findBaseAddress(moduleName);
const funcAddr = Module.findExportByName(moduleName, funcName);

console.log(`[*] Module base: ${baseAddr}`);
console.log(`[*] Function address: ${funcAddr}`);
console.log(`[*] LLDB commands:`);
console.log(`    (lldb) process attach --pid ${Process.id}`);
console.log(`    (lldb) b ${funcAddr}`);

// Hook to pause for LLDB attachment
Interceptor.attach(funcAddr, {
    onEnter: function(args) {
        console.log(`[*] Function called. Attach LLDB now!`);

        // Wait for debugger
        while (!Debug.isDebuggerPresent()) {
            Thread.sleep(0.1);
        }

        console.log(`[+] LLDB attached. Continuing...`);
    }
});
```

**Workflow**:

```bash
# Terminal 1: Start Frida
frida -U -f com.example.app -l frida_lldb_bridge.js --no-pause

# Terminal 2: Attach LLDB when prompted
lldb
(lldb) platform select remote-android
(lldb) platform connect connect://localhost:1234
(lldb) process attach --pid 12345
(lldb) b 0x7a12345678
(lldb) continue
```

## Debugging Anti-Debug Techniques

### Detecting ptrace

```c
// Anti-debug check
bool is_debugged() {
    int status = ptrace(PTRACE_TRACEME, 0, NULL, NULL);
    if (status < 0) {
        return true;  // Already being traced
    }
    ptrace(PTRACE_DETACH, 0, NULL, NULL);
    return false;
}
```

**Bypass with LLDB**:

```
# Hook ptrace
(lldb) b ptrace
(lldb) breakpoint command add 1
> expr $x0 = 0  # Change return value to 0 (success)
> expr $x0 = -1  # Or force error
> continue
> DONE

# Alternative: Patch check
(lldb) disassemble --name is_debugged
(lldb) memory write 0x7a12345690 0x52800000  # mov w0, #0 (return false)
```

### TracerPid Check

```bash
# Anti-debug: Read /proc/self/status
if (grep_file("/proc/self/status", "TracerPid:\\t0")) {
    // Not debugged
} else {
    // Debugged → exit
}
```

**Bypass**:

```
# Hook open/read syscalls
(lldb) b open
(lldb) breakpoint command add 1
> # Check if opening /proc/self/status
> expr char* path = (char*)$x0
> expr if (strcmp(path, "/proc/self/status") == 0) { $x0 = (long)"/dev/null"; }
> continue
> DONE
```

## LLDB Python Scripting

### Custom Commands

```python
# custom_commands.py
import lldb

def print_jni_string(debugger, command, result, internal_dict):
    """
    Print Java string from JNIEnv
    Usage: print_jni_string <jstring_addr>
    """
    target = debugger.GetSelectedTarget()
    process = target.GetProcess()
    frame = process.GetSelectedThread().GetSelectedFrame()

    # Get JNIEnv*
    env_ptr = frame.FindVariable("env").GetValueAsUnsigned()

    # Get GetStringUTFChars function (offset 169)
    jni_funcs = process.ReadPointerFromMemory(env_ptr, lldb.SBError())
    get_string_utf = process.ReadPointerFromMemory(jni_funcs + 169*8, lldb.SBError())

    # Call GetStringUTFChars
    jstring_addr = int(command, 16)
    # ... implementation ...

    print(f"String: {result}")

def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand('command script add -f custom_commands.print_jni_string print_jni_string')
    print("Custom commands loaded")
```

## Conclusion

LLDB provides comprehensive capabilities for Android native debugging, from basic memory inspection to advanced exploit development. Combining LLDB with Frida, understanding ARM calling conventions, and leveraging Python scripting enables deep analysis of Android native code and systematic vulnerability research.

Modern Android security increasingly depends on native code protections, making LLDB proficiency essential for security researchers and exploit developers.

## References

1. LLVM Project (2023). "LLDB Documentation"
2. Google (2023). "Android NDK Debugging"
3. ARM (2022). "ARM64 Procedure Call Standard"
4. Google Project Zero (2021). "Android Native Exploitation"
