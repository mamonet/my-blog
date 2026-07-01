---
title: "Android Fuzzing: AFL++, Frida, and Coverage-Guided Native Library Testing"
description: "Comprehensive guide to fuzzing Android applications and native libraries using AFL++, libFuzzer, Frida-based in-memory fuzzing, and coverage instrumentation for discovering memory corruption vulnerabilities in ARM/ARM64 code."
pubDate: 2024-09-11
author: "Mamone Tarsia"
tags: ["reverse-engineering", "android", "fuzzing", "vulnerabilities"]
draft: false
---

## Introduction

Android applications increasingly rely on native libraries (C/C++ via JNI) for performance-critical operations, making them susceptible to memory corruption vulnerabilities. Fuzzing these components requires specialized techniques for ARM architecture, cross-compilation, and Android runtime integration.

## Android Fuzzing Landscape

### Attack Surface Analysis

```bash
# Extract and analyze APK
apktool d app.apk -o app_decompiled

# Find native libraries
find app_decompiled/lib -name "*.so"
# Output:
# lib/arm64-v8a/libnative.so
# lib/armeabi-v7a/libnative.so

# Identify JNI functions
nm -D app_decompiled/lib/arm64-v8a/libnative.so | grep Java_
# Output:
# 0000000000001234 T Java_com_example_Native_processData
# 0000000000005678 T Java_com_example_Native_decryptBuffer
```

**Interesting targets**:
- Image/video codecs
- Cryptographic implementations
- Compression libraries
- Network protocol parsers
- File format parsers

## AFL++ for Android

### Cross-Compilation Setup

```bash
# Install Android NDK
export ANDROID_NDK=/path/to/android-ndk-r25c

# Clone AFL++
git clone https://github.com/AFLplusplus/AFLplusplus.git
cd AFLplusplus
make

# Build AFL++ for Android ARM64
export CC=$ANDROID_NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android33-clang
export CXX=$ANDROID_NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android33-clang++

make clean
make AFL_NO_X86=1 ANDROID=1

# Output: afl-fuzz, afl-clang-fast for ARM64
```

### Instrumenting Native Libraries

```c
// Target: native library with parsing function
// File: native.c
#include <jni.h>
#include <string.h>

JNIEXPORT jint JNICALL
Java_com_example_Native_parseData(JNIEnv* env, jobject thiz, jbyteArray data) {
    jsize len = (*env)->GetArrayLength(env, data);
    jbyte* buffer = (*env)->GetByteArrayElements(env, data, NULL);

    // VULNERABLE: No length validation
    char internal_buf[256];
    memcpy(internal_buf, buffer, len);  // Buffer overflow!

    (*env)->ReleaseByteArrayElements(env, data, buffer, 0);

    return process_buffer(internal_buf, len);
}
```

**Compile with AFL++ instrumentation**:

```bash
# CMakeLists.txt for fuzzing harness
cmake_minimum_required(VERSION 3.18)
project(FuzzNative)

set(CMAKE_C_COMPILER /path/to/AFLplusplus/afl-clang-fast)
set(CMAKE_C_FLAGS "-fsanitize=address -g")

add_executable(fuzz_harness
    harness.c
    native.c
)
```

### Standalone Fuzzing Harness

```c
// harness.c - Standalone fuzzer without Android runtime
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Mock JNI environment for fuzzing
extern int process_buffer(const char* buf, size_t len);

#ifdef __AFL_HAVE_MANUAL_CONTROL
__AFL_FUZZ_INIT();
#endif

int main(int argc, char** argv) {
#ifdef __AFL_HAVE_MANUAL_CONTROL
    // Persistent mode
    __AFL_INIT();

    unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;

    while (__AFL_LOOP(10000)) {
        int len = __AFL_FUZZ_TESTCASE_LEN;

        // Call target function
        process_buffer((const char*)buf, len);
    }

#else
    // File-based mode
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <input_file>\n", argv[0]);
        return 1;
    }

    FILE* f = fopen(argv[1], "rb");
    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    fseek(f, 0, SEEK_SET);

    unsigned char* buf = malloc(len);
    fread(buf, 1, len, f);
    fclose(f);

    process_buffer((const char*)buf, len);
    free(buf);
#endif

    return 0;
}
```

**Build and run**:

```bash
# Build with AFL++ compiler
afl-clang-fast -fsanitize=address -o fuzz_harness harness.c native.c

# Create corpus
mkdir input output
echo "VALID_DATA" > input/seed1.bin

# Run AFL++
afl-fuzz -i input -o output -m none -- ./fuzz_harness @@
```

## libFuzzer Integration

### libFuzzer Harness

```cpp
// fuzz_target.cpp
#include <stdint.h>
#include <stddef.h>

extern "C" int process_buffer(const char* buf, size_t len);

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0) return 0;

    // Call target function
    process_buffer((const char*)data, size);

    return 0;
}
```

**Build with Clang**:

```bash
# Use Android NDK Clang with libFuzzer
$ANDROID_NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android33-clang++ \
    -fsanitize=fuzzer,address \
    -o fuzz_target \
    fuzz_target.cpp native.c

# Run on device
adb push fuzz_target /data/local/tmp/
adb shell /data/local/tmp/fuzz_target

# Or with corpus
adb push corpus /data/local/tmp/
adb shell /data/local/tmp/fuzz_target /data/local/tmp/corpus -max_total_time=3600
```

## Frida-Based In-Memory Fuzzing

### Instrumentation Script

```javascript
// frida_fuzzer.js
'use strict';

// Attach to running app
const moduleName = "libnative.so";
const targetFunc = "Java_com_example_Native_parseData";

const baseAddr = Module.findBaseAddress(moduleName);
const funcAddr = Module.findExportByName(moduleName, targetFunc);

console.log(`[*] Module base: ${baseAddr}`);
console.log(`[*] Target function: ${funcAddr}`);

// Hook target function
Interceptor.attach(funcAddr, {
    onEnter: function(args) {
        // args[0] = JNIEnv*
        // args[1] = jobject (this)
        // args[2] = jbyteArray (data)

        const env = args[0];
        const dataArray = args[2];

        // Get array length
        const getArrayLength = new NativeFunction(
            env.add(Process.pointerSize * 171).readPointer(),
            'int', ['pointer', 'pointer']
        );
        const len = getArrayLength(env, dataArray);

        console.log(`[*] parseData called with length: ${len}`);

        // Save context for mutation
        this.env = env;
        this.dataArray = dataArray;
        this.originalLen = len;
    },

    onLeave: function(retval) {
        console.log(`[*] Return value: ${retval}`);
    }
});

// Mutation function
function mutateInput(env, dataArray, originalLen) {
    // Get byte array
    const getByteArrayElements = new NativeFunction(
        env.add(Process.pointerSize * 183).readPointer(),
        'pointer', ['pointer', 'pointer', 'pointer']
    );

    const buffer = getByteArrayElements(env, dataArray, NULL);

    // Apply mutations
    const mutations = [
        () => { /* Bit flip */ Memory.writeU8(buffer, Memory.readU8(buffer) ^ 0xFF); },
        () => { /* Byte replace */ Memory.writeU8(buffer, 0x41); },
        () => { /* Integer overflow */ Memory.writeU32(buffer, 0xFFFFFFFF); },
    ];

    const mutation = mutations[Math.floor(Math.random() * mutations.length)];
    mutation();

    // Release array
    const releaseByteArrayElements = new NativeFunction(
        env.add(Process.pointerSize * 184).readPointer(),
        'void', ['pointer', 'pointer', 'pointer', 'int']
    );
    releaseByteArrayElements(env, dataArray, buffer, 0);
}

console.log("[*] Fuzzing harness ready");
```

**Run fuzzer**:

```bash
# Attach to running app
frida -U -f com.example.app -l frida_fuzzer.js --no-pause

# Or spawn and attach
frida -U com.example.app -l frida_fuzzer.js
```

### Crash Detection

```javascript
// crash_detector.js
'use strict';

// Monitor for crashes
Process.setExceptionHandler(function(details) {
    console.log("[!] CRASH DETECTED!");
    console.log("Type:", details.type);
    console.log("Address:", details.address);
    console.log("Memory:", JSON.stringify(details.memory));
    console.log("Context:", JSON.stringify(details.context));

    // Log crash to file
    const timestamp = Date.now();
    const crashFile = `/sdcard/crash_${timestamp}.json`;

    const file = new File(crashFile, 'w');
    file.write(JSON.stringify(details, null, 2));
    file.close();

    console.log(`[+] Crash saved to ${crashFile}`);

    return true;  // Don't terminate
});

// Also hook abort/signal handlers
Interceptor.attach(Module.findExportByName(null, 'abort'), {
    onEnter: function() {
        console.log("[!] abort() called");
        console.log(Thread.backtrace(this.context).map(DebugSymbol.fromAddress).join('\n'));
    }
});
```

## Coverage-Guided Fuzzing

### SanitizerCoverage Integration

```c
// Build with coverage instrumentation
// Add to CMakeLists.txt:
set(CMAKE_C_FLAGS "-fsanitize=address -fsanitize-coverage=trace-pc-guard")

// Coverage callback
extern "C" void __sanitizer_cov_trace_pc_guard(uint32_t *guard) {
    if (!*guard) return;

    // Log coverage to shared memory for AFL++
    void *addr = __builtin_return_address(0);

    // Update AFL++ bitmap
    extern unsigned char __afl_area_ptr[65536];
    uint32_t edge = ((uintptr_t)addr) ^ ((uintptr_t)guard);
    __afl_area_ptr[edge % 65536]++;
}
```

### Frida Coverage Tracking

```javascript
// coverage_tracer.js
'use strict';

const moduleName = "libnative.so";
const module = Process.getModuleByName(moduleName);

const coverage = new Map();

// Instrument all basic blocks
const stalker = Stalker.follow({
    events: {
        call: false,
        ret: false,
        exec: true,  // Basic block execution
        block: false,
        compile: false
    },
    onReceive: function(events) {
        const parsedEvents = Stalker.parse(events, {
            annotate: false,
            stringify: false
        });

        for (const event of parsedEvents) {
            if (event[0] === 'exec') {
                const addr = event[1];

                // Only track our module
                if (addr >= module.base && addr < module.base.add(module.size)) {
                    const offset = addr.sub(module.base);
                    coverage.set(offset.toString(), (coverage.get(offset.toString()) || 0) + 1);
                }
            }
        }
    }
});

// Dump coverage after fuzzing
rpc.exports = {
    dumpCoverage: function() {
        const sorted = Array.from(coverage.entries()).sort((a, b) => b[1] - a[1]);
        return sorted;
    },

    getCoverageCount: function() {
        return coverage.size;
    }
};

console.log("[*] Coverage tracing started");
```

## On-Device Fuzzing

### Android System Fuzzing

```bash
# Push fuzzer to device
adb push fuzz_harness /data/local/tmp/
adb push corpus /data/local/tmp/corpus
adb shell chmod +x /data/local/tmp/fuzz_harness

# Run on device
adb shell "cd /data/local/tmp && ./fuzz_harness -i corpus -o crashes @@"

# Monitor crashes
adb logcat -s DEBUG
```

### Continuous Fuzzing

```python
#!/usr/bin/env python3
"""
Continuous Android fuzzing automation
"""
import subprocess
import time
import os

def push_fuzzer(device_id, fuzzer_path, corpus_path):
    """Push fuzzer and corpus to device"""
    subprocess.run(['adb', '-s', device_id, 'push', fuzzer_path, '/data/local/tmp/'])
    subprocess.run(['adb', '-s', device_id, 'push', corpus_path, '/data/local/tmp/corpus/'])
    subprocess.run(['adb', '-s', device_id, 'shell', 'chmod', '+x', '/data/local/tmp/fuzz_harness'])

def start_fuzzer(device_id):
    """Start fuzzer in background"""
    cmd = [
        'adb', '-s', device_id, 'shell',
        'cd /data/local/tmp && '
        './fuzz_harness -i corpus -o crashes -m none -t 1000 @@'
    ]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return proc

def monitor_crashes(device_id, output_dir):
    """Monitor and download crashes"""
    while True:
        time.sleep(60)  # Check every minute

        # List crash files
        result = subprocess.run(
            ['adb', '-s', device_id, 'shell', 'ls', '/data/local/tmp/crashes/crashes/'],
            capture_output=True, text=True
        )

        crash_files = result.stdout.strip().split('\n')

        for crash_file in crash_files:
            if crash_file.startswith('id:'):
                local_path = os.path.join(output_dir, crash_file)

                if not os.path.exists(local_path):
                    # Download crash
                    subprocess.run([
                        'adb', '-s', device_id, 'pull',
                        f'/data/local/tmp/crashes/crashes/{crash_file}',
                        local_path
                    ])
                    print(f"[+] New crash: {crash_file}")

                    # Analyze crash
                    analyze_crash(local_path)

def analyze_crash(crash_file):
    """Analyze crash file"""
    print(f"[*] Analyzing {crash_file}")

    # Run with ASAN
    result = subprocess.run(
        ['./fuzz_harness', crash_file],
        capture_output=True, text=True,
        env={'ASAN_OPTIONS': 'symbolize=1'}
    )

    if 'AddressSanitizer' in result.stderr:
        print(f"[!] ASAN violation detected")
        print(result.stderr)

if __name__ == '__main__':
    device_id = subprocess.run(['adb', 'devices', '-l'], capture_output=True, text=True)
    device_id = device_id.stdout.split('\n')[1].split()[0]

    push_fuzzer(device_id, './fuzz_harness', './corpus')
    start_fuzzer(device_id)
    monitor_crashes(device_id, './crashes_local')
```

## Crash Triage

### ASAN Output Analysis

```
=================================================================
==12345==ERROR: AddressSanitizer: heap-buffer-overflow on address 0xb4000000 at pc 0xb6f12340 bp 0xbefff000 sp 0xbeffeff0
WRITE of size 512 at 0xb4000100 thread T0
    #0 0xb6f12340 in memcpy /build/glibc/string/memcpy.c:123
    #1 0xb6f23456 in process_buffer /app/native.c:45
    #2 0xb6f34567 in Java_com_example_Native_parseData /app/native.c:78

0xb4000100 is located 0 bytes to the right of 256-byte region [0xb4000000,0xb4000100)
allocated by thread T0 here:
    #0 0xb6e12345 in malloc
    #1 0xb6f23400 in process_buffer /app/native.c:42

SUMMARY: AddressSanitizer: heap-buffer-overflow /build/glibc/string/memcpy.c:123 in memcpy
```

**Analysis**:
- **Type**: Heap buffer overflow
- **Location**: `process_buffer()` at native.c:45
- **Root cause**: Writes 512 bytes to 256-byte buffer
- **Exploitability**: Likely exploitable (controlled overflow size)

### Automated Crash Deduplication

```python
import hashlib
import os
import subprocess

def get_crash_signature(crash_file, harness):
    """Generate unique crash signature from ASAN output"""
    result = subprocess.run(
        [harness, crash_file],
        capture_output=True,
        text=True,
        env={'ASAN_OPTIONS': 'symbolize=1'}
    )

    # Extract stack trace
    lines = result.stderr.split('\n')
    stack_trace = []

    for line in lines:
        if line.strip().startswith('#'):
            # Parse frame
            parts = line.split()
            if len(parts) >= 3:
                func_name = parts[3] if len(parts) > 3 else parts[2]
                stack_trace.append(func_name)

    # Hash first 5 frames
    signature = '|'.join(stack_trace[:5])
    return hashlib.md5(signature.encode()).hexdigest()

def deduplicate_crashes(crash_dir, harness):
    """Group crashes by unique signature"""
    buckets = {}

    for filename in os.listdir(crash_dir):
        if filename.startswith('id:'):
            path = os.path.join(crash_dir, filename)
            sig = get_crash_signature(path, harness)

            if sig not in buckets:
                buckets[sig] = []

            buckets[sig].append(filename)

    # Print unique crashes
    for i, (sig, files) in enumerate(buckets.items()):
        print(f"\n[*] Crash bucket {i} ({len(files)} samples)")
        print(f"    Signature: {sig}")
        print(f"    Representative: {files[0]}")

    return buckets
```

## Case Studies

### CVE-2020-0451: Android Media Framework

**Target**: libstagefright (media codec library)

**Vulnerability**: Heap buffer overflow in MPEG4 parser

**Fuzzing approach**:

```c
// Harness for MPEG4 parser
#include <media/stagefright/MediaExtractor.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Create data source from input
    sp<DataSource> source = DataSourceFactory::CreateFromURI(
        NULL, "file:///fuzzing_input.mp4", NULL
    );

    // Attempt to parse
    sp<MediaExtractor> extractor = MediaExtractorFactory::Create(source);

    if (extractor != NULL) {
        size_t numTracks = extractor->countTracks();
        for (size_t i = 0; i < numTracks; i++) {
            sp<MediaSource> track = extractor->getTrack(i);
            track->start();
            // ... trigger parsing
        }
    }

    return 0;
}
```

**Results**: Discovered heap overflow leading to RCE via MMS.

## Conclusion

Android fuzzing requires tailored approaches for native code testing, cross-architecture compilation, and device-specific constraints. Combining AFL++, libFuzzer, and Frida enables comprehensive coverage of Android attack surfaces, from standalone libraries to integrated JNI components.

Modern Android vulnerabilities increasingly reside in native code, making systematic fuzzing essential for security research and proactive vulnerability discovery.

## References

1. Google (2023). "Android libFuzzer Integration"
2. AFLplusplus (2023). "Fuzzing on Android"
3. Quarkslab (2020). "Frida-based In-Memory Fuzzing"
4. Google Project Zero (2020). "Android Media Framework Vulnerabilities"
