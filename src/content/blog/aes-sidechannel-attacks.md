---
title: "AES Side-Channel Attacks: Cache Timing and Power Analysis Vulnerabilities"
description: "Practical analysis of side-channel vulnerabilities in AES implementations, including cache-timing attacks, differential power analysis (DPA), and constant-time mitigation techniques."
pubDate: 2023-06-12
author: "Mamoun Tarsha-Kurdi"
tags: ["cryptography", "vulnerabilities", "aes", "side-channels"]
draft: false
---

## Introduction

While AES is mathematically secure, real-world implementations leak information through physical side channels: timing, power consumption, and electromagnetic radiation. Understanding these attacks is essential for secure implementation.

## AES Algorithm Review

### Structure

AES-128 processes 128-bit blocks using 10 rounds:

```python
def aes_encrypt(plaintext, key):
    """
    AES-128 encryption
    """
    state = plaintext
    round_keys = key_expansion(key)  # Generate 11 round keys

    # Initial round
    state = add_round_key(state, round_keys[0])

    # Main rounds (9 rounds)
    for round_num in range(1, 10):
        state = sub_bytes(state)        # S-box substitution
        state = shift_rows(state)       # Row permutation
        state = mix_columns(state)      # Column mixing
        state = add_round_key(state, round_keys[round_num])

    # Final round (no MixColumns)
    state = sub_bytes(state)
    state = shift_rows(state)
    state = add_round_key(state, round_keys[10])

    return state
```

### S-Box Lookup

The S-box is the only non-linear component:

```python
# Rijndael S-box (256 bytes)
SBOX = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
    # ... (256 total values)
]

def sub_bytes(state):
    """Apply S-box to each byte"""
    return bytes([SBOX[b] for b in state])
```

**Vulnerability**: Table lookups leak information through cache timing!

## Cache-Timing Attacks

### CPU Cache Basics

Modern CPUs use multi-level caches:

```
L1: 32 KB, ~4 cycles
L2: 256 KB, ~12 cycles
L3: 8 MB, ~40 cycles
RAM: GB, ~200 cycles
```

**Cache line**: 64 bytes loaded together

### Vulnerability in Table-Based AES

Standard implementation uses pre-computed tables:

```python
# T-tables for fast AES (per-round lookup tables)
T0 = [
    0xc66363a5, 0xf87c7c84, 0xee777799, 0xf67b7b8d,
    # ... 256 entries of 32-bit values
]

def aes_round_fast(state, round_key):
    """
    Fast AES using T-tables
    VULNERABLE to cache timing!
    """
    result = [0] * 16

    for i in range(4):
        result[4*i:4*i+4] = (
            T0[state[4*i]] ^
            T1[state[4*i+1]] ^
            T2[state[4*i+2]] ^
            T3[state[4*i+3]] ^
            round_key[4*i:4*i+4]
        )

    return bytes(result)
```

### Attack Mechanism

**Observation**: Table access time depends on cache state.

```python
def measure_access_time(table, index):
    """Measure time to access table[index]"""
    start = time.perf_counter_ns()
    value = table[index]  # Access
    end = time.perf_counter_ns()
    return end - start

# Cache hit: ~4 ns
# Cache miss: ~200 ns (50x slower!)
```

**Attack**: Observe encryption timing for different plaintexts.

### Bernstein's Attack (2005)

First practical remote cache-timing attack on AES:

```python
def cache_timing_attack(encryption_oracle):
    """
    Recover AES key by timing S-box accesses
    Works even over network with ~15ms precision!
    """
    key_candidate_scores = [[0] * 256 for _ in range(16)]

    for trial in range(10000):
        # Choose plaintext to isolate key byte
        plaintext = os.urandom(16)

        # Measure encryption time
        start = time.perf_counter_ns()
        ciphertext = encryption_oracle(plaintext)
        elapsed = time.perf_counter_ns() - start

        # Correlation: timing variations depend on S-box access pattern
        # which depends on plaintext XOR key
        for byte_pos in range(16):
            for key_guess in range(256):
                # Predict S-box index
                sbox_index = plaintext[byte_pos] ^ key_guess

                # Cache line accessed (64-byte aligned)
                cache_line = sbox_index // (64 // 4)  # 16 S-box entries per line

                # Score based on timing
                if elapsed > THRESHOLD:  # Cache miss likely
                    key_candidate_scores[byte_pos][key_guess] += 1

    # Most likely key bytes
    recovered_key = bytes([
        max(range(256), key=lambda k: scores[k])
        for scores in key_candidate_scores
    ])

    return recovered_key
```

**Success rate**: ~90% with 2^20 samples
**Requirements**: Same CPU, shared cache

### Prime+Probe Attack

More powerful technique:

```python
def prime_cache():
    """Fill cache with attacker's data"""
    dummy_array = bytearray(32 * 1024)  # Fill L1 cache
    for i in range(len(dummy_array)):
        dummy_array[i] = i & 0xFF

def probe_cache():
    """Measure which cache lines were evicted"""
    timing_results = []

    for line in range(CACHE_LINES):
        start = time.perf_counter_ns()
        value = dummy_array[line * CACHE_LINE_SIZE]
        elapsed = time.perf_counter_ns() - start

        timing_results.append(elapsed)

    return timing_results

def prime_probe_attack():
    """
    1. Prime: Fill cache with known data
    2. Wait: Victim encrypts (evicts some cache lines)
    3. Probe: Measure which lines were evicted
    4. Deduce: Which S-box entries were accessed
    """
    prime_cache()

    # Victim encryption happens here
    trigger_encryption()

    # Measure evictions
    timings = probe_cache()

    # Analyze pattern
    accessed_lines = [i for i, t in enumerate(timings)
                      if t > MISS_THRESHOLD]

    # accessed_lines reveals S-box indices → key information
    return analyze_pattern(accessed_lines)
```

## Differential Power Analysis (DPA)

### Power Consumption Basics

CMOS circuits consume power proportional to bit transitions:

```
P ∝ Hamming Weight of data being processed
```

**Hamming Weight**: Number of 1-bits in binary representation.

```python
def hamming_weight(byte_value):
    """Count number of 1-bits"""
    return bin(byte_value).count('1')

# Examples:
# 0x00 (00000000) → HW = 0
# 0xFF (11111111) → HW = 8
# 0x55 (01010101) → HW = 4
```

### Attack Setup

**Equipment**:
- Digital oscilloscope (1 GHz+)
- Current probe on VDD pin
- ~1000 power traces per key byte

```python
def capture_power_trace(plaintext, device):
    """
    Capture power consumption during AES encryption
    Returns: Array of power samples (typically 1M samples)
    """
    # Trigger encryption
    device.set_plaintext(plaintext)
    device.start_encryption()

    # Sample power at high frequency (e.g., 1 GHz)
    power_trace = oscilloscope.capture(samples=1_000_000)

    return power_trace
```

### Correlation Power Analysis (CPA)

Most effective DPA variant:

```python
def correlation_power_analysis(power_traces, plaintexts):
    """
    Recover AES key using correlation between power and Hamming weight
    """
    num_traces = len(power_traces)
    num_samples = len(power_traces[0])
    key_candidates = range(256)

    recovered_key = []

    for byte_position in range(16):
        max_correlation = -1
        best_key_guess = 0

        for key_guess in key_candidates:
            # Hypothetical power consumption
            hypothetical = []

            for plaintext in plaintexts:
                # Predict S-box output
                sbox_input = plaintext[byte_position] ^ key_guess
                sbox_output = SBOX[sbox_input]

                # Predict power (Hamming weight model)
                power_prediction = hamming_weight(sbox_output)
                hypothetical.append(power_prediction)

            # Correlation between prediction and actual power
            correlations = []
            for sample_point in range(num_samples):
                actual_power = [trace[sample_point] for trace in power_traces]
                corr = pearson_correlation(hypothetical, actual_power)
                correlations.append(abs(corr))

            max_corr = max(correlations)

            if max_corr > max_correlation:
                max_correlation = max_corr
                best_key_guess = key_guess

        recovered_key.append(best_key_guess)
        print(f"Byte {byte_position}: 0x{best_key_guess:02x} (corr={max_correlation:.4f})")

    return bytes(recovered_key)

def pearson_correlation(X, Y):
    """Pearson correlation coefficient"""
    import numpy as np
    return np.corrcoef(X, Y)[0, 1]
```

**Success rate**: >99% with 1000 traces
**Requirements**: Physical access, ~$5000 equipment

### Template Attacks

Most powerful (offline profiling):

```python
def template_attack():
    """
    Phase 1: Profiling (attacker owns identical device)
    - For each key byte k, collect power traces
    - Build statistical model (mean, covariance)

    Phase 2: Attack (on target device)
    - Collect single trace
    - Maximum likelihood estimation
    """
    # Profiling phase
    templates = {}
    for key_value in range(256):
        traces = capture_traces_with_key(key_value, num_traces=1000)
        templates[key_value] = {
            'mean': np.mean(traces, axis=0),
            'cov': np.cov(traces.T)
        }

    # Attack phase
    target_trace = capture_single_trace(target_device)

    # Find most likely key
    likelihoods = []
    for key_value in range(256):
        likelihood = multivariate_gaussian_pdf(
            target_trace,
            templates[key_value]['mean'],
            templates[key_value]['cov']
        )
        likelihoods.append(likelihood)

    recovered_key = max(range(256), key=lambda k: likelihoods[k])
    return recovered_key
```

**Success rate**: Single trace often sufficient
**Requirements**: Profiling device, advanced statistics

## Constant-Time Implementations

### Bitslicing

Process 64 encryptions in parallel using bitwise operations:

```python
def aes_bitslice_sbox(input_bits):
    """
    Constant-time S-box using boolean circuit
    No table lookups → No cache timing leaks
    """
    # S-box as 8-input, 8-output boolean circuit
    # ~200 AND/OR/XOR gates total

    # Example for 1 output bit (simplified):
    U = [input_bits[i] for i in range(8)]

    # Multiplicative inverse in GF(2^8)
    # Implemented as boolean circuit
    inv = galois_inverse(U)  # ~150 gates

    # Affine transformation
    output = affine_transform(inv)  # ~50 gates

    return output  # All operations constant-time
```

**Performance**: ~50% slower than table-based
**Security**: Immune to cache timing

### AES-NI Instructions

Modern CPUs provide constant-time AES hardware:

```c
// Intel AES-NI intrinsics
#include <wmmintrin.h>

__m128i aes_encrypt_ni(__m128i plaintext, __m128i* round_keys) {
    __m128i state = plaintext;

    state = _mm_xor_si128(state, round_keys[0]);

    for (int i = 1; i < 10; i++) {
        state = _mm_aesenc_si128(state, round_keys[i]);
    }

    state = _mm_aesenclast_si128(state, round_keys[10]);

    return state;
}
```

**Performance**: 7 cycles/byte (10x faster than software)
**Security**: Hardened against side channels

### Power Analysis Mitigations

**Masking**: Randomize intermediate values

```python
def masked_sbox(input_byte, mask):
    """
    Boolean masking to defeat DPA
    Invariant: input_byte = masked_input ^ mask
    """
    # Mask S-box input
    masked_input = input_byte ^ mask

    # Masked S-box lookup (pre-computed)
    masked_output = MASKED_SBOX[mask][masked_input]

    # Output is also masked
    # Caller must remove mask later
    return masked_output
```

**Shuffling**: Randomize operation order

```python
def shuffled_aes(state, round_key):
    """Randomize byte processing order each round"""
    indices = list(range(16))
    random.shuffle(indices)

    result = bytearray(16)
    for i in indices:
        result[i] = SBOX[state[i] ^ round_key[i]]

    return bytes(result)
```

## Real-World Attacks

### OpenSSL CVE-2006-2940

Vulnerable code (pre-2006):

```c
// VULNERABLE: Table-based AES
static const u32 Te0[256] = { /* ... */ };

void AES_encrypt(const u8 *in, u8 *out, const AES_KEY *key) {
    // Table lookups leak via cache timing
    s0 = Te0[in[0] ^ key->rd_key[0]];  // Cache-dependent timing!
    // ...
}
```

**Impact**: Remote key recovery from HTTPS servers
**Fix**: Constant-time implementation or AES-NI

### Smartphone Secure Elements

Many chips vulnerable to power analysis:

```
2018: Infineon TPM vulnerability (CVE-2017-15361)
2021: Various secure elements extractable via DPA
```

**Requirements**: Physical proximity, specialized equipment

## Detection and Prevention

### Timing Audit

```python
def audit_timing_leaks(function, inputs):
    """
    Statistical test for timing variations
    """
    import scipy.stats

    timings_by_input = {}

    for inp in inputs:
        start = time.perf_counter_ns()
        function(inp)
        elapsed = time.perf_counter_ns() - start

        timings_by_input.setdefault(inp, []).append(elapsed)

    # ANOVA test: Do inputs affect timing?
    groups = list(timings_by_input.values())
    f_stat, p_value = scipy.stats.f_oneway(*groups)

    if p_value < 0.05:
        print("WARNING: Timing leak detected!")
        return False
    else:
        print("OK: No significant timing variation")
        return True
```

### Best Practices

1. **Use AES-NI** when available
2. **Bitslicing** for software implementations
3. **Avoid table lookups** on secret-dependent indices
4. **Test for constant time** using statistical methods
5. **Physical security** for high-value targets

## Conclusion

Side-channel attacks demonstrate that cryptographic security requires more than mathematical strength. Implementation matters critically.

Modern systems must use:
- Hardware AES (AES-NI) for constant-time operation
- Bitsliced implementations when hardware unavailable
- Power analysis mitigations (masking, shuffling) for embedded devices
- Regular auditing for timing leaks

As attackers refine side-channel techniques, defensive implementation becomes increasingly critical for real-world security.

## References

1. Bernstein, D.J. (2005). "Cache-timing attacks on AES"
2. Kocher, P., et al. (1999). "Differential Power Analysis"
3. Chari, S., et al. (1999). "Towards Sound Approaches to Counteract Power-Analysis Attacks"
4. Osvik, D.A., et al. (2006). "Cache Attacks and Countermeasures: The Case of AES"
