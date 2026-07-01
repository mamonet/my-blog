---
title: "Cryptographic Hash Function Collisions: From MD5 to SHA-3 Security Analysis"
description: "Comprehensive analysis of collision resistance in cryptographic hash functions, examining practical attacks on MD5 and SHA-1, and security margins in modern SHA-2 and SHA-3 families."
pubDate: 2023-12-28
author: "Mamone Tarsia"
tags: ["cryptography", "hash-functions", "vulnerabilities", "mathematics"]
draft: false
---

## Introduction

Cryptographic hash functions are fundamental to digital security, yet finding collisions has proven devastating for several widely-deployed algorithms. Understanding collision attacks is essential for secure system design and hash function selection.

## Hash Function Security Properties

A cryptographic hash **H: {0,1}* → {0,1}^n** must satisfy:

###

 1. Pre-image Resistance
```
Given h, computationally infeasible to find m such that H(m) = h
Security requirement: 2^n operations
```

### 2. Second Pre-image Resistance
```
Given m₁, infeasible to find m₂ ≠ m₁ such that H(m₁) = H(m₂)
Security requirement: 2^n operations
```

### 3. Collision Resistance
```
Infeasible to find any m₁ ≠ m₂ such that H(m₁) = H(m₂)
Security requirement: 2^(n/2) operations (birthday bound)
```

## Birthday Attack

### Theoretical Foundation

**Birthday Paradox**: With 23 random people, P(shared birthday) > 50%

Generalized: Drawing √(2N) samples from N-element set gives collision probability ≈ 50%.

For n-bit hash:
```
N = 2^n possible hashes
√(2·2^n) = √2 · 2^(n/2) ≈ 2^(n/2) hashes needed
```

### Generic Algorithm

```python
def birthday_attack(hash_func, output_bits):
    """
    Generic collision finder
    Expected work: 2^(output_bits/2)
    """
    import random

    seen = {}  # Hash table: hash -> message
    attempts = 0

    while True:
        # Generate random message
        msg = random.randbytes(64)
        h = hash_func(msg)

        if h in seen and seen[h] != msg:
            # Collision found!
            return (seen[h], msg, h)

        seen[h] = msg
        attempts += 1

        # Expected attempts ≈ √(π/2 · 2^n) ≈ 1.25 · 2^(n/2)
        if attempts % 1000000 == 0:
            print(f"Attempts: {attempts:,}")
```

**Complexity**: O(2^(n/2)) time, O(2^(n/2)) space

Limits practical security:
- 64-bit hash: ~2^32 = 4 billion hashes
- 128-bit hash: ~2^64 = 18 quintillion hashes
- 256-bit hash: ~2^128 hashes (infeasible)

## MD5 Collision Attacks

### Algorithm Structure

MD5 processes 512-bit blocks using 4 rounds of 16 steps each:

```python
def md5_round(A, B, C, D, M, s, t, func):
    """
    Single MD5 step
    func ∈ {F, G, H, I} for rounds 1-4
    """
    # Round functions
    F = lambda x,y,z: (x & y) | (~x & z)
    G = lambda x,y,z: (x & z) | (y & ~z)
    H = lambda x,y,z: x ^ y ^ z
    I = lambda x,y,z: y ^ (x | ~z)

    temp = (A + func(B, C, D) + M + t) & 0xFFFFFFFF
    temp = rotate_left(temp, s)
    A = (B + temp) & 0xFFFFFFFF

    return A
```

### Differential Cryptanalysis

Wang et al. (2004) discovered differential path:

```
ΔM → ΔH = 0

where ΔM is carefully crafted message difference
```

**Key Insight**: Certain message differences propagate predictably through MD5 rounds.

### Practical Collision (2004)

```python
# Collision found by Wang et al.
M1 = bytes.fromhex(
    "d131dd02c5e6eec4693d9a0698aff95c"
    "2fcab58712467eab4004583eb8fb7f89"
    # ... (full 128 bytes)
)

M2 = bytes.fromhex(
    "d131dd02c5e6eec4693d9a0698aff95c"
    "2fcab50712467eab4004583eb8fb7f89"  # Differs in byte 18
    # ... (full 128 bytes)
)

assert md5(M1) == md5(M2)
assert M1 != M2
```

**Computation**: ~1 hour on 2004 hardware
**Modern hardware**: Seconds

### Chosen-Prefix Collisions

More dangerous: Control prefix of both messages:

```python
def chosen_prefix_collision(prefix1, prefix2):
    """
    Find M1, M2 such that:
    H(prefix1 || M1) = H(prefix2 || M2)
    """
    # 1. Compute hash state after prefixes
    state1 = md5_state(prefix1)
    state2 = md5_state(prefix2)

    # 2. Find collision block
    collision = find_collision_block(state1, state2)

    return collision
```

**Impact**: Forge certificates, documents with same hash but different content

**Timeline**:
- 2007: Chosen-prefix in ~1 day
- 2012: Chosen-prefix in ~10 hours
- 2019: Chosen-prefix in ~10 seconds

## SHA-1 Collision Attacks

### Algorithm Differences

SHA-1 improvements over MD5:
- 160-bit output (vs 128-bit)
- 80 rounds (vs 64)
- Message expansion
- Better mixing functions

### Theoretical Attack (2005)

Wang et al. showed theoretical complexity:

```
2^69 operations (vs 2^80 birthday bound)
```

Not practical until 2017.

### SHAttered Attack (2017)

Google/CWI demonstrated first practical collision:

```
PDF prefix technique:
- Identical prefix (header)
- Two different JPEG images
- Crafted collision blocks
- Identical suffix
```

**Resources**:
- 6,500 CPU-years
- 110 GPU-years
- $110,000 in cloud computing

```python
# Simplified collision structure
def create_sha1_collision():
    """
    Structure of SHAttered PDFs
    """
    prefix = create_pdf_header()

    # Image 1: Blue square
    image1 = jpeg_blue_square()

    # Image 2: Red square
    image2 = jpeg_red_square()

    # Find collision blocks C1, C2
    C1, C2 = shattered_collision_blocks()

    pdf1 = prefix + C1 + image1
    pdf2 = prefix + C2 + image2

    assert sha1(pdf1) == sha1(pdf2)
    assert pdf1 != pdf2

    return (pdf1, pdf2)
```

**Result**: Two valid PDFs displaying different images with identical SHA-1 hash.

### Chosen-Prefix for SHA-1 (2020)

Leurent & Peyrin reduced cost:

```
Computation: ~10^18 operations
Cost: ~$100,000 (2020)
Timeline: ~2 months on 900 GPUs
```

**Impact**: Theoretical PGP/GnuPG key impersonation.

## SHA-2 Security Analysis

### Family Overview

| Variant | Output | Block | Rounds | Status |
|---------|--------|-------|--------|--------|
| SHA-224 | 224-bit| 512   | 64     | Secure |
| SHA-256 | 256-bit| 512   | 64     | Secure |
| SHA-384 | 384-bit| 1024  | 80     | Secure |
| SHA-512 | 512-bit| 1024  | 80     | Secure |

### Best Known Attacks

**SHA-256**: No collision attacks better than birthday.

Best reduced-round attacks:
```
31/64 rounds: 2^65.5 (theoretical, not practical)
46/64 rounds: Pseudo-collision in compression function
Full 64 rounds: No attack
```

**Security margin**: ~31 rounds (48% of total)

### Implementation

```python
def sha256_compression(state, block):
    """
    SHA-256 compression function
    Processes 512-bit block
    """
    # Initialize working variables
    a, b, c, d, e, f, g, h = state

    # Message schedule
    W = [0] * 64
    for t in range(16):
        W[t] = int.from_bytes(block[t*4:(t+1)*4], 'big')

    for t in range(16, 64):
        s0 = ror(W[t-15], 7) ^ ror(W[t-15], 18) ^ (W[t-15] >> 3)
        s1 = ror(W[t-2], 17) ^ ror(W[t-2], 19) ^ (W[t-2] >> 10)
        W[t] = (W[t-16] + s0 + W[t-7] + s1) & 0xFFFFFFFF

    # 64 rounds
    for t in range(64):
        S1 = ror(e, 6) ^ ror(e, 11) ^ ror(e, 25)
        ch = (e & f) ^ (~e & g)
        temp1 = (h + S1 + ch + K[t] + W[t]) & 0xFFFFFFFF

        S0 = ror(a, 2) ^ ror(a, 13) ^ ror(a, 22)
        maj = (a & b) ^ (a & c) ^ (b & c)
        temp2 = (S0 + maj) & 0xFFFFFFFF

        h, g, f, e, d, c, b, a = \
            g, f, e, (d+temp1)&0xFFFFFFFF, c, b, a, (temp1+temp2)&0xFFFFFFFF

    # Add to state
    return [(x + y) & 0xFFFFFFFF for x, y in
            zip([a,b,c,d,e,f,g,h], state)]
```

## SHA-3 (Keccak)

### Sponge Construction

SHA-3 uses different paradigm:

```
Sponge[f, pad, r](M) = Absorb → Squeeze

Absorb: XOR input blocks into state
Squeeze: Output extracted from state
```

```python
def keccak_sponge(message, rate, capacity, output_len):
    """
    SHA-3 sponge construction
    State: 1600 bits = rate + capacity
    """
    state = [0] * 25  # 25 × 64-bit lanes

    # Absorbing phase
    blocks = pad_message(message, rate)
    for block in blocks:
        for i in range(rate // 64):
            state[i] ^= block[i]
        state = keccak_f(state)  # Permutation

    # Squeezing phase
    output = []
    while len(output) < output_len:
        output.extend(state[:rate // 64])
        state = keccak_f(state)

    return output[:output_len]
```

### Security Analysis

**SHA3-256** parameters:
```
Rate (r): 1088 bits
Capacity (c): 512 bits (2× output for security)
Rounds: 24
```

**Best attacks**: No practical collision attacks

Reduced-round analysis:
```
8/24 rounds: 2^384 complexity (theoretical)
Full 24 rounds: No attacks
```

**Security margin**: 16 rounds (67% of total)

## Practical Implications

### Certificate Forgery

MD5/SHA-1 collisions enable certificate attacks:

```python
def forge_certificate():
    """
    Theoretical MD5 collision attack on certificates
    (Prevented by modern CAs)
    """
    # 1. Create valid CSR (Certificate Signing Request)
    legit_csr = create_csr("example.com")

    # 2. Create malicious CSR with same MD5
    evil_csr = create_csr("*.com", collision_with=legit_csr)

    # 3. Submit legit_csr to CA
    cert = ca_sign(legit_csr)  # Uses MD5 (old CAs)

    # 4. Replace CSR content with evil_csr
    # Cert signature still valid due to MD5 collision!

    return forged_cert
```

**Mitigations**:
- CAs banned MD5 in 2011
- SHA-1 banned in 2016
- Certificates now use SHA-256+

### Git Commits

Git uses SHA-1 for commit IDs:

```bash
# Potential attack (theoretical)
git commit -m "Benign change"
# Commit: abc123...

# Create collision
malicious_commit = create_sha1_collision(abc123)

# Replace commit object
# Same SHA-1, different content!
```

**Mitigation**: Git transitioning to SHA-256 (2020+)

## Migration Recommendations

### Algorithm Selection (2024)

| Use Case | Recommended | Avoid |
|----------|-------------|-------|
| Digital signatures | SHA-256, SHA-512 | MD5, SHA-1 |
| File integrity | SHA3-256, BLAKE3 | MD5 |
| Certificates | SHA-256 | SHA-1 |
| Password hashing | Argon2, bcrypt | Any fast hash |
| Git/VCS | SHA-256 | SHA-1 |

### Safe Hash Usage

```python
# INSECURE: Direct hash comparison
def verify_download_bad(file_data, expected_md5):
    return md5(file_data) == expected_md5

# SECURE: Use HMAC with secret key
def verify_download_good(file_data, key, expected_mac):
    mac = hmac_sha256(key, file_data)
    return constant_time_compare(mac, expected_mac)

# SECURE: Use collision-resistant hash
def verify_download_better(file_data, expected_sha256):
    return sha256(file_data) == expected_sha256
```

## Conclusion

Collision resistance is paramount for hash function security. MD5 and SHA-1 are completely broken for collision resistance and must not be used in security-critical contexts.

Modern systems should exclusively use SHA-256/SHA-512 or SHA-3 family. For new designs, consider BLAKE3 for performance-critical applications.

The cryptographic community's response to hash function breaks demonstrates the importance of:
1. Conservative security margins
2. Diversity in cryptographic primitives
3. Proactive migration before attacks become practical

## References

1. Wang, X., et al. (2005). "Finding Collisions in the Full SHA-1"
2. Stevens, M., et al. (2017). "The first collision for full SHA-1"
3. Leurent, G., Peyrin, T. (2020). "SHA-1 is a Shambles"
4. NIST (2015). "SHA-3 Standard: Permutation-Based Hash and Extendable-Output Functions"
