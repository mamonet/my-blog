---
title: "zk-SNARKs: Zero-Knowledge Succinct Non-Interactive Arguments of Knowledge"
description: "Technical deep dive into zk-SNARK construction, covering arithmetic circuits, quadratic arithmetic programs (QAPs), and the Groth16 proving system used in Zcash and Ethereum."
pubDate: 2023-12-28
author: "Mamoun Tarsha-Kurdi"
tags: ["cryptography", "zero-knowledge", "mathematics", "blockchain"]
draft: false
---

## Introduction

zk-SNARKs enable proving computational correctness without revealing inputs, revolutionizing privacy in blockchain systems. Understanding their mathematical foundations is essential for secure implementation and protocol design.

## Zero-Knowledge Proof Properties

A zero-knowledge proof system must satisfy:

### 1. Completeness
```
If statement is true → Honest prover convinces verifier
Pr[Verify(proof, statement) = accept | statement is true] = 1
```

### 2. Soundness
```
If statement is false → No prover can convince verifier
Pr[Verify(proof, statement) = accept | statement is false] < ε
```

### 3. Zero-Knowledge
```
Proof reveals nothing beyond statement truth
∃ Simulator that generates indistinguishable proofs without witness
```

## SNARK Properties

**Succinct**: Proof size poly-logarithmic in computation size
**Non-Interactive**: Single message from prover to verifier
**Argument**: Computationally sound (not information-theoretic)
**of Knowledge**: Prover must "know" witness

## Arithmetic Circuits

### Circuit Representation

Computation expressed as arithmetic circuit over field **𝔽p**:

```python
class Gate:
    def __init__(self, type, left_input, right_input, output):
        self.type = type  # 'add' or 'mul'
        self.left = left_input
        self.right = right_input
        self.output = output

def build_circuit_x_cubed_plus_x_plus_5():
    """
    Compute f(x) = x³ + x + 5
    Circuit gates:
    - v1 = x * x
    - v2 = v1 * x  (x³)
    - v3 = v2 + x
    - out = v3 + 5
    """
    circuit = [
        Gate('mul', 'x', 'x', 'v1'),      # x²
        Gate('mul', 'v1', 'x', 'v2'),     # x³
        Gate('add', 'v2', 'x', 'v3'),     # x³ + x
        Gate('add', 'v3', '5', 'out'),    # x³ + x + 5
    ]
    return circuit
```

### Flattening Constraints

Convert to Rank-1 Constraint System (R1CS):

```
(Ax) ∘ (Bx) = Cx
```

where **x** is witness vector, **A, B, C** are constraint matrices.

Example for **f(x) = x³ + x + 5**:

```python
def flatten_to_r1cs():
    """
    R1CS representation
    Variables: [1, x, out, v1, v2, v3]
    """
    # Constraint 1: x * x = v1
    A1 = [0, 1, 0, 0, 0, 0]  # x
    B1 = [0, 1, 0, 0, 0, 0]  # x
    C1 = [0, 0, 0, 1, 0, 0]  # v1

    # Constraint 2: v1 * x = v2
    A2 = [0, 0, 0, 1, 0, 0]  # v1
    B2 = [0, 1, 0, 0, 0, 0]  # x
    C2 = [0, 0, 0, 0, 1, 0]  # v2

    # Constraint 3: (v2 + x) * 1 = v3
    A3 = [0, 1, 0, 0, 1, 0]  # v2 + x
    B3 = [1, 0, 0, 0, 0, 0]  # 1
    C3 = [0, 0, 0, 0, 0, 1]  # v3

    # Constraint 4: (v3 + 5) * 1 = out
    A4 = [5, 0, 0, 0, 0, 1]  # v3 + 5
    B4 = [1, 0, 0, 0, 0, 0]  # 1
    C4 = [0, 0, 1, 0, 0, 0]  # out

    return (A, B, C)  # Stack constraints
```

## Quadratic Arithmetic Programs (QAPs)

### Transformation

Convert R1CS to QAP using Lagrange interpolation:

```python
def r1cs_to_qap(A, B, C, num_vars, num_constraints):
    """
    Interpolate constraint matrices as polynomials
    """
    from numpy.polynomial import Polynomial

    # Evaluation points (roots of unity work well)
    points = [i+1 for i in range(num_constraints)]

    A_polys = []
    B_polys = []
    C_polys = []

    for var_idx in range(num_vars):
        # Extract column for this variable across all constraints
        a_values = [A[constraint][var_idx] for constraint in range(num_constraints)]
        b_values = [B[constraint][var_idx] for constraint in range(num_constraints)]
        c_values = [C[constraint][var_idx] for constraint in range(num_constraints)]

        # Interpolate polynomials
        A_polys.append(Polynomial.fit(points, a_values, num_constraints-1))
        B_polys.append(Polynomial.fit(points, b_values, num_constraints-1))
        C_polys.append(Polynomial.fit(points, c_values, num_constraints-1))

    return (A_polys, B_polys, C_polys)
```

### QAP Check

Valid witness satisfies:

```
A(x) · B(x) - C(x) = H(x) · Z(x)
```

where:
- **A(x) = Σ wᵢ·Aᵢ(x)** (witness-weighted sum of A polynomials)
- **B(x) = Σ wᵢ·Bᵢ(x)**
- **C(x) = Σ wᵢ·Cᵢ(x)**
- **Z(x) = (x-1)(x-2)...(x-m)** (target polynomial, zeros at evaluation points)
- **H(x)** is quotient polynomial

```python
def compute_qap_polynomials(witness, A_polys, B_polys, C_polys):
    """
    Compute A(x), B(x), C(x) from witness
    """
    A_x = sum(w * poly for w, poly in zip(witness, A_polys))
    B_x = sum(w * poly for w, poly in zip(witness, B_polys))
    C_x = sum(w * poly for w, poly in zip(witness, C_polys))

    return (A_x, B_x, C_x)

def compute_H(A_x, B_x, C_x, Z_x):
    """
    Compute quotient H(x) = (A(x)·B(x) - C(x)) / Z(x)
    Must divide evenly if witness is valid
    """
    numerator = A_x * B_x - C_x
    H_x, remainder = divmod(numerator, Z_x)

    assert remainder == 0, "Invalid witness: doesn't satisfy constraints"

    return H_x
```

## Groth16 zk-SNARK

### Trusted Setup

Generate Common Reference String (CRS):

```python
def trusted_setup(A_polys, B_polys, C_polys, Z_poly, tau):
    """
    Setup phase (per-circuit, requires trusted party)
    tau: toxic waste (secret, must be destroyed)
    """
    from py_ecc.bn128 import G1, G2, pairing, multiply, add

    # Powers of tau in exponent
    # [τ⁰G₁, τ¹G₁, τ²G₁, ..., τⁿG₁]
    powers_tau_G1 = [multiply(G1, pow(tau, i, CURVE_ORDER))
                     for i in range(MAX_DEGREE)]

    powers_tau_G2 = [multiply(G2, pow(tau, i, CURVE_ORDER))
                     for i in range(MAX_DEGREE)]

    # Evaluate polynomials at τ
    # {Aᵢ(τ)·G₁, Bᵢ(τ)·G₁, Bᵢ(τ)·G₂, Cᵢ(τ)·G₁}
    A_tau = [multiply(G1, A_poly(tau)) for A_poly in A_polys]
    B_tau_G1 = [multiply(G1, B_poly(tau)) for B_poly in B_polys]
    B_tau_G2 = [multiply(G2, B_poly(tau)) for B_polys in B_polys]
    C_tau = [multiply(G1, C_poly(tau)) for C_poly in C_polys]

    # Z(τ)·G₁ for verification
    Z_tau = multiply(G1, Z_poly(tau))

    # Random elements for zero-knowledge
    alpha = random_scalar()
    beta = random_scalar()
    gamma = random_scalar()
    delta = random_scalar()

    proving_key = {
        'A_tau': A_tau,
        'B_tau_G1': B_tau_G1,
        'B_tau_G2': B_tau_G2,
        'C_tau': C_tau,
        'Z_tau': Z_tau,
        'alpha': multiply(G1, alpha),
        'beta_G1': multiply(G1, beta),
        'beta_G2': multiply(G2, beta),
        'delta': multiply(G1, delta),
    }

    verification_key = {
        'alpha_G1': multiply(G1, alpha),
        'beta_G2': multiply(G2, beta),
        'gamma_G2': multiply(G2, gamma),
        'delta_G2': multiply(G2, delta),
        # IC: input commitment (public inputs only)
    }

    # CRITICAL: Delete tau, alpha, beta, gamma, delta
    # "Toxic waste" - if revealed, can forge proofs!

    return (proving_key, verification_key)
```

### Proof Generation

```python
def generate_proof(witness, proving_key):
    """
    Generate zk-SNARK proof
    Witness = [public_inputs | private_inputs]
    """
    # Compute A(τ), B(τ), C(τ) using witness
    A_tau = sum(w * A_i for w, A_i in zip(witness, proving_key['A_tau']))
    B_tau_G1 = sum(w * B_i for w, B_i in zip(witness, proving_key['B_tau_G1']))
    B_tau_G2 = sum(w * B_i for w, B_i in zip(witness, proving_key['B_tau_G2']))
    C_tau = sum(w * C_i for w, C_i in zip(witness, proving_key['C_tau']))

    # Add randomness for zero-knowledge
    r = random_scalar()
    s = random_scalar()

    # Proof elements (3 group elements total!)
    pi_A = add(A_tau, multiply(proving_key['alpha'], 1))
    pi_A = add(pi_A, multiply(proving_key['delta'], r))

    pi_B = add(B_tau_G2, multiply(proving_key['beta_G2'], 1))
    pi_B = add(pi_B, multiply(proving_key['delta'], s))

    # H(τ)·Z(τ)/δ computation (omitted for brevity)
    pi_C = compute_C_element(witness, H_tau, r, s, proving_key)

    proof = (pi_A, pi_B, pi_C)

    return proof
```

### Verification

Single pairing equation:

```python
def verify_proof(proof, public_inputs, verification_key):
    """
    Verify zk-SNARK proof with single pairing check
    """
    pi_A, pi_B, pi_C = proof

    # Compute input commitment from public inputs
    IC = sum(pub * ic_i for pub, ic_i in
             zip(public_inputs, verification_key['IC']))

    # Single pairing equation:
    # e(π_A, π_B) = e(α, β) · e(IC, γ) · e(π_C, δ)

    lhs = pairing(pi_A, pi_B)

    rhs = pairing(verification_key['alpha_G1'], verification_key['beta_G2'])
    rhs *= pairing(IC, verification_key['gamma_G2'])
    rhs *= pairing(pi_C, verification_key['delta_G2'])

    return lhs == rhs
```

**Proof size**: 3 group elements (~128 bytes on BN128)
**Verification**: 3 pairings (~2ms)

## Security Analysis

### Trusted Setup Ceremony

**Problem**: Setup generates toxic waste (τ, α, β, etc.)

**Solution**: Multi-party computation (MPC)

```
n participants contribute randomness
τ = τ₁ + τ₂ + ... + τₙ

Security: Even 1 honest participant ensures security
```

**Example**: Zcash Powers of Tau (2017)
- 200+ participants
- Air-gapped computers
- Hardware destruction
- Multiple continents

### Knowledge Soundness

**Theorem**: If prover can create valid proof, can extract witness.

Relies on:
1. **Discrete log hardness** in elliptic curve groups
2. **q-SDH assumption**: Given (G, τG, τ²G, ..., τⁿG), hard to compute (1/(τ+c))·G

## Zcash Implementation

### Shielded Transactions

```python
def create_shielded_transaction(sender_sk, receiver_pk, amount):
    """
    Private transaction using zk-SNARKs
    Proves: sender owns coins, amount > 0, no double-spend
    Reveals: Nothing about sender, receiver, or amount
    """
    # Witness (private)
    witness = {
        'sender_sk': sender_sk,
        'receiver_pk': receiver_pk,
        'amount': amount,
        'note_commitment': compute_commitment(receiver_pk, amount),
        'nullifier': hash(sender_sk, note_serial),  # Prevent double-spend
    }

    # Public inputs
    public = {
        'root': merkle_root,  # Proves coin exists
        'nullifier': witness['nullifier'],  # Published to prevent reuse
        'new_commitment': witness['note_commitment'],  # New coin
    }

    # Generate proof
    proof = generate_proof(witness, proving_key)

    return (proof, public)
```

### Performance

On modern hardware:

| Operation | Time | Notes |
|-----------|------|-------|
| Proof generation | ~6s | CPU-intensive |
| Verification | ~2ms | Very fast |
| Proof size | 192 bytes | Constant |

## Ethereum Applications

### Tornado Cash

Privacy mixer using zk-SNARKs:

```solidity
contract TornadoCash {
    mapping(bytes32 => bool) public nullifiers;
    mapping(bytes32 => bool) public commitments;

    function deposit(bytes32 commitment) external payable {
        require(msg.value == DENOMINATION);
        commitments[commitment] = true;
    }

    function withdraw(
        bytes calldata proof,
        bytes32 nullifier,
        address recipient
    ) external {
        // Verify proof shows:
        // 1. Knows preimage of commitment in tree
        // 2. Nullifier derived correctly
        // 3. Recipient matches proof
        require(verifyProof(proof, nullifier, recipient));
        require(!nullifiers[nullifier], "Already withdrawn");

        nullifiers[nullifier] = true;
        payable(recipient).transfer(DENOMINATION);
    }
}
```

### zkRollups

Layer-2 scaling:

```
Batch 1000 transactions
Generate single zk-SNARK proving validity
Post proof + state root on L1 (~100 bytes)

Cost: ~1% of processing individual txs
Throughput: 1000x improvement
```

## Limitations and Alternatives

### Groth16 Disadvantages

1. **Trusted setup per circuit**
2. **Not quantum-resistant** (pairing-based)
3. **Circuit changes require new setup**

### Alternatives

**PLONK** (2019):
- Universal setup (works for any circuit)
- Larger proofs (~400 bytes)

**STARKs**:
- No trusted setup
- Quantum-resistant
- Larger proofs (~100 KB)
- Faster proving for large circuits

## Conclusion

zk-SNARKs enable unprecedented privacy and scalability in blockchain systems. Groth16 provides optimal proof size and verification time, making it ideal for resource-constrained environments.

Understanding the mathematical foundations—arithmetic circuits, QAPs, and elliptic curve pairings—is essential for secure implementation and protocol design.

As zero-knowledge technology matures, expect widespread adoption beyond cryptocurrency: private authentication, confidential computing, and regulatory compliance with privacy.

## References

1. Groth, J. (2016). "On the Size of Pairing-based Non-interactive Arguments"
2. Ben-Sasson, E., et al. (2014). "Succinct Non-Interactive Zero Knowledge for a von Neumann Architecture"
3. Gabizon, A., et al. (2019). "PLONK: Permutations over Lagrange-bases for Oecumenical Noninteractive arguments of Knowledge"
4. Bowe, S., et al. (2017). "Scalable Multi-party Computation for zk-SNARK Parameters"
