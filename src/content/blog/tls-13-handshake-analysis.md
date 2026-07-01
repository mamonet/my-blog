---
title: "TLS 1.3 Handshake Protocol: Technical Analysis and Security Improvements"
description: "Detailed examination of TLS 1.3 handshake protocol changes, 0-RTT data transmission, forward secrecy guarantees, and cryptographic improvements over TLS 1.2."
pubDate: 2024-02-05
author: "Mamone Tarsia"
tags: ["tls", "protocols", "cryptography", "security"]
draft: false
---

## Introduction

TLS 1.3, published in RFC 8446 (August 2018), represents the most significant protocol revision in over a decade. Understanding the handshake improvements is critical for secure deployment and configuration.

## TLS 1.2 vs 1.3 Handshake Comparison

### TLS 1.2 Full Handshake (2-RTT)

```
Client                                Server
  |                                     |
  |---------- ClientHello ------------->|
  |                                     |
  |<--------- ServerHello --------------|
  |<--------- Certificate --------------|
  |<---- ServerKeyExchange -------------|
  |<----- CertificateRequest ----------|  (optional)
  |<------- ServerHelloDone ------------|
  |                                     |
  |--------- Certificate -------------->|  (optional)
  |---- ClientKeyExchange ------------->|
  |--- CertificateVerify -------------->|  (optional)
  |------ [ChangeCipherSpec] ---------->|
  |---------- Finished ---------------->|
  |                                     |
  |<----- [ChangeCipherSpec] -----------|
  |<--------- Finished -----------------|
  |                                     |
  |<====== Application Data ==========>|

Total: 2-RTT before application data
```

### TLS 1.3 Full Handshake (1-RTT)

```
Client                                Server
  |                                     |
  |---------- ClientHello ------------->|  + key_share
  |        + key_share                  |  + signature
  |                                     |
  |<--------- ServerHello --------------|
  |<---- {EncryptedExtensions} ---------|
  |<------- {Certificate} --------------|
  |<--- {CertificateVerify} ------------|
  |<---------- {Finished} --------------|
  |                                     |
  |--------- {Certificate} ------------>|  (optional)
  |---- {CertificateVerify} ----------->|  (optional)
  |---------- {Finished} -------------->|
  |                                     |
  |<====== Application Data ==========>|

Total: 1-RTT before application data
{} = encrypted under handshake traffic keys
```

**Key improvement**: 50% reduction in handshake latency.

## TLS 1.3 Handshake Deep Dive

### ClientHello Message

```python
class ClientHello:
    """TLS 1.3 ClientHello structure"""
    def __init__(self):
        self.legacy_version = 0x0303  # TLS 1.2 for compatibility
        self.random = os.urandom(32)  # Client random
        self.legacy_session_id = b''  # Empty or legacy value

        # Cipher suites (TLS 1.3 only supports AEAD)
        self.cipher_suites = [
            0x1301,  # TLS_AES_128_GCM_SHA256
            0x1302,  # TLS_AES_256_GCM_SHA384
            0x1303,  # TLS_CHACHA20_POLY1305_SHA256
        ]

        # Extensions
        self.extensions = {
            'supported_versions': [0x0304],  # TLS 1.3
            'supported_groups': [
                0x001d,  # x25519 (required)
                0x0017,  # secp256r1
                0x001e,  # x448
            ],
            'signature_algorithms': [
                0x0804,  # rsa_pss_rsae_sha256
                0x0805,  # rsa_pss_rsae_sha384
                0x0806,  # rsa_pss_rsae_sha512
                0x0403,  # ecdsa_secp256r1_sha256
            ],
            'key_share': {
                # Pre-generate key shares for expected groups
                'client_shares': [
                    ('x25519', generate_x25519_keypair()),
                ]
            }
        }

def generate_x25519_keypair():
    """Generate X25519 ephemeral key pair"""
    from cryptography.hazmat.primitives.asymmetric import x25519

    private_key = x25519.X25519PrivateKey.generate()
    public_key = private_key.public_key()

    return {
        'private': private_key,
        'public': public_key.public_bytes_raw()
    }
```

**Critical change**: Client sends key_share in first message, enabling 1-RTT.

### ServerHello Message

```python
class ServerHello:
    """TLS 1.3 ServerHello structure"""
    def __init__(self, client_hello):
        self.version = 0x0303  # Legacy version
        self.random = os.urandom(32)  # Server random

        # Select cipher suite from client's list
        self.cipher_suite = select_cipher_suite(
            client_hello.cipher_suites
        )  # e.g., TLS_AES_128_GCM_SHA256

        # Extensions
        self.extensions = {
            'supported_versions': 0x0304,  # TLS 1.3
            'key_share': {
                # Server's ephemeral key share
                'server_share': generate_server_key_share(
                    client_hello.extensions['key_share']
                )
            }
        }

def generate_server_key_share(client_key_shares):
    """Generate server's ephemeral key"""
    # Select group (prefer x25519)
    selected_group = 'x25519'

    # Generate ephemeral key
    server_private = x25519.X25519PrivateKey.generate()
    server_public = server_private.public_key()

    # Compute shared secret
    client_public_bytes = client_key_shares['client_shares'][0][1]['public']
    client_public_key = x25519.X25519PublicKey.from_public_bytes(
        client_public_bytes
    )

    shared_secret = server_private.exchange(client_public_key)

    return {
        'group': selected_group,
        'public': server_public.public_bytes_raw(),
        'shared_secret': shared_secret
    }
```

### Key Derivation (HKDF)

TLS 1.3 uses HKDF for all key derivation:

```python
def derive_handshake_keys(shared_secret, client_hello, server_hello):
    """
    Derive handshake traffic keys using HKDF-Expand-Label
    """
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF, HKDFExpand

    # Hash function based on cipher suite
    hash_algo = hashes.SHA256()  # for TLS_AES_128_GCM_SHA256

    # Early Secret (all zeros for non-PSK)
    early_secret = HKDF(
        algorithm=hash_algo,
        length=32,
        salt=b'\x00' * 32,
        info=b'',
    ).derive(b'\x00' * 32)

    # Derive-Secret for handshake
    handshake_secret = derive_secret(
        early_secret,
        b'derived',
        b'',
        hash_algo
    )

    # Extract with ECDHE shared secret
    handshake_secret = HKDF(
        algorithm=hash_algo,
        length=32,
        salt=handshake_secret,
        info=b'',
    ).derive(shared_secret)

    # Derive client/server handshake traffic secrets
    transcript_hash = hash_messages(client_hello, server_hello)

    client_handshake_traffic_secret = derive_secret(
        handshake_secret,
        b'c hs traffic',
        transcript_hash,
        hash_algo
    )

    server_handshake_traffic_secret = derive_secret(
        handshake_secret,
        b's hs traffic',
        transcript_hash,
        hash_algo
    )

    return {
        'client': client_handshake_traffic_secret,
        'server': server_handshake_traffic_secret,
        'handshake_secret': handshake_secret
    }

def derive_secret(secret, label, messages_hash, hash_algo):
    """HKDF-Expand-Label from RFC 8446"""
    hkdf_label = create_hkdf_label(
        length=32,  # Hash output length
        label=label,
        context=messages_hash
    )

    return HKDFExpand(
        algorithm=hash_algo,
        length=32,
        info=hkdf_label,
    ).derive(secret)

def create_hkdf_label(length, label, context):
    """
    struct {
        uint16 length;
        opaque label<7..255>;
        opaque context<0..255>;
    } HkdfLabel;
    """
    tls13_label = b'tls13 ' + label

    return (
        length.to_bytes(2, 'big') +
        len(tls13_label).to_bytes(1, 'big') + tls13_label +
        len(context).to_bytes(1, 'big') + context
    )
```

### Encrypted Handshake Messages

After ServerHello, all messages are encrypted:

```python
def encrypt_handshake_message(message, traffic_secret):
    """
    Encrypt handshake message using AEAD
    """
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    # Derive key and IV from traffic secret
    key = derive_key(traffic_secret, key_length=16)  # AES-128
    iv = derive_iv(traffic_secret, iv_length=12)     # GCM nonce

    # TLS 1.3 record format
    content_type = 0x16  # Handshake
    length = len(message)

    # Construct TLSInnerPlaintext
    inner_plaintext = message + content_type.to_bytes(1, 'big')

    # Encrypt with AEAD (AES-GCM)
    aesgcm = AESGCM(key)

    # Nonce is IV XOR sequence number
    nonce = xor_bytes(iv, seq_num.to_bytes(12, 'big'))

    # Additional data: TLSCiphertext header
    additional_data = (
        b'\x17' +  # Application data (encrypted handshake)
        b'\x03\x03' +  # Legacy version
        length.to_bytes(2, 'big')
    )

    ciphertext = aesgcm.encrypt(nonce, inner_plaintext, additional_data)

    return ciphertext
```

### Certificate and CertificateVerify

```python
def send_certificate_verify(private_key, transcript_hash):
    """
    Sign handshake transcript to prove certificate ownership
    """
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding, rsa

    # Construct signed content
    context_string = b' ' * 64 + b'TLS 1.3, server CertificateVerify' + b'\x00'
    content = context_string + transcript_hash

    # Sign with certificate private key
    if isinstance(private_key, rsa.RSAPrivateKey):
        signature = private_key.sign(
            content,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

    return {
        'algorithm': 0x0804,  # rsa_pss_rsae_sha256
        'signature': signature
    }
```

## 0-RTT Data (Early Data)

### Resumption and 0-RTT

```python
def create_0rtt_client_hello(psk, early_data):
    """
    Send application data in first flight (0-RTT)
    Requires pre-shared key from previous session
    """
    client_hello = ClientHello()

    # Add PSK extension
    client_hello.extensions['pre_shared_key'] = {
        'identities': [(psk['identity'], psk['obfuscated_ticket_age'])],
        'binders': [compute_psk_binder(psk, client_hello)]
    }

    # Add early data indication
    client_hello.extensions['early_data'] = {}

    # Derive early traffic secret
    early_secret = derive_early_secret(psk['secret'])
    client_early_traffic_secret = derive_secret(
        early_secret,
        b'c e traffic',
        hash_messages(client_hello)
    )

    # Encrypt early data
    encrypted_early_data = encrypt_application_data(
        early_data,
        client_early_traffic_secret
    )

    return (client_hello, encrypted_early_data)
```

### 0-RTT Security Considerations

**Vulnerability**: 0-RTT data can be replayed!

```python
# INSECURE: Replay attack on 0-RTT
def replay_attack():
    """
    Attacker captures 0-RTT request and replays it
    """
    # Legitimate request
    captured_0rtt = capture_network_traffic()

    # Replay multiple times
    for _ in range(100):
        send_to_server(captured_0rtt)

    # Each replay executes same request!
    # E.g., "transfer $1000" executed 100 times
```

**Mitigation**: Server must ensure idempotency

```python
def handle_0rtt_data(early_data, client_address):
    """
    Secure 0-RTT handling
    """
    # 1. Check for replay using single-use token
    if is_replayed(early_data['token']):
        reject_0rtt()
        return

    # 2. Only allow idempotent operations
    if not is_idempotent(early_data['request']):
        reject_0rtt()
        return

    # 3. Use anti-replay window
    if not in_time_window(early_data['timestamp'], max_age=10):
        reject_0rtt()
        return

    # 4. Process request
    process_early_data(early_data)
```

## Removed Features (TLS 1.2 → 1.3)

### Removed Cipher Suites

```python
# REMOVED: All non-AEAD cipher suites
REMOVED_CIPHERS = [
    'TLS_RSA_WITH_AES_128_CBC_SHA',      # Static RSA
    'TLS_RSA_WITH_3DES_EDE_CBC_SHA',     # 3DES
    'TLS_DHE_RSA_WITH_AES_128_CBC_SHA',  # CBC mode
    # ... all CBC, RC4, MD5, SHA-1 ciphers
]

# ALLOWED: Only AEAD ciphers with PFS
ALLOWED_CIPHERS = [
    'TLS_AES_128_GCM_SHA256',            # AES-GCM
    'TLS_AES_256_GCM_SHA384',
    'TLS_CHACHA20_POLY1305_SHA256',      # ChaCha20
]
```

### Removed Compression

```python
# TLS 1.2: Compression support (VULNERABLE to CRIME)
compression_methods = [0x00, 0x01]  # Null, DEFLATE

# TLS 1.3: Compression removed entirely
compression_methods = [0x00]  # Null only
```

**Reason**: CRIME attack (2012) extracted secrets through compression side channels.

### Removed Renegotiation

```python
# TLS 1.2: In-connection renegotiation
def handle_renegotiation():
    """REMOVED in TLS 1.3"""
    # Client can request new handshake mid-connection
    # Led to numerous vulnerabilities (CVE-2009-3555, etc.)
    pass

# TLS 1.3: Use post-handshake messages instead
def update_keys():
    """KeyUpdate message for forward secrecy"""
    send_key_update_request()
    # Generates new application traffic keys
```

## Forward Secrecy Guarantees

### Ephemeral Diffie-Hellman Only

```python
# TLS 1.2: Static RSA key exchange (NO forward secrecy)
def rsa_key_exchange_vulnerable():
    """
    Server's RSA private key decrypts all past sessions
    If key compromised → all recorded traffic decrypted
    """
    # Client encrypts pre-master secret with server's RSA public key
    pre_master_secret = os.urandom(48)
    encrypted_pms = rsa_encrypt(server_rsa_public, pre_master_secret)

    # Attacker with server's private key can decrypt
    # all recorded ciphertexts!
    return encrypted_pms

# TLS 1.3: Only (EC)DHE (mandatory forward secrecy)
def ecdhe_key_exchange_secure():
    """
    Ephemeral keys deleted after handshake
    Past sessions remain secure even if long-term key compromised
    """
    # Generate ephemeral key (deleted after handshake)
    ephemeral_key = generate_x25519_keypair()

    # Compute shared secret
    shared_secret = ecdhe_exchange(ephemeral_key, peer_public)

    # Delete ephemeral private key
    del ephemeral_key['private']

    # Compromising server's certificate key does NOT
    # compromise past session keys!
```

### Post-Handshake Key Update

```python
def initiate_key_update():
    """
    Rotate application traffic keys without new handshake
    Provides ongoing forward secrecy
    """
    # Send KeyUpdate message
    key_update_msg = {
        'request_update': True  # Request peer to also update
    }

    send_encrypted_message(key_update_msg, current_app_secret)

    # Derive new application traffic secret
    new_secret = HKDF_Expand_Label(
        current_app_secret,
        b'traffic upd',
        b'',
        hash_length
    )

    # Switch to new keys
    current_app_secret = new_secret
    sequence_number = 0  # Reset sequence

    return new_secret
```

## Implementation with GnuTLS

### Server Configuration

```c
#include <gnutls/gnutls.h>

int setup_tls13_server() {
    gnutls_certificate_credentials_t cred;
    gnutls_session_t session;

    // Initialize credentials
    gnutls_certificate_allocate_credentials(&cred);
    gnutls_certificate_set_x509_key_file(
        cred,
        "server-cert.pem",
        "server-key.pem",
        GNUTLS_X509_FMT_PEM
    );

    // Create session
    gnutls_init(&session, GNUTLS_SERVER);

    // Set priority string (TLS 1.3 only)
    gnutls_priority_set_direct(
        session,
        "NORMAL:-VERS-ALL:+VERS-TLS1.3",
        NULL
    );

    // Set credentials
    gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, cred);

    return 0;
}
```

### Client Configuration

```python
import gnutls.connection
import gnutls.crypto

def create_tls13_client():
    """Python GnuTLS client"""
    # Create credentials
    cred = gnutls.crypto.X509Credentials()

    # Load CA certificates
    cred.set_x509_trust_file('/etc/ssl/certs/ca-certificates.crt')

    # Create session
    session = gnutls.connection.ClientSession(
        socket.socket(),
        cred
    )

    # Set TLS 1.3 only
    session.set_priority('NORMAL:-VERS-ALL:+VERS-TLS1.3')

    # Enable session resumption
    session.set_session_cache(gnutls.connection.SessionCache())

    return session
```

## Performance Improvements

### Latency Reduction

```
TLS 1.2 Full Handshake:
    2-RTT + TCP 3-way handshake = ~300ms (100ms RTT)

TLS 1.3 Full Handshake:
    1-RTT + TCP 3-way handshake = ~200ms (100ms RTT)
    33% improvement

TLS 1.3 with 0-RTT:
    0-RTT + TCP handshake = ~100ms (100ms RTT)
    67% improvement over TLS 1.2
```

### Computational Cost

```python
# Benchmark on modern CPU
import time

def benchmark_handshakes(num_iterations=1000):
    """Compare TLS 1.2 vs 1.3 performance"""

    # TLS 1.2 RSA handshake
    start = time.perf_counter()
    for _ in range(num_iterations):
        perform_tls12_rsa_handshake()
    tls12_rsa_time = time.perf_counter() - start

    # TLS 1.3 ECDHE handshake
    start = time.perf_counter()
    for _ in range(num_iterations):
        perform_tls13_ecdhe_handshake()
    tls13_time = time.perf_counter() - start

    print(f"TLS 1.2 RSA: {tls12_rsa_time:.2f}s ({tls12_rsa_time/num_iterations*1000:.1f}ms/handshake)")
    print(f"TLS 1.3:     {tls13_time:.2f}s ({tls13_time/num_iterations*1000:.1f}ms/handshake)")
    print(f"Speedup:     {tls12_rsa_time/tls13_time:.2f}x")

# Typical results (Intel i7):
# TLS 1.2 RSA: 2.8ms/handshake (RSA-2048 decrypt)
# TLS 1.3:     0.4ms/handshake (X25519 ECDHE)
# Speedup:     7x
```

## Migration Recommendations

### Deployment Strategy

```nginx
# Nginx configuration
server {
    listen 443 ssl http2;

    # Enable TLS 1.3 (with 1.2 fallback)
    ssl_protocols TLSv1.2 TLSv1.3;

    # TLS 1.3 cipher suites (prioritize)
    ssl_ciphers TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:ECDHE-RSA-AES128-GCM-SHA256;

    ssl_prefer_server_ciphers off;  # Let client choose for TLS 1.3

    # Enable 0-RTT (carefully!)
    ssl_early_data on;

    # Certificate
    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;
}
```

### 0-RTT Deployment

```nginx
# Proxy configuration for 0-RTT
location /api {
    # Prevent replay attacks

    # Option 1: Reject 0-RTT for sensitive endpoints
    if ($ssl_early_data = "1") {
        return 425;  # Too Early
    }

    # Option 2: Add header for backend validation
    proxy_set_header Early-Data $ssl_early_data;
    proxy_pass http://backend;
}
```

## Conclusion

TLS 1.3 represents a major security and performance upgrade. Key improvements:
- Mandatory forward secrecy (no static RSA)
- 1-RTT handshake (50% latency reduction)
- Simplified cipher suite selection (AEAD only)
- Removed vulnerable features (compression, renegotiation, weak ciphers)

Organizations should prioritize TLS 1.3 deployment while maintaining TLS 1.2 compatibility for legacy clients. Disable TLS 1.0/1.1 entirely.

## References

1. RFC 8446 - The Transport Layer Security (TLS) Protocol Version 1.3
2. GnuTLS Manual - https://gnutls.org/manual/
3. Rescorla, E. (2018). "The Transport Layer Security (TLS) Protocol Version 1.3"
4. Bhargavan, K., Leurent, G. (2016). "Transcript Collision Attacks: Breaking Authentication in TLS, IKE, and SSH"
