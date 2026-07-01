---
title: "TLS Downgrade Attacks: POODLE, FREAK, and Logjam Analysis"
description: "Technical analysis of protocol downgrade attacks targeting TLS/SSL, including POODLE, FREAK, Logjam, and DROWN vulnerabilities with mitigation strategies."
pubDate: 2023-07-25
author: "Mamone Tarsia"
tags: ["tls", "vulnerabilities", "protocols", "security"]
draft: false
---

## Introduction

TLS protocol downgrade attacks exploit backward compatibility mechanisms to force use of weak cryptography. Understanding these attacks is critical for secure server configuration.

## POODLE Attack (CVE-2014-3566)

### Padding Oracle On Downgraded Legacy Encryption

**Target**: SSLv3 CBC-mode ciphers

**Vulnerability**: SSL 3.0 padding validation flaw

```python
def sslv3_cbc_decrypt(ciphertext, key, iv):
    """
    SSLv3 CBC decryption with padding oracle vulnerability
    """
    from Crypto.Cipher import AES
    
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext)
    
    # Extract padding length
    padding_length = plaintext[-1]
    
    # VULNERABILITY: SSLv3 only checks last byte!
    # Doesn't validate entire padding
    if padding_length > len(plaintext):
        raise Exception("Invalid padding")
    
    # Remove padding (potentially wrong!)
    return plaintext[:-padding_length-1]

# TLS 1.0+ validates ALL padding bytes:
def tls10_cbc_decrypt(ciphertext, key, iv):
    """Secure TLS 1.0+ padding validation"""
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext)
    
    padding_length = plaintext[-1]
    
    # Check ALL padding bytes equal padding_length
    for i in range(padding_length + 1):
        if plaintext[-(i+1)] != padding_length:
            raise Exception("Invalid padding")
    
    return plaintext[:-padding_length-1]
```

### Attack Technique

```python
def poodle_attack(target_url, session_cookie):
    """
    POODLE attack to extract session cookie
    Requires ~256 requests per byte
    """
    import requests
    
    recovered_cookie = b''
    
    for byte_pos in range(len(session_cookie)):
        for guess in range(256):
            # Force SSLv3 downgrade
            session = requests.Session()
            session.mount('https://', SSLv3Adapter())
            
            # Craft request to position target byte in specific block
            padding_request = craft_request(
                target_byte_position=byte_pos,
                guess_value=guess
            )
            
            try:
                response = session.post(target_url, data=padding_request)
                
                # If padding valid → correct guess
                if response.status_code == 200:
                    recovered_cookie += bytes([guess])
                    break
            except:
                # Padding error → wrong guess
                continue
    
    return recovered_cookie
```

**Mitigation**:
```nginx
# Disable SSLv3 entirely
ssl_protocols TLSv1.2 TLSv1.3;
```

## FREAK Attack (CVE-2015-0204)

### Factoring RSA Export Keys

**Target**: Export-grade RSA (512-bit)

**Vulnerability**: Server accepts RSA_EXPORT even when not advertised

```python
def freak_attack_client_hello():
    """
    Client advertises strong ciphers only
    """
    client_hello = {
        'cipher_suites': [
            0x002F,  # TLS_RSA_WITH_AES_128_CBC_SHA (strong)
            0x0035,  # TLS_RSA_WITH_AES_256_CBC_SHA (strong)
        ]
    }
    return client_hello

def vulnerable_server_response():
    """
    Vulnerable server allows export cipher anyway!
    """
    server_hello = {
        'cipher_suite': 0x0008,  # TLS_RSA_EXPORT_WITH_DES40_CBC_SHA
        'certificate': {
            'key_size': 512  # Weak export key!
        }
    }
    return server_hello

def factor_512bit_rsa(modulus_512bit):
    """
    Factor 512-bit RSA in ~7 hours on EC2
    Cost: ~$100
    """
    from sage.all import factor
    
    # Use GNFS or CADO-NFS
    p, q = factor(modulus_512bit)
    
    return (p, q)
```

**Mitigation**:
```python
# OpenSSL config: Disable export ciphers
ssl_cipher_suite = "HIGH:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!SRP:!CAMELLIA"
```

## Logjam Attack (CVE-2015-4000)

### Diffie-Hellman Export Downgrade

**Target**: DHE_EXPORT (512-bit DH groups)

```python
def logjam_precomputation():
    """
    One-time precomputation for 512-bit DH group
    Cost: Academic cluster, several months
    """
    p = 0xD4BCD524...  # Common 512-bit prime
    g = 2
    
    # Precompute discrete log database
    # After precomputation, individual DH sessions broken in seconds
    database = number_field_sieve_precompute(p, g)
    
    return database

def break_dh_session(server_public, client_public, precomp_db):
    """
    Recover shared secret using precomputation
    Real-time attack: <30 seconds
    """
    # Recover server's private exponent
    server_private = discrete_log_lookup(server_public, precomp_db)
    
    # Compute shared secret
    shared_secret = pow(client_public, server_private, p)
    
    return shared_secret
```

**Mitigation**:
```bash
# Generate strong DH parameters (2048-bit minimum)
openssl dhparam -out dhparams.pem 2048

# Nginx configuration
ssl_dhparam /path/to/dhparams.pem;
ssl_ciphers 'ECDHE-RSA-AES128-GCM-SHA256:!DHE';  # Prefer ECDHE
```

## DROWN Attack (CVE-2016-0800)

### Decrypting RSA with Obsolete and Weakened eNcryption

**Target**: Servers supporting both TLS and SSLv2

```python
def drown_attack(tls_ciphertext, sslv2_oracle):
    """
    Use SSLv2 as oracle to decrypt TLS 1.2 RSA ciphertext
    Requires: Same RSA key used for both protocols
    """
    # SSLv2 has Bleichenbacher oracle vulnerability
    # Use it to decrypt TLS ciphertext
    
    num_queries = 1000  # Queries to SSLv2 server
    
    for i in range(num_queries):
        # Modify ciphertext for SSLv2 query
        modified = bleichenbacher_transform(tls_ciphertext, i)
        
        # Query SSLv2 server
        response = sslv2_oracle.decrypt(modified)
        
        if response.is_valid_padding():
            # Oracle revealed information
            update_search_space(modified, response)
    
    # After ~1000 queries, recover plaintext
    plaintext = extract_plaintext()
    
    return plaintext
```

**Mitigation**:
```nginx
# Disable SSLv2 (should be default everywhere)
ssl_protocols TLSv1.2 TLSv1.3;  # No SSLv2/SSLv3/TLS1.0/1.1
```

## Protocol Downgrade Prevention

### TLS_FALLBACK_SCSV (RFC 7507)

```python
def client_with_fallback_protection():
    """
    Client indicates if performing downgrade attempt
    """
    # First attempt: TLS 1.3
    client_hello_v13 = {
        'version': 0x0304,
        'cipher_suites': [...]
    }
    
    try:
        return tls_handshake(client_hello_v13)
    except:
        # Fallback to TLS 1.2
        client_hello_v12 = {
            'version': 0x0303,
            'cipher_suites': [
                ...,
                0x5600  # TLS_FALLBACK_SCSV ← Signals fallback!
            ]
        }
        
        return tls_handshake(client_hello_v12)

def server_fallback_check(client_hello):
    """
    Server detects and rejects inappropriate downgrades
    """
    if 0x5600 in client_hello['cipher_suites']:  # TLS_FALLBACK_SCSV
        # Client is falling back from higher version
        max_server_version = 0x0304  # TLS 1.3
        
        if client_hello['version'] < max_server_version:
            # Inappropriate fallback - possible attack!
            return alert_inappropriate_fallback()
    
    # Continue handshake
    return server_hello()
```

## Server Hardening

### Modern TLS Configuration

```nginx
# Nginx: Secure TLS configuration (2024)
server {
    listen 443 ssl http2;
    
    # Protocol versions
    ssl_protocols TLSv1.2 TLSv1.3;
    
    # Cipher suites (ordered by preference)
    ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305';
    
    ssl_prefer_server_ciphers off;  # TLS 1.3 client chooses
    
    # DH parameters (2048-bit minimum)
    ssl_dhparam /etc/nginx/dhparams.pem;
    
    # HSTS (force HTTPS for 1 year)
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
    
    # OCSP stapling
    ssl_stapling on;
    ssl_stapling_verify on;
    
    # Session resumption
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;
    ssl_session_tickets off;  # Prefer session cache
}
```

### Apache Configuration

```apache
# Apache: Secure TLS configuration
<VirtualHost *:443>
    SSLEngine on
    
    # Protocols
    SSLProtocol -all +TLSv1.2 +TLSv1.3
    
    # Cipher suites
    SSLCipherSuite ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305
    SSLHonorCipherOrder off
    
    # HSTS
    Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
    
    # Certificates
    SSLCertificateFile /path/to/cert.pem
    SSLCertificateKeyFile /path/to/key.pem
    SSLCertificateChainFile /path/to/chain.pem
</VirtualHost>
```

## Testing and Validation

### SSL Labs Test

```bash
# Test server configuration
curl -s "https://api.ssllabs.com/api/v3/analyze?host=example.com" | jq
```

### testssl.sh

```bash
# Comprehensive TLS testing
git clone https://github.com/drwetter/testssl.sh.git
cd testssl.sh
./testssl.sh --protocols --ciphers --vulnerable example.com

# Check for specific vulnerabilities
./testssl.sh --poodle --freak --logjam --drown example.com
```

### Custom Vulnerability Scanner

```python
import ssl
import socket

def test_protocol_support(hostname, port=443):
    """Test which TLS/SSL protocols are supported"""
    protocols = {
        'SSLv2': ssl.PROTOCOL_SSLv2,     # Should FAIL
        'SSLv3': ssl.PROTOCOL_SSLv3,     # Should FAIL
        'TLS 1.0': ssl.PROTOCOL_TLSv1,   # Should FAIL
        'TLS 1.1': ssl.PROTOCOL_TLSv1_1, # Should FAIL
        'TLS 1.2': ssl.PROTOCOL_TLSv1_2, # Should SUCCEED
        'TLS 1.3': ssl.PROTOCOL_TLS,     # Should SUCCEED
    }
    
    results = {}
    
    for name, protocol in protocols.items():
        try:
            context = ssl.SSLContext(protocol)
            with socket.create_connection((hostname, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    results[name] = {
                        'supported': True,
                        'version': ssock.version(),
                        'cipher': ssock.cipher()
                    }
        except:
            results[name] = {'supported': False}
    
    return results

# Test server
results = test_protocol_support('example.com')

for protocol, info in results.items():
    if info['supported']:
        print(f"[!] {protocol} SUPPORTED - {info.get('cipher')}")
        if protocol in ['SSLv2', 'SSLv3', 'TLS 1.0', 'TLS 1.1']:
            print(f"    VULNERABLE: {protocol} should be disabled!")
    else:
        print(f"[+] {protocol} disabled")
```

## Conclusion

Downgrade attacks exploit protocol negotiation mechanisms. Modern configurations must:
1. Disable SSLv2, SSLv3, TLS 1.0, TLS 1.1
2. Enforce strong cipher suites (AEAD only)
3. Use 2048-bit DH parameters minimum
4. Enable TLS_FALLBACK_SCSV
5. Implement HSTS for HTTPS enforcement

Regular testing with tools like SSL Labs and testssl.sh ensures ongoing security.

## References

1. CVE-2014-3566 - POODLE: SSLv3 vulnerability
2. CVE-2015-0204 - FREAK: Factoring RSA Export Keys
3. CVE-2015-4000 - Logjam: TLS connections using weak Diffie-Hellman
4. CVE-2016-0800 - DROWN: Decrypting TLS using SSLv2
5. RFC 7507 - TLS Fallback Signaling Cipher Suite Value
