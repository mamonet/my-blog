---
title: "TLS Session Resumption: Session IDs, Session Tickets, and 0-RTT Security"
description: "Technical analysis of TLS session resumption mechanisms including session IDs, session tickets (RFC 5077), TLS 1.3 PSK resumption, and security implications of 0-RTT data."
pubDate: 2024-06-03
author: "Mamoun Tarsha-Kurdi"
tags: ["tls", "protocols", "performance", "security"]
draft: false
---

## Introduction

TLS session resumption reduces handshake latency by reusing previous security parameters. Understanding resumption mechanisms is critical for both performance optimization and security analysis.

## Session ID Resumption (RFC 5246)

### Mechanism

```python
def tls_session_id_resumption():
    """
    TLS 1.2 Session ID resumption
    """
    # Initial full handshake
    initial_handshake = {
        'client_hello': {'session_id': b''},
        'server_hello': {'session_id': os.urandom(32)},  # Server generates ID
        'handshake': 'full 2-RTT handshake'
    }
    
    # Server stores session state
    session_cache[session_id] = {
        'master_secret': derived_master_secret,
        'cipher_suite': selected_cipher,
        'timestamp': time.time()
    }
    
    # Resumption handshake
    resumption_handshake = {
        'client_hello': {'session_id': previous_session_id},
        'server_hello': {
            'session_id': previous_session_id,  # Same ID → resumption
            'cipher_suite': cached_cipher
        },
        'handshake': 'abbreviated 1-RTT handshake'
    }
    
    # Derive new keys from cached master_secret
    new_keys = derive_keys(
        cached_master_secret,
        new_client_random,
        new_server_random
    )
```

### Server-Side Session Cache

```c
// OpenSSL session cache configuration
SSL_CTX *ctx = SSL_CTX_new(TLS_method());

// Enable session cache (default size: 20480 entries)
SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_SERVER);

// Set cache size
SSL_CTX_sess_set_cache_size(ctx, 10000);

// Set timeout (5 minutes)
SSL_CTX_set_timeout(ctx, 300);

// Custom session cache (e.g., Redis)
SSL_CTX_sess_set_new_cb(ctx, session_new_callback);
SSL_CTX_sess_set_get_cb(ctx, session_get_callback);
SSL_CTX_sess_set_remove_cb(ctx, session_remove_callback);
```

**Limitations**:
- Server must maintain session state
- Not scalable for load-balanced servers
- Session tied to specific server

## Session Tickets (RFC 5077)

### Stateless Resumption

```python
def create_session_ticket(session_state, ticket_key):
    """
    Create encrypted session ticket
    Server stores NO state!
    """
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    
    # Serialize session state
    ticket_data = {
        'master_secret': session_state['master_secret'],
        'cipher_suite': session_state['cipher_suite'],
        'timestamp': int(time.time()),
        'protocol_version': 0x0303  # TLS 1.2
    }
    
    plaintext = json.dumps(ticket_data).encode()
    
    # Encrypt with server's secret key
    aesgcm = AESGCM(ticket_key)
    nonce = os.urandom(12)
    
    encrypted_ticket = aesgcm.encrypt(nonce, plaintext, b'')
    
    # Ticket structure
    ticket = {
        'key_name': ticket_key_id,  # 16 bytes
        'iv': nonce,                # 12 bytes
        'encrypted_state': encrypted_ticket,
        'mac': hmac_sha256(ticket_key, encrypted_ticket)
    }
    
    return serialize_ticket(ticket)

def resume_with_ticket(ticket, ticket_keys):
    """
    Decrypt and validate session ticket
    """
    parsed = parse_ticket(ticket)
    
    # Find decryption key by key_name
    ticket_key = ticket_keys.get(parsed['key_name'])
    if not ticket_key:
        return None  # Unknown key → full handshake
    
    # Verify MAC
    expected_mac = hmac_sha256(ticket_key, parsed['encrypted_state'])
    if not constant_time_compare(expected_mac, parsed['mac']):
        return None  # Invalid ticket
    
    # Decrypt
    aesgcm = AESGCM(ticket_key)
    try:
        plaintext = aesgcm.decrypt(parsed['iv'], parsed['encrypted_state'], b'')
        session_state = json.loads(plaintext)
    except:
        return None  # Decryption failed
    
    # Check expiration
    if time.time() - session_state['timestamp'] > 86400:  # 24 hours
        return None  # Expired
    
    return session_state
```

### Key Rotation

```python
class TicketKeyManager:
    """
    Rotate session ticket encryption keys
    Maintains forward secrecy
    """
    def __init__(self):
        self.keys = {}
        self.current_key_id = None
        self.rotation_interval = 3600  # 1 hour
        
        # Generate initial key
        self.rotate_key()
    
    def rotate_key(self):
        """Generate new encryption key"""
        key_id = os.urandom(16)
        key = os.urandom(32)  # AES-256 key
        
        self.keys[key_id] = {
            'key': key,
            'created': time.time()
        }
        
        self.current_key_id = key_id
        
        # Remove old keys (keep last 3 for decryption)
        if len(self.keys) > 3:
            oldest = min(self.keys.items(), key=lambda x: x[1]['created'])
            del self.keys[oldest[0]]
    
    def get_current_key(self):
        """Get key for encrypting new tickets"""
        return self.keys[self.current_key_id]
    
    def get_decryption_key(self, key_id):
        """Get key for decrypting ticket"""
        return self.keys.get(key_id)
```

## TLS 1.3 PSK Resumption

### Pre-Shared Key Mode

```python
def tls13_psk_handshake():
    """
    TLS 1.3 resumption using PSK
    """
    # Server sends NewSessionTicket after handshake
    new_session_ticket = {
        'ticket_lifetime': 86400,  # 24 hours
        'ticket_age_add': random.randint(0, 2**32),  # Obfuscation
        'ticket_nonce': os.urandom(16),
        'ticket': encrypted_session_state,
        'extensions': {
            'early_data': {'max_early_data_size': 16384}
        }
    }
    
    # Client stores: (ticket, resumption_master_secret)
    
    # Resumption handshake
    client_hello = {
        'extensions': {
            'pre_shared_key': {
                'identities': [(ticket, obfuscated_ticket_age)],
                'binders': [compute_psk_binder(ticket, client_hello)]
            },
            'psk_key_exchange_modes': ['psk_dhe_ke'],  # PSK with (EC)DHE
        }
    }
    
    server_hello = {
        'extensions': {
            'pre_shared_key': {'selected_identity': 0}
        }
    }
    
    # 1-RTT resumption (or 0-RTT with early_data)
```

### PSK Binder Calculation

```python
def compute_psk_binder(psk, partial_client_hello):
    """
    Cryptographic binding of PSK to handshake
    Prevents PSK substitution attacks
    """
    # Derive binder key from resumption_master_secret
    early_secret = HKDF_Extract(salt=b'\x00'*32, ikm=psk['secret'])
    
    binder_key = Derive_Secret(
        early_secret,
        label=b'res binder',
        context=b''
    )
    
    # Hash ClientHello up to (but not including) binders
    transcript_hash = SHA256(partial_client_hello)
    
    # Compute Finished-like MAC
    finished_key = HKDF_Expand_Label(
        binder_key,
        label=b'finished',
        context=b'',
        length=32
    )
    
    binder = HMAC_SHA256(finished_key, transcript_hash)
    
    return binder
```

## 0-RTT Early Data

### Implementation

```python
def send_0rtt_data(psk, early_data):
    """
    Send application data in first flight (0-RTT)
    """
    # Derive early_traffic_secret
    early_secret = HKDF_Extract(b'\x00'*32, psk['secret'])
    
    client_early_traffic_secret = Derive_Secret(
        early_secret,
        b'c e traffic',
        hash_messages(client_hello)
    )
    
    # Encrypt early data
    encrypted = encrypt_record(
        early_data,
        client_early_traffic_secret,
        content_type=APPLICATION_DATA
    )
    
    # Send: ClientHello + EncryptedExtensions + early_data
    return (client_hello, encrypted)
```

### Replay Protection

```python
class AntiReplayCache:
    """
    Prevent 0-RTT replay attacks
    """
    def __init__(self, window_seconds=10):
        self.seen_tickets = set()
        self.window = window_seconds
    
    def is_replay(self, ticket_hash, timestamp):
        """
        Check if 0-RTT request is replay
        """
        # Check timestamp freshness
        if abs(time.time() - timestamp) > self.window:
            return True  # Outside window → reject
        
        # Check if seen before
        if ticket_hash in self.seen_tickets:
            return True  # Replay!
        
        # Mark as seen
        self.seen_tickets.add(ticket_hash)
        
        # Clean old entries (sliding window)
        self.cleanup_old_entries()
        
        return False
    
    def cleanup_old_entries(self):
        """Remove entries older than window"""
        # Implementation: Use timestamped entries
        cutoff = time.time() - self.window
        self.seen_tickets = {
            ticket for ticket, ts in self.ticket_timestamps.items()
            if ts > cutoff
        }
```

## Performance Impact

### Latency Comparison

```
Full Handshake (TLS 1.2):
    TCP 3-way: 50ms
    TLS 2-RTT: 100ms
    Total: 150ms

Session ID Resumption (TLS 1.2):
    TCP 3-way: 50ms
    TLS 1-RTT: 50ms
    Total: 100ms (33% faster)

Session Ticket Resumption (TLS 1.2):
    TCP 3-way: 50ms
    TLS 1-RTT: 50ms
    Total: 100ms (33% faster)

TLS 1.3 PSK Resumption:
    TCP 3-way: 50ms
    TLS 1-RTT: 50ms
    Total: 100ms (33% faster)

TLS 1.3 0-RTT:
    TCP 3-way: 50ms
    TLS 0-RTT: 0ms
    Total: 50ms (67% faster!)
```

### Server Configuration

```nginx
# Nginx: Session resumption configuration
http {
    # Session cache (shared across workers)
    ssl_session_cache shared:SSL:50m;  # 50MB cache
    ssl_session_timeout 1d;  # 24 hours
    
    # Session tickets
    ssl_session_tickets on;
    ssl_session_ticket_key /etc/nginx/ticket_keys/current.key;
    ssl_session_ticket_key /etc/nginx/ticket_keys/previous.key;
    
    # TLS 1.3 early data
    ssl_early_data on;
    
    server {
        listen 443 ssl http2;
        
        # Protect against 0-RTT replay
        location / {
            # Check Early-Data header
            if ($ssl_early_data = "1") {
                # Only allow idempotent methods
                if ($request_method !~ ^(GET|HEAD)$) {
                    return 425;  # Too Early
                }
            }
            
            proxy_set_header Early-Data $ssl_early_data;
            proxy_pass http://backend;
        }
    }
}
```

## Security Considerations

### Session Fixation

```python
def prevent_session_fixation():
    """
    Generate new session ID after authentication
    """
    # Before authentication
    initial_session_id = request.session.session_id
    
    # Authenticate user
    if authenticate(username, password):
        # Regenerate session ID
        request.session.regenerate_id()
        
        # Old session ID now invalid
        session_cache.delete(initial_session_id)
        
        return new_session_id
```

### Forward Secrecy with Tickets

```python
def ticket_key_rotation_strategy():
    """
    Rotate ticket keys to maintain forward secrecy
    Compromised key only affects tickets encrypted with that key
    """
    # Key rotation schedule
    schedules = {
        'aggressive': 3600,      # 1 hour
        'balanced': 86400,       # 24 hours
        'conservative': 604800   # 1 week
    }
    
    # Keep N previous keys for decryption
    retention_count = 3
    
    # After key deleted, tickets encrypted with it become invalid
    # → Limits exposure window
```

### 0-RTT Replay Mitigations

```python
def secure_0rtt_handling():
    """
    Best practices for 0-RTT data
    """
    # 1. Strict anti-replay (single-use tokens)
    if not anti_replay_check(request):
        return reject_0rtt()
    
    # 2. Idempotency enforcement
    allowed_methods = {'GET', 'HEAD'}
    if request.method not in allowed_methods:
        return reject_0rtt()
    
    # 3. Rate limiting
    if exceeds_rate_limit(client_ip, window='10s'):
        return reject_0rtt()
    
    # 4. Separate handler for early data
    if request.is_early_data:
        return handle_early_data_securely(request)
    
    return process_normal_request(request)
```

## Monitoring and Metrics

```python
def track_resumption_metrics():
    """
    Monitor session resumption effectiveness
    """
    metrics = {
        'total_handshakes': 0,
        'full_handshakes': 0,
        'resumed_sessions': 0,
        'resumed_0rtt': 0,
        'resumption_failures': 0
    }
    
    # Calculate resumption rate
    resumption_rate = metrics['resumed_sessions'] / metrics['total_handshakes']
    
    # Alert if resumption rate drops (cache issues?)
    if resumption_rate < 0.7:  # Below 70%
        alert("Low TLS resumption rate: {:.1%}".format(resumption_rate))
    
    # Track 0-RTT acceptance
    early_data_rate = metrics['resumed_0rtt'] / metrics['resumed_sessions']
    
    return metrics
```

## Conclusion

Session resumption significantly improves TLS performance:
- 33-67% latency reduction
- Reduced server CPU usage
- Better user experience

Recommendations:
1. Enable session caching or tickets
2. Rotate ticket keys regularly (daily)
3. Use 0-RTT cautiously (GET/HEAD only)
4. Implement anti-replay for 0-RTT
5. Monitor resumption metrics

Modern deployments should use TLS 1.3 with PSK resumption and carefully configured 0-RTT for optimal performance and security.

## References

1. RFC 5246 - The Transport Layer Security (TLS) Protocol Version 1.2
2. RFC 5077 - Transport Layer Security (TLS) Session Resumption without Server-Side State
3. RFC 8446 - The Transport Layer Security (TLS) Protocol Version 1.3
4. Sy, E., et al. (2018). "Tracking Users across the Web via TLS Session Resumption"
