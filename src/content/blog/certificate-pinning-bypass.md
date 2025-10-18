---
title: "TLS Certificate Pinning: Implementation and Bypass Techniques"
description: "Analysis of certificate pinning mechanisms in mobile applications, common implementation vulnerabilities, and bypass techniques using Frida, SSL proxies, and custom trust stores."
pubDate: 2024-12-09
author: "Mamoun Tarsha-Kurdi"
tags: ["tls", "mobile-security", "certificates", "reverse-engineering"]
draft: false
---

## Introduction

Certificate pinning enhances TLS security by rejecting certificates from untrusted CAs, even if system-trusted. However, incorrect implementation creates vulnerabilities exploitable during penetration testing and reverse engineering.

## Certificate Pinning Mechanisms

### Public Key Pinning

```java
// Android: Pin specific public key
public class PinningTrustManager implements X509TrustManager {
    private static final String PINNED_PUBLIC_KEY_HASH =
        "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType)
            throws CertificateException {

        // Get leaf certificate
        X509Certificate cert = chain[0];

        // Extract public key
        PublicKey publicKey = cert.getPublicKey();

        // Compute SHA-256 hash
        byte[] spkiBytes = publicKey.getEncoded();
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] hash = md.digest(spkiBytes);
        String actualHash = "sha256/" + Base64.encodeToString(hash, Base64.NO_WRAP);

        // Compare with pinned hash
        if (!actualHash.equals(PINNED_PUBLIC_KEY_HASH)) {
            throw new CertificateException("Certificate pin mismatch!");
        }
    }
}
```

### Certificate Pinning

```swift
// iOS: Pin entire certificate
class CertificatePinner: NSObject, URLSessionDelegate {
    let pinnedCertificates: [SecCertificate]

    init(certificateFiles: [String]) {
        var certs: [SecCertificate] = []

        for filename in certificateFiles {
            guard let path = Bundle.main.path(forResource: filename, ofType: "cer"),
                  let data = try? Data(contentsOf: URL(fileURLWithPath: path)),
                  let cert = SecCertificateCreateWithData(nil, data as CFData) else {
                continue
            }
            certs.append(cert)
        }

        self.pinnedCertificates = certs
    }

    func urlSession(_ session: URLSession,
                    didReceive challenge: URLAuthenticationChallenge,
                    completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {

        guard let serverTrust = challenge.protectionSpace.serverTrust else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }

        // Get server certificate
        guard let serverCert = SecTrustGetCertificateAtIndex(serverTrust, 0) else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }

        // Check if matches any pinned certificate
        let serverCertData = SecCertificateCopyData(serverCert) as Data

        for pinnedCert in pinnedCertificates {
            let pinnedCertData = SecCertificateCopyData(pinnedCert) as Data

            if serverCertData == pinnedCertData {
                // Pin match!
                let credential = URLCredential(trust: serverTrust)
                completionHandler(.useCredential, credential)
                return
            }
        }

        // No match - reject connection
        completionHandler(.cancelAuthenticationChallenge, nil)
    }
}
```

## Bypass Techniques

### 1. Frida Dynamic Instrumentation

```javascript
// Frida script to bypass Android SSL pinning
Java.perform(function() {
    console.log("[*] Bypassing SSL pinning...");

    // Hook TrustManager
    var TrustManager = Java.use('javax.net.ssl.X509TrustManager');
    var SSLContext = Java.use('javax.net.ssl.SSLContext');

    // Create custom TrustManager that accepts all certificates
    var TrustManagerImpl = Java.registerClass({
        name: 'com.sensepost.test.TrustManagerImpl',
        implements: [TrustManager],
        methods: {
            checkClientTrusted: function(chain, authType) {
                console.log("[+] checkClientTrusted called, bypassing...");
            },
            checkServerTrusted: function(chain, authType) {
                console.log("[+] checkServerTrusted called, bypassing...");
            },
            getAcceptedIssuers: function() {
                console.log("[+] getAcceptedIssuers called");
                return [];
            }
        }
    });

    // Hook SSLContext.init()
    SSLContext.init.overload(
        '[Ljavax.net.ssl.KeyManager;',
        '[Ljavax.net.ssl.TrustManager;',
        'java.security.SecureRandom'
    ).implementation = function(keyManager, trustManager, secureRandom) {
        console.log("[+] SSLContext.init() called");
        console.log("[+] Replacing TrustManager with custom implementation");

        var customTrustManager = TrustManagerImpl.$new();
        this.init(keyManager, [customTrustManager], secureRandom);
    };

    console.log("[*] SSL pinning bypass complete!");
});
```

### 2. Objection Framework

```bash
# Automated SSL pinning bypass
objection --gadget com.example.app explore

# Inside objection REPL
android sslpinning disable

# Verify bypass
android sslpinning watchfor
```

### 3. Custom Trust Store (Root Required)

```python
#!/usr/bin/env python3
"""
Add Burp Suite CA to Android system trust store
Requires root access
"""
import subprocess
import hashlib

def install_burp_ca_system_wide():
    """Install Burp CA as system-trusted certificate"""

    # 1. Get Burp Suite CA certificate (DER format)
    # Export from Burp: Proxy > Options > Import/Export CA Certificate

    burp_cert_path = "burp-ca-cert.der"

    # 2. Convert to PEM format
    subprocess.run([
        'openssl', 'x509',
        '-inform', 'DER',
        '-in', burp_cert_path,
        '-out', 'burp-ca-cert.pem'
    ])

    # 3. Compute hash for Android filename format
    with open('burp-ca-cert.pem', 'rb') as f:
        cert_data = f.read()

    cert_hash = hashlib.md5(cert_data).hexdigest()[:8]
    android_cert_name = f"{cert_hash}.0"

    # 4. Push to Android system certificate store
    subprocess.run(['adb', 'root'])
    subprocess.run(['adb', 'remount'])
    subprocess.run([
        'adb', 'push',
        'burp-ca-cert.pem',
        f'/system/etc/security/cacerts/{android_cert_name}'
    ])

    # 5. Set correct permissions
    subprocess.run([
        'adb', 'shell',
        'chmod', '644',
        f'/system/etc/security/cacerts/{android_cert_name}'
    ])

    # 6. Reboot device
    subprocess.run(['adb', 'reboot'])

    print(f"[+] Burp CA installed as {android_cert_name}")
    print("[+] Device rebooting...")
    print("[+] SSL pinning should now be ineffective for most apps")

if __name__ == '__main__':
    install_burp_ca_system_wide()
```

### 4. Patching APK

```bash
#!/bin/bash
# Patch Android APK to disable certificate pinning

APK="target_app.apk"
OUTPUT="target_app_patched.apk"

# 1. Decompile APK
apktool d "$APK" -o app_decompiled

# 2. Modify Network Security Config
cat > app_decompiled/res/xml/network_security_config.xml << 'EOF'
<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <base-config>
        <trust-anchors>
            <!-- Trust system certificates -->
            <certificates src="system" />
            <!-- Trust user-added certificates (Burp, mitmproxy, etc.) -->
            <certificates src="user" />
        </trust-anchors>
    </base-config>
</network-security-config>
EOF

# 3. Reference in AndroidManifest.xml
sed -i 's/<application /<application android:networkSecurityConfig="@xml\/network_security_config" /' \
    app_decompiled/AndroidManifest.xml

# 4. Remove pinning code from smali (if present)
# Find and patch TrustManager implementations
find app_decompiled/smali -name "*.smali" -exec sed -i \
    's/invoke-virtual.*checkServerTrusted/# &/' {} \;

# 5. Rebuild APK
apktool b app_decompiled -o "$OUTPUT"

# 6. Sign APK
keytool -genkey -v -keystore my-key.keystore -alias my-key \
    -keyalg RSA -keysize 2048 -validity 10000 \
    -storepass android -keypass android \
    -dname "CN=Test, O=Test, C=US"

jarsigner -verbose -sigalg SHA1withRSA -digestalg SHA1 \
    -keystore my-key.keystore -storepass android \
    "$OUTPUT" my-key

# 7. Align APK
zipalign -v 4 "$OUTPUT" "${OUTPUT/.apk/_aligned.apk}"

echo "[+] Patched APK: ${OUTPUT/.apk/_aligned.apk}"
echo "[+] Install with: adb install ${OUTPUT/.apk/_aligned.apk}"
```

## Secure Implementation

### Android Network Security Config

```xml
<!-- res/xml/network_security_config.xml -->
<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <domain-config>
        <domain includeSubdomains="true">api.example.com</domain>
        <pin-set expiration="2025-12-31">
            <!-- Pin public key hash (SPKI) -->
            <pin digest="SHA-256">base64hash==</pin>
            <!-- Backup pin (different key) -->
            <pin digest="SHA-256">backuphash==</pin>
        </pin-set>
    </domain-config>

    <!-- Debug-only: Allow user certificates in debug builds -->
    <debug-overrides>
        <trust-anchors>
            <certificates src="user" />
        </trust-anchors>
    </debug-overrides>
</network-security-config>
```

### iOS App Transport Security

```xml
<!-- Info.plist -->
<key>NSAppTransportSecurity</key>
<dict>
    <key>NSPinnedDomains</key>
    <dict>
        <key>api.example.com</key>
        <dict>
            <key>NSIncludesSubdomains</key>
            <true/>
            <key>NSPinnedLeafIdentities</key>
            <array>
                <dict>
                    <key>SPKI-SHA256-BASE64</key>
                    <string>base64hash==</string>
                </dict>
            </array>
        </dict>
    </dict>
</dict>
```

### Certificate Generation for Testing

```bash
#!/bin/bash
# Generate self-signed certificate for testing pinning

# 1. Generate private key
openssl genrsa -out server.key 2048

# 2. Generate certificate
openssl req -new -x509 -key server.key -out server.crt -days 365 \
    -subj "/C=US/ST=State/L=City/O=Org/CN=api.example.com"

# 3. Extract public key hash for pinning
openssl x509 -in server.crt -pubkey -noout | \
    openssl pkey -pubin -outform der | \
    openssl dgst -sha256 -binary | \
    base64

# Output: base64hash== (use this in pinning configuration)
```

## Detection and Monitoring

### Runtime Integrity Checks

```java
public class CertificatePinningDetector {
    /**
     * Detect if certificate pinning has been bypassed
     */
    public static boolean detectBypass() {
        try {
            // Check if Frida is injected
            if (detectFrida()) {
                Log.w("Security", "Frida detected - potential bypass!");
                return true;
            }

            // Check if running in emulator/rooted device
            if (isRooted() || isEmulator()) {
                Log.w("Security", "Rooted/emulator environment detected");
                return true;
            }

            // Check SSL context
            SSLContext context = SSLContext.getInstance("TLS");
            TrustManager[] trustManagers = getTrustManagers(context);

            if (trustManagers == null || trustManagers.length == 0) {
                Log.w("Security", "No trust managers - potential bypass!");
                return true;
            }

            // Verify trust manager class is expected
            for (TrustManager tm : trustManagers) {
                String className = tm.getClass().getName();

                // Check for known bypass class names
                if (className.contains("TrustManagerImpl") ||
                    className.contains("NaiveTrustManager") ||
                    className.contains("AllTrustManager")) {
                    Log.w("Security", "Suspicious TrustManager: " + className);
                    return true;
                }
            }

            return false;
        } catch (Exception e) {
            Log.e("Security", "Error detecting bypass", e);
            return false;
        }
    }

    private static boolean detectFrida() {
        // Check for Frida artifacts
        File[] suspiciousFiles = {
            new File("/data/local/tmp/frida-server"),
            new File("/data/local/tmp/frida-agent"),
        };

        for (File file : suspiciousFiles) {
            if (file.exists()) {
                return true;
            }
        }

        // Check for Frida ports
        try {
            Socket socket = new Socket("localhost", 27042);
            socket.close();
            return true;  // Frida default port is open
        } catch (IOException e) {
            // Port not open - good
        }

        return false;
    }
}
```

## Best Practices

### Multi-Layer Security

```kotlin
// Kotlin: Implement defense in depth
class SecureAPIClient {
    companion object {
        // 1. Certificate pinning
        private val pinnedPublicKeys = arrayOf(
            "sha256/primary_key_hash==",
            "sha256/backup_key_hash=="
        )

        // 2. Root detection
        fun isDeviceSecure(): Boolean {
            return !RootBeer(context).isRooted &&
                   !isEmulator() &&
                   !hasHooks()
        }

        // 3. Integrity checks
        fun verifyAppIntegrity(): Boolean {
            val packageInfo = context.packageManager
                .getPackageInfo(context.packageName, PackageManager.GET_SIGNATURES)

            val signature = packageInfo.signatures[0]
            val md = MessageDigest.getInstance("SHA-256")
            val digest = md.digest(signature.toByteArray())

            // Compare with known good signature
            return digest.contentEquals(KNOWN_SIGNATURE_HASH)
        }
    }

    init {
        // Perform security checks on initialization
        if (!isDeviceSecure()) {
            throw SecurityException("Insecure environment detected")
        }

        if (!verifyAppIntegrity()) {
            throw SecurityException("App integrity check failed")
        }
    }
}
```

### Key Rotation Strategy

```python
"""
Certificate pinning with graceful key rotation
"""
class PinningConfig:
    def __init__(self):
        self.pins = {
            'current': [
                'sha256/current_primary_hash==',
                'sha256/current_backup_hash=='
            ],
            'next': [
                'sha256/next_primary_hash==',
                'sha256/next_backup_hash=='
            ]
        }

        # Rotation schedule
        self.rotation_date = datetime(2025, 6, 1)

    def get_active_pins(self):
        """Return pins to enforce based on current date"""
        now = datetime.now()

        if now < self.rotation_date:
            # Accept both current and next pins during transition
            return self.pins['current'] + self.pins['next']
        else:
            # After rotation date, only accept new pins
            return self.pins['next']
```

## Conclusion

Certificate pinning significantly enhances security but must be implemented correctly to avoid:
1. Operational issues during certificate rotation
2. Easy bypass through dynamic instrumentation
3. Debugging difficulties during development

Recommendations:
- Use public key pinning (more flexible than certificate pinning)
- Include backup pins for rotation
- Implement multi-layer security (root detection, integrity checks)
- Use Android Network Security Config or iOS ATS for declarative pinning
- Monitor for bypass attempts in production

## References

1. OWASP Mobile Security Testing Guide - Certificate Pinning
2. RFC 7469 - Public Key Pinning Extension for HTTP
3. Android Developers - Network Security Configuration
4. Apple Developer - App Transport Security
