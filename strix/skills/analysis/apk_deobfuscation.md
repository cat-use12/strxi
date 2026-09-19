---
name: apk_deobfuscation
description: Deep APK reverse engineering — DEX decompilation, string decryption, Smali analysis, Flutter/React Native, certificate pinning bypass
---

# APK Deep Reverse Engineering

## Toolchain Setup

```bash
# Core decompilation
apktool d target.apk -o decoded/       # resources + smali
d2j-dex2jar target.apk -o target.jar  # dex → jar
jadx target.apk -d jadx_out/           # all-in-one decompiler (best for reading)

# Supplemental
jadx-gui target.apk                    # GUI version with xref
apksigner verify --verbose target.apk  # signature info
aapt dump badging target.apk           # manifest summary

# Install jadx:
# brew install jadx
# or: https://github.com/skylot/jadx/releases
```

## Initial Recon

```bash
# Architecture / native libs
file decoded/lib/**/*.so
strings decoded/lib/armeabi-v7a/*.so | grep -i "http\|key\|token\|secret"

# Permissions and components
cat decoded/AndroidManifest.xml | grep -E "(permission|service|receiver|activity|provider|exported)"

# Check for common C2 SDKs
grep -r "okhttp\|retrofit\|volley\|socket.io\|mqtt\|websocket" jadx_out/ -l

# Assets (config files, encrypted blobs)
ls -la decoded/assets/
file decoded/assets/*
```

## String Decryption

### Pattern 1 — Base64 constants

```python
import base64, re

code = open("jadx_out/sources/com/target/app/Config.java").read()
b64_strings = re.findall(r'"([A-Za-z0-9+/]{20,}={0,2})"', code)
for s in b64_strings:
    try:
        dec = base64.b64decode(s)
        print(f"{s[:20]}... → {dec}")
    except:
        pass
```

### Pattern 2 — XOR encrypted strings (common in obfuscated APKs)

```smali
# Smali pattern to recognize:
# const-string v0, "encrypted_hex_string"
# invoke-static {v0, v1}, Lcom/obf/a;->a(Ljava/lang/String;I)Ljava/lang/String;
```

```python
# Implement the decrypt function from Smali:
def decrypt_xor(ciphertext_hex: str, key: int) -> str:
    data = bytes.fromhex(ciphertext_hex)
    return bytes(b ^ (key & 0xFF) for b in data).decode('utf-8', errors='replace')

# Find the key value (often a hardcoded int in the class)
# smali: const/16 v1, 0x3a
print(decrypt_xor("7b1c3a2b", 0x3a))
```

### Pattern 3 — AES encrypted strings

```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import base64

# Key and IV often hardcoded in the class or derived from BuildConfig
key = b"1234567890123456"  # 16/24/32 bytes
iv  = b"abcdefghijklmnop"  # 16 bytes

def aes_decrypt(b64_cipher: str) -> str:
    cipher = AES.new(key, AES.MODE_CBC, iv)
    raw = base64.b64decode(b64_cipher)
    return unpad(cipher.decrypt(raw), AES.block_size).decode()

# From jadx, find all calls to the decrypt method and extract the arguments
```

## Smali Analysis

```smali
# Key Smali patterns:

# String decryption call
const-string v0, "7f3a1b2c"
const/4 v1, 0x5
invoke-static {v0, v1}, Lcom/util/Crypt;->d(Ljava/lang/String;I)Ljava/lang/String;
move-result-object v2
# v2 now holds decrypted string

# Network call (OkHttp)
new-instance v0, Lokhttp3/Request$Builder;
invoke-virtual {v0, v1}, Lokhttp3/Request$Builder;->url(Ljava/lang/String;)Lokhttp3/Request$Builder;
# v1 is the URL

# Reflection-based class loading (used to hide class names)
const-string v0, "com.hidden.Payload"
invoke-static {v0}, Ljava/lang/Class;->forName(Ljava/lang/String;)Ljava/lang/Class;

# Find all invoke-virtual/invoke-static in smali:
grep -r "invoke-.*Lcom/target/" decoded/smali/ | grep -i "decrypt\|decode\|cipher"
```

## Flutter APK Reversing

Flutter compiles to native ARM code — not Java. The Dart code is in `libapp.so`.

```bash
# Check if Flutter:
ls decoded/lib/arm64-v8a/
# Look for: libflutter.so + libapp.so

# Extract strings from libapp.so
strings decoded/lib/arm64-v8a/libapp.so | grep -i "http\|api\|token\|secret\|base_url" | head -50

# Network endpoints are often stored as constants
strings decoded/lib/arm64-v8a/libapp.so | grep "https\?://"

# Blutter (Dart VM snapshot decompiler)
# https://github.com/worawit/blutter
python3 blutter.py decoded/lib/arm64-v8a/ output/
# Generates: asm files, object pool dump, class/method list

# Common Flutter C2 patterns:
strings libapp.so | grep -E "(socket|ws://|wss://|/api/|Bearer)"
```

## React Native APK Reversing

```bash
# RN bundles JS inside assets/
ls decoded/assets/
# Look for: index.android.bundle or main.jsbundle

# Deobfuscate JS bundle
npm install -g js-beautify hermes-dec
# If Hermes bytecode:
file decoded/assets/index.android.bundle
# "Hermes JavaScript bytecode" → need hermes-dec
hermes-dec decoded/assets/index.android.bundle -o decompiled.js

# Then beautify:
js-beautify decompiled.js -o pretty.js

# Extract C2 from bundle:
grep -o '"https\?://[^"]*"' pretty.js | sort -u
grep -i "token\|secret\|api_key\|bot\|admin" pretty.js | head -30
```

## Certificate Pinning Bypass

### Method 1 — Frida (runtime)

```javascript
// Universal SSL unpin (Frida)
Java.perform(function() {
    // TrustManager bypass
    var TrustManager = Java.registerClass({
        name: 'com.custom.TrustManager',
        implements: [Java.use('javax.net.ssl.X509TrustManager')],
        methods: {
            checkClientTrusted: function(chain, authType) {},
            checkServerTrusted: function(chain, authType) {},
            getAcceptedIssuers: function() { return []; }
        }
    });
    var SSLContext = Java.use('javax.net.ssl.SSLContext');
    SSLContext.init.overload(
        '[Ljavax.net.ssl.KeyManager;',
        '[Ljavax.net.ssl.TrustManager;',
        'java.security.SecureRandom'
    ).implementation = function(km, tm, sr) {
        this.init(km, [TrustManager.$new()], sr);
    };
});
```

### Method 2 — Patching smali

```bash
# Find pinning class in smali
grep -r "checkServerTrusted\|sha256\|sha1\|CertificatePinner" decoded/smali/ -l

# In the checkServerTrusted method, add:
# return-void   (at the top, skip all checks)

# Rebuild and sign:
apktool b decoded/ -o patched.apk
apksigner sign --ks debug.keystore --ks-key-alias androiddebugkey patched.apk
adb install patched.apk
```

## HMAC / Signature Reverse Engineering

```java
// Common pattern in Java (from jadx):
Mac mac = Mac.getInstance("HmacSHA256");
mac.init(new SecretKeySpec("hardcoded_key".getBytes(), "HmacSHA256"));
String sig = Base64.encodeToString(mac.doFinal(payload.getBytes()), 0);
```

```python
# Replicate in Python:
import hmac, hashlib, base64
key = b"hardcoded_key"
payload = b"timestamp=1234567890&nonce=abcdef"
sig = base64.b64encode(hmac.new(key, payload, hashlib.sha256).digest()).decode()
print("X-Signature:", sig)
```

## Hidden API Endpoint Discovery

```bash
# All URLs in the APK (decoded)
grep -r "http" jadx_out/ | grep -oE "https?://[^\"' )>]+" | sort -u

# API paths without domain
grep -r '"/api/\|/v1/\|/v2/\|/internal/' jadx_out/ | grep -oE '"(/[^"]{5,})"' | sort -u

# WebSocket endpoints
grep -r "ws://\|wss://" jadx_out/

# BuildConfig values (often contain base URLs, API keys)
cat jadx_out/sources/*/BuildConfig.java 2>/dev/null
grep -r "BuildConfig\." jadx_out/sources/ | grep -i "url\|key\|token\|secret"
```

## Automated Secret Hunting

```python
import re, os

PATTERNS = {
    'api_key':       r'(?i)(api[_-]?key|apikey)\s*[=:]\s*["\']([A-Za-z0-9_\-]{20,})["\']',
    'bearer_token':  r'Bearer\s+([A-Za-z0-9\-._~+/]+=*)',
    'bot_token':     r'\d{9,10}:AA[A-Za-z0-9_-]{35}',
    'aws_key':       r'AKIA[0-9A-Z]{16}',
    'private_key':   r'-----BEGIN [A-Z ]+PRIVATE KEY-----',
    'password':      r'(?i)(password|passwd|pwd)\s*[=:]\s*["\']([^"\']{6,})["\']',
    'base_url':      r'(?i)(base_url|api_url|server_url)\s*[=:]\s*["\']([^"\']+)["\']',
}

def hunt_secrets(directory):
    for root, _, files in os.walk(directory):
        for fname in files:
            if fname.endswith(('.java', '.kt', '.smali', '.xml', '.json', '.js')):
                path = os.path.join(root, fname)
                try:
                    content = open(path, encoding='utf-8', errors='ignore').read()
                    for name, pattern in PATTERNS.items():
                        matches = re.findall(pattern, content)
                        if matches:
                            print(f"\n[{name}] {path}")
                            for m in matches:
                                print(f"  → {m}")
                except:
                    pass

hunt_secrets('jadx_out/')
```
