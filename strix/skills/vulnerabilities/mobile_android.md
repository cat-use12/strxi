---
name: mobile_android
description: Android application security testing — static analysis, dynamic hooking with Frida, traffic interception, common vulnerabilities
---

# Android App Security Testing

## Setup & Tools

```bash
# Static analysis tools
pip install apktool jadx  # or download jars
# apktool: https://apktool.org/
# jadx: https://github.com/skylot/jadx

# Dynamic: Frida
pip install frida-tools frida
# frida-server must run on device/emulator matching arch

# ADB
adb devices
adb shell                      # shell into device
adb install app.apk            # install APK
adb logcat                     # device logs

# Emulator (recommended for testing)
# Android Studio → AVD Manager → API 28 (rooted easier)
# Or: Genymotion, Corellium
```

## Static Analysis

### Decompile APK

```bash
# Extract + decompile resources (AndroidManifest, resources.arsc, smali)
apktool d app.apk -o app_decoded

# Decompile to Java (better readability)
jadx -d app_java app.apk
# Or GUI: jadx-gui app.apk

# Extract raw APK contents
unzip app.apk -d app_extracted
```

### AndroidManifest.xml — Critical Review Points

```bash
cat app_decoded/AndroidManifest.xml

# Look for:
# android:debuggable="true"  → allows ADB debugging on prod
# android:allowBackup="true" → can backup app data without root
# android:networkSecurityConfig → check if cleartext traffic allowed
# exported="true" on Activities/Services/Providers without permission
# Custom permissions with protection level "normal" (anyone can use)
```

### Secret Hunting

```bash
# Hardcoded strings in Java/Kotlin source
grep -rn "api_key\|apikey\|secret\|password\|token\|AWS\|firebase\|Bearer\|Basic " app_java/ --include="*.java"

# In resources
grep -rn "key\|secret\|token\|password" app_decoded/res/ app_decoded/assets/

# In smali (compiled bytecode)
grep -rn "const-string" app_decoded/smali/ | grep -i "key\|secret\|token\|password" | head -30

# Check strings.xml
cat app_decoded/res/values/strings.xml | grep -i "key\|secret\|token\|url\|endpoint"

# Firebase config
cat app_decoded/res/values/google-services.json 2>/dev/null
find app_decoded -name "google-services.json" -o -name "*.json" | xargs grep -l "firebase\|project_id" 2>/dev/null
```

### Network Security Config

```bash
cat app_decoded/res/xml/network_security_config.xml
# Look for:
# <trust-anchors> with <certificates src="user"/> → trusts user CAs (Burp easy)
# <base-config cleartextTrafficPermitted="true"> → HTTP allowed
# No config = default = no user CAs trusted on Android 7+ (need bypass)
```

### Exported Components

```bash
# Exported Activities (can be started by any app)
grep -A5 'exported="true"' app_decoded/AndroidManifest.xml | grep -i activity

# Start exported activity:
adb shell am start -n com.victim.app/.ExportedActivity
adb shell am start -n com.victim.app/.ExportedActivity --es "extra_key" "extra_value"

# Exported Content Providers (data access)
adb shell content query --uri content://com.victim.app.provider/users

# Exported Services
adb shell am startservice -n com.victim.app/.VulnerableService
```

## Dynamic Analysis with Frida

### Setup Frida Server on Device

```bash
# Download frida-server matching frida version and device arch
# https://github.com/frida/frida/releases
# adb push frida-server-XX-android-x86_64 /data/local/tmp/frida-server
adb push frida-server /data/local/tmp/frida-server
adb shell chmod 755 /data/local/tmp/frida-server
adb shell /data/local/tmp/frida-server &

# Verify connection
frida-ps -U         # list processes on USB device
frida-ps -U | grep com.victim
```

### SSL Pinning Bypass

```javascript
// Save as sslpinning.js
// Universal SSL pinning bypass (covers OkHttp, TrustManager, Conscrypt)

Java.perform(function() {
    // TrustManager override
    var TrustManager = Java.registerClass({
        name: 'com.strix.TrustAll',
        implements: [Java.use('javax.net.ssl.X509TrustManager')],
        methods: {
            checkClientTrusted: function(chain, authType) {},
            checkServerTrusted: function(chain, authType) {},
            getAcceptedIssuers: function() { return []; }
        }
    });
    
    var SSLContext = Java.use('javax.net.ssl.SSLContext');
    var TLS = SSLContext.getInstance('TLS');
    TLS.init(null, [TrustManager.$new()], null);
    SSLContext.getDefault.implementation = function() { return TLS; };
    
    // OkHttp3 CertificatePinner bypass
    try {
        var CertificatePinner = Java.use('okhttp3.CertificatePinner');
        CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function() {
            console.log('[*] CertificatePinner.check bypassed for: ' + arguments[0]);
        };
    } catch(e) {}
    
    // Conscrypt
    try {
        var PlatformTrustManager = Java.use('com.android.org.conscrypt.TrustManagerImpl');
        PlatformTrustManager.verifyChain.implementation = function(untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData) {
            return untrustedChain;
        };
    } catch(e) {}
    
    console.log('[*] SSL Pinning bypassed');
});
```

```bash
# Run bypass:
frida -U -l sslpinning.js -f com.victim.app --no-pause
# Or hook running process:
frida -U -l sslpinning.js com.victim.app
```

### Root Detection Bypass

```javascript
// root_bypass.js
Java.perform(function() {
    // RootBeer bypass
    try {
        var RootBeer = Java.use('com.scottyab.rootbeer.RootBeer');
        RootBeer.isRooted.implementation = function() { return false; };
        RootBeer.isRootedWithoutBusyBoxCheck.implementation = function() { return false; };
    } catch(e) {}
    
    // Generic isRooted methods
    var classNames = ['com.rooting.detection.Checker', 'sg.straitstimes.android.RootChecker'];
    classNames.forEach(function(className) {
        try {
            var cls = Java.use(className);
            cls.isRooted.implementation = function() { return false; };
        } catch(e) {}
    });
    
    // File.exists() intercept for /su, /magisk etc.
    var File = Java.use('java.io.File');
    File.exists.implementation = function() {
        var path = this.getAbsolutePath();
        if (path.indexOf('su') !== -1 || path.indexOf('magisk') !== -1 || path.indexOf('SuperSU') !== -1) {
            console.log('[*] Root check bypassed for: ' + path);
            return false;
        }
        return this.exists.call(this);
    };
    
    console.log('[*] Root detection bypassed');
});
```

### Hook Arbitrary Methods (Intercept/Modify)

```javascript
// Generic hook template
Java.perform(function() {
    var TargetClass = Java.use('com.victim.app.LoginManager');
    
    // Hook a method
    TargetClass.checkPassword.implementation = function(username, password) {
        console.log('[*] checkPassword called: ' + username + ' / ' + password);
        // Call original
        var result = this.checkPassword(username, password);
        console.log('[*] Result: ' + result);
        // Override result
        return true;  // always return true
    };
    
    // Hook overloaded method
    TargetClass.encrypt.overload('java.lang.String', '[B').implementation = function(data, key) {
        console.log('[*] encrypt called with: ' + data);
        return this.encrypt(data, key);
    };
});
```

```bash
# Enumerate all methods of a class:
frida -U -e "Java.perform(function(){ var c = Java.use('com.victim.app.LoginManager'); console.log(JSON.stringify(Object.getOwnPropertyNames(c))); })" com.victim.app
```

## Traffic Interception (Burp Suite / Caido)

```bash
# Set proxy on device: Settings → WiFi → Proxy → Manual → 192.168.1.x:8080

# Install Burp CA:
# Burp → Proxy → CA Certificate → download → push to device
adb push burp.cer /sdcard/Download/burp.cer
# Install via Settings → Security → Install from storage

# Android 7+ (user CA not trusted by default):
# Option 1: Root + move cert to system
adb shell "mount -o rw,remount /system"
adb push burp.cer /system/etc/security/cacerts/9a5ba575.0
adb shell "chmod 644 /system/etc/security/cacerts/9a5ba575.0"

# Option 2: Use Frida SSL bypass (above)
# Option 3: Patch APK networkSecurityConfig
```

## Common Android Vulnerabilities

### Insecure Data Storage

```bash
# Shared preferences (cleartext)
adb shell run-as com.victim.app cat shared_prefs/prefs.xml

# SQLite databases
adb shell run-as com.victim.app ls databases/
adb pull /data/data/com.victim.app/databases/app.db
sqlite3 app.db ".tables"; sqlite3 app.db "SELECT * FROM users"

# External storage (world-readable)
adb shell ls /sdcard/Android/data/com.victim.app/

# Logs
adb logcat | grep com.victim.app | grep -i "password\|token\|key\|secret"
```

### Deeplink / Intent Injection

```bash
# Find deeplinks in manifest
grep -i "scheme\|host\|pathPrefix\|VIEW\|BROWSABLE" app_decoded/AndroidManifest.xml

# Test deeplink:
adb shell am start -a android.intent.action.VIEW -d "victim://login?redirect=evil.com"
adb shell am start -a android.intent.action.VIEW -d "https://victim.com/oauth?redirect=evil.com"
```

### Content Provider Injection

```bash
# Query content provider
adb shell content query --uri content://com.victim.app.provider/users

# SQLi in content provider:
adb shell content query --uri "content://com.victim.app.provider/users" \
  --projection "* FROM users--"

# Path traversal in file provider:
adb shell content query --uri "content://com.victim.app.fileprovider/../../../etc/passwd"
```

### Tapjacking / Task Hijacking

```bash
# Check for exported activities that handle sensitive actions
# LaunchMode: singleTask / singleInstance with improper back stack handling
grep -i "launchMode\|taskAffinity" app_decoded/AndroidManifest.xml
```

## Automated Scanning

```bash
# MobSF (Mobile Security Framework)
docker run -it --rm -p 8000:8000 opensecurity/mobile-security-framework-mobsf
# Upload APK at http://localhost:8000

# QARK
pip install qark
qark --apk app.apk --report-type html

# AndroBugs
python androbugs.py -f app.apk
```
