"""Mobile application security testing tools for Strix.

Provides tools for:
- APK static analysis (manifest review, secret hunting)
- ADB device automation
- Frida script generation (SSL pinning bypass, root detection bypass, method hooking)
- iOS IPA analysis (Info.plist, entitlements)
"""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
import tempfile
from pathlib import Path

try:
    from agents import function_tool, RunContextWrapper
    _HAS_AGENTS = True
except ImportError:
    _HAS_AGENTS = False

logger = logging.getLogger(__name__)


def _run(cmd: list[str], timeout: int = 30) -> tuple[str, str, int]:
    """Run a subprocess command, return (stdout, stderr, returncode)."""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout, r.stderr, r.returncode
    except subprocess.TimeoutExpired:
        return "", f"Command timed out after {timeout}s", 1
    except FileNotFoundError:
        return "", f"Command not found: {cmd[0]}", 127
    except Exception as e:
        return "", str(e), 1


if _HAS_AGENTS:

    @function_tool
    async def adb_command(
        ctx: RunContextWrapper,
        command: str,
        device_serial: str = "",
    ) -> str:
        """Run an ADB command on connected Android device or emulator.

        Args:
            command: ADB command without the 'adb' prefix, e.g. "shell id", "shell pm list packages"
            device_serial: Device serial (from 'adb devices') if multiple devices connected
        """
        if not shutil.which("adb"):
            return "adb not found. Install Android SDK Platform Tools: https://developer.android.com/studio/releases/platform-tools"

        parts = command.split()
        cmd = ["adb"]
        if device_serial:
            cmd.extend(["-s", device_serial])
        cmd.extend(parts)

        stdout, stderr, rc = _run(cmd, timeout=30)
        result = stdout + (f"\n[stderr]: {stderr}" if stderr else "")
        return result.strip() or f"(exit code {rc})"

    @function_tool
    async def list_android_devices(ctx: RunContextWrapper) -> str:
        """List connected Android devices and emulators."""
        if not shutil.which("adb"):
            return "adb not found."
        stdout, stderr, _ = _run(["adb", "devices", "-l"])
        return stdout or stderr

    @function_tool
    async def analyze_apk(
        ctx: RunContextWrapper,
        apk_path: str,
    ) -> str:
        """Analyze an APK for security issues — checks manifest, permissions, exported components, and hardcoded secrets.

        Args:
            apk_path: Path to the APK file, e.g. "/workspace/app.apk" or "/tmp/target.apk"
        """
        path = Path(apk_path)
        if not path.exists():
            return f"APK not found: {apk_path}"

        findings: list[str] = []

        # Check tools
        has_apktool = shutil.which("apktool") or shutil.which("apktool.jar")
        has_aapt = shutil.which("aapt") or shutil.which("aapt2")
        has_jadx = shutil.which("jadx")

        # Basic APK info using aapt
        if has_aapt:
            tool = "aapt2" if shutil.which("aapt2") else "aapt"
            stdout, _, _ = _run([tool, "dump", "badging", str(path)], timeout=30)
            if stdout:
                lines = stdout.split("\n")
                for line in lines[:20]:
                    if any(k in line for k in ["package:", "application-label", "sdkVersion", "targetSdkVersion", "uses-permission"]):
                        findings.append(f"[INFO] {line.strip()}")

        # Decompile with apktool for manifest analysis
        with tempfile.TemporaryDirectory() as tmpdir:
            decompiled = Path(tmpdir) / "app"
            if has_apktool:
                cmd = ["apktool", "d", str(path), "-o", str(decompiled), "-f", "--no-src"]
                stdout, stderr, rc = _run(cmd, timeout=60)
                if rc != 0:
                    findings.append(f"[WARN] apktool decode failed: {stderr[:200]}")

            manifest = decompiled / "AndroidManifest.xml"
            if manifest.exists():
                content = manifest.read_text(errors="replace")

                # Dangerous flags
                checks = {
                    'android:debuggable="true"': "[HIGH] App is debuggable (ADB debugging enabled in production)",
                    'android:allowBackup="true"': "[MEDIUM] Backup allowed — app data can be extracted without root",
                    'cleartextTrafficPermitted="true"': "[MEDIUM] Cleartext (HTTP) traffic permitted",
                    'usesCleartextTraffic': "[MEDIUM] Cleartext traffic referenced",
                    'android:exported="true"': "[INFO] Exported components found — check each for access control",
                    'protection="normal"': "[LOW] Permission with 'normal' protection level (any app can request)",
                }
                for pattern, message in checks.items():
                    if pattern in content:
                        findings.append(message)

                # Count exported components
                exported_count = content.count('android:exported="true"')
                if exported_count > 0:
                    findings.append(f"[INFO] {exported_count} exported component(s) found in manifest")

            # Secret hunting in resources
            resources_dir = decompiled / "res"
            smali_dir = decompiled / "smali"
            secret_patterns = [
                "api_key", "apikey", "api-key",
                "secret", "password", "passwd",
                "token", "bearer", "auth",
                "firebase", "aws", "s3://",
                "private_key", "BEGIN RSA",
            ]

            for search_dir in [resources_dir, decompiled / "assets"]:
                if search_dir.exists():
                    for f in search_dir.rglob("*"):
                        if f.is_file() and f.suffix in [".xml", ".json", ".properties", ".txt", ".conf"]:
                            try:
                                text = f.read_text(errors="replace").lower()
                                hits = [p for p in secret_patterns if p in text]
                                if hits:
                                    findings.append(f"[MEDIUM] Potential secrets in {f.relative_to(decompiled)}: {', '.join(hits)}")
                            except Exception:
                                pass

        if not findings:
            findings.append("[INFO] No obvious issues detected. Manual review recommended.")

        result = f"APK Analysis: {path.name}\n" + "=" * 50 + "\n"
        result += "\n".join(findings)
        result += "\n\nTools available:\n"
        result += f"  apktool: {'yes' if has_apktool else 'not installed'}\n"
        result += f"  jadx: {'yes' if has_jadx else 'not installed'}\n"
        result += f"  aapt: {'yes' if has_aapt else 'not installed'}\n"
        return result

    @function_tool
    async def generate_frida_script(
        ctx: RunContextWrapper,
        script_type: str,
        target_class: str = "",
        target_method: str = "",
        package: str = "",
    ) -> str:
        """Generate a Frida script for Android/iOS hooking.

        Args:
            script_type: Type of script to generate:
                - "ssl_bypass": Universal SSL pinning bypass
                - "root_bypass": Root/jailbreak detection bypass
                - "hook_method": Hook and log a specific method
                - "dump_classes": Enumerate all loaded classes
                - "trace_crypto": Trace encryption/decryption calls
                - "intercept_http": Intercept HTTP/HTTPS requests
            target_class: Class to hook (for hook_method)
            target_method: Method to hook (for hook_method)
            package: App package name, e.g. "com.target.app"
        """
        scripts = {
            "ssl_bypass": '''// Universal SSL Pinning Bypass for Android
// Usage: frida -U -l ssl_bypass.js -f {package} --no-pause

Java.perform(function() {{
    console.log("[*] SSL Bypass script loaded");

    // 1. TrustManager override
    try {{
        var TrustManager = Java.registerClass({{
            name: 'com.strix.UniversalTrustManager',
            implements: [Java.use('javax.net.ssl.X509TrustManager')],
            methods: {{
                checkClientTrusted: function(chain, authType) {{}},
                checkServerTrusted: function(chain, authType) {{}},
                getAcceptedIssuers: function() {{ return []; }}
            }}
        }});

        var SSLContext = Java.use('javax.net.ssl.SSLContext');
        var ctx = SSLContext.getInstance('TLS');
        ctx.init(null, [TrustManager.$new()], null);
        SSLContext.getDefault.implementation = function() {{ return ctx; }};
        console.log("[+] TrustManager bypass done");
    }} catch(e) {{ console.log("[-] TrustManager: " + e); }}

    // 2. OkHttp3 CertificatePinner
    try {{
        var CertPinner = Java.use('okhttp3.CertificatePinner');
        CertPinner.check.overload('java.lang.String', 'java.util.List').implementation = function(host, chain) {{
            console.log("[*] CertificatePinner.check bypassed: " + host);
        }};
        CertPinner.check.overload('java.lang.String', 'kotlin.jvm.functions.Function0').implementation = function(host, fn) {{
            console.log("[*] CertificatePinner.check (kotlin) bypassed: " + host);
        }};
        console.log("[+] OkHttp3 bypass done");
    }} catch(e) {{ console.log("[-] OkHttp3: " + e); }}

    // 3. Conscrypt
    try {{
        var Conscrypt = Java.use('com.android.org.conscrypt.TrustManagerImpl');
        Conscrypt.verifyChain.implementation = function(untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData) {{
            console.log("[*] Conscrypt.verifyChain bypassed for: " + host);
            return untrustedChain;
        }};
        console.log("[+] Conscrypt bypass done");
    }} catch(e) {{ console.log("[-] Conscrypt: " + e); }}

    // 4. HttpsURLConnection HostnameVerifier
    try {{
        var HttpsURLConnection = Java.use('javax.net.ssl.HttpsURLConnection');
        HttpsURLConnection.setDefaultHostnameVerifier.implementation = function(verifier) {{}};
        console.log("[+] HostnameVerifier bypass done");
    }} catch(e) {{ console.log("[-] HostnameVerifier: " + e); }}

    console.log("[*] SSL pinning bypass complete — proxy traffic should now flow through");
}});
''',

            "root_bypass": '''// Root Detection Bypass for Android
// Usage: frida -U -l root_bypass.js -f {package} --no-pause

Java.perform(function() {{
    console.log("[*] Root bypass script loaded");

    var rootIndicators = [
        '/su', '/sbin/su', '/system/bin/su', '/system/xbin/su',
        '/system/sbin/su', '/data/local/su', '/data/local/bin/su',
        '/data/local/xbin/su', '/magisk', '/system/app/Superuser.apk',
        '/system/app/SuperSU', '/data/data/eu.chainfire.supersu',
        '/system/xbin/which',
    ];

    // File.exists() hook
    try {{
        var File = Java.use('java.io.File');
        File.exists.implementation = function() {{
            var path = this.getAbsolutePath();
            for (var i = 0; i < rootIndicators.length; i++) {{
                if (path === rootIndicators[i] || path.indexOf('magisk') !== -1 || path.indexOf('Superuser') !== -1) {{
                    console.log('[*] Root indicator blocked: ' + path);
                    return false;
                }}
            }}
            return this.exists.call(this);
        }};
        console.log('[+] File.exists hook done');
    }} catch(e) {{ console.log('[-] File.exists: ' + e); }}

    // RootBeer specific bypass
    try {{
        var RootBeer = Java.use('com.scottyab.rootbeer.RootBeer');
        ['isRooted', 'isRootedWithoutBusyBoxCheck', 'detectRootManagementApps',
         'detectPotentiallyDangerousApps', 'checkForBinary', 'detectTestKeys',
         'checkForDangerousProps', 'checkForRWPaths'].forEach(function(method) {{
            try {{
                RootBeer[method].implementation = function() {{
                    console.log('[*] RootBeer.' + '{method}' + ' → false');
                    return false;
                }};
            }} catch(e) {{}}
        }});
        console.log('[+] RootBeer bypass done');
    }} catch(e) {{ console.log('[-] RootBeer: ' + e); }}

    // Runtime.exec() interception for 'su' commands
    try {{
        var Runtime = Java.use('java.lang.Runtime');
        Runtime.exec.overload('java.lang.String').implementation = function(cmd) {{
            if (cmd.indexOf('su') !== -1 || cmd.indexOf('which') !== -1) {{
                console.log('[*] Runtime.exec blocked: ' + cmd);
                throw Java.use('java.io.IOException').$new('No such file or directory');
            }}
            return this.exec(cmd);
        }};
        console.log('[+] Runtime.exec hook done');
    }} catch(e) {{ console.log('[-] Runtime.exec: ' + e); }}

    console.log('[*] Root detection bypass complete');
}});
''',

            "hook_method": f'''// Method Hook — {target_class}.{target_method}
// Usage: frida -U -l hook.js -f {package or "com.target.app"} --no-pause

Java.perform(function() {{
    console.log("[*] Hook loaded");

    try {{
        var TargetClass = Java.use('{target_class or "com.target.ClassName"}');

        // Hook method (adjust overload signature if needed)
        TargetClass['{target_method or "targetMethod"}'].implementation = function() {{
            // Log all arguments
            for (var i = 0; i < arguments.length; i++) {{
                console.log('[*] arg[' + i + '] = ' + JSON.stringify(arguments[i]));
            }}

            // Call original and log result
            var result = this['{target_method or "targetMethod"}'].apply(this, arguments);
            console.log('[*] return = ' + JSON.stringify(result));

            // Optionally override return value:
            // return "patched_return_value";
            return result;
        }};

        console.log('[+] Hooked {target_class or "com.target.ClassName"}.{target_method or "targetMethod"}');
    }} catch(e) {{
        console.log('[-] Hook failed: ' + e);
        console.log('[*] Try enumerating methods first with dump_classes script');
    }}
}});
''',

            "dump_classes": f'''// Enumerate loaded classes and methods
// Usage: frida -U -l dump_classes.js {package or "com.target.app"}

Java.perform(function() {{
    var classes = Java.enumerateLoadedClassesSync();
    var target = '{target_class or ""}';
    var filtered = target ? classes.filter(function(c) {{ return c.indexOf(target) !== -1; }}) : classes;

    console.log('[*] Total classes: ' + classes.length);
    if (target) console.log('[*] Matching "' + target + '": ' + filtered.length);

    filtered.slice(0, 50).forEach(function(cls) {{
        console.log('CLASS: ' + cls);
        try {{
            var methods = Java.use(cls).class.getDeclaredMethods();
            methods.forEach(function(m) {{
                console.log('  METHOD: ' + m.getName() + ' → ' + m.toString());
            }});
        }} catch(e) {{}}
    }});
}});
''',

            "trace_crypto": '''// Trace AES/RSA/DES encryption and decryption
// Usage: frida -U -l trace_crypto.js -f com.target.app --no-pause

Java.perform(function() {{
    console.log("[*] Crypto tracer loaded");

    // Cipher (AES, DES, RSA, etc.)
    var Cipher = Java.use('javax.crypto.Cipher');
    Cipher.doFinal.overload('[B').implementation = function(data) {{
        console.log('[*] Cipher.doFinal called');
        console.log('    Algorithm: ' + this.getAlgorithm());
        console.log('    Mode: ' + (this.getOpmode() === 1 ? 'ENCRYPT' : 'DECRYPT'));
        console.log('    Input hex: ' + bytesToHex(data));
        var result = this.doFinal(data);
        console.log('    Output hex: ' + bytesToHex(result));
        try {{
            console.log('    Output string: ' + bytesToStr(result));
        }} catch(e) {{}}
        return result;
    }};

    // MessageDigest (MD5, SHA-256)
    var MessageDigest = Java.use('java.security.MessageDigest');
    MessageDigest.digest.overload('[B').implementation = function(data) {{
        console.log('[*] MessageDigest.digest: ' + this.getAlgorithm());
        console.log('    Input: ' + bytesToStr(data));
        var result = this.digest(data);
        console.log('    Digest: ' + bytesToHex(result));
        return result;
    }};

    // Base64
    var Base64 = Java.use('android.util.Base64');
    Base64.encodeToString.overload('[B', 'int').implementation = function(data, flags) {{
        var result = this.encodeToString(data, flags);
        console.log('[*] Base64.encode: ' + bytesToStr(data) + ' → ' + result);
        return result;
    }};

    function bytesToHex(bytes) {{
        var hex = '';
        for (var i = 0; i < bytes.length; i++) {{
            hex += ('0' + (bytes[i] & 0xFF).toString(16)).slice(-2);
        }}
        return hex;
    }}

    function bytesToStr(bytes) {{
        var str = '';
        for (var i = 0; i < bytes.length; i++) {{
            str += String.fromCharCode(bytes[i] & 0xFF);
        }}
        return str;
    }}

    console.log("[*] Crypto tracer ready");
}});
''',

            "intercept_http": '''// Intercept HTTP/HTTPS requests (OkHttp3 + HttpURLConnection)
// Usage: frida -U -l intercept_http.js -f com.target.app --no-pause

Java.perform(function() {{
    console.log("[*] HTTP interceptor loaded");

    // OkHttp3 (most common)
    try {{
        var OkHttpClient = Java.use('okhttp3.OkHttpClient');
        var Request = Java.use('okhttp3.Request');
        var RealCall = Java.use('okhttp3.internal.connection.RealCall');

        RealCall.execute.implementation = function() {{
            var request = this.request();
            console.log('[HTTP] ' + request.method() + ' ' + request.url());

            // Log headers
            var headers = request.headers();
            for (var i = 0; i < headers.size(); i++) {{
                console.log('  Header: ' + headers.name(i) + ': ' + headers.value(i));
            }}

            var response = this.execute();
            console.log('[HTTP] Response: ' + response.code());
            return response;
        }};
        console.log('[+] OkHttp3 intercept done');
    }} catch(e) {{ console.log('[-] OkHttp3: ' + e); }}

    // HttpURLConnection
    try {{
        var URL = Java.use('java.net.URL');
        URL.openConnection.overload().implementation = function() {{
            console.log('[HTTP] openConnection: ' + this.toString());
            return this.openConnection();
        }};
        console.log('[+] HttpURLConnection intercept done');
    }} catch(e) {{ console.log('[-] HttpURLConnection: ' + e); }}

    console.log('[*] HTTP interceptor ready');
}});
''',
        }

        script = scripts.get(script_type.lower())
        if not script:
            available = list(scripts.keys())
            return f"Unknown script type: {script_type}\nAvailable: {', '.join(available)}"

        # Format with package name
        script = script.replace("{package}", package or "com.target.app")

        usage = f"\n\n# Usage:\n"
        if script_type == "dump_classes":
            usage += f"frida -U -l {script_type}.js {package or 'com.target.app'}"
        else:
            usage += f"frida -U -l {script_type}.js -f {package or 'com.target.app'} --no-pause"

        return script + usage

    @function_tool
    async def run_frida_script(
        ctx: RunContextWrapper,
        package: str,
        script_path: str,
        spawn: bool = True,
        device_serial: str = "",
    ) -> str:
        """Run a Frida script against an Android app (requires frida-server running on device).

        Args:
            package: App package name, e.g. "com.target.app"
            script_path: Path to the Frida JS script file
            spawn: If True, spawn the app (restart). If False, attach to running app
            device_serial: ADB device serial if multiple devices
        """
        if not shutil.which("frida"):
            return (
                "frida not installed. Install: pip install frida-tools\n"
                "Also push frida-server to device:\n"
                "  adb push frida-server /data/local/tmp/frida-server\n"
                "  adb shell chmod 755 /data/local/tmp/frida-server\n"
                "  adb shell /data/local/tmp/frida-server &"
            )

        if not Path(script_path).exists():
            return f"Script not found: {script_path}"

        cmd = ["frida"]
        if device_serial:
            cmd.extend(["-D", device_serial])
        else:
            cmd.append("-U")  # USB/emulator

        cmd.extend(["-l", script_path])

        if spawn:
            cmd.extend(["-f", package, "--no-pause"])
        else:
            cmd.append(package)

        stdout, stderr, rc = _run(cmd, timeout=15)
        output = stdout + ("\n[stderr]: " + stderr if stderr else "")
        return output.strip() or f"frida exited with code {rc}"

    @function_tool
    async def install_apk(
        ctx: RunContextWrapper,
        apk_path: str,
        device_serial: str = "",
        reinstall: bool = True,
    ) -> str:
        """Install an APK on connected Android device.

        Args:
            apk_path: Path to the APK file
            device_serial: ADB device serial for specific device
            reinstall: Allow reinstall over existing app
        """
        if not shutil.which("adb"):
            return "adb not found."

        cmd = ["adb"]
        if device_serial:
            cmd.extend(["-s", device_serial])
        cmd.append("install")
        if reinstall:
            cmd.append("-r")
        cmd.append(apk_path)

        stdout, stderr, rc = _run(cmd, timeout=60)
        return (stdout + "\n" + stderr).strip()

else:
    def adb_command(*a, **kw): raise ImportError("agents SDK not installed")
    def list_android_devices(*a, **kw): raise ImportError("agents SDK not installed")
    def analyze_apk(*a, **kw): raise ImportError("agents SDK not installed")
    def generate_frida_script(*a, **kw): raise ImportError("agents SDK not installed")
    def run_frida_script(*a, **kw): raise ImportError("agents SDK not installed")
    def install_apk(*a, **kw): raise ImportError("agents SDK not installed")
