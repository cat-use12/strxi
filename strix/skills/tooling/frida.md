---
name: frida
description: Frida dynamic instrumentation reference — Java hooking, native hooking, memory read/write, iOS/Android
---

# Frida Reference

## Installation & Setup

```bash
# Host tools
pip install frida-tools frida

# Android: push frida-server to device
# 1. Find frida version:
frida --version

# 2. Download matching frida-server for device arch:
# https://github.com/frida/frida/releases
# aarch64 = arm64, x86_64 = emulator

# 3. Push and start:
adb push frida-server /data/local/tmp/frida-server
adb shell chmod 755 /data/local/tmp/frida-server
adb shell /data/local/tmp/frida-server &

# Verify connection:
frida-ps -U           # USB device
frida-ps -e           # emulator
frida-ps -D <serial>  # specific device
```

## Running Scripts

```bash
# Spawn app (restart):
frida -U -l script.js -f com.target.app --no-pause

# Attach to running app:
frida -U -l script.js com.target.app
frida -U -l script.js <pid>

# One-liner eval:
frida -U -e "Java.perform(function(){ var a = Java.use('com.target.Class'); console.log(a); })" com.target.app

# With specific device:
frida -D <serial> -l script.js -f com.target.app --no-pause

# iOS:
frida -U -l script.js -f com.target.app --no-pause  # same flags
```

## Java API (Android)

```javascript
// Execute in Java context
Java.perform(function() {

    // Load a class
    var MyClass = Java.use('com.example.MyClass');

    // Hook instance method
    MyClass.myMethod.implementation = function(arg1, arg2) {
        console.log('[*] myMethod called: ' + arg1 + ', ' + arg2);
        var result = this.myMethod(arg1, arg2);  // call original
        console.log('[*] result: ' + result);
        return result;                           // return original result
        // or: return "patched";                 // override result
    };

    // Hook overloaded method
    MyClass.myMethod.overload('java.lang.String', 'int').implementation = function(s, n) {
        console.log('[*] String+int overload: ' + s + ', ' + n);
        return this.myMethod(s, n);
    };

    // Get class instance from heap
    Java.choose('com.example.MyClass', {
        onMatch: function(instance) {
            console.log('[*] instance: ' + instance);
            console.log('[*] field: ' + instance.myField.value);
            instance.myField.value = 'patched';   // modify field
        },
        onComplete: function() {}
    });

    // Create new instance
    var obj = MyClass.$new();
    var obj2 = MyClass.$new('arg1', 42);

    // Call static method
    MyClass.staticMethod(arg);
    var result = MyClass.staticMethod('hello');

    // Enumerate loaded classes
    Java.enumerateLoadedClassesSync().forEach(function(c) {
        if (c.indexOf('target') !== -1) console.log(c);
    });
});
```

## Native API (C/C++ functions)

```javascript
// Hook native function by address
Interceptor.attach(ptr('0xdeadbeef'), {
    onEnter: function(args) {
        console.log('[*] native called');
        console.log('    arg0: ' + args[0]);
        console.log('    arg0 str: ' + args[0].readUtf8String());
    },
    onLeave: function(retval) {
        console.log('[*] native returned: ' + retval);
        retval.replace(1);  // override return value
    }
});

// Hook by export name
var openssl_ctx = Module.findExportByName('libssl.so', 'SSL_read');
Interceptor.attach(openssl_ctx, {
    onEnter: function(args) {
        this.ssl = args[0];
        this.buf = args[1];
        this.num = args[2].toInt32();
    },
    onLeave: function(retval) {
        var len = retval.toInt32();
        if (len > 0) {
            console.log('[TLS] decrypted ' + len + ' bytes:');
            console.log(hexdump(this.buf.readByteArray(len)));
        }
    }
});

// Memory read/write
Memory.readByteArray(ptr('0x1234'), 16)  // read 16 bytes
Memory.readUtf8String(ptr('0x1234'))     // read C string
Memory.writeByteArray(ptr('0x1234'), [0x90, 0x90])  // NOP
Memory.writeUtf8String(ptr('0x1234'), 'patched')

// Allocate memory
var buf = Memory.alloc(64);
Memory.writeUtf8String(buf, 'payload');
```

## Module Enumeration

```javascript
// List all loaded modules
Process.enumerateModules().forEach(function(m) {
    console.log(m.name + ' @ ' + m.base + ' size:' + m.size);
});

// Find a module
var lib = Process.findModuleByName('libssl.so');
console.log(lib.base + ' - ' + lib.size);

// Exports of a module
Module.enumerateExports('libssl.so').forEach(function(e) {
    if (e.name.indexOf('SSL') !== -1)
        console.log(e.name + ' @ ' + e.address);
});

// Imports of a module
Module.enumerateImports('libtarget.so').forEach(function(i) {
    console.log(i.name + ' @ ' + i.address);
});
```

## Memory Scanning

```javascript
// Scan for bytes in all writable memory
Memory.scan(ptr('0'), 0xffffffff, '2f 62 69 6e 2f 73 68', {
    onMatch: function(address, size) {
        console.log('/bin/sh found at: ' + address);
    },
    onComplete: function() {}
});

// Scan for pattern with wildcards
Memory.scan(module.base, module.size, 'ff ?? ?? ?? c3', {
    onMatch: function(addr, size) {
        console.log('pattern at: ' + addr);
    },
    onComplete: function() {}
});

// Find string in all modules
Process.enumerateModules().forEach(function(m) {
    Memory.scanSync(m.base, m.size, '66 6c 61 67 7b').forEach(function(r) {
        console.log('[!] "flag{" at ' + r.address + ' in ' + m.name);
    });
});
```

## Stalker (Code Tracing)

```javascript
// Trace all instructions executed by thread
Stalker.follow(Process.getCurrentThreadId(), {
    events: {
        call: true,
        ret: true,
        exec: false,
    },
    onReceive: function(events) {
        var parsed = Stalker.parse(events, { annotate: true });
        parsed.forEach(function(e) {
            console.log(e);
        });
    }
});

// Trace for specific module only
Stalker.follow(tid, {
    transform: function(iterator) {
        var instruction;
        while ((instruction = iterator.next()) !== null) {
            if (instruction.address >= moduleBase && instruction.address < moduleEnd) {
                iterator.putCallout(function(context) {
                    console.log(instruction.address + ': ' + instruction.toString());
                });
            }
            iterator.keep();
        }
    }
});
```

## iOS Specifics

```javascript
// ObjC method hook
var hook = ObjC.classes.NSURLSession['- dataTaskWithRequest:completionHandler:'];
Interceptor.attach(hook.implementation, {
    onEnter: function(args) {
        var request = new ObjC.Object(args[2]);
        console.log('[HTTP] ' + request.HTTPMethod() + ' ' + request.URL());
    }
});

// Swift method hook (by mangled name)
var fn = Module.findExportByName('TargetApp', '_TFC9TargetApp11AppDelegate...');
// Use Frida's Swift bridge or class-dump + ObjC bridge

// KeyChain intercept
var SecItemCopyMatching = new NativeFunction(
    Module.findExportByName(null, 'SecItemCopyMatching'),
    'int', ['pointer', 'pointer']
);
```

## Frida RPC (Python controller)

```python
import frida

# Attach
device = frida.get_usb_device()
session = device.attach('com.target.app')

script = session.create_script("""
    rpc.exports = {
        hook: function(className, method) {
            Java.perform(function() {
                var cls = Java.use(className);
                cls[method].implementation = function() {
                    var result = this[method].apply(this, arguments);
                    send({type: 'hook', class: className, method: method, result: String(result)});
                    return result;
                };
            });
        }
    };
""")

def on_message(message, data):
    print('[msg]', message)

script.on('message', on_message)
script.load()

api = script.exports
api.hook('com.example.LoginManager', 'checkPassword')
```

## Common Patterns

```javascript
// === SSL unpinning (one-liner check) ===
Java.perform(function() {
    Java.use('javax.net.ssl.SSLContext')
        .init.implementation = function(km, tm, random) {
            this.init(km, [Java.use('javax.net.ssl.X509TrustManager').$new()], random);
        };
});

// === Anti-emulator bypass ===
Java.perform(function() {
    var Build = Java.use('android.os.Build');
    Build.FINGERPRINT.value = 'google/walleye/walleye:8.1.0/OPM1.171019.011/4448085:user/release-keys';
    Build.MODEL.value = 'Pixel 2';
    Build.MANUFACTURER.value = 'Google';
});

// === Log all method calls of a class ===
Java.perform(function() {
    var cls = Java.use('com.target.app.SomeClass');
    var methods = cls.class.getDeclaredMethods();
    methods.forEach(function(method) {
        var name = method.getName();
        try {
            cls[name].implementation = function() {
                console.log('[TRACE] ' + name + '(' + Array.from(arguments).join(', ') + ')');
                return this[name].apply(this, arguments);
            };
        } catch(e) {}
    });
});
```
