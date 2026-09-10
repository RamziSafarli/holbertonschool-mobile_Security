1. Hooking Native Functions in Android

Flag

Holberton{native_hooking_is_no_different_at_all}

1. APK extraction

The target APK was unpacked as a ZIP archive. The APK contains both DEX bytecode and native libraries:

classes.dex

classes2.dex

classes3.dex

classes4.dex

classes5.dex

lib/arm64-v8a/libnative-lib.so

lib/armeabi-v7a/libnative-lib.so

lib/x86/libnative-lib.so

lib/x86_64/libnative-lib.so

The application package identified from the DEX data is:

com.holberton.task2_1d

2. Identify the native function

Searching the DEX strings shows:

native-lib

getSecretMessage

secretMessage

Get Secret Message

The native library exports this JNI symbol:

Java_com_holberton_task2_1d_MainActivity_getSecretMessage

This confirms that MainActivity.getSecretMessage() is implemented in native code through JNI.

A useful command is:

readelf -Ws lib/x86_64/libnative-lib.so | grep getSecretMessage

which resolves the exported function.

3. Locate the encrypted data

The native library does not contain the flag in plain text. In .rodata, the important bytes are:

48 70 6d 64 68 77 7c 7c 83 9d 6e 62 75 6b 79 6a
67 75 84 91 6b 6a 6f 69 62 6e 7b 6c 83 91 5f 65
6a 68 69 6a 7a 72 83 96 5f 62 75 61 64 71 74 8a

These are 48 encrypted bytes.

4. Reverse the native function

The exported JNI function copies these 48 bytes into a local buffer and then loops over every byte.

The important native logic is:

for (i = 0; i < strlen(buffer); i++) {
    key = lit(i % 10);
    buffer[i] = buffer[i] - key;
}

The helper at address 0x7e0 is lit(int). Its disassembly implements an iterative Fibonacci calculation:

if (n <= 1)
    return n;

previous = 0;
current = 1;
for (i = 2; i <= n; i++) {
    next = previous + current;
    previous = current;
    current = next;
}
return next;

So the decryption key for byte i is:

F(i % 10)

with Fibonacci values:

F(0..9) = 0, 1, 1, 2, 3, 5, 8, 13, 21, 34

5. Reproduce the decryption statically

The same transformation can be reproduced in Python:

data = bytes.fromhex(
    "48706d6468777c7c839d6e62756b796a"
    "677584916b6a6f69626e7b6c83915f65"
    "6a68696a7a7283965f6275616471748a"
)

fib = [0, 1, 1, 2, 3, 5, 8, 13, 21, 34]

flag = ''.join(
    chr((byte - fib[i % 10]) % 256)
    for i, byte in enumerate(data)
)

print(flag)

Output:

Holberton{native_hooking_is_no_different_at_all}

6. Dynamic analysis with Frida

After installing the APK and starting the app:

adb install task1_d.apk
adb shell pm list packages | grep holberton

The JNI function can be hooked by its exported symbol. A Frida script can intercept the function and print its return value:

const sym = Module.findExportByName(
    "libnative-lib.so",
    "Java_com_holberton_task2_1d_MainActivity_getSecretMessage"
);

Interceptor.attach(sym, {
    onEnter(args) {
        console.log("[+] getSecretMessage() called");
    },

    onLeave(retval) {
        Java.performNow(function () {
            const JString = Java.use("java.lang.String");
            const value = Java.cast(retval, JString);
            console.log("[+] return = " + value.toString());
        });
    }
});

Run it with:

frida -U -f com.holberton.task2_1d -l hook.js

Then press Get Secret Message in the application. The native function is invoked and the decrypted return value is observable from the hook.

7. What happened

The complete data flow is:

Android UI
   -> MainActivity.getSecretMessage()
   -> JNI export
   -> libnative-lib.so
   -> encrypted bytes in .rodata
   -> Fibonacci key F(i % 10)
   -> byte subtraction
   -> New Java String / jstring
   -> flag

The app keeps the flag out of the visible interface, but the native function returns the decrypted jstring. Frida makes that runtime value directly observable.

8. Final result

Holberton{native_hooking_is_no_different_at_all}
