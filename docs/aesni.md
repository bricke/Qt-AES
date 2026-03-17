# AES-NI Hardware Acceleration

← [Back to README](../README.md)

---

On x86/x86-64 CPUs that support the AES-NI instruction set, Qt-AES can use native hardware
instructions for a significant throughput improvement over the pure software implementation.

> [!NOTE]
> AES-NI is only supported on x86/x86-64. Enabling it on any other architecture will produce
> a CMake configure error.
>
> **Windows / MSVC:** MSVC does not require a separate compiler flag to enable AES-NI
> intrinsics — they are available by default on x64 targets. The `-maes` flag check in
> CMakeLists.txt is a no-op under MSVC, which is expected and correct.

---

## What is accelerated

All five modes are hardware-accelerated:

| Mode | Encrypt | Decrypt |
|------|---------|---------|
| ECB  | ✅ | ✅ |
| CBC  | ✅ | ✅ |
| CTR  | ✅ | ✅ |
| CFB  | ✅ | ✅ |
| OFB  | ✅ | ✅ |

CFB and OFB use the forward AES cipher for both encrypt and decrypt (as the standard requires),
so they take the encryption key schedule in both directions.

---

## Enabling AES-NI

Pass `-DQTAES_ENABLE_AESNI=ON` at configure time:

```sh
cmake -B build \
  -DQTAES_ENABLE_AESNI=ON \
  -DQTAES_ENABLE_TESTS=ON \
  -DCMAKE_PREFIX_PATH=/path/to/Qt
cmake --build build
ctest --test-dir build -V
```

---

## Runtime detection

Even with `QTAES_ENABLE_AESNI=ON`, the library queries the CPU at runtime via `CPUID`. If the
running CPU does not support AES-NI the library silently falls back to the software
implementation — no code changes are required.

---

## API transparency

AES-NI is entirely transparent to the caller. The same `encode()` / `decode()` API is used
regardless of whether hardware acceleration is active. Ciphertext produced by the hardware path
is identical to the software path and fully interoperable.
