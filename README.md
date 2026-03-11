<div align="center">

# Qt-AES

**Small and portable AES encryption library for Qt**

[![CI](https://github.com/bricke/Qt-AES/actions/workflows/ci.yml/badge.svg)](https://github.com/bricke/Qt-AES/actions/workflows/ci.yml)
[![CI (AES-NI)](https://github.com/bricke/Qt-AES/actions/workflows/ci-aesni.yml/badge.svg)](https://github.com/bricke/Qt-AES/actions/workflows/ci-aesni.yml)
[![License: Unlicense](https://img.shields.io/badge/license-Unlicense-blue.svg)](http://unlicense.org/)

AES-128 · AES-192 · AES-256 &nbsp;|&nbsp; ECB · CBC · CFB · OFB · CTR &nbsp;|&nbsp; PBKDF2 key derivation &nbsp;|&nbsp; Partial AES-NI support

</div>

---

## Features

- All AES key sizes — 128, 192, 256 bit
- Five cipher modes — ECB, CBC, CFB, OFB, CTR
- Three padding schemes — ISO (default), PKCS7, ZERO
- PBKDF2-HMAC key derivation (RFC 2898) — no QtNetwork required
- Optional hardware acceleration via AES-NI (ECB and CBC)
- Qt 5 and Qt 6 compatible
- Single dependency: `QtCore`

---

## Getting Started

### Install the library

```sh
cmake -B build -DCMAKE_PREFIX_PATH=/path/to/Qt -DCMAKE_INSTALL_PREFIX=/path/to/install
cmake --build build
cmake --install build
```

Enable optional features:

```sh
cmake -B build \
  -DQTAES_ENABLE_AESNI=ON \    # Hardware AES-NI acceleration (ECB/CBC only)
  -DQTAES_ENABLE_TESTS=ON \    # Build unit tests
  -DQTAES_ENABLE_WERROR=ON     # Treat warnings as errors
```

### Use in your project

In your `CMakeLists.txt`:

```cmake
find_package(QtAES REQUIRED)
target_link_libraries(your_target PRIVATE QtAES::QtAES)
```

Then include as you would any Qt class header:

```cpp
#include <QAESEncryption>
```

Pass the install prefix to CMake so `find_package` can locate the library:

```sh
cmake -B build -DCMAKE_PREFIX_PATH=/path/to/install
```

### Embed as a subdirectory

Alternatively, copy the source tree into your project and use `add_subdirectory`:

```cmake
add_subdirectory(Qt-AES)
target_link_libraries(your_target PRIVATE QtAES::QtAES)
```

---

## API Reference

### Instance methods

| Method | Description |
|--------|-------------|
| `encode(rawText, key, iv)` | Encrypt `rawText` with `key`. `iv` required for CBC/CFB/OFB. |
| `decode(rawText, key, iv)` | Decrypt `rawText` with `key`. `iv` required for CBC/CFB/OFB. |
| `removePadding(rawText)` | Strip padding from a decrypted buffer. |
| `expandKey(key, isEncryptionKey)` | Expand a raw key into the Rijndael key schedule. |

### Static methods

| Method | Description |
|--------|-------------|
| `QAESEncryption::Crypt(...)` | Static encrypt — no instance needed. |
| `QAESEncryption::Decrypt(...)` | Static decrypt — no instance needed. |
| `QAESEncryption::RemovePadding(...)` | Static padding removal. |
| `QAESEncryption::ExpandKey(...)` | Static key expansion. |
| `QAESEncryption::generateKey(password, salt, level, algo, iterations)` | Derive an AES-ready key via PBKDF2-HMAC (see below). |

### Constructor

```cpp
QAESEncryption(Aes level, Mode mode, Padding padding = ISO);
```

<details>
<summary><strong>Supported values</strong></summary>

| Enum | Values |
|------|--------|
| `QAESEncryption::Aes` | `AES_128`, `AES_192`, `AES_256` |
| `QAESEncryption::Mode` | `ECB`, `CBC`, `CFB`, `OFB`, `CTR` |
| `QAESEncryption::Padding` | `ISO` (default), `PKCS7`, `ZERO` |

</details>

---

## Usage Examples

### Basic encrypt / decrypt

```cpp
#include "qaesencryption.h"

QAESEncryption encryption(QAESEncryption::AES_128, QAESEncryption::ECB);

QByteArray encoded = encryption.encode(plainText, key);
QByteArray decoded = encryption.decode(encoded, key);
```

### Recommended: PBKDF2 key derivation with salt

Use `generateKey()` to derive a secure key from a password and a random salt.
Store the salt (and IV) alongside the ciphertext — they are not secret.

```cpp
#include "qaesencryption.h"

QAESEncryption encryption(QAESEncryption::AES_256, QAESEncryption::CBC, QAESEncryption::PKCS7);

QByteArray salt = /* random 16+ bytes from a CSPRNG */;
QByteArray iv   = /* random 16 bytes */;

QByteArray key = QAESEncryption::generateKey(password.toUtf8(), salt,
                                             QAESEncryption::AES_256);

QByteArray cipherText = encryption.encode(plainText.toUtf8(), key, iv);

// Decrypt — re-derive the same key from the stored salt:
QByteArray key2     = QAESEncryption::generateKey(password.toUtf8(), salt,
                                                  QAESEncryption::AES_256);
QByteArray decrypted = encryption.removePadding(encryption.decode(cipherText, key2, iv));
```

> [!NOTE]
> `generateKey()` uses Qt's `QMessageAuthenticationCode`, which is not guaranteed to be
> constant-time. For security-critical applications prefer a dedicated library such as
> OpenSSL (`PKCS5_PBKDF2_HMAC`) or libsodium.

### CBC-256 with QString

```cpp
#include <QCryptographicHash>
#include "qaesencryption.h"

QAESEncryption encryption(QAESEncryption::AES_256, QAESEncryption::CBC);

QByteArray hashKey = QCryptographicHash::hash(key.toLocal8Bit(), QCryptographicHash::Sha256);
QByteArray hashIV  = QCryptographicHash::hash(iv.toLocal8Bit(),  QCryptographicHash::Md5);

QByteArray encoded  = encryption.encode(inputStr.toLocal8Bit(), hashKey, hashIV);
QByteArray decoded  = encryption.decode(encoded, hashKey, hashIV);
QString    result   = QString(encryption.removePadding(decoded));
```

### Static invocation

```cpp
#include <QCryptographicHash>
#include "qaesencryption.h"

QByteArray hashKey = QCryptographicHash::hash(key.toLocal8Bit(), QCryptographicHash::Sha256);
QByteArray hashIV  = QCryptographicHash::hash(iv.toLocal8Bit(),  QCryptographicHash::Md5);

QByteArray encrypted = QAESEncryption::Crypt(QAESEncryption::AES_256, QAESEncryption::CBC,
                                             inputStr.toLocal8Bit(), hashKey, hashIV);

QString decrypted = QString(QAESEncryption::RemovePadding(
                        QAESEncryption::Decrypt(QAESEncryption::AES_256, QAESEncryption::CBC,
                                                encrypted, hashKey, hashIV)));
```

---

## Thread Safety

Instances are thread-safe. All mutable state during an `encode()` / `decode()` operation is kept on the call stack — no member variables are written after construction. Multiple threads may safely call `encode()` or `decode()` on the same instance concurrently without a mutex.

The static methods (`Crypt`, `Decrypt`, `ExpandKey`, `RemovePadding`, `generateKey`) are also safe to call concurrently.

---

## AES-NI Hardware Acceleration

On x86/x86-64 CPUs that support the AES-NI instruction set, Qt-AES can use native hardware instructions for a significant throughput improvement over the pure software implementation.

> [!NOTE]
> AES-NI is only supported on x86/x86-64. Enabling it on any other architecture will produce a CMake configure error.
>
> **Windows / MSVC:** MSVC does not require a separate compiler flag to enable AES-NI intrinsics — they are available by default on x64 targets. The `-maes` flag check in CMakeLists.txt is a no-op under MSVC, which is expected and correct.

### What is accelerated

| Mode | Encrypt | Decrypt |
|------|---------|---------|
| ECB  | ✅ | ✅ |
| CBC  | ✅ | ✅ |
| CTR  | ✅ | ✅ |
| CFB  | — | — |
| OFB  | — | — |

CFB and OFB fall back to the software path transparently.

### Enabling AES-NI

Pass `-DQTAES_ENABLE_AESNI=ON` at configure time:

```sh
cmake -B build \
  -DQTAES_ENABLE_AESNI=ON \
  -DQTAES_ENABLE_TESTS=ON \
  -DCMAKE_PREFIX_PATH=/path/to/Qt
cmake --build build
ctest --test-dir build -V
```

### Runtime detection

Even with `QTAES_ENABLE_AESNI=ON`, the library queries the CPU at runtime via `CPUID`. If the running CPU does not support AES-NI the library silently falls back to the software implementation — no code changes are required.

### API transparency

AES-NI is entirely transparent to the caller. The same `encode()` / `decode()` API is used regardless of whether hardware acceleration is active. Ciphertext produced by the hardware path is identical to the software path and fully interoperable.

---

## Unit Testing

Test vectors are taken from [NIST SP 800-38A](http://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf) for ECB, CBC, OFB, and CTR modes.
`generateKey()` is validated against five PBKDF2-HMAC-SHA256 vectors cross-checked with Python's `hashlib.pbkdf2_hmac`.

```sh
cmake -B build -DQTAES_ENABLE_TESTS=ON -DCMAKE_PREFIX_PATH=/path/to/Qt
cmake --build build
ctest --test-dir build -V
```

---

## Disclaimer

This code is **not audited or AES-certified** by any competent authority. Use it at your own risk.

---

## License

Released under the [Unlicense](http://unlicense.org/) — public domain, no restrictions.

---

<div align="center">
Questions or suggestions? Open an issue on <a href="https://github.com/bricke/Qt-AES/issues">GitHub</a>.
</div>
