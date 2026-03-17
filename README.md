<div align="center">

# Qt-AES

**Small and portable AES encryption library for Qt**

[![CI](https://github.com/bricke/Qt-AES/actions/workflows/ci.yml/badge.svg)](https://github.com/bricke/Qt-AES/actions/workflows/ci.yml)
[![CI (AES-NI)](https://github.com/bricke/Qt-AES/actions/workflows/ci-aesni.yml/badge.svg)](https://github.com/bricke/Qt-AES/actions/workflows/ci-aesni.yml)
[![CI (Sanitizers)](https://github.com/bricke/Qt-AES/actions/workflows/ci-sanitizers.yml/badge.svg)](https://github.com/bricke/Qt-AES/actions/workflows/ci-sanitizers.yml)
[![CI (Fuzzing)](https://github.com/bricke/Qt-AES/actions/workflows/ci-fuzzing.yml/badge.svg)](https://github.com/bricke/Qt-AES/actions/workflows/ci-fuzzing.yml)
[![CI (OpenSSL Cross-check)](https://github.com/bricke/Qt-AES/actions/workflows/ci-openssl-crosscheck.yml/badge.svg)](https://github.com/bricke/Qt-AES/actions/workflows/ci-openssl-crosscheck.yml)
[![License: Unlicense](https://img.shields.io/badge/license-Unlicense-blue.svg)](http://unlicense.org/)

AES-128 · AES-192 · AES-256 &nbsp;|&nbsp; ECB · CBC · CFB · OFB · CTR &nbsp;|&nbsp; PBKDF2 key derivation &nbsp;|&nbsp; Partial AES-NI support

</div>

---

## Features

- All AES key sizes — 128, 192, 256 bit
- Five cipher modes — ECB, CBC, CFB, OFB, CTR
- Four padding schemes — ISO (default), PKCS7, ZERO, NONE (stream modes)
- PBKDF2-HMAC key derivation (RFC 2898) — no QtNetwork required
- Optional hardware acceleration via AES-NI (all modes)
- Qt 5 and Qt 6 compatible
- Single dependency: `QtCore`

---

## Quick Start

Add to your `CMakeLists.txt`:

```cmake
find_package(QtAES REQUIRED)
target_link_libraries(your_target PRIVATE QtAES::QtAES)
```

```cpp
#include <QAESEncryption>

QAESEncryption enc(QAESEncryption::AES_256, QAESEncryption::CBC, QAESEncryption::PKCS7);
QByteArray cipher = enc.encode(plainText, key, iv);
QByteArray plain  = enc.removePadding(enc.decode(cipher, key, iv));
```

---

## Documentation

| Topic | |
|---|---|
| Installation & CMake options | [docs/getting-started.md](docs/getting-started.md) |
| API Reference | [docs/api-reference.md](docs/api-reference.md) |
| Usage Examples | [docs/examples.md](docs/examples.md) |
| AES-NI Acceleration | [docs/aesni.md](docs/aesni.md) |
| Testing & Fuzzing | [docs/testing.md](docs/testing.md) |

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
