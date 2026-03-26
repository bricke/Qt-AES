# Usage Examples

← [Back to README](../README.md)

---

## Best Practices

### Use a random IV for every encryption

The IV must be **unique per encryption operation** for CBC, CFB, OFB, and CTR modes.
Reusing an IV with the same key leaks information about the plaintext.
Generate it with Qt's cryptographically secure random generator:

```cpp
QByteArray iv(16, 0);
QRandomGenerator::system()->fillRange(
    reinterpret_cast<quint32*>(iv.data()), iv.size() / sizeof(quint32));
```

The IV is **not secret** — store or transmit it alongside the ciphertext.

### Store the IV with the ciphertext

A common pattern is to prepend the IV so it travels with the ciphertext:

```cpp
// Encrypt
QByteArray payload = iv + cipherText;   // store or send this

// Decrypt
QByteArray iv         = payload.left(16);
QByteArray cipherText = payload.mid(16);
```

### Derive keys from passwords with PBKDF2

Never use a raw password string as a key. Use `generateKey()` with a random salt and
store the salt alongside the ciphertext (it is not secret):

```cpp
QByteArray salt(16, 0);
QRandomGenerator::system()->fillRange(
    reinterpret_cast<quint32*>(salt.data()), salt.size() / sizeof(quint32));

QByteArray key = QAESEncryption::generateKey(password.toUtf8(), salt,
                                             QAESEncryption::AES_256);
```

### Avoid ECB mode for non-trivial data

ECB encrypts each block independently, so identical plaintext blocks produce identical
ciphertext blocks — patterns in the data remain visible. Prefer CBC, CFB, OFB, or CTR.

### Side-channel resistance

The default software path uses lookup tables for the AES S-box, which are susceptible
to CPU cache-timing attacks. For deployments where local side-channel resistance matters:

- **Preferred:** enable AES-NI hardware acceleration (`-DQTAES_ENABLE_AESNI=ON`) — the
  hardware instructions are inherently constant-time.
- **Alternative:** enable the constant-time S-box (`-DQTAES_CONSTANT_TIME_SBOX=ON`) —
  replaces table lookups with the Boyar-Peralta algebraic circuit (register-only
  operations, no data-dependent memory accesses). This is slower than the table-based
  path but works on all platforms.

---

## Basic encrypt / decrypt

```cpp
#include "qaesencryption.h"

QAESEncryption encryption(QAESEncryption::AES_128, QAESEncryption::ECB);

QByteArray encoded = encryption.encode(plainText, key);
QByteArray decoded = encryption.decode(encoded, key);
```

---

## Recommended: PBKDF2 key derivation with salt

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
QByteArray key2      = QAESEncryption::generateKey(password.toUtf8(), salt,
                                                   QAESEncryption::AES_256);
QByteArray decrypted = encryption.removePadding(encryption.decode(cipherText, key2, iv));
```

> [!NOTE]
> `generateKey()` uses Qt's `QMessageAuthenticationCode`, which is not guaranteed to be
> constant-time. For security-critical applications prefer a dedicated library such as
> OpenSSL (`PKCS5_PBKDF2_HMAC`) or libsodium.

---

## CBC-256 with QString

```cpp
#include <QCryptographicHash>
#include "qaesencryption.h"

QAESEncryption encryption(QAESEncryption::AES_256, QAESEncryption::CBC);

QByteArray hashKey = QCryptographicHash::hash(key.toLocal8Bit(), QCryptographicHash::Sha256);
QByteArray hashIV  = QCryptographicHash::hash(iv.toLocal8Bit(),  QCryptographicHash::Md5);

QByteArray encoded = encryption.encode(inputStr.toLocal8Bit(), hashKey, hashIV);
QByteArray decoded = encryption.decode(encoded, hashKey, hashIV);
QString    result  = QString(encryption.removePadding(decoded));
```

---

## Static invocation

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

## Interoperability with OpenSSL CLI

Qt-AES produces raw binary ciphertext that is byte-for-byte compatible with
OpenSSL's `enc` command when the key, IV, and padding settings match.

Two rules cover all cases:
- **Block modes (ECB, CBC):** use `Padding::PKCS7` in Qt; OpenSSL applies PKCS7 by default (no extra flag needed).
- **Stream modes (CFB, OFB, CTR):** use `Padding::NONE` in Qt; pass `-nopad` to OpenSSL.

Always supply the raw hex key with `-K` (uppercase) and the IV with `-iv`.
Never use `-pass` — that activates OpenSSL's own key-derivation and produces incompatible output.

### Qt → OpenSSL

**AES-128-CBC** (block mode, PKCS7 padding)

```cpp
QByteArray key = QByteArray::fromHex("2b7e151628aed2a6abf7158809cf4f3c");
QByteArray iv  = QByteArray::fromHex("000102030405060708090a0b0c0d0e0f");

QAESEncryption enc(QAESEncryption::AES_128, QAESEncryption::CBC, QAESEncryption::PKCS7);
QByteArray cipher = enc.encode("Hello, world!", key, iv);

QFile f("cipher.bin");
f.open(QFile::WriteOnly);
f.write(cipher);
```

```sh
openssl enc -aes-128-cbc -d \
  -K 2b7e151628aed2a6abf7158809cf4f3c \
  -iv 000102030405060708090a0b0c0d0e0f \
  -in cipher.bin
# → Hello, world!
```

**AES-256-CFB** (stream mode, no padding)

```cpp
QByteArray key = QByteArray::fromHex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4");
QByteArray iv  = QByteArray::fromHex("000102030405060708090a0b0c0d0e0f");

QAESEncryption enc(QAESEncryption::AES_256, QAESEncryption::CFB, QAESEncryption::NONE);
QByteArray cipher = enc.encode("Hello, world!", key, iv);

QFile f("cipher.bin");
f.open(QFile::WriteOnly);
f.write(cipher);
```

```sh
# -aes-256-cfb is CFB128 (full-block feedback), which matches Qt-AES's CFB implementation
openssl enc -aes-256-cfb -d -nopad \
  -K 603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4 \
  -iv 000102030405060708090a0b0c0d0e0f \
  -in cipher.bin
# → Hello, world!
```

**AES-192-OFB** (stream mode, no padding)

```cpp
QByteArray key = QByteArray::fromHex("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b");
QByteArray iv  = QByteArray::fromHex("000102030405060708090a0b0c0d0e0f");

QAESEncryption enc(QAESEncryption::AES_192, QAESEncryption::OFB, QAESEncryption::NONE);
QByteArray cipher = enc.encode("Hello, world!", key, iv);

QFile f("cipher.bin");
f.open(QFile::WriteOnly);
f.write(cipher);
```

```sh
openssl enc -aes-192-ofb -d -nopad \
  -K 8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b \
  -iv 000102030405060708090a0b0c0d0e0f \
  -in cipher.bin
# → Hello, world!
```

### OpenSSL → Qt

**AES-128-CBC** (block mode, PKCS7 padding)

```sh
printf 'Hello, world!' | openssl enc -aes-128-cbc \
  -K 2b7e151628aed2a6abf7158809cf4f3c \
  -iv 000102030405060708090a0b0c0d0e0f \
  > cipher.bin
```

```cpp
QByteArray key = QByteArray::fromHex("2b7e151628aed2a6abf7158809cf4f3c");
QByteArray iv  = QByteArray::fromHex("000102030405060708090a0b0c0d0e0f");

QFile f("cipher.bin");
f.open(QFile::ReadOnly);
QByteArray cipher = f.readAll();

QAESEncryption enc(QAESEncryption::AES_128, QAESEncryption::CBC, QAESEncryption::PKCS7);
QByteArray plain = enc.removePadding(enc.decode(cipher, key, iv));
// plain == "Hello, world!"
```

**AES-256-CFB** (stream mode, no padding)

```sh
printf 'Hello, world!' | openssl enc -aes-256-cfb -nopad \
  -K 603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4 \
  -iv 000102030405060708090a0b0c0d0e0f \
  > cipher.bin
```

```cpp
QByteArray key = QByteArray::fromHex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4");
QByteArray iv  = QByteArray::fromHex("000102030405060708090a0b0c0d0e0f");

QFile f("cipher.bin");
f.open(QFile::ReadOnly);
QByteArray cipher = f.readAll();

QAESEncryption enc(QAESEncryption::AES_256, QAESEncryption::CFB, QAESEncryption::NONE);
QByteArray plain = enc.decode(cipher, key, iv);
// plain == "Hello, world!"
```

**AES-192-OFB** (stream mode, no padding)

```sh
printf 'Hello, world!' | openssl enc -aes-192-ofb -nopad \
  -K 8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b \
  -iv 000102030405060708090a0b0c0d0e0f \
  > cipher.bin
```

```cpp
QByteArray key = QByteArray::fromHex("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b");
QByteArray iv  = QByteArray::fromHex("000102030405060708090a0b0c0d0e0f");

QFile f("cipher.bin");
f.open(QFile::ReadOnly);
QByteArray cipher = f.readAll();

QAESEncryption enc(QAESEncryption::AES_192, QAESEncryption::OFB, QAESEncryption::NONE);
QByteArray plain = enc.decode(cipher, key, iv);
// plain == "Hello, world!"
```
