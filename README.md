# Qt-AES
Small and portable AES encryption class for Qt.
Native support for all key sizes - 128/192/256 bits - ECB, CBC, CFB and OFB modes for all key sizes.
Partial AES-NI support.

## Usage

### Available Methods
```
// Encode rawText with key
// iv is required for CBC, CFB and OFB modes
// returns the encrypted byte array
QByteArray encode(const QByteArray rawText, const QByteArray key, const QByteArray iv = QByteArray());

// Decode rawText with key
// iv is required for CBC, CFB and OFB modes
// returns the decrypted byte array
QByteArray decode(const QByteArray rawText, const QByteArray key, const QByteArray iv = QByteArray());

// Key expansion in Rijndael schedule
// returns the expanded key as byte array
QByteArray expandKey(const QByteArray key);

// Remove padding from a decrypted byte array
QByteArray removePadding(const QByteArray rawText);

// Derive an AES-ready key from a password and salt using PBKDF2-HMAC (RFC 2898)
// returns a key of the exact byte length required by the chosen AES level
static QByteArray generateKey(const QByteArray password, const QByteArray salt,
                              QAESEncryption::Aes level,
                              QCryptographicHash::Algorithm algo = QCryptographicHash::Sha256,
                              int iterations = 10000);
```
The same methods are available as static calls
```
QAESEncryption::Crypt        => encode(...)
QAESEncryption::Decrypt      => decode(...)
QAESEncryption::ExpandKey    => expandKey(...)
QAESEncryption::RemovePadding => removePadding(...)
QAESEncryption::generateKey  => generateKey(...)
```

#### AES Levels
The class supports all AES key lengths

* AES_128
* AES_192
* AES_256

#### Modes
The class supports the following operating modes

* ECB
* CBC
* CFB
* OFB

#### Padding
By default the padding method is `ISO`, however, the class supports:

* ZERO
* PKCS7
* ISO

### Example
Sample code using a 128bit key in ECB mode
```cpp
#include "qaesencryption.h"

QAESEncryption encryption(QAESEncryption::AES_128, QAESEncryption::ECB);
QByteArray encodedText = encryption.encode(plainText, key);

QByteArray decodedText = encryption.decode(encodedText, key);
```

#### Key derivation with salt (recommended)
Use `generateKey()` to derive a key from a password and a random salt via PBKDF2.
The salt must be stored alongside the ciphertext and must not be reused across encryptions.

```cpp
#include "qaesencryption.h"

QAESEncryption encryption(QAESEncryption::AES_256, QAESEncryption::CBC, QAESEncryption::PKCS7);

QString password("your-password");
QByteArray salt = /* random 16+ bytes, e.g. from a CSPRNG */;
QByteArray iv   = /* random 16 bytes */;

QByteArray key = QAESEncryption::generateKey(password.toUtf8(), salt,
                                             QAESEncryption::AES_256);

QByteArray cipherText = encryption.encode(plainText.toUtf8(), key, iv);

// To decrypt (salt and iv must be stored/transmitted alongside cipherText):
QByteArray derivedKey  = QAESEncryption::generateKey(password.toUtf8(), salt,
                                                     QAESEncryption::AES_256);
QByteArray decrypted   = encryption.removePadding(encryption.decode(cipherText, derivedKey, iv));
```

> **Note:** `generateKey()` uses Qt's `QMessageAuthenticationCode`, which is not guaranteed to be
> constant-time. For security-critical applications prefer a dedicated library such as OpenSSL
> (`PKCS5_PBKDF2_HMAC`) or libsodium.

#### Example for 256bit CBC using QString (raw hash — no salt)
```cpp
#include <QCryptographicHash>
#include "qaesencryption.h"

QAESEncryption encryption(QAESEncryption::AES_256, QAESEncryption::CBC);

QString inputStr("The Advanced Encryption Standard (AES), also known by its original name Rijndael "
                 "is a specification for the encryption of electronic data established by the U.S. "
                "National Institute of Standards and Technology (NIST) in 2001");
QString key("your-string-key");
QString iv("your-IV-vector");

QByteArray hashKey = QCryptographicHash::hash(key.toLocal8Bit(), QCryptographicHash::Sha256);
QByteArray hashIV  = QCryptographicHash::hash(iv.toLocal8Bit(), QCryptographicHash::Md5);

QByteArray encodeText = encryption.encode(inputStr.toLocal8Bit(), hashKey, hashIV);
QByteArray decodeText = encryption.decode(encodeText, hashKey, hashIV);

QString decodedString = QString(encryption.removePadding(decodeText));

//decodedString == inputStr !!
```

### Example via static invocation
Static invocation without creating instances, 256 bit key, ECB mode, starting from *QString* text/key
```cpp
#include <QCryptographicHash>
#include "qaesencryption.h"

QString inputStr("The Advanced Encryption Standard (AES), also known by its original name Rijndael "
                 "is a specification for the encryption of electronic data established by the U.S. "
                "National Institute of Standards and Technology (NIST) in 2001");
QString key("your-string-key");
QString iv("your-IV-vector");

QByteArray hashKey = QCryptographicHash::hash(key.toLocal8Bit(), QCryptographicHash::Sha256);
QByteArray hashIV  = QCryptographicHash::hash(iv.toLocal8Bit(), QCryptographicHash::Md5);

// Static invocation
QByteArray encrypted = QAESEncryption::Crypt(QAESEncryption::AES_256, QAESEncryption::CBC,
                        inputStr.toLocal8Bit(), hashKey, hashIV);
//...
// Removal of padding via static function
QString decodedString = QString(QAESEncryption::RemovePadding(decrypted));
```

## AES New Instructions Set
To use the hardware acceleration provided by the AES New Instructions Set, enable the
`QTAES_ENABLE_AESNI` CMake option (off by default):
```
cmake -DQTAES_ENABLE_AESNI=ON ...
```
If the CPU supports AES-NI the code will switch to use it automatically.
AES-NI acceleration is available for ECB and CBC modes only.

## Unit Testing
The unit test vectors used are included in [NIST SP 800-38A](http://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf).
`generateKey()` is validated against the PBKDF2-HMAC-SHA256 vectors verified with Python's `hashlib.pbkdf2_hmac`.

Please note that this code is not audited or AES-certified by any competent authority, use it at your own risk.

## Dependencies
* qtcore

No OpenSSL required.

## Contact
Questions or suggestions are welcome!
Please use the GitHub issue tracking to report suggestions or issues.

## License
This software is provided under the [UNLICENSE](http://unlicense.org/)

## Known Issues
Please take a look at the list of currently open issues
