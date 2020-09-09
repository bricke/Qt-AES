# Qt-AES
Small and portable AES encryption class for Qt.
Native support for all key sizes - 128/192/256 bits - ECB, CBC, CFB and OFB modes
AES-NI support for all key sizes - ECB, CBC modes

## Usage

### Available Methods
```
// Encode of rawText with key
// iv is used in CBC mode
// return the encrypted byte array
QByteArray encode(const QByteArray rawText, const QByteArray key, const QByteArray iv = QByteArray());

// Decode of rawText with key
// iv is used in CBC mode
// return the decrypted byte array
QByteArray decode(const QByteArray rawText, const QByteArray key, const QByteArray iv = QByteArray());

// Key expansion in Rijndael schedule
// return the new expanded key as byte array
QByteArray expandKey(const QByteArray key);
```
The same methods are available as static calls
```
QAESEncryption::Crypt => encode(...)
QAESEncryption::Decrypt => decode(...)
QAESEncryption::ExpandKey => expandKey(...)
```

#### AES Levels
The class supports all AES key lenghts

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
```
#include "qaesencryption.h"

QAESEncryption encryption(QAESEncryption::AES_128, QAESEncryption::ECB);
QByteArray encodedText = encryption.encode(plainText, key);

QByteArray decodedText = encryption.decode(encodedText, key);
```

Example for 256bit CBC using QString
```
#include <QCryptographicHash>
#include "qaesencryption.h"

QAESEncryption encryption(QAESEncryption::AES_256, QAESEncryption::CBC);

QString inputStr("The Advanced Encryption Standard (AES), also known by its original name Rijndael "
                 "is a specification for the encryption of electronic data established by the U.S. "
                "National Institute of Standards and Technology (NIST) in 2001");
QString key("your-string-key");
QString iv("your-IV-vector");

QByteArray hashKey = QCryptographicHash::hash(key.toLocal8Bit(), QCryptographicHash::Sha256);
QByteArray hashIV = QCryptographicHash::hash(iv.toLocal8Bit(), QCryptographicHash::Md5);

QByteArray encodeText = encryption.encode(inputStr.toLocal8Bit(), hashKey, hashIV);
QByteArray decodeText = encryption.decode(encodeText, hashKey, hashIV);

QString decodedString = QString(encryption.removePadding(decodeText));

//decodedString == inputStr !!
```

### Example via static invocation
Static invocation without creating instances, 256 bit key, ECB mode, starting from *QString* text/key
```
#include <QCryptographicHash>
#include "qaesencryption.h"

QString inputStr("The Advanced Encryption Standard (AES), also known by its original name Rijndael "
                 "is a specification for the encryption of electronic data established by the U.S. "
                "National Institute of Standards and Technology (NIST) in 2001");
QString key("your-string-key");
QString iv("your-IV-vector");

QByteArray hashKey = QCryptographicHash::hash(key.toLocal8Bit(), QCryptographicHash::Sha256);
QByteArray hashIV = QCryptographicHash::hash(iv.toLocal8Bit(), QCryptographicHash::Md5);

//Static invocation
QByteArray encrypted = QAESEncryption::Crypt(QAESEncryption::AES_256, QAESEncryption::CBC, 
                        inputStr.toLocal8Bit(), hashKey, hashIV);
//...
// Removal of Padding via Static function
QString decodedString = QString(QAESEncryption::RemovePadding(decodeText));

```

## AES New Instructions Set
To use the hardware acceleration provided by the AES New Instructions Set, define USE_INTEL_AES_IF_AVAILABLE
If the CPU supports it, the code will switch to use AESNI automatically.
The feature is enabled by default

## Unit Testing
The unit testing vectors used are included in [NIST-Recommendation for Block Cipher Modes of Operation](http://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf)

Please note that this code is not audited or AES-certified by any competent authority, use it at your own risk.

## Dependencies
* qtcore

No OpenSSL required.

## Contact
Question or suggestions are welcome!
Please use the GitHub issue tracking to report suggestions or issues.

## License
This software is provided under the [UNLICENSE](http://unlicense.org/)

## Known Issues
Please take a look at the list of currently open issues
