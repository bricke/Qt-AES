# Qt-AES
Small and portable AES encryption class for Qt.
Supports all key sizes - 128/192/256 bits - ECB and CBC modes

## Usage

### Usage via instance
Example for 128bit ECB
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
  QByteArray hashIV = QCryptographicHash::hash(iv.toLocal8Bit(), QCryptographicHash::Sha256);

  QByteArray encodeText = encryption.encode(inputStr.toLocal8Bit(), hashKey, hashIV);
  QByteArray decodeText = encryption.decode(encodeText, hashKey, hashIV);
```

### Usage via static invocation
Example of static invocation without creating instances
```
#include <QCryptographicHash>
#include "qaesencryption.h"

  QString inputStr("The Advanced Encryption Standard (AES), also known by its original name Rijndael "
                   "is a specification for the encryption of electronic data established by the U.S. "
                  "National Institute of Standards and Technology (NIST) in 2001");
  QString key("your-string-key");
  QString iv("your-IV-vector");

  QByteArray hashKey = QCryptographicHash::hash(key.toLocal8Bit(), QCryptographicHash::Sha256);
  QByteArray hashIV = QCryptographicHash::hash(iv.toLocal8Bit(), QCryptographicHash::Sha256);

  //Static invocation
  QAESEncryption::Crypt(QAESEncryption::AES_256, QAESEncryption::CBC, inputStr.toLocal8Bit(), hashKey, hashIV);

```

## Unit Testing
The unit testing vectors used are included in [NIST-Recommendation for Block Cipher Modes of Operation](http://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf)

## Contact
Question or suggestions are welcome!
Please use the GitHub issue tracking to report suggestions or issues.

## Licence
This software is provided under the [UNLICENSE](http://unlicense.org/)
