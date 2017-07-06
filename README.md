# Qt-AES
AES Encryption in Qt.
Supports all key sizes - 128/192/256 and ECB/CBC modes

## Usage
Import the header file
```#include "qaesencryption.h"

...

QAESEncryption encryption(QAESEncryption::AES_128, QAESEncryption::ECB);
QByteArray encodedHex = encryption.encode(hexText, keyHex);
QByteArray decodedHex = encryption.decode(hexText, keyHex);
```

## Tips
In AES the key needs to be 128/192/256 bits long, an MD5 Hash can be used to generate a 128 bit long QByteArray from a QString, a SHA256 can be used to generate a 256bit key.
See the *main.cpp* file for references on usage
