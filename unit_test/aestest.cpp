#include "aestest.h"

#include <QDebug>
#include <QByteArray>
#include <QCryptographicHash>
#include <QFile>
#include "qaesencryption.h"

// =================== generateKey TESTS =========================

void AesTest::GenerateKeyLengthAES128()
{
    QCOMPARE(QAESEncryption::generateKey("pw", "salt", QAESEncryption::AES_128).size(), 16);
}

void AesTest::GenerateKeyLengthAES192()
{
    QCOMPARE(QAESEncryption::generateKey("pw", "salt", QAESEncryption::AES_192).size(), 24);
}

void AesTest::GenerateKeyLengthAES256()
{
    QCOMPARE(QAESEncryption::generateKey("pw", "salt", QAESEncryption::AES_256).size(), 32);
}

void AesTest::GenerateKeyDeterministic()
{
    QByteArray k1 = QAESEncryption::generateKey("password", "somesalt", QAESEncryption::AES_256);
    QByteArray k2 = QAESEncryption::generateKey("password", "somesalt", QAESEncryption::AES_256);
    QCOMPARE(k1, k2);
}

void AesTest::GenerateKeyEmptyPassword()
{
    QVERIFY(QAESEncryption::generateKey(QByteArray(), "salt", QAESEncryption::AES_256).isEmpty());
}

void AesTest::GenerateKeyEmptySalt()
{
    QVERIFY(QAESEncryption::generateKey("password", QByteArray(), QAESEncryption::AES_256).isEmpty());
}

void AesTest::GenerateKeyDifferentSalts()
{
    QByteArray k1 = QAESEncryption::generateKey("password", "salt-one", QAESEncryption::AES_256);
    QByteArray k2 = QAESEncryption::generateKey("password", "salt-two", QAESEncryption::AES_256);
    QVERIFY(k1 != k2);
}

void AesTest::GenerateKeyDifferentIterations()
{
    QByteArray k1 = QAESEncryption::generateKey("password", "salt", QAESEncryption::AES_256,
                                                QCryptographicHash::Sha256, 1000);
    QByteArray k2 = QAESEncryption::generateKey("password", "salt", QAESEncryption::AES_256,
                                                QCryptographicHash::Sha256, 2000);
    QVERIFY(k1 != k2);
}

void AesTest::GenerateKeyKnownAnswer()
{
    // All vectors verified against:
    //   python3 -c "import hashlib; print(hashlib.pbkdf2_hmac('sha256', pw, salt, c, dk).hex())"

    // Vector 1: c=1, dkLen=32 (AES-256)
    QCOMPARE(QAESEncryption::generateKey("password", "salt", QAESEncryption::AES_256,
                                         QCryptographicHash::Sha256, 1),
             QByteArray::fromHex("120fb6cffcf8b32c43e7225256c4f837"
                                 "a86548c92ccc35480805987cb70be17b"));

    // Vector 2: c=2, dkLen=32 (AES-256)
    QCOMPARE(QAESEncryption::generateKey("password", "salt", QAESEncryption::AES_256,
                                         QCryptographicHash::Sha256, 2),
             QByteArray::fromHex("ae4d0c95af6b46d32d0adff928f06dd0"
                                 "2a303f8ef3c251dfd6e2d85a95474c43"));

    // Vector 3: c=4096, dkLen=32 (AES-256)
    QCOMPARE(QAESEncryption::generateKey("password", "salt", QAESEncryption::AES_256,
                                         QCryptographicHash::Sha256, 4096),
             QByteArray::fromHex("c5e478d59288c841aa530db6845c4c8d"
                                 "962893a001ce4e11a4963873aa98134a"));

    // Vector 4: long password and salt, c=4096, dkLen=16 (AES-128, first 16 bytes of 40-byte output)
    // Full 40-byte result: 348c89dbcbd32b2f32d814b8116e84cf2b17347ebc1800181c4e2a1fb8dd53e1c635518c7dac47e9
    QCOMPARE(QAESEncryption::generateKey("passwordPASSWORDpassword",
                                         "saltSALTsaltSALTsaltSALTsaltSALTsalt",
                                         QAESEncryption::AES_128,
                                         QCryptographicHash::Sha256, 4096),
             QByteArray::fromHex("348c89dbcbd32b2f32d814b8116e84cf"));

    // Vector 5: embedded NUL bytes, c=4096, dkLen=16 (AES-128)
    QByteArray pwWithNul  = QByteArray("pass\x00word",  9);
    QByteArray saltWithNul = QByteArray("sa\x00lt",     5);
    QCOMPARE(QAESEncryption::generateKey(pwWithNul, saltWithNul, QAESEncryption::AES_128,
                                         QCryptographicHash::Sha256, 4096),
             QByteArray::fromHex("89b69d0516f829893c696226650a8687"));
}

void AesTest::GenerateKeyRoundTripCBC256()
{
    QAESEncryption enc(QAESEncryption::AES_256, QAESEncryption::CBC, QAESEncryption::PKCS7);
    QByteArray plain("Salted CBC-256 round-trip test.");
    QByteArray ivBytes = QByteArray::fromHex("000102030405060708090a0b0c0d0e0f");
    QByteArray key = QAESEncryption::generateKey("correct horse battery staple",
                                                 QByteArray::fromHex("deadbeefcafebabe0102030405060708"),
                                                 QAESEncryption::AES_256);
    QCOMPARE(key.size(), 32);
    QByteArray cipher = enc.encode(plain, key, ivBytes);
    QByteArray decoded = enc.removePadding(enc.decode(cipher, key, ivBytes));
    QCOMPARE(decoded, plain);
}

void AesTest::GenerateKeyRoundTripCFB128()
{
    QAESEncryption enc(QAESEncryption::AES_128, QAESEncryption::CFB, QAESEncryption::ISO);
    QByteArray plain("CFB-128 salted key derivation test.");
    QByteArray ivBytes = QByteArray::fromHex("aabbccddeeff00112233445566778899");
    QByteArray key = QAESEncryption::generateKey("my-password",
                                                 QByteArray::fromHex("0102030405060708090a0b0c0d0e0f10"),
                                                 QAESEncryption::AES_128);
    QCOMPARE(key.size(), 16);
    QByteArray cipher = enc.encode(plain, key, ivBytes);
    QByteArray decoded = enc.removePadding(enc.decode(cipher, key, ivBytes));
    QCOMPARE(decoded, plain);
}

void AesTest::initTestCase()
{
#ifdef USE_INTEL_AES_IF_AVAILABLE
    qDebug() << "AESNI Enabled";
#endif
    quint8 key_16[16] =  {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
    for (int i=0; i<16; i++)
        key16.append(key_16[i]);

    quint8 key_24[24] = { 0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52, 0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5, 0x62, 0xf8,
                       0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b};
    for (int i=0; i<24; i++)
        key24.append(key_24[i]);

    quint8 key_32[32]= { 0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
                       0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4 };
    for (int i=0; i<32; i++)
        key32.append(key_32[i]);

    quint8 iv_16[16]     = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
    for (int i=0; i<16; i++)
        iv.append(iv_16[i]);

    quint8 in_text[16]    = { 0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a };
    quint8 out_text[16]   = { 0x3a, 0xd7, 0x7b, 0xb4, 0x0d, 0x7a, 0x36, 0x60, 0xa8, 0x9e, 0xca, 0xf3, 0x24, 0x66, 0xef, 0x97 };
    quint8 out_text_2[16] = { 0xbd, 0x33, 0x4f, 0x1d, 0x6e, 0x45, 0xf2, 0x5f, 0xf7, 0x12, 0xa2, 0x14, 0x57, 0x1f, 0xa5, 0xcc };
    quint8 out_text_3[16] = { 0xf3, 0xee, 0xd1, 0xbd, 0xb5, 0xd2, 0xa0, 0x3c, 0x06, 0x4b, 0x5a, 0x7e, 0x3d, 0xb1, 0x81, 0xf8 };
    quint8 out_text_4[16] = { 0x3b, 0x3f, 0xd9, 0x2e, 0xb7, 0x2d, 0xad, 0x20, 0x33, 0x34, 0x49, 0xf8, 0xe8, 0x3c, 0xfb, 0x4a };

    for (int i=0; i<16; i++){
        in.append(in_text[i]);
        outECB128.append(out_text[i]);
        outECB192.append(out_text_2[i]);
        outECB256.append(out_text_3[i]);
        outOFB128.append(out_text_4[i]);
    }

    quint8 text_cbc[64]   = { 0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
                              0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
                              0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
                              0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10 };

    quint8 output_cbc[64] = { 0x76, 0x49, 0xab, 0xac, 0x81, 0x19, 0xb2, 0x46, 0xce, 0xe9, 0x8e, 0x9b, 0x12, 0xe9, 0x19, 0x7d,
                              0x50, 0x86, 0xcb, 0x9b, 0x50, 0x72, 0x19, 0xee, 0x95, 0xdb, 0x11, 0x3a, 0x91, 0x76, 0x78, 0xb2,
                              0x73, 0xbe, 0xd6, 0xb8, 0xe3, 0xc1, 0x74, 0x3b, 0x71, 0x16, 0xe6, 0x9e, 0x22, 0x22, 0x95, 0x16,
                              0x3f, 0xf1, 0xca, 0xa1, 0x68, 0x1f, 0xac, 0x09, 0x12, 0x0e, 0xca, 0x30, 0x75, 0x86, 0xe1, 0xa7 };

    for (int i=0; i<64; i++){
        inCBC128.append(text_cbc[i]);
        outCBC128.append(output_cbc[i]);
    }

}


//==================ECB TESTING=========================

void AesTest::ECB128Crypt()
{
    QByteArray hexText, outputHex;
    QAESEncryption encryption(QAESEncryption::AES_128, QAESEncryption::ECB);
    QCOMPARE(encryption.encode(in, key16), outECB128);
}

void AesTest::ECB128Decrypt()
{
    QAESEncryption encryption(QAESEncryption::AES_128, QAESEncryption::ECB);

    QCOMPARE(encryption.decode(outECB128, key16), in);
}

void AesTest::ECB192Crypt()
{
    QByteArray outputHex;
    QAESEncryption encryption(QAESEncryption::AES_192, QAESEncryption::ECB);

    QCOMPARE(encryption.encode(in, key24), outECB192);
}

void AesTest::ECB192Decrypt()
{
    QByteArray hexText;
    QAESEncryption encryption(QAESEncryption::AES_192, QAESEncryption::ECB);

    QCOMPARE(encryption.decode(outECB192, key24), in);
}

void AesTest::ECB256Crypt()
{
    QAESEncryption encryption(QAESEncryption::AES_256, QAESEncryption::ECB);

    QCOMPARE(encryption.encode(in, key32), outECB256);
}

void AesTest::ECB256Decrypt()
{
    QAESEncryption encryption(QAESEncryption::AES_256, QAESEncryption::ECB);

    QCOMPARE(encryption.decode(outECB256, key32), in);
}

void AesTest::ECB256String()
{
    QAESEncryption encryption(QAESEncryption::AES_256, QAESEncryption::ECB, QAESEncryption::Padding::ISO);

    QString inputStr("The Advanced Encryption Standard (AES), also known by its original name Rijndael "
                        "is a specification for the encryption of electronic data established by the U.S. "
                        "National Institute of Standards and Technology (NIST) in 2001");
    QString key("123456789123");

    QByteArray hashKey = QCryptographicHash::hash(key.toLocal8Bit(), QCryptographicHash::Sha256);

    QByteArray encodeText = encryption.encode(inputStr.toLocal8Bit(), hashKey);
    QByteArray decodedText = encryption.removePadding(encryption.decode(encodeText, hashKey));

    QCOMPARE(QString(decodedText), inputStr);
}


//==================CBC TESTING=========================

void AesTest::CBC128Crypt()
{
    QAESEncryption encryption(QAESEncryption::AES_128, QAESEncryption::CBC);

    QCOMPARE(encryption.encode(inCBC128, key16, iv), outCBC128);
}

void AesTest::CBC128Decrypt()
{
    QAESEncryption encryption(QAESEncryption::AES_128, QAESEncryption::CBC);

    QCOMPARE(encryption.decode(outCBC128, key16, iv), inCBC128);
}

//=================== CFB TESTING ============================

void AesTest::CFB256String()
{
    QAESEncryption encryption(QAESEncryption::AES_256, QAESEncryption::CFB, QAESEncryption::PKCS7);

    QString inputStr("The Advanced Encryption Standard (AES), also known by its original name Rijndael "
                        "is a specification for the encryption of electronic data established by the U.S. "
                        "National Institute of Standards and Technology (NIST) in 2001");
    QString key("123456789123");

    QByteArray hashKey = QCryptographicHash::hash(key.toLocal8Bit(), QCryptographicHash::Sha256);

    QByteArray encodeText = encryption.encode(inputStr.toLocal8Bit(), hashKey, iv);
    QByteArray decodedText = encryption.removePadding(encryption.decode(encodeText, hashKey, iv));
    QCOMPARE(QString(decodedText), inputStr);
}

void AesTest::CFB256SmallSizeText()
{
    QAESEncryption encryption(QAESEncryption::AES_256, QAESEncryption::CFB);

    QFile textFile(":/unit_test/alices-in-wonderland.txt");
    QByteArray input;
    if (textFile.open(QFile::ReadOnly))
        input = textFile.readAll();
    else
        QFAIL("File alices-in-wonderland.txt not found!");

    QString key("123456789123");

    QByteArray hashKey = QCryptographicHash::hash(key.toLocal8Bit(), QCryptographicHash::Sha256);
    QByteArray encodeText = encryption.encode(input, hashKey, iv);
    QByteArray decodedText = encryption.removePadding(encryption.decode(encodeText, hashKey, iv));
    QCOMPARE(decodedText, input);
}

void AesTest::CFB256MediumSizeText()
{
    QAESEncryption encryption(QAESEncryption::AES_256, QAESEncryption::CFB);

    QFile textFile(":/unit_test/la-divina-commedia.txt");
    QByteArray input;
    if (textFile.open(QFile::ReadOnly))
        input = textFile.readAll();
    else
        QFAIL("File la-divina-commedia.txt not found!");

    QString key("123456789123");

    QByteArray hashKey = QCryptographicHash::hash(key.toLocal8Bit(), QCryptographicHash::Sha256);
    QByteArray encodeText = encryption.encode(input, hashKey, iv);
    QByteArray decodedText = encryption.removePadding(encryption.decode(encodeText, hashKey, iv));
    QCOMPARE(decodedText, input);
}

void AesTest::CFB256LargeSizeText()
{
    QAESEncryption encryption(QAESEncryption::AES_256, QAESEncryption::CFB);

    QFile textFile(":/unit_test/moby-dick.txt");
    QByteArray input;
    if (textFile.open(QFile::ReadOnly))
        input = textFile.readAll();
    else
        QFAIL("File moby-dick.txt not found!");

    QString key("123456789123");

    QByteArray hashKey = QCryptographicHash::hash(key.toLocal8Bit(), QCryptographicHash::Sha256);
    QByteArray encodeText = encryption.encode(input, hashKey, iv);
    QByteArray decodedText = encryption.removePadding(encryption.decode(encodeText, hashKey, iv));
    QCOMPARE(decodedText, input);
}

void AesTest::CFB256XLargeSizeText()
{
    QAESEncryption encryption(QAESEncryption::AES_256, QAESEncryption::CFB);

    QFile textFile(":/unit_test/shakespeare-complete-works.txt");
    QByteArray input;
    if (textFile.open(QFile::ReadOnly))
        input = textFile.readAll();
    else
        QFAIL("File shakespeare-complete-works.txt not found!");

    QString key("123456789123");

    QByteArray hashKey = QCryptographicHash::hash(key.toLocal8Bit(), QCryptographicHash::Sha256);
    QByteArray encodeText = encryption.encode(input, hashKey, iv);
    QByteArray decodedText = encryption.removePadding(encryption.decode(encodeText, hashKey, iv));
    QCOMPARE(decodedText, input);
}

void AesTest::OFB128Crypt()
{
    QAESEncryption encryption(QAESEncryption::AES_128, QAESEncryption::OFB);

    QCOMPARE(encryption.encode(in, key16, iv), outOFB128);
}

void AesTest::OFB256String()
{
    QAESEncryption encryption(QAESEncryption::AES_256, QAESEncryption::OFB, QAESEncryption::PKCS7);

    QString inputStr("The Advanced Encryption Standard (AES), also known by its original name Rijndael "
                        "is a specification for the encryption of electronic data established by the U.S. "
                        "National Institute of Standards and Technology (NIST) in 2001");
    QString key("123456789123");

    QByteArray hashKey = QCryptographicHash::hash(key.toLocal8Bit(), QCryptographicHash::Sha256);
    QByteArray encodeText = encryption.encode(inputStr.toLocal8Bit(), hashKey, iv);

    QByteArray decodedText = encryption.removePadding(encryption.decode(encodeText, hashKey, iv));
    QCOMPARE(inputStr, QString(decodedText));
}

void AesTest::CBC256StringEvenISO()
{
    QAESEncryption encryption(QAESEncryption::AES_256, QAESEncryption::CBC);

    //16 byte string
    QString inputStr("1234567890123456");
    QString key("123456789123");

    QByteArray hashKey = QCryptographicHash::hash(key.toLocal8Bit(), QCryptographicHash::Sha256);
    QByteArray encodeText = encryption.encode(inputStr.toLocal8Bit(), hashKey, iv);
    QByteArray decodeText = encryption.decode(encodeText, hashKey, iv);

    QString decodedString = QString(encryption.removePadding(decodeText));

    QCOMPARE(QString(decodeText), decodedString);

}

void AesTest::CBC256StringEvenPKCS7()
{
    QAESEncryption encryption(QAESEncryption::AES_256, QAESEncryption::CBC, QAESEncryption::PKCS7);

    //16 byte string
    QString inputStr("1234567890123456");
    int blockLen = 16;
    QString key("123456789123");

    QByteArray hashKey = QCryptographicHash::hash(key.toLocal8Bit(), QCryptographicHash::Sha256);
    QByteArray encodeText = encryption.encode(inputStr.toLocal8Bit(), hashKey, iv);
    QByteArray decodeText = encryption.decode(encodeText, hashKey, iv);
    QByteArray padding = decodeText.remove(0, encryption.removePadding(decodeText).length());

    QCOMPARE(padding.size(), blockLen);
}
