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

void AesTest::GenerateKeyIterationCapExceeded()
{
    // iterations > 500000 should be rejected to prevent callers causing an indefinite hang
    QVERIFY(QAESEncryption::generateKey("password", "salt", QAESEncryption::AES_256,
                                        QCryptographicHash::Sha256, 500001).isEmpty());
    QVERIFY(!QAESEncryption::generateKey("password", "salt", QAESEncryption::AES_256,
                                         QCryptographicHash::Sha256, 500000).isEmpty());
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

void AesTest::CFB128KnownAnswer()
{
    // NIST SP 800-38A, F.3.13/F.3.14 — CFB128-AES128 Encrypt/Decrypt (two blocks).
    // Verifies both the software and (when built with AES-NI) hardware paths against
    // authoritative vectors. Same key and IV as the OFB128 test.
    //
    // P1: 6bc1bee22e409f96e93d7e117393172a → C1: 3b3fd92eb72dad20333449f8e83cfb4a
    // P2: ae2d8a571e03ac9c9eb76fac45af8e51 → C2: c8a64537a0b3a93fcde3cdad9f1ce58b
    QByteArray pt = QByteArray::fromHex("6bc1bee22e409f96e93d7e117393172a"
                                        "ae2d8a571e03ac9c9eb76fac45af8e51");
    QByteArray ct = QByteArray::fromHex("3b3fd92eb72dad20333449f8e83cfb4a"
                                        "c8a64537a0b3a93fcde3cdad9f1ce58b");

    QAESEncryption enc(QAESEncryption::AES_128, QAESEncryption::CFB);
    QCOMPARE(enc.encode(pt, key16, iv), ct);
    QCOMPARE(enc.decode(ct, key16, iv), pt);
}

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

void AesTest::CFB256FileRoundTrip_data()
{
    QTest::addColumn<QString>("resource");
    QTest::newRow("small")   << QString(":/unit_test/alices-in-wonderland.txt");
    QTest::newRow("medium")  << QString(":/unit_test/la-divina-commedia.txt");
    QTest::newRow("large")   << QString(":/unit_test/moby-dick.txt");
    QTest::newRow("xlarge")  << QString(":/unit_test/shakespeare-complete-works.txt");
}

void AesTest::CFB256FileRoundTrip()
{
    QFETCH(QString, resource);

    QFile textFile(resource);
    QByteArray input;
    if (textFile.open(QFile::ReadOnly))
        input = textFile.readAll();
    else
        QFAIL(qPrintable("Resource not found: " + resource));

    QAESEncryption encryption(QAESEncryption::AES_256, QAESEncryption::CFB);
    QByteArray hashKey = QCryptographicHash::hash(QString("123456789123").toLocal8Bit(),
                                                  QCryptographicHash::Sha256);
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

// =================== PKCS7 PADDING VALIDATION TESTS ====

void AesTest::PKCS7RemovePaddingValid()
{
    // Build a block with valid PKCS7 padding: 4 bytes of \x04
    QByteArray data("Hello!!!");        // 8 bytes
    data.append(QByteArray(4, '\x04')); // 4-byte PKCS7 pad → 12 bytes total
    QByteArray result = QAESEncryption::RemovePadding(data, QAESEncryption::PKCS7);
    QCOMPARE(result, QByteArray("Hello!!!"));
}

void AesTest::PKCS7RemovePaddingWrongLastByte()
{
    // Last byte says padding length = 3 but it doesn't match the preceding bytes.
    QByteArray data("Hello!!!");
    data.append('\x05'); // padLen = 5 but only 1 byte appended — wrong
    // RemovePadding must NOT strip anything; buffer returned unchanged.
    QByteArray result = QAESEncryption::RemovePadding(data, QAESEncryption::PKCS7);
    QCOMPARE(result, data);
}

void AesTest::PKCS7RemovePaddingInconsistentBytes()
{
    // Last byte says 4, but preceding bytes are not all \x04.
    QByteArray data("Hello!!!");
    data.append('\x01');
    data.append('\x02');
    data.append('\x03');
    data.append('\x04'); // padLen = 4, but bytes are 01 02 03 04 — invalid
    QByteArray result = QAESEncryption::RemovePadding(data, QAESEncryption::PKCS7);
    QCOMPARE(result, data);
}

void AesTest::PKCS7RemovePaddingZeroLength()
{
    // padLen == 0 is invalid PKCS7 (value must be 1–16).
    QByteArray data("Hello!!!");
    data.append('\x00');
    QByteArray result = QAESEncryption::RemovePadding(data, QAESEncryption::PKCS7);
    QCOMPARE(result, data);
}

void AesTest::PKCS7RemovePaddingTooLarge()
{
    // padLen == 17 exceeds the maximum block size (16) — invalid.
    QByteArray data(32, '\x11'); // 0x11 == 17
    QByteArray result = QAESEncryption::RemovePadding(data, QAESEncryption::PKCS7);
    QCOMPARE(result, data);
}

// =================== OK PARAMETER TESTS ================

void AesTest::OkParamEncodeSuccess()
{
    QAESEncryption enc(QAESEncryption::AES_128, QAESEncryption::ECB);
    bool ok = false;
    QByteArray result = enc.encode(QByteArray("1234567890123456"), key16, QByteArray(), &ok);
    QVERIFY(ok);
    QVERIFY(!result.isEmpty());
}

void AesTest::OkParamEncodeWrongKeySize()
{
    QAESEncryption enc(QAESEncryption::AES_256, QAESEncryption::ECB);
    bool ok = true;
    // key16 is 16 bytes — wrong for AES-256 which requires 32.
    QByteArray result = enc.encode(QByteArray("1234567890123456"), key16, QByteArray(), &ok);
    QVERIFY(!ok);
    QVERIFY(result.isEmpty());
}

void AesTest::OkParamEncodeMissingIV()
{
    QAESEncryption enc(QAESEncryption::AES_128, QAESEncryption::CBC);
    bool ok = true;
    // CBC requires an IV; passing none should fail.
    QByteArray result = enc.encode(QByteArray("1234567890123456"), key16, QByteArray(), &ok);
    QVERIFY(!ok);
    QVERIFY(result.isEmpty());
}

void AesTest::OkParamDecodeSuccess()
{
    QAESEncryption enc(QAESEncryption::AES_128, QAESEncryption::ECB);
    bool encOk = false;
    QByteArray cipher = enc.encode(QByteArray("1234567890123456"), key16, QByteArray(), &encOk);
    QVERIFY(encOk);

    bool decOk = false;
    QByteArray result = enc.decode(cipher, key16, QByteArray(), &decOk);
    QVERIFY(decOk);
    QVERIFY(!result.isEmpty());
}

void AesTest::OkParamDecodeWrongKeySize()
{
    QAESEncryption enc(QAESEncryption::AES_256, QAESEncryption::ECB);
    bool ok = true;
    QByteArray result = enc.decode(QByteArray(32, '\x00'), key16, QByteArray(), &ok);
    QVERIFY(!ok);
    QVERIFY(result.isEmpty());
}

void AesTest::OkParamDecodeUnaligned()
{
    // Non-block-aligned ciphertext for a block mode must fail.
    QAESEncryption enc(QAESEncryption::AES_128, QAESEncryption::CBC);
    bool ok = true;
    QByteArray result = enc.decode(QByteArray(17, '\x00'), key16, iv, &ok);
    QVERIFY(!ok);
    QVERIFY(result.isEmpty());
}

void AesTest::OkParamRemovePaddingValid()
{
    QByteArray data("Hello!!!");
    data.append(QByteArray(8, '\x08')); // valid PKCS7: 8 bytes of 0x08
    bool ok = false;
    QByteArray result = QAESEncryption::RemovePadding(data, QAESEncryption::PKCS7, &ok);
    QVERIFY(ok);
    QCOMPARE(result, QByteArray("Hello!!!"));
}

void AesTest::OkParamRemovePaddingInvalid()
{
    QByteArray data("Hello!!!");
    data.append('\x05'); // padLen=5 but only 1 byte — invalid PKCS7
    bool ok = true;
    QAESEncryption::RemovePadding(data, QAESEncryption::PKCS7, &ok);
    QVERIFY(!ok);
}

// =================== CTR TESTS =========================
// Test vectors from NIST SP 800-38A, Appendix F.5.
// Counter increment: 128-bit big-endian (byte[15] is least significant).

void AesTest::CTR128KnownAnswer()
{
    // F.5.1 — AES-128-CTR, single block
    QByteArray key = QByteArray::fromHex("2b7e151628aed2a6abf7158809cf4f3c");
    QByteArray nonce = QByteArray::fromHex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
    QByteArray pt  = QByteArray::fromHex("6bc1bee22e409f96e93d7e117393172a");
    QByteArray ct  = QByteArray::fromHex("874d6191b620e3261bef6864990db6ce");

    QAESEncryption enc(QAESEncryption::AES_128, QAESEncryption::CTR);
    QCOMPARE(enc.encode(pt, key, nonce), ct);
    QCOMPARE(enc.decode(ct, key, nonce), pt);
}

void AesTest::CTR192KnownAnswer()
{
    // F.5.3 — AES-192-CTR, single block
    QByteArray key = QByteArray::fromHex("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b");
    QByteArray nonce = QByteArray::fromHex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
    QByteArray pt  = QByteArray::fromHex("6bc1bee22e409f96e93d7e117393172a");
    QByteArray ct  = QByteArray::fromHex("1abc932417521ca24f2b0459fe7e6e0b");

    QAESEncryption enc(QAESEncryption::AES_192, QAESEncryption::CTR);
    QCOMPARE(enc.encode(pt, key, nonce), ct);
    QCOMPARE(enc.decode(ct, key, nonce), pt);
}

void AesTest::CTR256KnownAnswer()
{
    // F.5.5 — AES-256-CTR, single block
    QByteArray key = QByteArray::fromHex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4");
    QByteArray nonce = QByteArray::fromHex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
    QByteArray pt  = QByteArray::fromHex("6bc1bee22e409f96e93d7e117393172a");
    QByteArray ct  = QByteArray::fromHex("601ec313775789a5b7a7f504bbf3d228");

    QAESEncryption enc(QAESEncryption::AES_256, QAESEncryption::CTR);
    QCOMPARE(enc.encode(pt, key, nonce), ct);
    QCOMPARE(enc.decode(ct, key, nonce), pt);
}

void AesTest::CTR128MultiBlock()
{
    // F.5.1 — AES-128-CTR, 4 blocks
    QByteArray key = QByteArray::fromHex("2b7e151628aed2a6abf7158809cf4f3c");
    QByteArray nonce = QByteArray::fromHex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
    QByteArray pt  = QByteArray::fromHex("6bc1bee22e409f96e93d7e117393172a"
                                         "ae2d8a571e03ac9c9eb76fac45af8e51"
                                         "30c81c46a35ce411e5fbc1191a0a52ef"
                                         "f69f2445df4f9b17ad2b417be66c3710");
    QByteArray ct  = QByteArray::fromHex("874d6191b620e3261bef6864990db6ce"
                                         "9806f66b7970fdff8617187bb9fffdff"
                                         "5ae4df3edbd5d35e5b4f09020db03eab"
                                         "1e031dda2fbe03d1792170a0f3009cee");

    QAESEncryption enc(QAESEncryption::AES_128, QAESEncryption::CTR);
    QCOMPARE(enc.encode(pt, key, nonce), ct);
    QCOMPARE(enc.decode(ct, key, nonce), pt);
}

void AesTest::CTRPartialBlock()
{
    // CTR produces output the same length as input — no padding, no block-alignment required.
    QByteArray key = QByteArray::fromHex("2b7e151628aed2a6abf7158809cf4f3c");
    QByteArray nonce = QByteArray::fromHex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
    QByteArray pt("Hello!");  // 6 bytes — not block-aligned

    QAESEncryption enc(QAESEncryption::AES_128, QAESEncryption::CTR);
    QByteArray ct = enc.encode(pt, key, nonce);
    QCOMPARE(ct.size(), pt.size());
    QCOMPARE(enc.decode(ct, key, nonce), pt);
}

void AesTest::CTRRoundTrip()
{
    QByteArray key = QByteArray::fromHex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4");
    QByteArray nonce = QByteArray::fromHex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
    QByteArray pt("CTR mode round-trip: no padding, output length equals input length.");

    QAESEncryption enc(QAESEncryption::AES_256, QAESEncryption::CTR);
    QByteArray ct = enc.encode(pt, key, nonce);
    QCOMPARE(ct.size(), pt.size());
    QCOMPARE(enc.decode(ct, key, nonce), pt);
}

// =================== AES-NI TESTS =========================
// These tests only compile and run when QTAES_ENABLE_AESNI=ON.
// They verify that the hardware path produces the same output as the
// NIST SP 800-38A known-answer vectors used by the software-path tests,
// confirming the two code paths are equivalent.

#ifdef USE_INTEL_AES_IF_AVAILABLE
void AesTest::AesNiCTR128KnownAnswer()
{
    // Same NIST F.5.1 vector used by the software path — verifies hardware path produces
    // identical output.
    QByteArray key = QByteArray::fromHex("2b7e151628aed2a6abf7158809cf4f3c");
    QByteArray nonce = QByteArray::fromHex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
    QByteArray pt  = QByteArray::fromHex("6bc1bee22e409f96e93d7e117393172a"
                                         "ae2d8a571e03ac9c9eb76fac45af8e51"
                                         "30c81c46a35ce411e5fbc1191a0a52ef"
                                         "f69f2445df4f9b17ad2b417be66c3710");
    QByteArray ct  = QByteArray::fromHex("874d6191b620e3261bef6864990db6ce"
                                         "9806f66b7970fdff8617187bb9fffdff"
                                         "5ae4df3edbd5d35e5b4f09020db03eab"
                                         "1e031dda2fbe03d1792170a0f3009cee");

    QAESEncryption enc(QAESEncryption::AES_128, QAESEncryption::CTR);
    QCOMPARE(enc.encode(pt, key, nonce), ct);
    QCOMPARE(enc.decode(ct, key, nonce), pt);
}

void AesTest::AesNiCTR256KnownAnswer()
{
    QByteArray key = QByteArray::fromHex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4");
    QByteArray nonce = QByteArray::fromHex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
    QByteArray pt  = QByteArray::fromHex("6bc1bee22e409f96e93d7e117393172a");
    QByteArray ct  = QByteArray::fromHex("601ec313775789a5b7a7f504bbf3d228");

    QAESEncryption enc(QAESEncryption::AES_256, QAESEncryption::CTR);
    QCOMPARE(enc.encode(pt, key, nonce), ct);
    QCOMPARE(enc.decode(ct, key, nonce), pt);
}

void AesTest::AesNiCTRPartialBlock()
{
    QByteArray key = QByteArray::fromHex("2b7e151628aed2a6abf7158809cf4f3c");
    QByteArray nonce = QByteArray::fromHex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
    QByteArray pt("Hello!");

    QAESEncryption enc(QAESEncryption::AES_128, QAESEncryption::CTR);
    QByteArray ct = enc.encode(pt, key, nonce);
    QCOMPARE(ct.size(), pt.size());
    QCOMPARE(enc.decode(ct, key, nonce), pt);
}

void AesTest::AesNiCTRRoundTrip()
{
    QByteArray key = QByteArray::fromHex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4");
    QByteArray nonce = QByteArray::fromHex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
    QByteArray pt("AES-NI CTR round-trip — hardware keystream must match software keystream.");

    QAESEncryption enc(QAESEncryption::AES_256, QAESEncryption::CTR);
    QByteArray ct = enc.encode(pt, key, nonce);
    QCOMPARE(ct.size(), pt.size());
    QCOMPARE(enc.decode(ct, key, nonce), pt);
}

void AesTest::AesNiECB128KnownAnswer()
{
    QAESEncryption encryption(QAESEncryption::AES_128, QAESEncryption::ECB);
    QCOMPARE(encryption.encode(in, key16), outECB128);
    QCOMPARE(encryption.decode(outECB128, key16), in);
}

void AesTest::AesNiECB192KnownAnswer()
{
    QAESEncryption encryption(QAESEncryption::AES_192, QAESEncryption::ECB);
    QCOMPARE(encryption.encode(in, key24), outECB192);
    QCOMPARE(encryption.decode(outECB192, key24), in);
}

void AesTest::AesNiECB256KnownAnswer()
{
    QAESEncryption encryption(QAESEncryption::AES_256, QAESEncryption::ECB);
    QCOMPARE(encryption.encode(in, key32), outECB256);
    QCOMPARE(encryption.decode(outECB256, key32), in);
}

void AesTest::AesNiCBC128KnownAnswer()
{
    QAESEncryption encryption(QAESEncryption::AES_128, QAESEncryption::CBC);
    QCOMPARE(encryption.encode(inCBC128, key16, iv), outCBC128);
    QCOMPARE(encryption.decode(outCBC128, key16, iv), inCBC128);
}

void AesTest::AesNiECB128RoundTrip()
{
    // Encrypt with AES-NI, then decrypt and verify recovery of original data.
    QAESEncryption encryption(QAESEncryption::AES_256, QAESEncryption::ECB, QAESEncryption::PKCS7);
    QByteArray plain("AES-NI ECB round-trip test data!");
    QByteArray cipher = encryption.encode(plain, key32);
    QByteArray decoded = encryption.removePadding(encryption.decode(cipher, key32));
    QCOMPARE(decoded, plain);
}

void AesTest::AesNiCBC256RoundTrip()
{
    // Encrypt with AES-NI CBC-256, decrypt and verify recovery of original data.
    QAESEncryption encryption(QAESEncryption::AES_256, QAESEncryption::CBC, QAESEncryption::PKCS7);
    QByteArray plain("AES-NI CBC-256 round-trip test — hardware acceleration path.");
    QByteArray cipher = encryption.encode(plain, key32, iv);
    QByteArray decoded = encryption.removePadding(encryption.decode(cipher, key32, iv));
    QCOMPARE(decoded, plain);
}

void AesTest::AesNiCFB128KnownAnswer()
{
    // NIST SP 800-38A, F.3.13 — CFB128-AES128 Encrypt (first two blocks).
    // IV: 000102030405060708090a0b0c0d0e0f
    // Key: 2b7e151628aed2a6abf7158809cf4f3c
    // P1: 6bc1bee22e409f96e93d7e117393172a  C1: 3b3fd92eb72dad20333449f8e83cfb4a
    // P2: ae2d8a571e03ac9c9eb76fac45af8e51  C2: c8a64537a0b3a93fcde3cdad9f1ce58b
    QByteArray nistKey  = QByteArray::fromHex("2b7e151628aed2a6abf7158809cf4f3c");
    QByteArray nistIv   = QByteArray::fromHex("000102030405060708090a0b0c0d0e0f");
    QByteArray pt       = QByteArray::fromHex("6bc1bee22e409f96e93d7e117393172a"
                                               "ae2d8a571e03ac9c9eb76fac45af8e51");
    QByteArray expected = QByteArray::fromHex("3b3fd92eb72dad20333449f8e83cfb4a"
                                               "c8a64537a0b3a93fcde3cdad9f1ce58b");

    QAESEncryption enc(QAESEncryption::AES_128, QAESEncryption::CFB);
    QCOMPARE(enc.encode(pt, nistKey, nistIv), expected);
    QCOMPARE(enc.decode(expected, nistKey, nistIv), pt);
}

void AesTest::AesNiCFB256RoundTrip()
{
    // Encrypt with AES-NI CFB-256, decrypt and verify round-trip.
    QAESEncryption encryption(QAESEncryption::AES_256, QAESEncryption::CFB, QAESEncryption::PKCS7);
    QByteArray plain("AES-NI CFB-256 round-trip test — hardware acceleration path.");
    QByteArray nonce = QByteArray::fromHex("000102030405060708090a0b0c0d0e0f");
    QByteArray cipherText = encryption.encode(plain, key32, nonce);
    QByteArray decoded = encryption.removePadding(encryption.decode(cipherText, key32, nonce));
    QCOMPARE(decoded, plain);
}

void AesTest::AesNiOFB128KnownAnswer()
{
    // NIST SP 800-38A, F.4.1 — OFB-AES128 Encrypt (first two blocks).
    // IV: 000102030405060708090a0b0c0d0e0f
    // Key: 2b7e151628aed2a6abf7158809cf4f3c
    // P1: 6bc1bee22e409f96e93d7e117393172a  C1: 3b3fd92eb72dad20333449f8e83cfb4a
    // P2: ae2d8a571e03ac9c9eb76fac45af8e51  C2: 7789508d16918f03f53c52dac54ed825
    QByteArray nistKey  = QByteArray::fromHex("2b7e151628aed2a6abf7158809cf4f3c");
    QByteArray nistIv   = QByteArray::fromHex("000102030405060708090a0b0c0d0e0f");
    QByteArray pt       = QByteArray::fromHex("6bc1bee22e409f96e93d7e117393172a"
                                               "ae2d8a571e03ac9c9eb76fac45af8e51");
    QByteArray expected = QByteArray::fromHex("3b3fd92eb72dad20333449f8e83cfb4a"
                                               "7789508d16918f03f53c52dac54ed825");

    QAESEncryption enc(QAESEncryption::AES_128, QAESEncryption::OFB);
    QCOMPARE(enc.encode(pt, nistKey, nistIv), expected);
    QCOMPARE(enc.decode(expected, nistKey, nistIv), pt);
}

void AesTest::AesNiOFB256RoundTrip()
{
    // Encrypt with AES-NI OFB-256, decrypt and verify round-trip.
    QAESEncryption encryption(QAESEncryption::AES_256, QAESEncryption::OFB, QAESEncryption::PKCS7);
    QByteArray plain("AES-NI OFB-256 round-trip test — hardware acceleration path.");
    QByteArray nonce = QByteArray::fromHex("000102030405060708090a0b0c0d0e0f");
    QByteArray cipherText = encryption.encode(plain, key32, nonce);
    QByteArray decoded = encryption.removePadding(encryption.decode(cipherText, key32, nonce));
    QCOMPARE(decoded, plain);
}
#endif

// =================== NONE PADDING — STREAM CIPHER MODES ================

void AesTest::CFBNoPaddingPartialBlock()
{
    // 7-byte plaintext — not block-aligned. NONE padding must round-trip exactly.
    QAESEncryption enc(QAESEncryption::AES_128, QAESEncryption::CFB, QAESEncryption::NONE);
    QByteArray plain("Hello!!");  // 7 bytes
    QByteArray cipherText = enc.encode(plain, key16, iv);
    QVERIFY(!cipherText.isEmpty());
    QCOMPARE(cipherText.size(), plain.size());  // ciphertext must be same length as plaintext
    QCOMPARE(enc.decode(cipherText, key16, iv), plain);
}

void AesTest::OFBNoPaddingPartialBlock()
{
    // 13-byte plaintext — not block-aligned. NONE padding must round-trip exactly.
    QAESEncryption enc(QAESEncryption::AES_256, QAESEncryption::OFB, QAESEncryption::NONE);
    QByteArray plain("Hello, World!");  // 13 bytes
    QByteArray cipherText = enc.encode(plain, key32, iv);
    QVERIFY(!cipherText.isEmpty());
    QCOMPARE(cipherText.size(), plain.size());
    QCOMPARE(enc.decode(cipherText, key32, iv), plain);
}

void AesTest::NoPaddingRejectedForECB()
{
    // ECB requires block-aligned input; NONE + unaligned must be rejected.
    QAESEncryption enc(QAESEncryption::AES_128, QAESEncryption::ECB, QAESEncryption::NONE);
    QByteArray plain("unaligned");  // 9 bytes — not a multiple of 16
    QVERIFY(enc.encode(plain, key16).isEmpty());
}

void AesTest::NoPaddingRejectedForCBC()
{
    // CBC requires block-aligned input; NONE + unaligned must be rejected.
    QAESEncryption enc(QAESEncryption::AES_256, QAESEncryption::CBC, QAESEncryption::NONE);
    QByteArray plain("short");  // 5 bytes
    QVERIFY(enc.encode(plain, key32, iv).isEmpty());
}

// =================== CONSTANT-TIME S-BOX TESTS =========================
// Exhaustive verification that the algebraic circuit matches the lookup table.
#ifdef QTAES_CONSTANT_TIME_SBOX
#include "aes_ct_sbox.h"

void AesTest::CtSboxForwardMatchesTable()
{
    // The canonical AES forward S-box table (FIPS 197, Figure 7).
    static const quint8 expected[256] = {
        0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
        0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
        0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
        0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
        0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
        0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
        0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
        0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
        0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
        0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
        0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
        0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
        0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
        0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
        0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
        0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
    };

    for (int i = 0; i < 256; ++i)
        QCOMPARE(AesCt::sbox(static_cast<quint8>(i)), expected[i]);
}

void AesTest::CtSboxInverseMatchesTable()
{
    // The canonical AES inverse S-box table (FIPS 197, Figure 14).
    static const quint8 expected[256] = {
        0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
        0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
        0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
        0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
        0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
        0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
        0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
        0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
        0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
        0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
        0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
        0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
        0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
        0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
        0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
        0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d
    };

    for (int i = 0; i < 256; ++i)
        QCOMPARE(AesCt::invSbox(static_cast<quint8>(i)), expected[i]);
}
#endif

void AesTest::EmptyInputECB()
{
    // Empty plaintext with PKCS7 padding must produce one full block of padding (16 bytes).
    // This exercises the edge case where getPadding() fills an entire block.
    QAESEncryption enc(QAESEncryption::AES_256, QAESEncryption::ECB, QAESEncryption::PKCS7);
    QByteArray cipher = enc.encode(QByteArray(), key32);
    QCOMPARE(cipher.size(), 16);
    QByteArray decoded = enc.removePadding(enc.decode(cipher, key32));
    QCOMPARE(decoded, QByteArray());
}

void AesTest::EmptyInputCBC()
{
    // Same check for CBC mode — empty plaintext round-trips correctly.
    QAESEncryption enc(QAESEncryption::AES_256, QAESEncryption::CBC, QAESEncryption::PKCS7);
    QByteArray cipher = enc.encode(QByteArray(), key32, iv);
    QCOMPARE(cipher.size(), 16);
    QByteArray decoded = enc.removePadding(enc.decode(cipher, key32, iv));
    QCOMPARE(decoded, QByteArray());
}
