#include "aes_openssl_crosscheck.h"
#include "qaesencryption.h"

#include <openssl/evp.h>

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// Encrypt or decrypt |input| using the given OpenSSL EVP cipher.
// When |usePadding| is false, PKCS7 padding is disabled on both ends.
static QByteArray opensslCrypt(const EVP_CIPHER *cipher,
                                const QByteArray &key,
                                const QByteArray &iv,
                                const QByteArray &input,
                                bool encrypt,
                                bool usePadding)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    Q_ASSERT(ctx);

    const unsigned char *keyPtr = reinterpret_cast<const unsigned char *>(key.constData());
    const unsigned char *ivPtr  = iv.isEmpty()
                                  ? nullptr
                                  : reinterpret_cast<const unsigned char *>(iv.constData());

    EVP_CipherInit_ex(ctx, cipher, nullptr, keyPtr, ivPtr, encrypt ? 1 : 0);
    EVP_CIPHER_CTX_set_padding(ctx, usePadding ? 1 : 0);

    // Allocate enough space: input + one extra block for possible padding.
    QByteArray out(input.size() + EVP_CIPHER_CTX_block_size(ctx), '\0');
    int outLen = 0;
    int finalLen = 0;

    EVP_CipherUpdate(ctx,
                     reinterpret_cast<unsigned char *>(out.data()),
                     &outLen,
                     reinterpret_cast<const unsigned char *>(input.constData()),
                     input.size());

    EVP_CipherFinal_ex(ctx,
                       reinterpret_cast<unsigned char *>(out.data()) + outLen,
                       &finalLen);

    EVP_CIPHER_CTX_free(ctx);
    out.resize(outLen + finalLen);
    return out;
}

// Return the OpenSSL EVP cipher matching the given Qt-AES enum values.
// QAESEncryption::Aes:  AES_128=0, AES_192=1, AES_256=2
// QAESEncryption::Mode: ECB=0, CBC=1, CFB=2, OFB=3, CTR=4
static const EVP_CIPHER *getOpenSSLCipher(int qtAes, int qtMode)
{
    using CipherFn = const EVP_CIPHER *(*)();
    static const CipherFn table[3][5] = {
        { EVP_aes_128_ecb, EVP_aes_128_cbc, EVP_aes_128_cfb128, EVP_aes_128_ofb, EVP_aes_128_ctr },
        { EVP_aes_192_ecb, EVP_aes_192_cbc, EVP_aes_192_cfb128, EVP_aes_192_ofb, EVP_aes_192_ctr },
        { EVP_aes_256_ecb, EVP_aes_256_cbc, EVP_aes_256_cfb128, EVP_aes_256_ofb, EVP_aes_256_ctr },
    };
    return table[qtAes][qtMode]();
}

// ---------------------------------------------------------------------------
// Test data
// ---------------------------------------------------------------------------

void AesOpenSSLCrossCheck::interopRoundTrip_data()
{
    QTest::addColumn<int>("qtAes");
    QTest::addColumn<int>("qtMode");
    QTest::addColumn<int>("qtPadding");
    QTest::addColumn<QByteArray>("key");
    QTest::addColumn<QByteArray>("iv");

    // NIST SP 800-38A keys
    const QByteArray key128 = QByteArray::fromHex("2b7e151628aed2a6abf7158809cf4f3c");
    const QByteArray key192 = QByteArray::fromHex("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b");
    const QByteArray key256 = QByteArray::fromHex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4");

    // NIST SP 800-38A IVs
    const QByteArray ivStd = QByteArray::fromHex("000102030405060708090a0b0c0d0e0f");
    const QByteArray ivCtr = QByteArray::fromHex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");

    const int PKCS7 = static_cast<int>(QAESEncryption::PKCS7);
    const int NONE  = static_cast<int>(QAESEncryption::NONE);

    const int ECB = static_cast<int>(QAESEncryption::ECB);
    const int CBC = static_cast<int>(QAESEncryption::CBC);
    const int CFB = static_cast<int>(QAESEncryption::CFB);
    const int OFB = static_cast<int>(QAESEncryption::OFB);
    const int CTR = static_cast<int>(QAESEncryption::CTR);

    const int AES128 = static_cast<int>(QAESEncryption::AES_128);
    const int AES192 = static_cast<int>(QAESEncryption::AES_192);
    const int AES256 = static_cast<int>(QAESEncryption::AES_256);

    // ECB — no IV
    QTest::newRow("ECB-AES128") << AES128 << ECB << PKCS7 << key128 << QByteArray();
    QTest::newRow("ECB-AES192") << AES192 << ECB << PKCS7 << key192 << QByteArray();
    QTest::newRow("ECB-AES256") << AES256 << ECB << PKCS7 << key256 << QByteArray();

    // CBC
    QTest::newRow("CBC-AES128") << AES128 << CBC << PKCS7 << key128 << ivStd;
    QTest::newRow("CBC-AES192") << AES192 << CBC << PKCS7 << key192 << ivStd;
    QTest::newRow("CBC-AES256") << AES256 << CBC << PKCS7 << key256 << ivStd;

    // CFB — stream mode, no padding
    QTest::newRow("CFB-AES128") << AES128 << CFB << NONE << key128 << ivStd;
    QTest::newRow("CFB-AES192") << AES192 << CFB << NONE << key192 << ivStd;
    QTest::newRow("CFB-AES256") << AES256 << CFB << NONE << key256 << ivStd;

    // OFB — stream mode, no padding
    QTest::newRow("OFB-AES128") << AES128 << OFB << NONE << key128 << ivStd;
    QTest::newRow("OFB-AES192") << AES192 << OFB << NONE << key192 << ivStd;
    QTest::newRow("OFB-AES256") << AES256 << OFB << NONE << key256 << ivStd;

    // CTR — stream mode, no padding; uses NIST CTR IV
    QTest::newRow("CTR-AES128") << AES128 << CTR << NONE << key128 << ivCtr;
    QTest::newRow("CTR-AES192") << AES192 << CTR << NONE << key192 << ivCtr;
    QTest::newRow("CTR-AES256") << AES256 << CTR << NONE << key256 << ivCtr;
}

// ---------------------------------------------------------------------------
// Interop round-trip
// ---------------------------------------------------------------------------

void AesOpenSSLCrossCheck::interopRoundTrip()
{
    QFETCH(int, qtAes);
    QFETCH(int, qtMode);
    QFETCH(int, qtPadding);
    QFETCH(QByteArray, key);
    QFETCH(QByteArray, iv);

    // NIST SP 800-38A standard 4-block (64-byte) plaintext
    const QByteArray plaintext = QByteArray::fromHex(
        "6bc1bee22e409f96e93d7e117393172a"
        "ae2d8a571e03ac9c9eb76fac45af8e51"
        "30c81c46a35ce411e5fbc1191a0a52ef"
        "f69f2445df4f9b17ad2b417be66c3710");

    const bool isPkcs7 = (qtPadding == static_cast<int>(QAESEncryption::PKCS7));
    const EVP_CIPHER *cipher = getOpenSSLCipher(qtAes, qtMode);

    QAESEncryption enc(static_cast<QAESEncryption::Aes>(qtAes),
                       static_cast<QAESEncryption::Mode>(qtMode),
                       static_cast<QAESEncryption::Padding>(qtPadding));

    // Direction 1: Qt encrypts → OpenSSL decrypts
    {
        const QByteArray qtCipher = enc.encode(plaintext, key, iv);
        QVERIFY2(!qtCipher.isEmpty(), "Qt encode returned empty");

        const QByteArray osslPlain = opensslCrypt(cipher, key, iv, qtCipher, false, isPkcs7);
        QCOMPARE(osslPlain, plaintext);
    }

    // Direction 2: OpenSSL encrypts → Qt decrypts
    {
        const QByteArray osslCipher = opensslCrypt(cipher, key, iv, plaintext, true, isPkcs7);
        QVERIFY2(!osslCipher.isEmpty(), "OpenSSL encrypt returned empty");

        QByteArray qtPlain = enc.decode(osslCipher, key, iv);
        if (isPkcs7) {
            qtPlain = enc.removePadding(qtPlain);
        }
        QCOMPARE(qtPlain, plaintext);
    }
}

// ---------------------------------------------------------------------------
// Corner cases
// ---------------------------------------------------------------------------

void AesOpenSSLCrossCheck::cornerCaseEmptyInput()
{
    // Empty input with a stream cipher (CFB + NONE) must encode to empty and
    // the round-trip must also yield empty.
    const QByteArray key = QByteArray::fromHex("2b7e151628aed2a6abf7158809cf4f3c");
    const QByteArray iv  = QByteArray::fromHex("000102030405060708090a0b0c0d0e0f");

    QAESEncryption enc(QAESEncryption::AES_128, QAESEncryption::CFB, QAESEncryption::NONE);

    const QByteArray qtCipher = enc.encode(QByteArray(), key, iv);
    QVERIFY(qtCipher.isEmpty());

    // OpenSSL also produces empty output for empty input.
    const QByteArray osslPlain = opensslCrypt(EVP_aes_128_cfb128(), key, iv, qtCipher, false, false);
    QVERIFY(osslPlain.isEmpty());
}

void AesOpenSSLCrossCheck::cornerCasePartialBlock()
{
    // 7-byte (sub-block) plaintext — exercises the stream-mode partial-block
    // code path in both Qt and OpenSSL.
    const QByteArray plaintext("PARTIAL");   // 7 bytes — not a multiple of 16
    const QByteArray key = QByteArray::fromHex("2b7e151628aed2a6abf7158809cf4f3c");
    const QByteArray iv  = QByteArray::fromHex("000102030405060708090a0b0c0d0e0f");

    QAESEncryption enc(QAESEncryption::AES_128, QAESEncryption::CFB, QAESEncryption::NONE);

    // Qt encrypts → OpenSSL decrypts
    {
        const QByteArray qtCipher = enc.encode(plaintext, key, iv);
        QCOMPARE(qtCipher.size(), plaintext.size());

        const QByteArray osslPlain =
            opensslCrypt(EVP_aes_128_cfb128(), key, iv, qtCipher, false, false);
        QCOMPARE(osslPlain, plaintext);
    }

    // OpenSSL encrypts → Qt decrypts
    {
        const QByteArray osslCipher =
            opensslCrypt(EVP_aes_128_cfb128(), key, iv, plaintext, true, false);
        QCOMPARE(osslCipher.size(), plaintext.size());

        const QByteArray qtPlain = enc.decode(osslCipher, key, iv);
        QCOMPARE(qtPlain, plaintext);
    }
}
