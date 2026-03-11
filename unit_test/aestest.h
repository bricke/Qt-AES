#ifndef AESTEST_H
#define AESTEST_H

#include <QObject>
#include <QByteArray>
#include <QTest>
#include "qaesencryption.h"

class AesTest : public QObject
{
    Q_OBJECT
private slots:
    void initTestCase();

    void ECB128Crypt();
    void ECB128Decrypt();

    void ECB192Crypt();
    void ECB192Decrypt();

    void ECB256Crypt();
    void ECB256Decrypt();

    void ECB256String();

    void CBC128Crypt();
    void CBC128Decrypt();

    void CFB256String();

    void CFB256SmallSizeText();
    void CFB256MediumSizeText();
    void CFB256LargeSizeText();
    void CFB256XLargeSizeText();

    void OFB128Crypt();
    void OFB256String();

    void CTR128KnownAnswer();
    void CTR192KnownAnswer();
    void CTR256KnownAnswer();
    void CTR128MultiBlock();
    void CTRPartialBlock();
    void CTRRoundTrip();

    void CBC256StringEvenISO();
    void CBC256StringEvenPKCS7();

    void PKCS7RemovePaddingValid();
    void PKCS7RemovePaddingWrongLastByte();
    void PKCS7RemovePaddingInconsistentBytes();
    void PKCS7RemovePaddingZeroLength();
    void PKCS7RemovePaddingTooLarge();

    void GenerateKeyLengthAES128();
    void GenerateKeyLengthAES192();
    void GenerateKeyLengthAES256();
    void GenerateKeyDeterministic();
    void GenerateKeyEmptyPassword();
    void GenerateKeyEmptySalt();
    void GenerateKeyDifferentSalts();
    void GenerateKeyDifferentIterations();
    void GenerateKeyKnownAnswer();
    void GenerateKeyRoundTripCBC256();
    void GenerateKeyRoundTripCFB128();
    void GenerateKeyIterationCapExceeded();

#ifdef USE_INTEL_AES_IF_AVAILABLE
    void AesNiCTR128KnownAnswer();
    void AesNiCTR256KnownAnswer();
    void AesNiCTRPartialBlock();
    void AesNiCTRRoundTrip();

    void AesNiECB128KnownAnswer();
    void AesNiECB192KnownAnswer();
    void AesNiECB256KnownAnswer();
    void AesNiCBC128KnownAnswer();
    void AesNiECB128RoundTrip();
    void AesNiCBC256RoundTrip();

    void AesNiCFB128KnownAnswer();
    void AesNiCFB256RoundTrip();
    void AesNiOFB128KnownAnswer();
    void AesNiOFB256RoundTrip();
#endif

    void cleanupTestCase(){}

private:
    QByteArray key16;
    QByteArray key24;
    QByteArray key32;
    QByteArray iv;
    QByteArray in;
    QByteArray outECB128;
    QByteArray outECB192;
    QByteArray outECB256;
    QByteArray inCBC128;
    QByteArray outCBC128;
    QByteArray outOFB128;
};

#endif // AESTEST_H
