#ifndef AESTEST_H
#define AESTEST_H

#include <QObject>
#include <QByteArray>
#include <QTest>

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

    void CFB256LongText();

    void OFB128Crypt();
    void OFB256String();

    void CBC256StringEvenISO();
    void CBC256StringEvenPKCS7();

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
