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

    void cleanupTestCase(){}

private:
    QByteArray key16, key24, key32;
    QByteArray iv;
    QByteArray in, outECB128, outECB192, outECB256;
    QByteArray inCBC128, outCBC128;
};

#endif // AESTEST_H
