#ifndef AESTEST_H
#define AESTEST_H

#include <QObject>
#include <QTest>

class AesTest : public QObject
{
    Q_OBJECT
private slots:
    void initTestCase() {}

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
};

#endif // AESTEST_H
