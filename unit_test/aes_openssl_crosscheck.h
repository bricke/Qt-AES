#ifndef AES_OPENSSL_CROSSCHECK_H
#define AES_OPENSSL_CROSSCHECK_H

#include <QObject>
#include <QTest>

class AesOpenSSLCrossCheck : public QObject
{
    Q_OBJECT
private slots:
    void interopRoundTrip_data();
    void interopRoundTrip();
    void cornerCaseEmptyInput();
    void cornerCasePartialBlock();
};

#endif // AES_OPENSSL_CROSSCHECK_H
