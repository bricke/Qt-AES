#include <QTest>
#include "aes_openssl_crosscheck.h"

int main(int argc, char *argv[])
{
    AesOpenSSLCrossCheck test;
    return QTest::qExec(&test, argc, argv);
}
