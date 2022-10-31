#include <QCoreApplication>
#include <QTest>

#ifdef __cplusplus
#include "unit_test/aestest.h"
#endif

int main(int argc, char *argv[])
{
    QCoreApplication a(argc, argv);
    AesTest test1;
    return QTest::qExec(&test1);
}


