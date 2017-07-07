#include <QCoreApplication>
#include <QTest>
#include "aestest.h"

int main(int argc, char *argv[])
{
    QCoreApplication a(argc, argv);

    AesTest test1;
    QTest::qExec(&test1);

    return 0;
}


