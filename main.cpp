#include <QCoreApplication>
#include <QByteArray>
#include <QDebug>
#include <QString>
#include "qaesencryption.h"

QString print(QByteArray in)
{
    QString ret="";
    for (int i=0; i < in.size();i++) {
        QString number = QString::number((quint8)in.at(i), 16);
        if (number.size()==1)
            number.insert(0, "0");
        ret.append(QString("%1").arg(number));
    }
    return ret;
}

bool testECBDecrypt()
{
    QByteArray hexText, keyHex, outputHex;
    QAESEncryption encryption(QAESEncryption::AES_128, QAESEncryption::ECB);

    const quint8 key[16]    = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
    const quint8 text[16]   = {0x43, 0xb1, 0xcd, 0x7f, 0x59, 0x8e, 0xce, 0x23, 0x88, 0x1b, 0x00, 0xe3, 0xed, 0x03, 0x06, 0x88};
    const quint8 output[16] = {0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef};

    for (int i=0; i<16; i++)
    {
        keyHex.append(key[i]);
        hexText.append(text[i]);
        outputHex.append(output[i]);
    }

    QByteArray decodedHex = encryption.decode(hexText, keyHex);

    if (outputHex == decodedHex)
        return true;
    return false;
}

bool testECBCrypt()
{
    QByteArray hexText, keyHex, outputHex;
    QAESEncryption encryption(QAESEncryption::AES_128, QAESEncryption::ECB);

    const quint8 key[16]    = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};

    const quint8 text[16]   = {0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a};
    const quint8 output[16] = {0x3a, 0xd7, 0x7b, 0xb4, 0x0d, 0x7a, 0x36, 0x60, 0xa8, 0x9e, 0xca, 0xf3, 0x24, 0x66, 0xef, 0x97};


    for (int i=0; i<16; i++)
    {
        keyHex.append(key[i]);
        hexText.append(text[i]);
        outputHex.append(output[i]);
    }

    QByteArray encodedHex = encryption.encode(hexText, keyHex);

    if (outputHex == encodedHex)
        return true;
    return false;
}

int main(int argc, char *argv[])
{
    QCoreApplication a(argc, argv);

    Q_ASSERT(testECBCrypt());
    Q_ASSERT(testECBDecrypt());

    return 0;
}


