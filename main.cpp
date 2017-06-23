#include <QCoreApplication>
#include <QByteArray>
#include <QDebug>
#include <QString>
#include <QCryptographicHash>
#include "qaesencryption.h"

QString print(QByteArray in)
{
    QString ret="";
    for (int i=0; i < in.size();i++) {
        ret.append(QString("0x%1 ").arg(QString::number((quint8)in.at(i), 16)));
    }
    return ret;
}

int main(int argc, char *argv[])
{
    QCoreApplication a(argc, argv);

    const quint8 text[16] = {0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a};
    const quint8 key[16]  = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
    QByteArray plainText, keyText;

    for (int i=0; i<16; i++)
    {
        plainText.append(text[i]);
        keyText.append(key[i]);
    }

    QAESEncryption encryption(QAESEncryption::AES_128, QAESEncryption::ECB);

    QByteArray encodedString = encryption.encode(plainText, keyText);
    QByteArray decodedString = encryption.decode(encodedString, keyText);

    qDebug() << "Key" << print(keyText);
    qDebug() << "Text" << print(plainText);
    qDebug() << "";
    qDebug() << "Crypt" << print(encodedString);
    qDebug() << "";
    qDebug() << "Decoded string is " << print(decodedString);

    return 0;
}


