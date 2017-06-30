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
        QString number = QString::number((quint8)in.at(i), 16);
        if (number.size()==1)
            number.insert(0, "0");
        ret.append(QString("%1").arg(number));
    }
    return ret;
}

int main(int argc, char *argv[])
{
    QCoreApplication a(argc, argv);

    const quint8 text[16] = {0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a};
    const quint8 key[16]  = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
    QByteArray hexText, keyHex;

    for (int i=0; i<16; i++)
    {
        hexText.append(text[i]);
        keyHex.append(key[i]);
    }

    QAESEncryption encryption(QAESEncryption::AES_128, QAESEncryption::ECB);

    QByteArray encodedHex = encryption.encode(hexText, keyHex);
    QByteArray decodedHex = encryption.decode(encodedHex, keyHex);

    qDebug() << "=========================HEX==========================\n";

    qDebug() << "Key" << print(keyHex);
    qDebug() << "Text" << print(hexText);
    qDebug() << "";
    qDebug() << "Crypt" << print(encodedHex);
    qDebug() << "";
    qDebug() << "Decoded text is " << print(decodedHex);

    qDebug() << "\n=======================STRING=========================";

    QString keyString = "25f9e794323b453885f5181f1b624d0b";
    QString plainText = "AES is a subset of the Rijndael cipher developed by two Belgian cryptographers, Vincent Rijmen and Joan Daemen.";
    QByteArray encodedString = encryption.encode(plainText.toLocal8Bit(), keyString.toLocal8Bit());
    QByteArray decodedString = encryption.decode(encodedString, keyString.toLocal8Bit());

    qDebug() << "Key" << keyString;
    qDebug() << "Text" << plainText;
    qDebug() << "";
    qDebug() << "Crypt HEX" << print(encodedString);
    qDebug() << "";
    qDebug() << "Decoded string is " << QString::fromLocal8Bit(decodedString);

    return 0;
}


