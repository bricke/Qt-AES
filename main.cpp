#include <QCoreApplication>
#include <QByteArray>
#include <QDebug>
#include <QString>
#include <QCryptographicHash>
#include "qaesencryption.h"

//const uint8_t iv[]   = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };

/*inline int getAlignedSize(int currSize, int alignment) {
    int padding = (alignment - currSize % alignment) % alignment;
    return currSize + padding;
}*/

/*QString encodeText(const QString rawText, const QString key);
QString decodeText(const QString hexEncodedText, const QString key);
*/

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
/*
QString encodeText(const QString rawText, const QString key) {
   QCryptographicHash hash(QCryptographicHash::Md5);
   hash.addData(key.toUtf8());
   QByteArray keyData = hash.result();

   const ushort *rawData = rawText.utf16();
   void *rawDataVoid = (void*)rawData;
   const char *rawDataChar = static_cast<const char*>(rawDataVoid);
   QByteArray inputData;

   // ushort is 2*uint8_t + 1 byte for '\0'
   inputData.append(rawDataChar, rawText.size() * 2 + 1);

   const int length = inputData.size();
   int encryptionLength = getAlignedSize(length, 16);

   QByteArray encodingBuffer(encryptionLength, 0);
   inputData.resize(encryptionLength);

   AES_CBC_encrypt_buffer((uint8_t*)encodingBuffer.data(), (uint8_t*)inputData.data(),
      encryptionLength, (const uint8_t*)keyData.data(), iv);

   QByteArray data(encodingBuffer.data(), encryptionLength);
   QString hex = QString::fromLatin1(data.toHex());
   return hex;
}

QString decodeText(const QString hexEncodedText, const QString key) {
   QCryptographicHash hash(QCryptographicHash::Md5);
   hash.addData(key.toUtf8());
   QByteArray keyData = hash.result();

   const int length = hexEncodedText.size();
   int encryptionLength = getAlignedSize(length, 16);

   QByteArray encodingBuffer(encryptionLength, 0);

   QByteArray encodedText = QByteArray::fromHex(hexEncodedText.toLatin1());
   encodedText.resize(encryptionLength);

   AES_CBC_decrypt_buffer((uint8_t*)encodingBuffer.data(), (uint8_t*)encodedText.data(),
     encryptionLength, (const uint8_t*)keyData.data(), iv);

   void *data = encodingBuffer.data();
   const ushort *decodedData = static_cast<const ushort*>(data);
   QString result = QString::fromUtf16(decodedData);

   return result;
}*/


