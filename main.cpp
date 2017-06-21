#include <QCoreApplication>
#include <QByteArray>
#include <QDebug>
#include <QString>
//#include <QCryptographicHash>
#include "qaesencryption.h"

//const uint8_t iv[]   = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };

/*inline int getAlignedSize(int currSize, int alignment) {
    int padding = (alignment - currSize % alignment) % alignment;
    return currSize + padding;
}*/

/*QString encodeText(const QString rawText, const QString key);
QString decodeText(const QString hexEncodedText, const QString key);
*/

int main(int argc, char *argv[])
{
    QCoreApplication a(argc, argv);

    qDebug() << "START";
    QByteArray srcString = "Hello World";
    QByteArray key = "1234";
    QAESEncryption encryption(QAESEncryption::AES_128, QAESEncryption::ECB);
    QByteArray encodedString = encryption.encode(srcString, key);

    qDebug() << "Encoded string is" << QString(encodedString);
    //qDebug() << "Decoded string is" << decodeText(encodedString, key);
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


