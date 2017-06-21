#ifndef QAESENCRYPTION_H
#define QAESENCRYPTION_H

#include <QObject>
#include <QByteArray>
#include <QVariant>

class QAESEncryption : public QObject
{
    Q_OBJECT
public:
    typedef enum {
        AES_128,
        AES_192,
        AES_256
    } AES;

    typedef enum {
        ECB,
        CBC
    } MODE;

    QAESEncryption(QAESEncryption::AES level, QAESEncryption::MODE mode);

    QByteArray encode(const QByteArray rawText, const QByteArray key, const QByteArray iv = NULL);
    QByteArray decode(const QByteArray encodedText, const QByteArray key, const QByteArray iv = NULL);

signals:

public slots:

private:
    //typedef uint8_t state[4][4];

    int m_nb = 4, m_blocklen = 16, m_mode, m_level;
    //QByteArray m_roundKey;
    //uint8_t* m_state[4][4];
    QByteArray* m_state;
    void* m_aesData;

    int m_nk, m_keyLen, m_nr, m_expandedKey;

    typedef struct{
        int nk = 8;
        int keylen = 32;
        int nr = 14;
        int expandedKey = 240;
    } AES256;

    typedef struct{
        int nk = 6;
        int keylen = 24;
        int nr = 12;
        int expandedKey = 209;
    } AES192;

    typedef struct{
        int nk = 4;
        int keylen = 16;
        int nr = 10;
        int expandedKey = 176;
    } AES128;

    uint8_t getSBoxValue(uint8_t num);
    uint8_t getSBoxInvert(uint8_t num);
    QByteArray expandKey(const QByteArray key);
    void addRoundKey(int round, const QByteArray expKey);
    void subBytes();
    void shiftRows();
    void mixColumns();
    void invMixColumns();
    void invSubBytes();
    void invShiftRows();
    QByteArray cipher(const QByteArray expKey, const QByteArray plainText);
    void invCipher();
};

#endif // QAESENCRYPTION_H
