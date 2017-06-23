#include "qaesencryption.h"
#include <QDebug>

#define Multiply(x, y)                                \
      (  ((y & 1) * x) ^                              \
      ((y>>1 & 1) * xTime(x)) ^                       \
      ((y>>2 & 1) * xTime(xTime(x))) ^                \
      ((y>>3 & 1) * xTime(xTime(xTime(x)))) ^         \
      ((y>>4 & 1) * xTime(xTime(xTime(xTime(x))))))   \


QAESEncryption::QAESEncryption(QAESEncryption::AES level, QAESEncryption::MODE mode) : m_level(level), m_mode(mode)
{
    m_state = NULL;

    switch (level)
    {
    case AES_128: {
        AES128 aes;
        m_nk = aes.nk;
        m_keyLen = aes.keylen;
        m_nr = aes.nr;
        m_expandedKey = aes.expandedKey;
        qDebug() << "AES128";
        }
        break;
    case AES_192: {
        AES192 aes;
        m_nk = aes.nk;
        m_keyLen = aes.keylen;
        m_nr = aes.nr;
        m_expandedKey = aes.expandedKey;
        qDebug() << "AES192";
        }
        break;
    case AES_256: {
        AES256 aes;
        m_nk = aes.nk;
        m_keyLen = aes.keylen;
        m_nr = aes.nr;
        m_expandedKey = aes.expandedKey;
        qDebug() << "AES256";
        }
        break;
    default: {
        AES128 aes;
        m_nk = aes.nk;
        m_keyLen = aes.keylen;
        m_nr = aes.nr;
        m_expandedKey = aes.expandedKey;
        qDebug() << "Defaulting to AES128";
        }
        break;
    }

}

QByteArray QAESEncryption::expandKey(const QByteArray key)
{
  int i, k;
  quint8 tempa[4]; // Used for the column/row operations
  QByteArray roundKey(key);
  qDebug() << "Key expansion before" << roundKey.size();

  // The first round key is the key itself.
  // ...

  // All other round keys are found from the previous round keys.
  //i == Nk
  for(i = m_nk; i < m_nb * (m_nr + 1); i++)
  {
    {
      tempa[0] = (quint8) roundKey.at((i-1) * 4 + 0);
      tempa[1] = (quint8) roundKey.at((i-1) * 4 + 1);
      tempa[2] = (quint8) roundKey.at((i-1) * 4 + 2);
      tempa[3] = (quint8) roundKey.at((i-1) * 4 + 3);
    }

    if (i % m_nk == 0)
    {
      // This function shifts the 4 bytes in a word to the left once.
      // [a0,a1,a2,a3] becomes [a1,a2,a3,a0]

      // Function RotWord()
      {
        k = tempa[0];
        tempa[0] = tempa[1];
        tempa[1] = tempa[2];
        tempa[2] = tempa[3];
        tempa[3] = k;
      }

      // SubWord() is a function that takes a four-byte input word and
      // applies the S-box to each of the four bytes to produce an output word.

      // Function Subword()
      {
        tempa[0] = getSBoxValue(tempa[0]);
        tempa[1] = getSBoxValue(tempa[1]);
        tempa[2] = getSBoxValue(tempa[2]);
        tempa[3] = getSBoxValue(tempa[3]);
      }

      tempa[0] =  tempa[0] ^ Rcon[i/m_nk];
    }
    if (m_level == AES_256 && i % m_nk == 4)
    {
      // Function Subword()
      {
        qDebug() << "AES_256";
        tempa[0] = getSBoxValue(tempa[0]);
        tempa[1] = getSBoxValue(tempa[1]);
        tempa[2] = getSBoxValue(tempa[2]);
        tempa[3] = getSBoxValue(tempa[3]);
      }
    }
    roundKey.insert(i * 4 + 0, roundKey.at((i - m_nk) * 4 + 0) ^ tempa[0]);
    roundKey.insert(i * 4 + 1, roundKey.at((i - m_nk) * 4 + 1) ^ tempa[1]);
    roundKey.insert(i * 4 + 2, roundKey.at((i - m_nk) * 4 + 2) ^ tempa[2]);
    roundKey.insert(i * 4 + 3, roundKey.at((i - m_nk) * 4 + 3) ^ tempa[3]);
  }

  //qDebug() << print(roundKey);
  return roundKey;
}

// This function adds the round key to state.
// The round key is added to the state by an XOR function.
void QAESEncryption::addRoundKey(quint8 round, const QByteArray expKey)
{
  QByteArray::iterator it = m_state->begin();
  for(int i=0; i < 16; i++)
      it[i] = (quint8)it[i] ^ (quint8)expKey.at(round * m_nb * 4 + (i/4) * m_nb + (i%4));
}

// The SubBytes Function Substitutes the values in the
// state matrix with values in an S-box.
void QAESEncryption::subBytes()
{
  QByteArray::iterator it = m_state->begin();
  for(int i = 0; i < 16; i++)
    it[i] = getSBoxValue((quint8) it[i]);
}

// The ShiftRows() function shifts the rows in the state to the left.
// Each row is shifted with different offset.
// Offset = Row number. So the first row is not shifted.
void QAESEncryption::shiftRows()
{
    QByteArray::iterator it = m_state->begin();
    quint8 temp;

     //Shift 1 to left
    temp = (quint8) it[4];
    it[4] = it[4+1];
    it[4+1] = it[4+2];
    it[4+2] = it[4+3];
    it[4+3] = temp;

    //Shift 2 to left
    temp = (quint8) it[8];
    it[8] = it[8+2];
    it[8+2] = temp;
    temp = it[8+1];
    it[8+1] = it[8+3];
    it[8+3] = temp;

    //Shift 3 to left
    temp = (quint8) it[12];
    it[12] = it[12+3];
    it[12+3] = it[12+2];
    it[12+2] = it[12+1];
    it[12+1] = temp;
}

// MixColumns function mixes the columns of the state matrix
//optimized!!
void QAESEncryption::mixColumns()
{
  QByteArray::iterator it = m_state->begin();
  quint8 Tmp,Tm,t;
  for(int i = 0; i < 16; i+=4)
  {
    t   = (quint8) it[i];
    Tmp = (quint8) it[i] ^ (quint8) it[i+1] ^ (quint8) it[i+2] ^ (quint8) it[i+3] ;

    Tm  = (quint8) it[i] ^ (quint8) it[i+1];
    Tm = xTime(Tm);
    it[i] = (quint8) it[i] ^ Tm ^ Tmp;

    Tm  = (quint8) it[i+1] ^ (quint8) it[i+2];
    Tm = xTime(Tm);
    it[i+1] = (quint8) it[i+1] ^ Tm ^ Tmp;

    Tm  = (quint8) it[i+2] ^ (quint8) it[i+3];
    Tm = xTime(Tm);
    it[i+2] = (quint8) it[i+2] ^ Tm ^ Tmp;

    Tm  = (quint8) it[i+3] ^ t;
    Tm = xTime(Tm);
    it[i+3] = (quint8)  it[i+3] ^ Tm ^ Tmp;
  }
}

// MixColumns function mixes the columns of the state matrix.
// The method used to multiply may be difficult to understand for the inexperienced.
// Please use the references to gain more information.
void QAESEncryption::invMixColumns()
{
  QByteArray::iterator it = m_state->begin();
  quint8 a,b,c,d;
  for(int i = 0; i < 16; i+=4)
  {
    a = (quint8) it[i];
    b = (quint8) it[i+1];
    c = (quint8) it[i+2];
    d = (quint8) it[i+3];

    it[i]   = (quint8) (Multiply(a, 0x0e) ^ Multiply(b, 0x0b) ^ Multiply(c, 0x0d) ^ Multiply(d, 0x09));
    it[i+1] = (quint8) (Multiply(a, 0x09) ^ Multiply(b, 0x0e) ^ Multiply(c, 0x0b) ^ Multiply(d, 0x0d));
    it[i+2] = (quint8) (Multiply(a, 0x0d) ^ Multiply(b, 0x09) ^ Multiply(c, 0x0e) ^ Multiply(d, 0x0b));
    it[i+3] = (quint8) (Multiply(a, 0x0b) ^ Multiply(b, 0x0d) ^ Multiply(c, 0x09) ^ Multiply(d, 0x0e));
  }
}

// The SubBytes Function Substitutes the values in the
// state matrix with values in an S-box.
void QAESEncryption::invSubBytes()
{
    QByteArray::iterator it = m_state->begin();
    for(int i = 0; i < 16; ++i)
        it[i] = getSBoxInvert(it[i]);
}

void QAESEncryption::invShiftRows()
{
    QByteArray::iterator it = m_state->begin();
    uint8_t temp;

    //Shift 1 to right
    temp = (quint8) it[4+3];
    it[4+3] = it[4+2];
    it[4+2] = it[4+1];
    it[4+1] = it[4];
    it[4] = temp;

    //Shift 2
    temp = (quint8) it[8+2];
    it[8+2] = it[8];
    it[8] = temp;
    temp = (quint8) it[8+3];
    it[8+3] = it[8+1];
    it[8+1] = temp;

    //Shift 3
    temp = (quint8) it[12+3];
    it[12+3] = it[12];
    it[12] = it[12+1];
    it[12+1] = it[12+2];
    it[12+2] = temp;
}

// Cipher is the main function that encrypts the PlainText.
QByteArray QAESEncryption::cipher(const QByteArray expKey, const QByteArray in)
{

  //m_state is the input buffer.... handle it!
  QByteArray output(in);
  m_state = &output;

  quint8 round = 0;

  // Add the First round key to the state before starting the rounds.
  addRoundKey(0, expKey);

  //qDebug() << print(output);
  // There will be Nr rounds.
  // The first Nr-1 rounds are identical.
  // These Nr-1 rounds are executed in the loop below.
  for(round = 1; round < m_nr; ++round)
  {
    subBytes();
    shiftRows();
    mixColumns();
    addRoundKey(round, expKey);
  }

  // The last round is given below.
  // The MixColumns function is not here in the last round.
  subBytes();
  shiftRows();
  addRoundKey(m_nr, expKey);

  return output;
}

QByteArray QAESEncryption::invCipher(const QByteArray expKey, const QByteArray in)
{
    //m_state is the input buffer.... handle it!
    QByteArray output(in);
    m_state = &output;
    uint8_t round = 0;

    // Add the First round key to the state before starting the rounds.
    addRoundKey(m_nr, expKey);

    // There will be Nr rounds.
    // The first Nr-1 rounds are identical.
    // These Nr-1 rounds are executed in the loop below.
    for(round=m_nr-1;round>0;round--)
    {
        invShiftRows();
        invSubBytes();
        addRoundKey(round, expKey);
        invMixColumns();
    }

    // The last round is given below.
    // The MixColumns function is not here in the last round.
    invShiftRows();
    invSubBytes();
    addRoundKey(0, expKey);

    return output;
}

QByteArray QAESEncryption::encode(const QByteArray rawText, const QByteArray key, const QByteArray iv)
{
   if (m_mode == CBC && iv.isNull())
       return QByteArray();

  //qDebug() << "key" << print(key);
  QByteArray expandedKey = expandKey(key);

  // The next function call encrypts the PlainText with the Key using AES algorithm.
  return cipher(expandedKey, rawText);
}

QString QAESEncryption::print(QByteArray in)
{
    QString ret="";
    for (int i=0; i < in.size();i++)
        ret.append(QString("0x%1 ").arg(QString::number((quint8)in.at(i), 16)));
    return ret;
}

QByteArray QAESEncryption::decode(const QByteArray rawText, const QByteArray key, const QByteArray iv)
{
   if (m_mode == CBC && iv.isNull())
       return QByteArray();

  QByteArray expandedKey = expandKey(key);

  return invCipher(expandedKey, rawText);
}
