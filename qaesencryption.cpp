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
        }
        break;
    case AES_256: {
        AES256 aes;
        m_nk = aes.nk;
        m_keyLen = aes.keylen;
        m_nr = aes.nr;
        m_expandedKey = aes.expandedKey;
        }
        break;
    default: {
        AES128 aes;
        m_nk = aes.nk;
        m_keyLen = aes.keylen;
        m_nr = aes.nr;
        m_expandedKey = aes.expandedKey;
        }
        break;
    }

}

uint8_t QAESEncryption::getSBoxValue(uint8_t num)
{
  return sbox[num];
}

uint8_t QAESEncryption::getSBoxInvert(uint8_t num)
{
  return rsbox[num];
}

QByteArray QAESEncryption::expandKey(const QByteArray key)
{
  int i, k;
  uint8_t tempa[4]; // Used for the column/row operations
  QByteArray roundKey(key);

  // The first round key is the key itself.
  for(i = 0; i < m_nk; ++i)
  {
    roundKey.insert((i * 4) + 0, key.at((i * 4) + 0));
    roundKey.insert((i * 4) + 1, key.at((i * 4) + 1));
    roundKey.insert((i * 4) + 2, key.at((i * 4) + 2));
    roundKey.insert((i * 4) + 3, key.at((i * 4) + 3));
  }

  // All other round keys are found from the previous round keys.
  //i == Nk
  for(; i < m_nb * (m_nr + 1); ++i)
  {
    {
      tempa[0] = roundKey.at((i-1) * 4 + 0);
      tempa[1] = roundKey.at((i-1) * 4 + 1);
      tempa[2] = roundKey.at((i-1) * 4 + 2);
      tempa[3] = roundKey.at((i-1) * 4 + 3);
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

  return roundKey;
}

// This function adds the round key to state.
// The round key is added to the state by an XOR function.
void QAESEncryption::addRoundKey(int round, const QByteArray expKey)
{
  for(int i=0; i < 16; i++)
      m_state->insert(i, m_state->at(i) ^ expKey.at(round * m_nb * 4 + (i/4) * m_nb + (i%4)));
}

// The SubBytes Function Substitutes the values in the
// state matrix with values in an S-box.
void QAESEncryption::subBytes()
{
  for(int i = 0; i < 16; i++)
    m_state->insert(i, getSBoxValue(m_state->at(i)));
}

// The ShiftRows() function shifts the rows in the state to the left.
// Each row is shifted with different offset.
// Offset = Row number. So the first row is not shifted.
void QAESEncryption::shiftRows()
{
    uint8_t temp;

     //Shift 1
    temp = m_state->at(4);
    m_state->insert(4, m_state->at(4+1));
    m_state->insert(4+1, m_state->at(4+2));
    m_state->insert(4+2, m_state->at(4+3));
    m_state->insert(4+3, temp);

    //Shift 2
    temp = m_state->at(8);
    m_state->insert(8, m_state->at(8+2));
    m_state->insert(8+2, temp);
    temp = m_state->at(8+1);
    m_state->insert(8+1, m_state->at(8+3));
    m_state->insert(8+3, temp);

    //Shift 3
    temp = m_state->at(12);
    m_state->insert(12, m_state->at(12+3));
    m_state->insert(12+3, m_state->at(12+2));
    m_state->insert(12+2, m_state->at(12+1));
    m_state->insert(12+1, temp);
}

// MixColumns function mixes the columns of the state matrix
//optimized!!
void QAESEncryption::mixColumns()
{
  uint8_t Tmp,Tm,t;
  for(int i = 0; i < 16; i+=4)
  {
    t   = m_state->at(i);
    Tmp = m_state->at(i) ^ m_state->at(i+1) ^ m_state->at(i+2) ^ m_state->at(i+3) ;

    Tm  = m_state->at(i) ^ m_state->at(i+1);
    Tm = xTime(Tm);
    m_state->insert(i, m_state->at(i) ^ Tm ^ Tmp);

    Tm  = m_state->at(i+1) ^ m_state->at(i+2);
    Tm = xTime(Tm);
    m_state->insert(i+1, m_state->at(i+1) ^ Tm ^ Tmp);

    Tm  = m_state->at(i+2) ^ m_state->at(i+3);
    Tm = xTime(Tm);
    m_state->insert(i+2, m_state->at(i+2) ^ Tm ^ Tmp);

    Tm  = m_state->at(i+3) ^ t;
    Tm = xTime(Tm);
    m_state->insert(i+3, m_state->at(i+3) ^ Tm ^ Tmp);
  }
}

// MixColumns function mixes the columns of the state matrix.
// The method used to multiply may be difficult to understand for the inexperienced.
// Please use the references to gain more information.
void QAESEncryption::invMixColumns()
{
  uint8_t a,b,c,d;
  for(int i = 0; i < 16; i+=4)
  {
    a = m_state->at(i);
    b = m_state->at(i+1);
    c = m_state->at(i+2);
    d = m_state->at(i+3);

    m_state->insert(i, Multiply(a, 0x0e) ^ Multiply(b, 0x0b) ^ Multiply(c, 0x0d) ^ Multiply(d, 0x09));
    m_state->insert(i+1, Multiply(a, 0x09) ^ Multiply(b, 0x0e) ^ Multiply(c, 0x0b) ^ Multiply(d, 0x0d));
    m_state->insert(i+2, Multiply(a, 0x0d) ^ Multiply(b, 0x09) ^ Multiply(c, 0x0e) ^ Multiply(d, 0x0b));
    m_state->insert(i+3, Multiply(a, 0x0b) ^ Multiply(b, 0x0d) ^ Multiply(c, 0x09) ^ Multiply(d, 0x0e));
  }
}

// The SubBytes Function Substitutes the values in the
// state matrix with values in an S-box.
void QAESEncryption::invSubBytes()
{
  for(int i = 0; i < 16; ++i)
      m_state->insert(i, getSBoxInvert(m_state->at(i)));
}

void QAESEncryption::invShiftRows()
{
  uint8_t temp;

   //Shift 1 to right
  temp = m_state->at(4+3);
  m_state->insert(4+3, m_state->at(4+2));
  m_state->insert(4+2, m_state->at(4+1));
  m_state->insert(4+1, m_state->at(4));
  m_state->insert(4, temp);

  //Shift 2
  temp = m_state->at(8+2);
  m_state->insert(8+2, m_state->at(8));
  m_state->insert(8, temp);
  temp = m_state->at(8+3);
  m_state->insert(8+3, m_state->at(8+1));
  m_state->insert(8+1, temp);

  //Shift 3
  temp = m_state->at(12+3);
  m_state->insert(12+3, m_state->at(12));
  m_state->insert(12, m_state->at(12+1));
  m_state->insert(12+1, m_state->at(12+2));
  m_state->insert(12+2, temp);
}

// Cipher is the main function that encrypts the PlainText.
QByteArray QAESEncryption::cipher(const QByteArray expKey, const QByteArray in)
{

  //m_state is the input buffer.... handle it!
  QByteArray output(in);
  m_state = &output;
  uint8_t round = 0;

  // Add the First round key to the state before starting the rounds.
  addRoundKey(0, expKey);

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

  //qDebug() << "Cyper " << print(output);

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
}

QByteArray QAESEncryption::encode(const QByteArray rawText, const QByteArray key, const QByteArray iv)
{
   if (m_mode == CBC && iv == NULL)
       return NULL; //EMIT ERROR!

  //qDebug() << "key" << print(key);
  QByteArray expandedKey = expandKey(key);

  qDebug() << rawText.size();

  // The next function call encrypts the PlainText with the Key using AES algorithm.
  return cipher(expandedKey, rawText);
}

QString QAESEncryption::print(QByteArray in)
{
    QString ret="";
    QByteArray out = in.toHex();
    for (int i=0; i < out.size();i++)
        ret.append(QString("0x%1 ").arg(out.at(i), 0, 16));
    return ret;
}

QByteArray QAESEncryption::decode(const QByteArray rawText, const QByteArray key, const QByteArray iv)
{
   if (m_mode == CBC && iv == NULL)
       return NULL; //EMIT ERROR!

  QByteArray expandedKey = expandKey(key);

  qDebug() << rawText.size();

  return invCipher(expandedKey, rawText);
}
