#ifndef AESNIENCTR_H
#define AESNIENCTR_H

#include <wmmintrin.h>

namespace {

/* CTR mode encryption and decryption are identical: each counter block is
 * AES-encrypted to produce a keystream block which is XORed with the
 * plaintext/ciphertext.  The counter is treated as a 128-bit big-endian
 * integer and incremented by 1 after each block (byte[15] is least
 * significant, matching NIST SP 800-38A).
 *
 * Note – the output buffer length equals the input length (no padding).
 * The counter[] array is updated in place to reflect the next unused
 * counter value after the call. */
void AES_CTR_xcrypt(const unsigned char *in,
                    unsigned char *out,
                    unsigned char counter[16],
                    unsigned long length,
                    const char *key,
                    int number_of_rounds)
{
    __m128i ctr_block, tmp, data;
    unsigned long i;
    int j;

    const unsigned long blocks   = length / 16;
    const unsigned long remainder = length % 16;

    for (i = 0; i < blocks; i++) {
        /* Encrypt the counter block to produce a keystream block. */
        ctr_block = _mm_loadu_si128((__m128i*)counter);
        tmp = _mm_xor_si128(ctr_block, ((__m128i*)key)[0]);
        for (j = 1; j < number_of_rounds; j++)
            tmp = _mm_aesenc_si128(tmp, ((__m128i*)key)[j]);
        tmp = _mm_aesenclast_si128(tmp, ((__m128i*)key)[j]);

        /* XOR keystream with input block. */
        data = _mm_loadu_si128((const __m128i*)(in + i * 16));
        _mm_storeu_si128((__m128i*)(out + i * 16), _mm_xor_si128(tmp, data));

        /* Increment counter as a 128-bit big-endian integer. */
        for (int k = 15; k >= 0; --k) {
            if (++counter[k] != 0)
                break;
        }
    }

    /* Handle partial last block: generate keystream, XOR byte by byte. */
    if (remainder > 0) {
        unsigned char keystream[16];
        ctr_block = _mm_loadu_si128((__m128i*)counter);
        tmp = _mm_xor_si128(ctr_block, ((__m128i*)key)[0]);
        for (j = 1; j < number_of_rounds; j++)
            tmp = _mm_aesenc_si128(tmp, ((__m128i*)key)[j]);
        tmp = _mm_aesenclast_si128(tmp, ((__m128i*)key)[j]);
        _mm_storeu_si128((__m128i*)keystream, tmp);

        for (unsigned long k = 0; k < remainder; k++)
            out[blocks * 16 + k] = in[blocks * 16 + k] ^ keystream[k];
    }
}

} // namespace

#endif // AESNIENCTR_H
