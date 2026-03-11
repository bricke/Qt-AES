#ifndef AESNIENCCFB_H
#define AESNIENCCFB_H

#include <wmmintrin.h>

namespace {

/* CFB (Cipher Feedback) mode.
 *
 * Both encrypt and decrypt use the FORWARD AES cipher (AESENC, not AESDEC).
 * The encryption key schedule must be passed for both directions.
 *
 * Encrypt:  C[i] = AES_E(C[i-1]) XOR P[i],   C[-1] = IV
 * Decrypt:  P[i] = AES_E(C[i-1]) XOR C[i],   C[-1] = IV
 *
 * Partial last block (length % 16 != 0) is handled byte-by-byte using
 * a local keystream buffer, so the output length equals the input length. */

void AES_CFB_encrypt(const unsigned char *in,
                     unsigned char *out,
                     unsigned char ivec[16],
                     unsigned long length,
                     const char *key,
                     int number_of_rounds)
{
    __m128i feedback, tmp;
    unsigned long i;
    int j;

    const unsigned long blocks    = length / 16;
    const unsigned long remainder = length % 16;

    feedback = _mm_loadu_si128((__m128i*)ivec);

    for (i = 0; i < blocks; i++) {
        /* Encrypt previous ciphertext block (or IV on first iteration). */
        tmp = _mm_xor_si128(feedback, ((__m128i*)key)[0]);
        for (j = 1; j < number_of_rounds; j++)
            tmp = _mm_aesenc_si128(tmp, ((__m128i*)key)[j]);
        tmp = _mm_aesenclast_si128(tmp, ((__m128i*)key)[j]);

        /* XOR with plaintext to produce ciphertext; keep for next iteration. */
        feedback = _mm_xor_si128(tmp, _mm_loadu_si128((const __m128i*)(in + i * 16)));
        _mm_storeu_si128((__m128i*)(out + i * 16), feedback);
    }

    /* Partial last block: generate keystream and XOR byte-by-byte. */
    if (remainder > 0) {
        unsigned char keystream[16];
        tmp = _mm_xor_si128(feedback, ((__m128i*)key)[0]);
        for (j = 1; j < number_of_rounds; j++)
            tmp = _mm_aesenc_si128(tmp, ((__m128i*)key)[j]);
        tmp = _mm_aesenclast_si128(tmp, ((__m128i*)key)[j]);
        _mm_storeu_si128((__m128i*)keystream, tmp);

        for (unsigned long k = 0; k < remainder; k++)
            out[blocks * 16 + k] = in[blocks * 16 + k] ^ keystream[k];
    }
}

void AES_CFB_decrypt(const unsigned char *in,
                     unsigned char *out,
                     unsigned char ivec[16],
                     unsigned long length,
                     const char *key,
                     int number_of_rounds)
{
    __m128i ciphertext, feedback, tmp;
    unsigned long i;
    int j;

    const unsigned long blocks    = length / 16;
    const unsigned long remainder = length % 16;

    feedback = _mm_loadu_si128((__m128i*)ivec);

    for (i = 0; i < blocks; i++) {
        ciphertext = _mm_loadu_si128((const __m128i*)(in + i * 16));

        /* CFB decrypt uses the forward cipher on the previous ciphertext block. */
        tmp = _mm_xor_si128(feedback, ((__m128i*)key)[0]);
        for (j = 1; j < number_of_rounds; j++)
            tmp = _mm_aesenc_si128(tmp, ((__m128i*)key)[j]);
        tmp = _mm_aesenclast_si128(tmp, ((__m128i*)key)[j]);

        _mm_storeu_si128((__m128i*)(out + i * 16), _mm_xor_si128(tmp, ciphertext));
        feedback = ciphertext; /* next iteration feeds on the ciphertext block */
    }

    /* Partial last block. */
    if (remainder > 0) {
        unsigned char keystream[16];
        tmp = _mm_xor_si128(feedback, ((__m128i*)key)[0]);
        for (j = 1; j < number_of_rounds; j++)
            tmp = _mm_aesenc_si128(tmp, ((__m128i*)key)[j]);
        tmp = _mm_aesenclast_si128(tmp, ((__m128i*)key)[j]);
        _mm_storeu_si128((__m128i*)keystream, tmp);

        for (unsigned long k = 0; k < remainder; k++)
            out[blocks * 16 + k] = in[blocks * 16 + k] ^ keystream[k];
    }
}

} // namespace

#endif // AESNIENCCFB_H
