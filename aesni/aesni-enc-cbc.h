#ifndef AESNIENCCBC_H
#define AESNIENCCBC_H

#include <chrono>
#include <iostream>
#include <wmmintrin.h>

namespace {

void AES_CBC_encrypt(const unsigned char *in,
                     unsigned char *out,
                     unsigned char ivec[16],
                     unsigned long length,
                     const char *key,
                     int number_of_rounds)
{
    __m128i feedback,data;
    unsigned long i;
    int j;

    if (length%16)
        length = length/16+1;
    else length /=16;

    feedback=_mm_loadu_si128 ((__m128i*)ivec);
    for(i=0; i < length; i++) {
        data = _mm_loadu_si128 (&((__m128i*)in)[i]);
        feedback = _mm_xor_si128 (data,feedback);
        feedback = _mm_xor_si128 (feedback,((__m128i*)key)[0]);
        for(j=1; j <number_of_rounds; j++)
            feedback = _mm_aesenc_si128 (feedback,((__m128i*)key)[j]);
        feedback = _mm_aesenclast_si128 (feedback,((__m128i*)key)[j]);
                _mm_storeu_si128 (&((__m128i*)out)[i],feedback);
    }
}

void AES_CBC_decrypt(const unsigned char *in,
                     unsigned char *out,
                     unsigned char ivec[16],
                     unsigned long length,
                     const char *key,
                     int number_of_rounds)
{
    __m128i data,feedback,last_in;
    unsigned long i;
    int j;
    if (length%16)
        length = length/16+1;
    else length /=16;
    feedback=_mm_loadu_si128 ((__m128i*)ivec);
    for(i=0; i < length; i++) {
        last_in=_mm_loadu_si128 (&((__m128i*)in)[i]);
        data = _mm_xor_si128 (last_in,((__m128i*)key)[0]);
        for(j=1; j <number_of_rounds; j++) {
            data = _mm_aesdec_si128 (data,((__m128i*)key)[j]);
        }
        data = _mm_aesdeclast_si128 (data,((__m128i*)key)[j]);
        data = _mm_xor_si128 (data,feedback);
        _mm_storeu_si128 (&((__m128i*)out)[i],data);
        feedback=last_in;
    }
}


}

#endif // AESNIENCCBC_H
