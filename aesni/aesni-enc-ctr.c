#include <wmmintrin.h>
#include <emmintrin.h>
#include <smmintrin.h>

#ifdef __cplusplus
extern "C" {
#endif

//void AES_CTR_encrypt (const unsigned char *in,
//                      unsigned char *out,
//                      const unsigned char ivec[8],
//                     const unsigned char nonce[4],
//                     unsigned long length,
//                     const unsigned char *key,
//                     int number_of_rounds)
//{
//    __m128i ctr_block, tmp, ONE, BSWAP_EPI64;
//    int i,j;
//    if (length%16)
//        length = length/16 + 1;
//    else length/=16;
//    ONE = _mm_set_epi32(0,1,0,0);
//    BSWAP_EPI64 = _mm_setr_epi8(7,6,5,4,3,2,1,0,15,14,13,12,11,10,9,8);
//    ctr_block = _mm_insert_epi64(ctr_block, *(long long*)ivec, 1);
//    ctr_block = _mm_insert_epi32(ctr_block, *(long*)nonce, 1);
//    ctr_block = _mm_srli_si128(ctr_block, 4);
//    ctr_block = _mm_shuffle_epi8(ctr_block, BSWAP_EPI64);
//    ctr_block = _mm_add_epi64(ctr_block, ONE);
//    for(i=0; i < length; i++) {
//        tmp = _mm_shuffle_epi8(ctr_block, BSWAP_EPI64);
//        ctr_block = _mm_add_epi64(ctr_block, ONE);
//        tmp = _mm_xor_si128(tmp, ((__m128i*)key)[0]);
//        for(j=1; j <number_of_rounds; j++) {
//            tmp = _mm_aesenc_si128 (tmp, ((__m128i*)key)[j]);
//        };
//        tmp = _mm_aesenclast_si128 (tmp, ((__m128i*)key)[j]);
//        tmp = _mm_xor_si128(tmp,_mm_loadu_si128(&((__m128i*)in)[i]));
//        _mm_storeu_si128 (&((__m128i*)out)[i],tmp);
//    }
//}

#ifdef __cplusplus
}
#endif
