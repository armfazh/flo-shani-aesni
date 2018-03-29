#ifndef SHA_NI_SHA_H
#define SHA_NI_SHA_H

#ifdef __cplusplus
extern "C"{
#endif

#define ALIGN_BYTES 32
#ifdef __INTEL_COMPILER
#define ALIGN __declspec(align(ALIGN_BYTES))
#else
#define ALIGN __attribute__ ((aligned (ALIGN_BYTES)))
#endif

#include <stdint.h>
#include <immintrin.h>

#define SHA256_HASH_SIZE 32 /*! <- SHA2-256 produces a 32-byte output. */

//typedef unsigned char
//    *(*SHA2Function)(const unsigned char *message, long unsigned int message_length, unsigned char *digest);
//typedef void(*SHA2Function_x2)(
//    const unsigned char *message0,
//    const unsigned char *message1,
//    long unsigned int message_length,
//    unsigned char *digest0,
//    unsigned char *digest1
//);
//typedef void(*SHA2Function_x4)(
//    const unsigned char *message0,
//    const unsigned char *message1,
//    const unsigned char *message2,
//    const unsigned char *message3,
//    long unsigned int message_length,
//    unsigned char *digest0,
//    unsigned char *digest1,
//    unsigned char *digest2,
//    unsigned char *digest3
//);
//
//typedef void(*SHA2Function_x8)(
//    const unsigned char *message0,
//    const unsigned char *message1,
//    const unsigned char *message2,
//    const unsigned char *message3,
//    const unsigned char *message4,
//    const unsigned char *message5,
//    const unsigned char *message6,
//    const unsigned char *message7,
//    long unsigned int message_length,
//    unsigned char *digest0,
//    unsigned char *digest1,
//    unsigned char *digest2,
//    unsigned char *digest3,
//    unsigned char *digest4,
//    unsigned char *digest5,
//    unsigned char *digest6,
//    unsigned char *digest7
//);

#define SHA_CORE_DEF(CORE)\
unsigned char * sha256##_##CORE(const unsigned char *message, long unsigned int message_length,unsigned char *digest);

#define SHA_X2_CORE_DEF(CORE_X2)\
void sha256_x2##_##CORE_X2(\
unsigned char *message[2],\
long unsigned int message_length,\
unsigned char *digest[2]);

#define SHA_X4_CORE_DEF(CORE_X4)\
void sha256_x4##_##CORE_X4(\
unsigned char *message[4],\
long unsigned int message_length,\
unsigned char *digest[4]);

#define SHA_X8_CORE_DEF(CORE_X8)\
void sha256_x8##_##CORE_X8(\
unsigned char *message[8],\
long unsigned int message_length,\
unsigned char *digest[8]);

/* Single-message implementation */
SHA_CORE_DEF(update_shani)

/* Pipelined implementations */
SHA_X2_CORE_DEF(update_shani_2x)
SHA_X4_CORE_DEF(update_shani_4x)
SHA_X8_CORE_DEF(update_shani_8x)

extern const ALIGN uint32_t CONST_K[64];

#define dec_sha256_vec_256b(NUM)  \
void sha256_vec_ ## NUM ## 256b ( \
  uint8_t *message[NUM],          \
  uint8_t *digest[NUM])

#define dec_sha256_Nw(NUM)        \
void sha256_ ## NUM ## w(         \
    uint8_t *message[NUM],        \
    unsigned int message_length,  \
    uint8_t *digest[NUM])

/* For arbitrary-large input messages */
dec_sha256_vec_256b(4);
dec_sha256_vec_256b(8);
/* For 256-bit input messages */
dec_sha256_Nw(4);
dec_sha256_Nw(8);

#ifdef __cplusplus
}
#endif

#endif //SHA_NI_SHA_H
