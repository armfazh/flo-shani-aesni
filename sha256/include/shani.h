//
// Created by armfazh on 4/17/17.
//

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

typedef unsigned char *(*SHA2Function)(const unsigned char *message, long unsigned int message_length,unsigned char *digest);
typedef void(*SHA2Function_x2)(
    const unsigned char *message0,
    const unsigned char *message1,
    long unsigned int message_length,
    unsigned char *digest0,
    unsigned char *digest1
);
typedef void(*SHA2Function_x4)(
    const unsigned char *message0,
    const unsigned char *message1,
    const unsigned char *message2,
    const unsigned char *message3,
    long unsigned int message_length,
    unsigned char *digest0,
    unsigned char *digest1,
    unsigned char *digest2,
    unsigned char *digest3
);

typedef void(*SHA2Function_x8)(
    const unsigned char *message0,
    const unsigned char *message1,
    const unsigned char *message2,
    const unsigned char *message3,
    const unsigned char *message4,
    const unsigned char *message5,
    const unsigned char *message6,
    const unsigned char *message7,
    long unsigned int message_length,
    unsigned char *digest0,
    unsigned char *digest1,
    unsigned char *digest2,
    unsigned char *digest3,
    unsigned char *digest4,
    unsigned char *digest5,
    unsigned char *digest6,
    unsigned char *digest7
);


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


#define SHA_CORE(CORE)\
unsigned char * sha256##_##CORE(const unsigned char *message, long unsigned int message_length,unsigned char *digest)\
{\
    uint32_t i=0;\
    uint32_t num_blocks = message_length/64;\
    uint32_t rem_bytes = message_length%64;\
    ALIGN uint8_t pad[128];\
    ALIGN uint32_t state[8];\
\
    /** Initializing state **/\
    state[0] = 0x6a09e667;\
    state[1] = 0xbb67ae85;\
    state[2] = 0x3c6ef372;\
    state[3] = 0xa54ff53a;\
    state[4] = 0x510e527f;\
    state[5] = 0x9b05688c;\
    state[6] = 0x1f83d9ab;\
    state[7] = 0x5be0cd19;\
    \
    CORE(state,message,num_blocks);\
\
    /** Padding message **/\
    for(i=0;i<rem_bytes;i++)\
    {\
        pad[i] = message[64*num_blocks+i];\
    }\
    pad[rem_bytes] = 0x80;\
    if (rem_bytes < 56)\
    {\
        for (i = rem_bytes + 1; i < 56; i++)\
        {\
            pad[i] = 0x0;\
        }\
        ((uint64_t*)pad)[7] = (uint64_t)__builtin_bswap64(message_length*8);\
        CORE(state,pad,1);\
    }\
    else\
    {\
        for (i = rem_bytes + 1; i < 120; i++)\
        {\
            pad[i] = 0x0;\
        }\
        ((uint64_t*)pad)[15] = (uint64_t)__builtin_bswap64(message_length*8);\
        CORE(state,pad,2);\
    }\
\
    for(i=0;i<SHA256_HASH_SIZE/4;i++)\
    {\
        ((uint32_t*)digest)[i] = (uint32_t)__builtin_bswap32(state[i]);\
    }\
\
    return digest;\
}

#define SHA_x2_CORE(CORE_X2)\
void sha256_x2##_##CORE_X2(\
unsigned char *message[2],\
long unsigned int message_length,\
unsigned char *digest[2])\
{\
    uint32_t i=0;\
    uint32_t num_blocks = message_length/64;\
    uint32_t rem_bytes = message_length%64;\
    ALIGN uint8_t pad0[128];\
    ALIGN uint8_t pad1[128];\
    ALIGN uint32_t state0[8];\
    ALIGN uint32_t state1[8];\
\
    /** Initializing state **/\
    state0[0] = 0x6a09e667;  state1[0] = 0x6a09e667;\
    state0[1] = 0xbb67ae85;  state1[1] = 0xbb67ae85;\
    state0[2] = 0x3c6ef372;  state1[2] = 0x3c6ef372;\
    state0[3] = 0xa54ff53a;  state1[3] = 0xa54ff53a;\
    state0[4] = 0x510e527f;  state1[4] = 0x510e527f;\
    state0[5] = 0x9b05688c;  state1[5] = 0x9b05688c;\
    state0[6] = 0x1f83d9ab;  state1[6] = 0x1f83d9ab;\
    state0[7] = 0x5be0cd19;  state1[7] = 0x5be0cd19;\
    \
    CORE_X2(state0,message[0],state1,message[1],num_blocks);\
\
    /** Padding message **/\
    for(i=0;i<rem_bytes;i++)\
    {\
        pad0[i] = message[0][64*num_blocks+i];\
        pad1[i] = message[1][64*num_blocks+i];\
    }\
    pad0[rem_bytes] = 0x80;\
    pad1[rem_bytes] = 0x80;\
    if (rem_bytes < 56)\
    {\
        for (i = rem_bytes + 1; i < 56; i++)\
        {\
            pad0[i] = 0x0;\
            pad1[i] = 0x0;\
        }\
        ((uint64_t*)pad0)[7] = (uint64_t)__builtin_bswap64(message_length*8);\
        ((uint64_t*)pad1)[7] = (uint64_t)__builtin_bswap64(message_length*8);\
        CORE_X2(state0,pad0,state1,pad1,1);\
    }\
    else\
    {\
        for (i = rem_bytes + 1; i < 120; i++)\
        {\
            pad0[i] = 0x0;\
            pad1[i] = 0x0;\
        }\
        ((uint64_t*)pad0)[15] = (uint64_t)__builtin_bswap64(message_length*8);\
        ((uint64_t*)pad1)[15] = (uint64_t)__builtin_bswap64(message_length*8);\
        CORE_X2(state0,pad0,state1,pad1,2);\
    }\
\
    for(i=0;i<SHA256_HASH_SIZE/4;i++)\
    {\
        ((uint32_t*)(digest[0]) )[i] = (uint32_t)__builtin_bswap32(state0[i]);\
        ((uint32_t*)(digest[1]) )[i] = (uint32_t)__builtin_bswap32(state1[i]);\
    }\
\
}


#define SHA_x4_CORE(CORE_X4)\
void sha256_x4##_##CORE_X4(\
unsigned char *message[4],\
long unsigned int message_length,\
unsigned char *digest[4])\
{\
    uint32_t i=0;\
    uint32_t num_blocks = message_length/64;\
    uint32_t rem_bytes = message_length%64;\
    ALIGN uint8_t pad0[128];\
    ALIGN uint8_t pad1[128];\
    ALIGN uint8_t pad2[128];\
    ALIGN uint8_t pad3[128];\
    ALIGN uint32_t state0[8];\
    ALIGN uint32_t state1[8];\
    ALIGN uint32_t state2[8];\
    ALIGN uint32_t state3[8];\
\
    /** Initializing state **/\
    state0[0] = 0x6a09e667;  state1[0] = 0x6a09e667;   state2[0] = 0x6a09e667;  state3[0] = 0x6a09e667;\
    state0[1] = 0xbb67ae85;  state1[1] = 0xbb67ae85;   state2[1] = 0xbb67ae85;  state3[1] = 0xbb67ae85;\
    state0[2] = 0x3c6ef372;  state1[2] = 0x3c6ef372;   state2[2] = 0x3c6ef372;  state3[2] = 0x3c6ef372;\
    state0[3] = 0xa54ff53a;  state1[3] = 0xa54ff53a;   state2[3] = 0xa54ff53a;  state3[3] = 0xa54ff53a;\
    state0[4] = 0x510e527f;  state1[4] = 0x510e527f;   state2[4] = 0x510e527f;  state3[4] = 0x510e527f;\
    state0[5] = 0x9b05688c;  state1[5] = 0x9b05688c;   state2[5] = 0x9b05688c;  state3[5] = 0x9b05688c;\
    state0[6] = 0x1f83d9ab;  state1[6] = 0x1f83d9ab;   state2[6] = 0x1f83d9ab;  state3[6] = 0x1f83d9ab;\
    state0[7] = 0x5be0cd19;  state1[7] = 0x5be0cd19;   state2[7] = 0x5be0cd19;  state3[7] = 0x5be0cd19;\
    \
    CORE_X4(state0,message[0],state1,message[1],state2,message[2],state3,message[3],num_blocks);\
\
    /** Padding message **/\
    for(i=0;i<rem_bytes;i++)\
    {\
        pad0[i] = message[0][64*num_blocks+i];\
        pad1[i] = message[1][64*num_blocks+i];\
        pad2[i] = message[2][64*num_blocks+i];\
        pad3[i] = message[3][64*num_blocks+i];\
    }\
    pad0[rem_bytes] = 0x80;\
    pad1[rem_bytes] = 0x80;\
    pad2[rem_bytes] = 0x80;\
    pad3[rem_bytes] = 0x80;\
    if (rem_bytes < 56)\
    {\
        for (i = rem_bytes + 1; i < 56; i++)\
        {\
            pad0[i] = 0x0;\
            pad1[i] = 0x0;\
            pad2[i] = 0x0;\
            pad3[i] = 0x0;\
        }\
        ((uint64_t*)pad0)[7] = (uint64_t)__builtin_bswap64(message_length*8);\
        ((uint64_t*)pad1)[7] = (uint64_t)__builtin_bswap64(message_length*8);\
        ((uint64_t*)pad2)[7] = (uint64_t)__builtin_bswap64(message_length*8);\
        ((uint64_t*)pad3)[7] = (uint64_t)__builtin_bswap64(message_length*8);\
        CORE_X4(state0,pad0,state1,pad1,state2,pad2,state3,pad3,1);\
    }\
    else\
    {\
        for (i = rem_bytes + 1; i < 120; i++)\
        {\
            pad0[i] = 0x0;\
            pad1[i] = 0x0;\
            pad2[i] = 0x0;\
            pad3[i] = 0x0;\
        }\
        ((uint64_t*)pad0)[15] = (uint64_t)__builtin_bswap64(message_length*8);\
        ((uint64_t*)pad1)[15] = (uint64_t)__builtin_bswap64(message_length*8);\
        ((uint64_t*)pad2)[15] = (uint64_t)__builtin_bswap64(message_length*8);\
        ((uint64_t*)pad3)[15] = (uint64_t)__builtin_bswap64(message_length*8);\
        CORE_X4(state0,pad0,state1,pad1,state2,pad2,state3,pad3,2);\
    }\
\
    for(i=0;i<SHA256_HASH_SIZE/4;i++)\
    {\
        ((uint32_t*)(digest[0]))[i] = (uint32_t)__builtin_bswap32(state0[i]);\
        ((uint32_t*)(digest[1]))[i] = (uint32_t)__builtin_bswap32(state1[i]);\
        ((uint32_t*)(digest[2]))[i] = (uint32_t)__builtin_bswap32(state2[i]);\
        ((uint32_t*)(digest[3]))[i] = (uint32_t)__builtin_bswap32(state3[i]);\
    }\
\
}

#define SHA_x8_CORE(CORE_X8)\
void sha256_x8##_##CORE_X8(\
unsigned char *message[8],\
long unsigned int message_length,\
unsigned char *digest[8])\
{\
    uint32_t i=0;\
    uint32_t num_blocks = message_length/64;\
    uint32_t rem_bytes = message_length%64;\
    ALIGN uint8_t pad0[128];\
    ALIGN uint8_t pad1[128];\
    ALIGN uint8_t pad2[128];\
    ALIGN uint8_t pad3[128];\
    ALIGN uint8_t pad4[128];\
    ALIGN uint8_t pad5[128];\
    ALIGN uint8_t pad6[128];\
    ALIGN uint8_t pad7[128];\
    ALIGN uint32_t state0[8];\
    ALIGN uint32_t state1[8];\
    ALIGN uint32_t state2[8];\
    ALIGN uint32_t state3[8];\
    ALIGN uint32_t state4[8];\
    ALIGN uint32_t state5[8];\
    ALIGN uint32_t state6[8];\
    ALIGN uint32_t state7[8];\
\
    /** Initializing state **/\
    state0[0] = 0x6a09e667;  state1[0] = 0x6a09e667;   state2[0] = 0x6a09e667;  state3[0] = 0x6a09e667;\
    state0[1] = 0xbb67ae85;  state1[1] = 0xbb67ae85;   state2[1] = 0xbb67ae85;  state3[1] = 0xbb67ae85;\
    state0[2] = 0x3c6ef372;  state1[2] = 0x3c6ef372;   state2[2] = 0x3c6ef372;  state3[2] = 0x3c6ef372;\
    state0[3] = 0xa54ff53a;  state1[3] = 0xa54ff53a;   state2[3] = 0xa54ff53a;  state3[3] = 0xa54ff53a;\
    state0[4] = 0x510e527f;  state1[4] = 0x510e527f;   state2[4] = 0x510e527f;  state3[4] = 0x510e527f;\
    state0[5] = 0x9b05688c;  state1[5] = 0x9b05688c;   state2[5] = 0x9b05688c;  state3[5] = 0x9b05688c;\
    state0[6] = 0x1f83d9ab;  state1[6] = 0x1f83d9ab;   state2[6] = 0x1f83d9ab;  state3[6] = 0x1f83d9ab;\
    state0[7] = 0x5be0cd19;  state1[7] = 0x5be0cd19;   state2[7] = 0x5be0cd19;  state3[7] = 0x5be0cd19;\
    state4[0] = 0x6a09e667;  state5[0] = 0x6a09e667;   state6[0] = 0x6a09e667;  state7[0] = 0x6a09e667;\
    state4[1] = 0xbb67ae85;  state5[1] = 0xbb67ae85;   state6[1] = 0xbb67ae85;  state7[1] = 0xbb67ae85;\
    state4[2] = 0x3c6ef372;  state5[2] = 0x3c6ef372;   state6[2] = 0x3c6ef372;  state7[2] = 0x3c6ef372;\
    state4[3] = 0xa54ff53a;  state5[3] = 0xa54ff53a;   state6[3] = 0xa54ff53a;  state7[3] = 0xa54ff53a;\
    state4[4] = 0x510e527f;  state5[4] = 0x510e527f;   state6[4] = 0x510e527f;  state7[4] = 0x510e527f;\
    state4[5] = 0x9b05688c;  state5[5] = 0x9b05688c;   state6[5] = 0x9b05688c;  state7[5] = 0x9b05688c;\
    state4[6] = 0x1f83d9ab;  state5[6] = 0x1f83d9ab;   state6[6] = 0x1f83d9ab;  state7[6] = 0x1f83d9ab;\
    state4[7] = 0x5be0cd19;  state5[7] = 0x5be0cd19;   state6[7] = 0x5be0cd19;  state7[7] = 0x5be0cd19;\
    \
    CORE_X8(state0,message[0],state1,message[1],state2,message[2],state3,message[3],state4,message[4],state5,message[5],state6,message[6],state7,message[7],num_blocks);\
\
    /** Padding message **/\
    for(i=0;i<rem_bytes;i++)\
    {\
        pad0[i] = message[0][64*num_blocks+i];\
        pad1[i] = message[1][64*num_blocks+i];\
        pad2[i] = message[2][64*num_blocks+i];\
        pad3[i] = message[3][64*num_blocks+i];\
        pad4[i] = message[4][64*num_blocks+i];\
        pad5[i] = message[5][64*num_blocks+i];\
        pad6[i] = message[6][64*num_blocks+i];\
        pad7[i] = message[7][64*num_blocks+i];\
    }\
    pad0[rem_bytes] = 0x80;\
    pad1[rem_bytes] = 0x80;\
    pad2[rem_bytes] = 0x80;\
    pad3[rem_bytes] = 0x80;\
    pad4[rem_bytes] = 0x80;\
    pad5[rem_bytes] = 0x80;\
    pad6[rem_bytes] = 0x80;\
    pad7[rem_bytes] = 0x80;\
    if (rem_bytes < 56)\
    {\
        for (i = rem_bytes + 1; i < 56; i++)\
        {\
            pad0[i] = 0x0;\
            pad1[i] = 0x0;\
            pad2[i] = 0x0;\
            pad3[i] = 0x0;\
            pad4[i] = 0x0;\
            pad5[i] = 0x0;\
            pad6[i] = 0x0;\
            pad7[i] = 0x0;\
        }\
        ((uint64_t*)pad0)[7] = (uint64_t)__builtin_bswap64(message_length*8);\
        ((uint64_t*)pad1)[7] = (uint64_t)__builtin_bswap64(message_length*8);\
        ((uint64_t*)pad2)[7] = (uint64_t)__builtin_bswap64(message_length*8);\
        ((uint64_t*)pad3)[7] = (uint64_t)__builtin_bswap64(message_length*8);\
        ((uint64_t*)pad4)[7] = (uint64_t)__builtin_bswap64(message_length*8);\
        ((uint64_t*)pad5)[7] = (uint64_t)__builtin_bswap64(message_length*8);\
        ((uint64_t*)pad6)[7] = (uint64_t)__builtin_bswap64(message_length*8);\
        ((uint64_t*)pad7)[7] = (uint64_t)__builtin_bswap64(message_length*8);\
        CORE_X8(state0,pad0,state1,pad1,state2,pad2,state3,pad3,state4,pad4,state5,pad5,state6,pad6,state7,pad7,1);\
    }\
    else\
    {\
        for (i = rem_bytes + 1; i < 120; i++)\
        {\
            pad0[i] = 0x0;\
            pad1[i] = 0x0;\
            pad2[i] = 0x0;\
            pad3[i] = 0x0;\
            pad4[i] = 0x0;\
            pad5[i] = 0x0;\
            pad6[i] = 0x0;\
            pad7[i] = 0x0;\
        }\
        ((uint64_t*)pad0)[15] = (uint64_t)__builtin_bswap64(message_length*8);\
        ((uint64_t*)pad1)[15] = (uint64_t)__builtin_bswap64(message_length*8);\
        ((uint64_t*)pad2)[15] = (uint64_t)__builtin_bswap64(message_length*8);\
        ((uint64_t*)pad3)[15] = (uint64_t)__builtin_bswap64(message_length*8);\
        ((uint64_t*)pad4)[15] = (uint64_t)__builtin_bswap64(message_length*8);\
        ((uint64_t*)pad5)[15] = (uint64_t)__builtin_bswap64(message_length*8);\
        ((uint64_t*)pad6)[15] = (uint64_t)__builtin_bswap64(message_length*8);\
        ((uint64_t*)pad7)[15] = (uint64_t)__builtin_bswap64(message_length*8);\
        CORE_X8(state0,pad0,state1,pad1,state2,pad2,state3,pad3,state4,pad4,state5,pad5,state6,pad6,state7,pad7,2);\
    }\
\
    for(i=0;i<SHA256_HASH_SIZE/4;i++)\
    {\
        ((uint32_t*)(digest[0]))[i] = (uint32_t)__builtin_bswap32(state0[i]);\
        ((uint32_t*)(digest[1]))[i] = (uint32_t)__builtin_bswap32(state1[i]);\
        ((uint32_t*)(digest[2]))[i] = (uint32_t)__builtin_bswap32(state2[i]);\
        ((uint32_t*)(digest[3]))[i] = (uint32_t)__builtin_bswap32(state3[i]);\
        ((uint32_t*)(digest[4]))[i] = (uint32_t)__builtin_bswap32(state4[i]);\
        ((uint32_t*)(digest[5]))[i] = (uint32_t)__builtin_bswap32(state5[i]);\
        ((uint32_t*)(digest[6]))[i] = (uint32_t)__builtin_bswap32(state6[i]);\
        ((uint32_t*)(digest[7]))[i] = (uint32_t)__builtin_bswap32(state7[i]);\
    }\
\
}


SHA_CORE_DEF(intel)
SHA_CORE_DEF(julio)
SHA_CORE_DEF(update_shani)

SHA_X2_CORE_DEF(update_shani_2x)
SHA_X4_CORE_DEF(update_shani_4x)
SHA_X8_CORE_DEF(update_shani_8x)


void sha256_multi(
        unsigned char **message,
        long unsigned int message_length,
        unsigned int num_messages,
        unsigned char **digest
);

void intel(uint32_t state[8], const uint8_t *msg, uint32_t num_blocks);
void julio(uint32_t state[8], const uint8_t *msg, uint32_t num_blocks);
void update_shani(uint32_t *state, const uint8_t *msg, uint32_t num_blocks);

void update_shani_2x(uint32_t *state_0,
                     const uint8_t *msg0,
                     uint32_t *state_1,
                     const uint8_t *msg1,
                     uint32_t num_blocks);
void update_shani_4x(uint32_t *state_0, const uint8_t *data_0, uint32_t *state_1, const uint8_t *data_1,
                     uint32_t *state_2, const uint8_t *data_2, uint32_t *state_3, const uint8_t *data_3,
                     uint32_t num_blocks);

void update_shani_8x(uint32_t *state_0,
                     const uint8_t *data_0,
                     uint32_t *state_1,
                     const uint8_t *data_1,
                     uint32_t *state_2,
                     const uint8_t *data_2,
                     uint32_t *state_3,
                     const uint8_t *data_3,
                     uint32_t *state_4,
                     const uint8_t *data_4,
                     uint32_t *state_5,
                     const uint8_t *data_5,
                     uint32_t *state_6,
                     const uint8_t *data_6,
                     uint32_t *state_7,
                     const uint8_t *data_7,
                     uint32_t num_blocks);

void multi(uint32_t **state_0,uint8_t **message, unsigned int num_messages,uint32_t num_blocks);


#ifdef __cplusplus
}
#endif

#endif //SHA_NI_SHA_H
