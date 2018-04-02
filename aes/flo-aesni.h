/*
 * The MIT License (MIT)
 * Copyright (c) 2018 Armando Faz
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
 * DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
 * OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE
 * OR OTHER DEALINGS IN THE SOFTWARE.
 */
#ifndef PROJECT_AESNI_H
#define PROJECT_AESNI_H

#ifdef __cplusplus
extern "C"{
#endif

#include <stdint.h>
#include <immintrin.h>

enum NRounds {
  AES_128 = 10,
  AES_192 = 12,
  AES_256 = 14
};

#ifndef ALIGN_BYTES
#define ALIGN_BYTES 64
#endif

#ifndef ALIGN
#ifdef __INTEL_COMPILER
#define ALIGN __declspec(align(ALIGN_BYTES))
#else
#define ALIGN __attribute__ ((aligned (ALIGN_BYTES)))
#endif
#endif

typedef uint8_t KeySchedule[(128/8)*11];
typedef uint8_t Key[(128/8)];


void AES_128_Key_Expansion (const unsigned char *userkey,
                            unsigned char *key);
void AES_CBC_encrypt(const unsigned char *in,
                     unsigned char *out,
                     unsigned char ivec[16],
                     unsigned long length,
                     unsigned char *key,
                     const int number_of_rounds);

void AES_CBC_decrypt(const unsigned char *in,
                     unsigned char *out,
                     unsigned char ivec[16],
                     unsigned long length,
                     unsigned char *key,
                     const int number_of_rounds);

void AES_CTR_encrypt (const unsigned char *in,
                      unsigned char *out,
                      const unsigned char ivec[8],
                      const unsigned char nonce[4],
                      unsigned long length,
                      const unsigned char *key,
                      const int number_of_rounds);

void AES_CTR_encrypt_pipe2(const unsigned char *in,
                      unsigned char *out,
                      const unsigned char ivec[8],
                      const unsigned char nonce[4],
                      unsigned long length,
                      const unsigned char *key,
                      const int number_of_rounds);

void AES_CTR_encrypt_pipe4(const unsigned char *in,
                      unsigned char *out,
                      const unsigned char ivec[8],
                      const unsigned char nonce[4],
                      unsigned long length,
                      const unsigned char *key,
                      const int number_of_rounds);

void AES_CTR_encrypt_pipe8(const unsigned char *in,
                      unsigned char *out,
                      const unsigned char ivec[8],
                      const unsigned char nonce[4],
                      unsigned long length,
                      const unsigned char *key,
                      const int number_of_rounds);

void AES_CBC_decrypt_pipe2(const unsigned char *in,
                           unsigned char *out,
                           unsigned char *ivec,
                           unsigned long length,
                           unsigned char *key_schedule,
                           const unsigned int nr);

void AES_CBC_decrypt_pipe4(const unsigned char *in,
                           unsigned char *out,
                           unsigned char *ivec,
                           unsigned long length,
                           unsigned char *key_schedule,
                           const unsigned int nr);

void AES_CBC_decrypt_pipe8(const unsigned char *in,
                           unsigned char *out,
                           unsigned char ivec[16],
                           unsigned long length,
                           unsigned char *key_schedule,
                           const unsigned int nr);

void AES_CBC_encrypt_2w(const unsigned char **in,
                   unsigned char **out,
                   unsigned char **ivec,
                   unsigned long length,
                   const unsigned char *key,
                   const int nr);

void AES_CBC_encrypt_4w(const unsigned char **in,
                   unsigned char **out,
                   unsigned char **ivec,
                   unsigned long length,
                   const unsigned char *key,
                   const int nr);

void AES_CBC_encrypt_6w(const unsigned char **in,
                   unsigned char **out,
                   unsigned char **ivec,
                   unsigned long length,
                   const unsigned char *key,
                   const int nr);

void AES_CBC_encrypt_8w(const unsigned char **in,
                   unsigned char **out,
                   unsigned char **ivec,
                   unsigned long length,
                   const unsigned char *key,
                   const int nr);

void AES_CBC_decrypt_2w(const unsigned char *in[2],
                   unsigned char *out[2],
                   unsigned char *ivec[2],
                   unsigned long length,
                   unsigned char *key,
                   const int number_of_rounds);

void AES_CBC_decrypt_4w(const unsigned char *in[4],
                   unsigned char *out[4],
                   unsigned char *ivec[4],
                   unsigned long length,
                   unsigned char *key,
                   const int number_of_rounds);

void AES_CBC_decrypt_8w(const unsigned char *in[8],
                   unsigned char *out[8],
                   unsigned char *ivec[8],
                   unsigned long length,
                   unsigned char *key,
                   const int number_of_rounds);

#ifdef __cplusplus
}
#endif

#endif //PROJECT_AESNI_H
