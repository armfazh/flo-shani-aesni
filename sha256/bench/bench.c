/**
 * Copyright (c) 2017 Armando Faz <armfazh@ic.unicamp.br>.
 * Institute of Computing.
 * University of Campinas, Brazil.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation, version 2 or greater.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
*/
#include <stdio.h>
#include <stdint.h>
#include <shani.h>
#include <openssl/sha.h>
#include "clocks.h"

#define MAX_SIZE_BITS 6

struct seqTimes{
  uint64_t size;
  uint64_t openssl;
  uint64_t shani;
};

#define BENCH_SHA_MULTI(FUNC, MSG_LEN, NUM)       \
do{                                               \
    int i_multi=0;                                \
    uint8_t *message[NUM];                        \
    uint8_t *digest[NUM];                         \
    for(i_multi=0;i_multi<NUM;i_multi++)          \
    {                                             \
        message[i_multi] = (uint8_t*)_mm_malloc((MSG_LEN)+1,ALIGN_BYTES);  \
        digest[i_multi] = (uint8_t*)_mm_malloc(32,ALIGN_BYTES);  \
        random_bytes(message[i_multi],MSG_LEN);   \
    }                                             \
    CLOCKS("",FUNC(message,MSG_LEN,digest));      \
    for(i_multi=0;i_multi<NUM;i_multi++)          \
    {                                             \
        _mm_free(message[i_multi]);               \
        _mm_free(digest[i_multi]);                \
    }                                             \
}while(0)

#define BENCH_SIZE_NW(FUNC, N)                 \
do{                                            \
    long BENCH = 0;                            \
    const unsigned long MAX_SIZE_BITS=21;      \
    unsigned long it=0;                        \
    for(it=0;it<MAX_SIZE_BITS;it++)            \
    {                                          \
        int message_size = 1<<it;              \
        BENCH = 512-it*20;                     \
        printf("%d",message_size);             \
        BENCH_SHA_MULTI(FUNC,message_size,N);  \
    }                                          \
}while(0)

void mb_avx2() {
  printf("Multibuffer SEQ/AVX/AVX2/SHANI \n");

//    BENCH_SIZE_1W(SHA256);
//  BENCH_SIZE_1W(crypto_hash_sphlib);
//  BENCH_SIZE_NW(ntru_sha256_4way_simd, 4);
//  BENCH_SIZE_NW(ntru_sha256_8way_simd, 8);
  // BENCH_SIZE_NW(sha256_4w_avx,4);
  //BENCH_SIZE_NW(sha256_8w_avx2,8);
//  BENCH_SIZE_1W(sha256_intel);
//  BENCH_SIZE_NW(sha256_x2_arm_x2, 2);
//  BENCH_SIZE_NW(sha256_x4_arm_x4, 4);
//  BENCH_SIZE_NW(sha256_x8_arm_x8, 8);
}

void print_table(struct seqTimes * table, int items)
{
  int i;
  printf("    SHA256: OpenSSL vs SHANI             \n");
  printf("╔════════╦══════════╦══════════╦══════════╗\n");
  printf("║ bytes  ║ OpenSSL  ║  SHANI   ║ Speedup  ║\n");
  printf("╠════════╩══════════╩══════════╩══════════╣\n");
  for(i=0;i<items;i++) {
    printf("║ %6ld ║ %8ld ║ %8ld ║ %8.2f ║\n",
           table[i].size,table[i].openssl,
           table[i].shani,1-table[i].openssl/(double)table[i].shani);
  }
  printf("╚════════╩══════════╩══════════╩══════════╝\n");
}

#define BENCH_SIZE_1W(FUNC,IMPL)       \
  do {                                 \
    long BENCH_TIMES = 0, CYCLES = 0;  \
    for(it=0;it<MAX_SIZE_BITS;it++) {  \
      int message_size = 1<<it;        \
      BENCH_TIMES = 512-it*20;         \
      CLOCKS(FUNC(message,message_size,digest));\
      table[it].size = message_size;   \
      table[it].IMPL = CYCLES;         \
    }                                  \
  }while(0)

void bench_1w(){
  struct seqTimes table[MAX_SIZE_BITS];
  unsigned long it=0;
  unsigned long MAX_SIZE=1<<MAX_SIZE_BITS;
  unsigned char * message = (unsigned char*)_mm_malloc(MAX_SIZE,ALIGN_BYTES);
  unsigned char digest[32];

  BENCH_SIZE_1W(SHA256,openssl);
  BENCH_SIZE_1W(sha256_update_shani,shani);
  print_table(table,MAX_SIZE_BITS);
  _mm_free(message);
}
#undef BENCH_SIZE_1W

int main(void) {

  printf("== Start of Benchmark ===\n");
  bench_1w();
  mb_avx2();
  printf("== End of Benchmark =====\n");
  return 0;
}
