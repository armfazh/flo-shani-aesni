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
#include <shani.h>
#include <openssl/sha.h>
#include <prng/flo-random.h>
#include <cpuid/flo-cpuid.h>
#include "clocks.h"

#define MAX_SIZE_BITS 7

struct seqTimings {
  uint64_t size;
  uint64_t openssl_shani;
  uint64_t openssl_native;
  uint64_t shani;
};

struct parallelTimings {
  uint64_t size;
  uint64_t _1x;
  uint64_t _2x;
  uint64_t _4x;
  uint64_t _8x;
};

void print_tableParallelSpeedup(struct parallelTimings *table, int items) {
  int i;
  printf("          Multiple-message Hashing \n");
  printf("╔═════════╦═════════╦═════════╦═════════╦═════════╗\n");
  printf("║  bytes  ║   1x    ║   2x    ║   4x    ║   8x    ║\n");
  printf("╠═════════╩═════════╩═════════╩═════════╩═════════╣\n");
  for (i = 0; i < items; i++) {
    printf("║%9ld║%9.2f║%9.2f║%9.2f║%9.2f║\n",
           table[i].size,
           1.0*table[i]._1x/(double)table[i]._1x,
           2.0*table[i]._1x/(double)table[i]._2x,
           4.0*table[i]._1x/(double)table[i]._4x,
           8.0*table[i]._1x/(double)table[i]._8x);
  }
  printf("╚═════════╩═════════╩═════════╩═════════╩═════════╝\n");
}

void print_tableParallelCPB(struct parallelTimings *table, int items) {
  int i;
  printf("          Multiple-message Hashing \n");
  printf("╔═════════╦═════════╦═════════╦═════════╦═════════╗\n");
  printf("║  bytes  ║   1x    ║   2x    ║   4x    ║   8x    ║\n");
  printf("╠═════════╩═════════╩═════════╩═════════╩═════════╣\n");
  for (i = 0; i < items; i++) {
    printf("║%9ld║%9.2f║%9.2f║%9.2f║%9.2f║\n",
           table[i].size,
           table[i]._1x/(double)table[i].size/1.0,
           table[i]._2x/(double)table[i].size/2.0,
           table[i]._4x/(double)table[i].size/4.0,
           table[i]._8x/(double)table[i].size/8.0);
  }
  printf("╚═════════╩═════════╩═════════╩═════════╩═════════╝\n");
}

#define BENCH_SIZE_1W(FUNC, IMPL)      \
  do {                                 \
    unsigned long it = 0;              \
    long BENCH_TIMES = 0, CYCLES = 0;  \
    for(it=0;it<MAX_SIZE_BITS;it++) {  \
      int message_size = 1<<it;        \
      BENCH_TIMES = 512-it*20;         \
      CLOCKS(FUNC(message,message_size,digest));\
      table[it].size = message_size;   \
      table[it].IMPL = CYCLES;         \
    }                                  \
  }while(0)


#define BENCH_SIZE_NW(FUNC, N)                   \
do{                                              \
    long BENCH_TIMES = 0, CYCLES = 0;            \
    unsigned long it=0;                          \
    unsigned long MAX_SIZE = 1 << MAX_SIZE_BITS; \
    uint8_t *message[N];                       \
    uint8_t *digest[N];                        \
    for(it=0;it<N;it++) {                        \
        message[it] = (uint8_t*)_mm_malloc(MAX_SIZE,ALIGN_BYTES);  \
        digest[it] = (uint8_t*)_mm_malloc(32,ALIGN_BYTES);  \
        random_bytes(message[it],MAX_SIZE);  \
    }                                        \
    for(it=0;it<MAX_SIZE_BITS;it++) {        \
        int message_size = 1<<it;            \
        BENCH_TIMES = 512-it*20;             \
        CLOCKS(FUNC(message,message_size,digest));  \
        table[it].size = message_size;   \
        table[it]._ ## N ## x = CYCLES;  \
    }                                    \
    for(it=0;it<N;it++) {                \
        _mm_free(message[it]);           \
        _mm_free(digest[it]);            \
    }                                    \
}while(0)

void bench_Nw() {
  struct parallelTimings table[MAX_SIZE_BITS] = {0};
  unsigned char digest[32];
  unsigned long MAX_SIZE = 1 << MAX_SIZE_BITS;
  unsigned char *message = (unsigned char *) _mm_malloc(MAX_SIZE, ALIGN_BYTES);

  if(hasSHANI()) {
    printf("Running 1x:\n");
    BENCH_SIZE_1W(sha256_update_shani, _1x);
    printf("Running 2x:\n");
    BENCH_SIZE_NW(sha256_x2_update_shani_2x, 2);
    printf("Running 4x:\n");
    BENCH_SIZE_NW(sha256_x4_update_shani_4x, 4);
    printf("Running 8x:\n");
    BENCH_SIZE_NW(sha256_x8_update_shani_8x, 8);
    print_tableParallelCPB(table, MAX_SIZE_BITS);
    print_tableParallelSpeedup(table, MAX_SIZE_BITS);
  }
  else{
    printf("This processor does not supports SHANI set.\n");
  }
}

void print_tableSeq(struct seqTimings *table, int items) {
  int i;
  printf("    SHA256: OpenSSL vs SHANI \n");
  printf("    Cycles per byte \n");
  printf("╔═════════╦═════════╦═════════╦═════════╦═════════╗\n");
  printf("║  Size   ║ OpenSSL ║ OpenSSL ║This work║ Speedup ║\n");
  printf("║ (bytes) ║  (x64)  ║ (shani) ║ (shani) ║x64/shani║\n");
  printf("╠═════════╩═════════╩═════════╩═════════╩═════════╣\n");
  for (i = 0; i < items; i++) {
    printf("║%9ld║%9.2f║%9.2f║%9.2f║%9.2f║\n", table[i].size,
           table[i].openssl_native/(double)table[i].size,
           table[i].openssl_shani/(double)table[i].size,
           table[i].shani/(double)table[i].size,
           table[i].openssl_native / (double) table[i].shani);
  }
  printf("╚═════════╩═════════╩═════════╩═════════╩═════════╝\n");
}

void print_tableOneSeq(struct seqTimings *table, int items) {
  int i;
  printf("   SHA256: OpenSSL \n");
  printf("   Cycles per byte \n");
  printf("╔═════════╦═════════╗\n");
  printf("║  Size   ║ OpenSSL ║\n");
  printf("║ (bytes) ║  (x64)  ║\n");
  printf("╠═════════╩═════════╣\n");
  for (i = 0; i < items; i++) {
    printf("║%9ld║%9.2f║\n", table[i].size,
           table[i].openssl_native/(double)table[i].size);
  }
  printf("╚═════════╩═════════╝\n");
}

void bench_1w() {
  struct seqTimings table[MAX_SIZE_BITS] = {0};
  unsigned long MAX_SIZE = 1 << MAX_SIZE_BITS;
  unsigned char *message = (unsigned char *) _mm_malloc(MAX_SIZE, ALIGN_BYTES);
  unsigned char digest[32];

  if(hasSHANI()) {
    printf("Running OpenSSL (shani):\n");
    BENCH_SIZE_1W(SHA256, openssl_shani);

    disableSHANI();
    printf("Running OpenSSL (native):\n");
    BENCH_SIZE_1W(SHA256, openssl_native);

    printf("Running shani:\n");
    BENCH_SIZE_1W(sha256_update_shani, shani);
    print_tableSeq(table, MAX_SIZE_BITS);
  }
  else{
    printf("Running OpenSSL (native):\n");
    BENCH_SIZE_1W(SHA256, openssl_native);
    printf("This processor does not supports SHANI set.\n");
    printf("Showing timings of OpenSSL only.\n");
    print_tableOneSeq(table, MAX_SIZE_BITS);
  }
  _mm_free(message);
}

int main(void) {
  machine_info();
  openssl_version();
  printf("== Start of Benchmark ===\n");
  bench_1w();
  bench_Nw();
  printf("== End of Benchmark =====\n");
  return 0;
}
