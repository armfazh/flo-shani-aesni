#include <stdio.h>
#include <aesni.h>
#include <prng/flo-random.h>
#include <cpuid/flo-cpuid.h>
#include "clocks.h"


struct aes_timings {
  uint64_t size;
  uint64_t _1x;
  uint64_t _2x;
  uint64_t _4x;
  uint64_t _6x;
  uint64_t _8x;
};

#define MAX_SIZE_BITS 13

#define BENCH_SIZE_1W_CBC(FUNC, K)                    \
do {                                                  \
  long BENCH_TIMES = 0, CYCLES = 0;                   \
  const unsigned long MAX_SIZE = 1 << MAX_SIZE_BITS;  \
  unsigned long it = 0;                               \
  unsigned char *message = (unsigned char *) _mm_malloc(MAX_SIZE + 1, ALIGN_BYTES); \
  unsigned char *cipher = (unsigned char *) _mm_malloc(MAX_SIZE + 1, ALIGN_BYTES); \
  KeySchedule round_keys;                             \
  Key key, ivec;                                      \
  random_bytes(key, sizeof(key));                     \
  random_bytes(ivec, sizeof(ivec));                   \
  AES_128_Key_Expansion(key, round_keys);             \
  for (it = 0; it < MAX_SIZE_BITS; it++) {            \
    int message_size = 1 << it;                       \
    BENCH_TIMES = 512 - it * 20;                      \
    CLOCKS(FUNC(cipher, message, ivec, message_size, round_keys, AES_128)); \
    table[it].size = message_size;                    \
    table[it]._ ## K ## x = CYCLES;                   \
  }                                                   \
  _mm_free(message);                                  \
  _mm_free(cipher);                                   \
} while(0)

#define BENCH_SIZE_1W_CTR(FUNC, K)                    \
do {                                                  \
  long BENCH_TIMES = 0, CYCLES = 0;                   \
  const unsigned long MAX_SIZE = 1 << MAX_SIZE_BITS;  \
  unsigned long it = 0;                               \
  unsigned char *message = (unsigned char *) _mm_malloc(MAX_SIZE + 1, ALIGN_BYTES); \
  unsigned char *cipher = (unsigned char *) _mm_malloc(MAX_SIZE + 1, ALIGN_BYTES); \
  KeySchedule round_keys;                             \
  Key key, ivec, nonce;                               \
  random_bytes(key, sizeof(key));                     \
  random_bytes(ivec, sizeof(ivec));                   \
  random_bytes(nonce, sizeof(nonce));                 \
  AES_128_Key_Expansion(key, round_keys);             \
  for (it = 0; it < MAX_SIZE_BITS; it++) {            \
    int message_size = 1 << it;                       \
    BENCH_TIMES = 512 - it * 20;                      \
    CLOCKS(FUNC(cipher, message, ivec, nonce, message_size, round_keys, AES_128)); \
    table[it].size = message_size;                    \
    table[it]._ ## K ## x = CYCLES;                   \
  }                                                   \
  _mm_free(message);                                  \
  _mm_free(cipher);                                   \
} while (0)

#define BENCH_CBC_MULTI(FUNC, MSG_LEN, N)      \
do{                                            \
    int i_multi=0;                             \
    uint8_t *message[N];                       \
    uint8_t *cipher[N];                        \
    uint8_t *ivec[N];                          \
    Key key;                                   \
    KeySchedule round_keys;                    \
    random_bytes(key,sizeof(key));             \
    AES_128_Key_Expansion(key,round_keys);     \
    for(i_multi=0;i_multi<N;i_multi++) {       \
        message[i_multi] = (uint8_t*)_mm_malloc((MSG_LEN)+1,ALIGN_BYTES); \
        cipher[i_multi] = (uint8_t*)_mm_malloc((MSG_LEN)+1,ALIGN_BYTES);  \
        ivec[i_multi] = (uint8_t*)_mm_malloc(16,ALIGN_BYTES);             \
        random_bytes(ivec[i_multi],16);  \
        random_bytes(message[i_multi],MSG_LEN);  \
    }                                            \
    CLOCKS(FUNC((const unsigned char**)cipher,message,ivec,MSG_LEN,round_keys,AES_128)); \
    table[it].size = message_size;             \
    table[it]._ ## N ## x = CYCLES;            \
    for(i_multi=0;i_multi<N;i_multi++) {       \
        _mm_free(message[i_multi]);            \
        _mm_free(cipher[i_multi]);             \
        _mm_free(ivec[i_multi]);               \
    }                                          \
}while(0)

#define BENCH_SIZE_NW(FUNC, N)                 \
do{                                            \
    long BENCH_TIMES = 0, CYCLES = 0;          \
    unsigned long it=0;                        \
    for(it=0;it<MAX_SIZE_BITS;it++) {          \
        int message_size = 1<<it;              \
        BENCH_TIMES = 512-it*20;               \
        BENCH_CBC_MULTI(FUNC,message_size,N);  \
    }                                          \
}while(0)

void print_multiple_message(struct aes_timings *table, int items) {
  int i;
  printf("            Cycles per byte \n");
  printf("╔═════════╦═════════╦═════════╦═════════╦═════════╦═════════╗\n");
  printf("║  bytes  ║   1x    ║   2x    ║   4x    ║   6x    ║   8x    ║\n");
  printf("╠═════════╩═════════╩═════════╩═════════╩═════════╩═════════╣\n");
  for (i = 0; i < items; i++) {
    printf("║%9ld║%9.2f║%9.2f║%9.2f║%9.2f║%9.2f║\n",
           table[i].size,
           table[i]._1x / (double) table[i].size / 1.0,
           table[i]._2x / (double) table[i].size / 2.0,
           table[i]._4x / (double) table[i].size / 4.0,
           table[i]._6x / (double) table[i].size / 6.0,
           table[i]._8x / (double) table[i].size / 8.0);
  }
  printf("╚═════════╩═════════╩═════════╩═════════╩═════════╩═════════╝\n");
}

void print_pipelined(struct aes_timings *table, int items) {
  int i;
  printf("            Cycles per byte \n");
  printf("╔═════════╦═════════╦═════════╦═════════╦═════════╗\n");
  printf("║  bytes  ║   1x    ║   2x    ║   4x    ║   8x    ║\n");
  printf("╠═════════╩═════════╩═════════╩═════════╩═════════╣\n");
  for (i = 0; i < items; i++) {
    printf("║%9ld║%9.2f║%9.2f║%9.2f║%9.2f║\n",
           table[i].size,
           table[i]._1x / (double) table[i].size,
           table[i]._2x / (double) table[i].size,
           table[i]._4x / (double) table[i].size,
           table[i]._8x / (double) table[i].size);
  }
  printf("╚═════════╩═════════╩═════════╩═════════╩═════════╝\n");
}

void bench_multiple_message_CBCenc() {
  struct aes_timings table[MAX_SIZE_BITS] = {{0, 0, 0, 0, 0, 0}};

  printf("Multiple-message CBC-Encryption:\n");
  printf("Running: CBC Enc \n");
  BENCH_SIZE_1W_CBC(AES_CBC_encrypt, 1);
  printf("Running: CBC Enc 2w\n");
  BENCH_SIZE_NW(AES_CBC_encrypt_2w, 2);
  printf("Running: CBC Enc 4w\n");
  BENCH_SIZE_NW(AES_CBC_encrypt_4w, 4);
  printf("Running: CBC Enc 6w\n");
  BENCH_SIZE_NW(AES_CBC_encrypt_6w, 6);
  printf("Running: CBC Enc 8w\n");
  BENCH_SIZE_NW(AES_CBC_encrypt_8w, 8);
  print_multiple_message(table, MAX_SIZE_BITS);
}

void bench_pipeline_CBC_dec() {
  struct aes_timings table[MAX_SIZE_BITS] = {{0, 0, 0, 0, 0, 0}};

  printf("Pipelined CBC Decryption:\n");
  printf("Running: CBC Dec \n");
  BENCH_SIZE_1W_CBC(AES_CBC_decrypt, 1);
  printf("Running: CBC Dec Pipe2\n");
  BENCH_SIZE_1W_CBC(AES_CBC_decrypt_pipe2, 2);
  printf("Running: CBC Dec Pipe4\n");
  BENCH_SIZE_1W_CBC(AES_CBC_decrypt_pipe4, 4);
  printf("Running: CBC Dec Pipe8\n");
  BENCH_SIZE_1W_CBC(AES_CBC_decrypt_pipe8, 8);
  print_pipelined(table, MAX_SIZE_BITS);
}

void bench_pipeline_CTR_enc() {
  struct aes_timings table[MAX_SIZE_BITS] = {{0, 0, 0, 0, 0, 0}};
  printf("Pipelined CTR Encryption:\n");
  printf("Running: CTR Enc \n");
  BENCH_SIZE_1W_CTR(AES_CTR_encrypt, 1);
  printf("Running: CTR Enc Pipe2 \n");
  BENCH_SIZE_1W_CTR(AES_CTR_encrypt_pipe2, 2);
  printf("Running: CTR Enc Pipe4 \n");
  BENCH_SIZE_1W_CTR(AES_CTR_encrypt_pipe4, 4);
  printf("Running: CTR Enc Pipe8 \n");
  BENCH_SIZE_1W_CTR(AES_CTR_encrypt_pipe8, 8);
  print_pipelined(table, MAX_SIZE_BITS);
}
void bench_pipeline() {
  bench_pipeline_CBC_dec();
  bench_pipeline_CTR_enc();
}

int main() {
  machine_info();
  openssl_version();
  printf("== Start of Benchmark ===\n");
  bench_multiple_message_CBCenc();
  bench_pipeline();
  printf("== End of Benchmark =====\n");
  return 0;
}
