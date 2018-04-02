/*The optimized implementation of AEGIS-128*/

#include <aegis.h>
#include <string.h>

#define LOAD(X)         _mm_load_si128((__m128i*) X)
#define STORE(X, Y)      _mm_store_si128((__m128i*) X, Y)
#define AES(X, Y)        _mm_aesenc_si128(X,Y)
#define XOR(X, Y)        _mm_xor_si128(X,Y)

// The initialization state of AEGIS
static void aegis128_initialization_opt(const unsigned char *key, const unsigned char *iv, __m128i *state) {
  int i;
  const ALIGN __m128i AEGIS_INIT_0 = _mm_set_epi8(0xdd, 0x28, 0xb5, 0x73, 0x42, 0x31, 0x11, 0x20,
                                                  0xf1, 0x2f, 0xc2, 0x6d, 0x55, 0x18, 0x3d, 0xdb);
  const ALIGN __m128i AEGIS_INIT_1 = _mm_set_epi8(0x62, 0x79, 0xe9, 0x90, 0x59, 0x37, 0x22, 0x15,
                                                  0x0d, 0x08, 0x05, 0x03, 0x02, 0x01, 0x01, 0x00);
  __m128i tmp;
  __m128i keytmp = LOAD(key);
  __m128i ivtmp = LOAD(iv);

  state[0] = ivtmp;
  state[1] = AEGIS_INIT_0;
  state[2] = AEGIS_INIT_1;
  state[3] = XOR(keytmp, AEGIS_INIT_1);
  state[4] = XOR(keytmp, AEGIS_INIT_0);
  state[0] = XOR(state[0], keytmp);

  keytmp = XOR(keytmp, ivtmp);
  for (i = 0; i < 10; i++) {
    //state update function
    tmp = state[4];
    state[4] = AES(state[3], state[4]);
    state[3] = AES(state[2], state[3]);
    state[2] = AES(state[1], state[2]);
    state[1] = AES(state[0], state[1]);
    state[0] = AES(tmp, state[0]);

    //xor msg with state[0]
    keytmp = XOR(keytmp, ivtmp);
    state[0] = XOR(state[0], keytmp);
  }
}

//the finalization state of AEGIS
static void aegis128_tag_generation_opt(unsigned long long msglen, unsigned long long adlen, unsigned char maclen,
                                        unsigned char *mac, __m128i *state) {
  int i;

  __m128i tmp;
  __m128i msgtmp;
  unsigned char t[16];
  unsigned char tt[16];

  for (i = 0; i < 16; i++) tt[i] = 0;

  uint64_t *ptt = 0;
  ptt = (uint64_t *) (tt + 0);
  *ptt = adlen << 3;
  ptt = (uint64_t *) (tt + 8);
  *ptt = msglen << 3;

  msgtmp = LOAD((__m128i *) tt);
  msgtmp = XOR(msgtmp, state[3]);

  for (i = 0; i < 7; i++) {
    //state update function
    tmp = state[4];
    state[4] = AES(state[3], state[4]);
    state[3] = AES(state[2], state[3]);
    state[2] = AES(state[1], state[2]);
    state[1] = AES(state[0], state[1]);
    state[0] = AES(tmp, state[0]);

    //xor "msg" with state[0]
    state[0] = XOR(state[0], msgtmp);
  }

  state[4] = XOR(state[4], state[3]);
  state[4] = XOR(state[4], state[2]);
  state[4] = XOR(state[4], state[1]);
  state[4] = XOR(state[4], state[0]);

  STORE(t, state[4]);
  //in this program, the mac length is assumed to be multiple of bytes
  memcpy(mac, t, maclen);
}

#define aegis128_enc_aut_step_opt(M, C, S)      \
    __asm__ __volatile__(                    \
        "vpand %2, %3, %%xmm0         \n\t"  \
        "vpxor (%5), %1, %%xmm1       \n\t"  \
        "vpxor %%xmm1, %%xmm0, %%xmm0 \n\t"  \
        "vpxor %4, %%xmm0, %%xmm0     \n\t"  \
        "vmovdqa %4, %%xmm1           \n\t"  \
        "vmovdqa %%xmm0, (%6)         \n\t"  \
        "vmovdqa %0, %%xmm0           \n\t"  \
        "vaesenc %4, %3, %4           \n\t"  \
        "vaesenc %3, %2, %3           \n\t"  \
        "vaesenc %2, %1, %2           \n\t"  \
        "vaesenc %1, %0, %1           \n\t"  \
        "vaesenc (%5), %%xmm1, %0     \n\t"  \
        "vpxor   %%xmm0, %0, %0       \n\t"  \
    : "+x"(S[0]),"+x"(S[1]),"+x"(S[2]),"+x"(S[3]),"+x"(S[4])  \
    : "r"(M), "r"(C)                         \
    : "memory", "%xmm0", "%xmm1"             \
    )

#define Enc(NN, S1, S2, S3, S4) \
    "vmovdqa " #S2 ", %%xmm1 \n\t" \
    "vpand   " #S3 ", %%xmm1, %%xmm1 \n\t"  \
    "vpxor   " #S1 ", %%xmm1, %%xmm1 \n\t"  \
    "vpxor   " #S4 ", %%xmm1, %%xmm1 \n\t"  \
    "vpxor   " #NN "(%5), %%xmm1, %%xmm1 \n\t"  \
    "vmovdqa %%xmm1, " #NN "(%6)   \n\t"

//encrypt a message
int crypto_aead_encrypt_opt(
    unsigned char *c, unsigned long long *clen,
    unsigned char *m, unsigned long long mlen,
    unsigned char *ad, unsigned long long adlen,
    unsigned char *npub,
    unsigned char *k) {
  unsigned long long i;
  ALIGN unsigned char plaintextblock[16];
  ALIGN unsigned char ciphertextblock[16];
  ALIGN unsigned char mac[16];
  ALIGN __m128i aegis128_state[5];

  //initialization stage
  aegis128_initialization_opt(k, npub, aegis128_state);

  //process the associated data
  for (i = 0; (i + 16) <= adlen; i += 16) {
    aegis128_enc_aut_step_opt(ad + i, ciphertextblock, aegis128_state);
  }

  //deal with the partial block of associated data
  //in this program, we assume that the message length is multiple of bytes.
  if ((adlen & 0xf) != 0) {
    memset(plaintextblock, 0, 16);
    memcpy(plaintextblock, ad + i, adlen & 0xf);
    aegis128_enc_aut_step_opt(plaintextblock, ciphertextblock, aegis128_state);
  }

  //encrypt the plaintext
  /*unsigned long long mlen_div4 = mlen/4;
  for (i = 0; (i+16*4) <= mlen_div4*4; i += 16*4)
  {
      aegis128_enc_aut_step4_1x(m + i, c + i, aegis128_state);
  } */
  for (i = 0; (i + 16) <= mlen; i += 16) {
    aegis128_enc_aut_step_opt(m + i, c + i, aegis128_state);
  }

  // Deal with the partial block
  // In this program, we assume that the message length is multiple of bytes.
  if ((mlen & 0xf) != 0) {
    memset(plaintextblock, 0, 16);
    memcpy(plaintextblock, m + i, mlen & 0xf);
    aegis128_enc_aut_step_opt(plaintextblock, ciphertextblock, aegis128_state);
    memcpy(c + i, ciphertextblock, mlen & 0xf);
  }
  //finalization stage, we assume that the tag length is multiple of bytes
  aegis128_tag_generation_opt(mlen, adlen, 16, mac, aegis128_state);

  *clen = mlen + 16;
  memcpy(c + mlen, mac, 16);
  return 0;
}
