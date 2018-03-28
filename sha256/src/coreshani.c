#include "shani.h"

/*** New compact version ***/
#define LOAD(X)     _mm_load_si128((__m128i const *)X)
#define LOAD_U(X)   _mm_loadu_si128((__m128i const *)X)
#define STORE(X, Y)  _mm_store_si128((__m128i *)X,Y)
#define ALIGNR(X, Y) _mm_alignr_epi8(X,Y,4)
#define ADD(X, Y)    _mm_add_epi32(X,Y)
#define HIGH(X)     _mm_srli_si128(X,8)
//#define HIGH(X)     _mm_shuffle_epi32(X, 0x0E)
#define SHA(X, Y, Z)  _mm_sha256rnds2_epu32(X,Y,Z)
#define MSG1(X, Y)   _mm_sha256msg1_epu32(X,Y)
#define MSG2(X, Y)   _mm_sha256msg2_epu32(X,Y)
#define CVLO(X, Y, Z) _mm_shuffle_epi32(_mm_unpacklo_epi64(X,Y),Z)
#define CVHI(X, Y, Z) _mm_shuffle_epi32(_mm_unpackhi_epi64(X,Y),Z)
#define L2B(X)      _mm_shuffle_epi8(X,MASK)

static const ALIGN uint64_t CONST_K[32] = {
    0x71374491428A2F98, 0xE9B5DBA5B5C0FBCF,
    0x59F111F13956C25B, 0xAB1C5ED5923F82A4,
    0x12835B01D807AA98, 0x550C7DC3243185BE,
    0x80DEB1FE72BE5D74, 0xC19BF1749BDC06A7,
    0xEFBE4786E49B69C1, 0x240CA1CC0FC19DC6,
    0x4A7484AA2DE92C6F, 0x76F988DA5CB0A9DC,
    0xA831C66D983E5152, 0xBF597FC7B00327C8,
    0xD5A79147C6E00BF3, 0x1429296706CA6351,
    0x2E1B213827B70A85, 0x53380D134D2C6DFC,
    0x766A0ABB650A7354, 0x92722C8581C2C92E,
    0xA81A664BA2BFE8A1, 0xC76C51A3C24B8B70,
    0xD6990624D192E819, 0x106AA070F40E3585,
    0x1E376C0819A4C116, 0x34B0BCB52748774C,
    0x4ED8AA4A391C0CB3, 0x682E6FF35B9CCA4F,
    0x78A5636F748F82EE, 0x8CC7020884C87814,
    0xA4506CEB90BEFFFA, 0xC67178F2BEF9A3F7
};

/** Intel SHA extensions using C intrinsics
 *  Written and place in public domain by Jeffrey Walton
 *  Based on code from Intel, and by Sean Gulley for
 *  the miTLS project.
 */
void intel(uint32_t state[8], const uint8_t *msg, uint32_t num_blocks) {
  __m128i STATE0, STATE1;
  __m128i MSG, TMP, MASK;
  __m128i MSG0, MSG1, MSG2, MSG3;
  __m128i ABEF_SAVE, CDGH_SAVE;

  /* Load initial values */
  TMP = _mm_loadu_si128((__m128i *) &state[0]);
  STATE1 = _mm_loadu_si128((__m128i *) &state[4]);
  MASK = _mm_set_epi64x(0x0c0d0e0f08090a0bULL, 0x0405060700010203ULL);

  TMP = _mm_shuffle_epi32(TMP, 0xB1);          /* CDAB */
  STATE1 = _mm_shuffle_epi32(STATE1, 0x1B);    /* EFGH */
  STATE0 = _mm_alignr_epi8(TMP, STATE1, 8);    /* ABEF */
  STATE1 = _mm_blend_epi16(STATE1, TMP, 0xF0); /* CDGH */

  while (num_blocks > 0) {
    /* Save current state */
    ABEF_SAVE = STATE0;
    CDGH_SAVE = STATE1;

    /* Rounds 0-3 */
    MSG = _mm_loadu_si128((const __m128i *) (msg + 0));
    MSG0 = _mm_shuffle_epi8(MSG, MASK);
    MSG = _mm_add_epi32(MSG0, _mm_set_epi64x(0xE9B5DBA5B5C0FBCFULL, 0x71374491428A2F98ULL));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);

    /* Rounds 4-7 */
    MSG1 = _mm_loadu_si128((const __m128i *) (msg + 16));
    MSG1 = _mm_shuffle_epi8(MSG1, MASK);
    MSG = _mm_add_epi32(MSG1, _mm_set_epi64x(0xAB1C5ED5923F82A4ULL, 0x59F111F13956C25BULL));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    MSG0 = _mm_sha256msg1_epu32(MSG0, MSG1);

    /* Rounds 8-11 */
    MSG2 = _mm_loadu_si128((const __m128i *) (msg + 32));
    MSG2 = _mm_shuffle_epi8(MSG2, MASK);
    MSG = _mm_add_epi32(MSG2, _mm_set_epi64x(0x550C7DC3243185BEULL, 0x12835B01D807AA98ULL));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    MSG1 = _mm_sha256msg1_epu32(MSG1, MSG2);

    /* Rounds 12-15 */
    MSG3 = _mm_loadu_si128((const __m128i *) (msg + 48));
    MSG3 = _mm_shuffle_epi8(MSG3, MASK);
    MSG = _mm_add_epi32(MSG3, _mm_set_epi64x(0xC19BF1749BDC06A7ULL, 0x80DEB1FE72BE5D74ULL));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    TMP = _mm_alignr_epi8(MSG3, MSG2, 4);
    MSG0 = _mm_add_epi32(MSG0, TMP);
    MSG0 = _mm_sha256msg2_epu32(MSG0, MSG3);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    MSG2 = _mm_sha256msg1_epu32(MSG2, MSG3);

    /* Rounds 16-19 */
    MSG = _mm_add_epi32(MSG0, _mm_set_epi64x(0x240CA1CC0FC19DC6ULL, 0xEFBE4786E49B69C1ULL));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    TMP = _mm_alignr_epi8(MSG0, MSG3, 4);
    MSG1 = _mm_add_epi32(MSG1, TMP);
    MSG1 = _mm_sha256msg2_epu32(MSG1, MSG0);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    MSG3 = _mm_sha256msg1_epu32(MSG3, MSG0);

    /* Rounds 20-23 */
    MSG = _mm_add_epi32(MSG1, _mm_set_epi64x(0x76F988DA5CB0A9DCULL, 0x4A7484AA2DE92C6FULL));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    TMP = _mm_alignr_epi8(MSG1, MSG0, 4);
    MSG2 = _mm_add_epi32(MSG2, TMP);
    MSG2 = _mm_sha256msg2_epu32(MSG2, MSG1);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    MSG0 = _mm_sha256msg1_epu32(MSG0, MSG1);

    /* Rounds 24-27 */
    MSG = _mm_add_epi32(MSG2, _mm_set_epi64x(0xBF597FC7B00327C8ULL, 0xA831C66D983E5152ULL));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    TMP = _mm_alignr_epi8(MSG2, MSG1, 4);
    MSG3 = _mm_add_epi32(MSG3, TMP);
    MSG3 = _mm_sha256msg2_epu32(MSG3, MSG2);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    MSG1 = _mm_sha256msg1_epu32(MSG1, MSG2);

    /* Rounds 28-31 */
    MSG = _mm_add_epi32(MSG3, _mm_set_epi64x(0x1429296706CA6351ULL, 0xD5A79147C6E00BF3ULL));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    TMP = _mm_alignr_epi8(MSG3, MSG2, 4);
    MSG0 = _mm_add_epi32(MSG0, TMP);
    MSG0 = _mm_sha256msg2_epu32(MSG0, MSG3);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    MSG2 = _mm_sha256msg1_epu32(MSG2, MSG3);

    /* Rounds 32-35 */
    MSG = _mm_add_epi32(MSG0, _mm_set_epi64x(0x53380D134D2C6DFCULL, 0x2E1B213827B70A85ULL));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    TMP = _mm_alignr_epi8(MSG0, MSG3, 4);
    MSG1 = _mm_add_epi32(MSG1, TMP);
    MSG1 = _mm_sha256msg2_epu32(MSG1, MSG0);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    MSG3 = _mm_sha256msg1_epu32(MSG3, MSG0);

    /* Rounds 36-39 */
    MSG = _mm_add_epi32(MSG1, _mm_set_epi64x(0x92722C8581C2C92EULL, 0x766A0ABB650A7354ULL));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    TMP = _mm_alignr_epi8(MSG1, MSG0, 4);
    MSG2 = _mm_add_epi32(MSG2, TMP);
    MSG2 = _mm_sha256msg2_epu32(MSG2, MSG1);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    MSG0 = _mm_sha256msg1_epu32(MSG0, MSG1);

    /* Rounds 40-43 */
    MSG = _mm_add_epi32(MSG2, _mm_set_epi64x(0xC76C51A3C24B8B70ULL, 0xA81A664BA2BFE8A1ULL));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    TMP = _mm_alignr_epi8(MSG2, MSG1, 4);
    MSG3 = _mm_add_epi32(MSG3, TMP);
    MSG3 = _mm_sha256msg2_epu32(MSG3, MSG2);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    MSG1 = _mm_sha256msg1_epu32(MSG1, MSG2);

    /* Rounds 44-47 */
    MSG = _mm_add_epi32(MSG3, _mm_set_epi64x(0x106AA070F40E3585ULL, 0xD6990624D192E819ULL));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    TMP = _mm_alignr_epi8(MSG3, MSG2, 4);
    MSG0 = _mm_add_epi32(MSG0, TMP);
    MSG0 = _mm_sha256msg2_epu32(MSG0, MSG3);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    MSG2 = _mm_sha256msg1_epu32(MSG2, MSG3);

    /* Rounds 48-51 */
    MSG = _mm_add_epi32(MSG0, _mm_set_epi64x(0x34B0BCB52748774CULL, 0x1E376C0819A4C116ULL));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    TMP = _mm_alignr_epi8(MSG0, MSG3, 4);
    MSG1 = _mm_add_epi32(MSG1, TMP);
    MSG1 = _mm_sha256msg2_epu32(MSG1, MSG0);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    MSG3 = _mm_sha256msg1_epu32(MSG3, MSG0);

    /* Rounds 52-55 */
    MSG = _mm_add_epi32(MSG1, _mm_set_epi64x(0x682E6FF35B9CCA4FULL, 0x4ED8AA4A391C0CB3ULL));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    TMP = _mm_alignr_epi8(MSG1, MSG0, 4);
    MSG2 = _mm_add_epi32(MSG2, TMP);
    MSG2 = _mm_sha256msg2_epu32(MSG2, MSG1);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);

    /* Rounds 56-59 */
    MSG = _mm_add_epi32(MSG2, _mm_set_epi64x(0x8CC7020884C87814ULL, 0x78A5636F748F82EEULL));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    TMP = _mm_alignr_epi8(MSG2, MSG1, 4);
    MSG3 = _mm_add_epi32(MSG3, TMP);
    MSG3 = _mm_sha256msg2_epu32(MSG3, MSG2);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);

    /* Rounds 60-63 */
    MSG = _mm_add_epi32(MSG3, _mm_set_epi64x(0xC67178F2BEF9A3F7ULL, 0xA4506CEB90BEFFFAULL));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);

    /* Combine state  */
    STATE0 = _mm_add_epi32(STATE0, ABEF_SAVE);
    STATE1 = _mm_add_epi32(STATE1, CDGH_SAVE);

    msg += 64;
    num_blocks--;
  }

  TMP = _mm_shuffle_epi32(STATE0, 0x1B);       /* FEBA */
  STATE1 = _mm_shuffle_epi32(STATE1, 0xB1);    /* DCHG */
  STATE0 = _mm_blend_epi16(TMP, STATE1, 0xF0); /* DCBA */
  STATE1 = _mm_alignr_epi8(STATE1, TMP, 8);    /* ABEF */

  /* Save state */
  _mm_storeu_si128((__m128i *) &state[0], STATE0);
  _mm_storeu_si128((__m128i *) &state[4], STATE1);
}

void julio(uint32_t state[8], const uint8_t *msg, uint32_t num_blocks) {
  int i = 0;
  __m128i STATE0, STATE1;
  __m128i MASK;
  __m128i ABEF_SAVE, CDGH_SAVE;
  __m128i T0, T1, T2; //new
  __m128i T[16];
  __m128i TMSG[4];

  // Load initial values
  T0 = _mm_loadu_si128((__m128i *) &state[0]);
  STATE1 = _mm_loadu_si128((__m128i *) &state[4]);
  MASK = _mm_set_epi64x(0x0c0d0e0f08090a0bULL, 0x0405060700010203ULL);

  T0 = _mm_shuffle_epi32(T0, 0xB1); // CDAB
  STATE1 = _mm_shuffle_epi32(STATE1, 0x1B); // EFGH
  STATE0 = _mm_alignr_epi8(T0, STATE1, 8); // ABEF
  STATE1 = _mm_blend_epi16(STATE1, T0, 0xF0); // CDGH

  T[0] = _mm_set_epi64x(0xE9B5DBA5B5C0FBCFULL, 0x71374491428A2F98ULL);
  T[1] = _mm_set_epi64x(0xAB1C5ED5923F82A4ULL, 0x59F111F13956C25BULL);
  T[2] = _mm_set_epi64x(0x550C7DC3243185BEULL, 0x12835B01D807AA98ULL);
  T[3] = _mm_set_epi64x(0xC19BF1749BDC06A7ULL, 0x80DEB1FE72BE5D74ULL);
  T[4] = _mm_set_epi64x(0x240CA1CC0FC19DC6ULL, 0xEFBE4786E49B69C1ULL);
  T[5] = _mm_set_epi64x(0x76F988DA5CB0A9DCULL, 0x4A7484AA2DE92C6FULL);
  T[6] = _mm_set_epi64x(0xBF597FC7B00327C8ULL, 0xA831C66D983E5152ULL);
  T[7] = _mm_set_epi64x(0x1429296706CA6351ULL, 0xD5A79147C6E00BF3ULL);
  T[8] = _mm_set_epi64x(0x53380D134D2C6DFCULL, 0x2E1B213827B70A85ULL);
  T[9] = _mm_set_epi64x(0x92722C8581C2C92EULL, 0x766A0ABB650A7354ULL);
  T[10] = _mm_set_epi64x(0xC76C51A3C24B8B70ULL, 0xA81A664BA2BFE8A1ULL);
  T[11] = _mm_set_epi64x(0x106AA070F40E3585ULL, 0xD6990624D192E819ULL);
  T[12] = _mm_set_epi64x(0x34B0BCB52748774CULL, 0x1E376C0819A4C116ULL);
  T[13] = _mm_set_epi64x(0x682E6FF35B9CCA4FULL, 0x4ED8AA4A391C0CB3ULL);
  T[14] = _mm_set_epi64x(0x8CC7020884C87814ULL, 0x78A5636F748F82EEULL);
  T[15] = _mm_set_epi64x(0xC67178F2BEF9A3F7ULL, 0xA4506CEB90BEFFFAULL);

  while (num_blocks > 0) {
    // Save current hash
    ABEF_SAVE = STATE0;
    CDGH_SAVE = STATE1;

    //Rounds 0-15
    for (i = 0; i < 4; i++) {
      TMSG[i] = _mm_loadu_si128((const __m128i *) (msg + 16 * i));
      TMSG[i] = _mm_shuffle_epi8(TMSG[i], MASK);
      T0 = _mm_add_epi32(TMSG[i], T[i]);
      T1 = _mm_shuffle_epi32(T0, 0x0E);
      STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, T0);
      STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, T1);
    }

    // Rounds 16-31
    for (i = 0; i < 4; i++) {
      TMSG[i] = _mm_sha256msg1_epu32(TMSG[i], TMSG[(i + 1) % 4]);
      T2 = _mm_alignr_epi8(TMSG[(i + 3) % 4], TMSG[(i + 2) % 4], 4);
      TMSG[i] = _mm_add_epi32(TMSG[i], T2);
      TMSG[i] = _mm_sha256msg2_epu32(TMSG[i], TMSG[(i + 3) % 4]);
      T0 = _mm_add_epi32(TMSG[i], T[i + 4]);
      T1 = _mm_shuffle_epi32(T0, 0x0E);
      STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, T0);
      STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, T1);
    }

    // Rounds 32-47
    for (i = 0; i < 4; i++) {
      TMSG[i] = _mm_sha256msg1_epu32(TMSG[i], TMSG[(i + 1) % 4]);
      T2 = _mm_alignr_epi8(TMSG[(i + 3) % 4], TMSG[(i + 2) % 4], 4);
      TMSG[i] = _mm_add_epi32(TMSG[i], T2);
      TMSG[i] = _mm_sha256msg2_epu32(TMSG[i], TMSG[(i + 3) % 4]);
      T0 = _mm_add_epi32(TMSG[i], T[i + 8]);
      T1 = _mm_shuffle_epi32(T0, 0x0E);
      STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, T0);
      STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, T1);
    }

    // Rounds 48-63
    for (i = 0; i < 4; i++) {
      TMSG[i] = _mm_sha256msg1_epu32(TMSG[i], TMSG[(i + 1) % 4]);
      T2 = _mm_alignr_epi8(TMSG[(i + 3) % 4], TMSG[(i + 2) % 4], 4);
      TMSG[i] = _mm_add_epi32(TMSG[i], T2);
      TMSG[i] = _mm_sha256msg2_epu32(TMSG[i], TMSG[(i + 3) % 4]);
      T0 = _mm_add_epi32(TMSG[i], T[i + 12]);
      T1 = _mm_shuffle_epi32(T0, 0x0E);
      STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, T0);
      STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, T1);
    }

    // Add values back to state
    STATE0 = _mm_add_epi32(STATE0, ABEF_SAVE);
    STATE1 = _mm_add_epi32(STATE1, CDGH_SAVE);

    msg += 64;
    num_blocks--;
  }

  T0 = _mm_shuffle_epi32(STATE0, 0x1B);       // FEBA
  STATE1 = _mm_shuffle_epi32(STATE1, 0xB1);   // DCHG
  STATE0 = _mm_blend_epi16(T0, STATE1, 0xF0); // DCBA
  STATE1 = _mm_alignr_epi8(STATE1, T0, 8);    // ABEF

  // Save state
  _mm_storeu_si128((__m128i *) &state[0], STATE0);
  _mm_storeu_si128((__m128i *) &state[4], STATE1);
}

void update_shani(uint32_t *state, const uint8_t *msg, uint32_t num_blocks) {
  const __m128i MASK = _mm_set_epi32(0x0c0d0e0f, 0x08090a0b, 0x04050607, 0x00010203);
  int i, j;
  __m128i A0, C0, ABEF, CDGH, X0, Y0, Ki, W0[4];

  X0 = LOAD(state + 0);
  Y0 = LOAD(state + 1);

  A0 = CVLO(X0, Y0, 0x1B);
  C0 = CVHI(X0, Y0, 0x1B);

  while (num_blocks > 0) {
    ABEF = A0;
    CDGH = C0;

    for (i = 0; i < 4; i++) {
      Ki = LOAD(CONST_K + i);
      W0[i] = L2B(LOAD_U(msg + i));
      X0 = ADD(W0[i], Ki);
      Y0 = HIGH(X0);
      C0 = SHA(C0, A0, X0);
      A0 = SHA(A0, C0, Y0);
    }
    for (j = 1; j < 4; j++) {
      for (i = 0; i < 4; i++) {
        Ki = LOAD(CONST_K + 4 * j + i);
        X0 = MSG1(W0[i], W0[(i + 1) % 4]);
        Y0 = ALIGNR(W0[(i + 3) % 4], W0[(i + 2) % 4]);
        X0 = ADD(X0, Y0);
        W0[i] = MSG2(X0, W0[(i + 3) % 4]);
        X0 = ADD(W0[i], Ki);
        Y0 = HIGH(X0);
        C0 = SHA(C0, A0, X0);
        A0 = SHA(A0, C0, Y0);
      }
    }

    A0 = ADD(A0, ABEF);
    C0 = ADD(C0, CDGH);

    msg += 64;
    num_blocks--;
  }

  X0 = CVHI(A0, C0, 0xB1);
  Y0 = CVLO(A0, C0, 0xB1);

  STORE(state + 0, X0);
  STORE(state + 1, Y0);
}

void update_shani_2x(
    uint32_t *state0, const uint8_t *msg0,
    uint32_t *state1, const uint8_t *msg1,
    uint32_t num_blocks) {
  const __m128i MASK = _mm_set_epi32(0x0c0d0e0f, 0x08090a0b, 0x04050607, 0x00010203);
  int i, j;//, i1, i2, i3;
  __m128i Ki;
  __m128i A0, C0, ABEF0, CDGH0, X0, Y0, W0[4];
  __m128i A1, C1, ABEF1, CDGH1, X1, Y1, W1[4];

  X0 = LOAD(state0 + 0);
  X1 = LOAD(state1 + 0);
  Y0 = LOAD(state0 + 1);
  Y1 = LOAD(state1 + 1);
  A0 = CVLO(X0, Y0, 0x1B);
  A1 = CVLO(X1, Y1, 0x1B);
  C0 = CVHI(X0, Y0, 0x1B);
  C1 = CVHI(X1, Y1, 0x1B);

  while (num_blocks > 0) {
    ABEF0 = A0;
    ABEF1 = A1;
    CDGH0 = C0;
    CDGH1 = C1;

    for (i = 0; i < 4; i++) {
      Ki = LOAD(CONST_K + i);
      W0[i] = L2B(LOAD_U(msg0 + i));
      W1[i] = L2B(LOAD_U(msg1 + i));
      X0 = ADD(W0[i], Ki);
      X1 = ADD(W1[i], Ki);
      Y0 = HIGH(X0);
      Y1 = HIGH(X1);
      C0 = SHA(C0, A0, X0);
      C1 = SHA(C1, A1, X1);
      A0 = SHA(A0, C0, Y0);
      A1 = SHA(A1, C1, Y1);
    }
    for (j = 1; j < 4; j++) {
      for (i = 0; i < 4; i++) {
        Ki = LOAD(CONST_K + 4 * j + i);
        X0 = MSG1(W0[i], W0[(i+1)%4]);
        X1 = MSG1(W1[i], W1[(i+1)%4]);
        Y0 = ALIGNR(W0[(i+3)%4], W0[(i+2)%4]);
        Y1 = ALIGNR(W1[(i+3)%4], W1[(i+2)%4]);
        X0 = ADD(X0, Y0);
        X1 = ADD(X1, Y1);
        W0[i] = MSG2(X0, W0[(i+3)%4]);
        W1[i] = MSG2(X1, W1[(i+3)%4]);
        X0 = ADD(W0[i], Ki);
        X1 = ADD(W1[i], Ki);
        Y0 = HIGH(X0);
        Y1 = HIGH(X1);
        C0 = SHA(C0, A0, X0);
        C1 = SHA(C1, A1, X1);
        A0 = SHA(A0, C0, Y0);
        A1 = SHA(A1, C1, Y1);
//        i1 = i2;
//        i2 = i3;
//        i3 = i;
      }
    }

    A0 = ADD(A0, ABEF0);
    A1 = ADD(A1, ABEF1);
    C0 = ADD(C0, CDGH0);
    C1 = ADD(C1, CDGH1);
    msg0 += 64;
    msg1 += 64;
    num_blocks--;
  }

  X0 = CVHI(A0, C0, 0xB1);
  X1 = CVHI(A1, C1, 0xB1);
  Y0 = CVLO(A0, C0, 0xB1);
  Y1 = CVLO(A1, C1, 0xB1);

  STORE(state0 + 0, X0);
  STORE(state1 + 0, X1);
  STORE(state0 + 1, Y0);
  STORE(state1 + 1, Y1);
}

void __update_shani_4x(
    uint32_t *state0, const uint8_t *msg0,
    uint32_t *state1, const uint8_t *msg1,
    uint32_t *state2, const uint8_t *msg2,
    uint32_t *state3, const uint8_t *msg3,
    uint32_t num_blocks) {
  const __m128i MASK = _mm_set_epi32(0x0c0d0e0f, 0x08090a0b, 0x04050607, 0x00010203);
  int i, j;//, i1, i2, i3;
  __m128i Ki;
  __m128i A0, C0, ABEF0, CDGH0, X0, Y0, W0[4];
  __m128i A1, C1, ABEF1, CDGH1, X1, Y1, W1[4];
  __m128i A2, C2, ABEF2, CDGH2, X2, Y2, W2[4];
  __m128i A3, C3, ABEF3, CDGH3, X3, Y3, W3[4];

  X0 = LOAD(state0 + 0);    X1 = LOAD(state1 + 0);    X2 = LOAD(state2 + 0);    X3 = LOAD(state3 + 0);
  Y0 = LOAD(state0 + 1);    Y1 = LOAD(state1 + 1);    Y2 = LOAD(state2 + 1);    Y3 = LOAD(state3 + 1);
  A0 = CVLO(X0, Y0, 0x1B);  A1 = CVLO(X1, Y1, 0x1B);  A2 = CVLO(X2, Y2, 0x1B);  A3 = CVLO(X3, Y3, 0x1B);
  C0 = CVHI(X0, Y0, 0x1B);  C1 = CVHI(X1, Y1, 0x1B);  C2 = CVHI(X2, Y2, 0x1B);  C3 = CVHI(X3, Y3, 0x1B);

  while (num_blocks > 0) {
    ABEF0 = A0;    ABEF1 = A1;  ABEF2 = A2;    ABEF3 = A3;
    CDGH0 = C0;    CDGH1 = C1;  CDGH2 = C2;    CDGH3 = C3;

    for (i = 0; i < 4; i++) {
      Ki = LOAD(CONST_K + i);
      W0[i] = L2B(LOAD_U(msg0 + i));      W1[i] = L2B(LOAD_U(msg1 + i));   W2[i] = L2B(LOAD_U(msg2 + i));      W3[i] = L2B(LOAD_U(msg3 + i));
      X0 = ADD(W0[i], Ki);                X1 = ADD(W1[i], Ki);             X2 = ADD(W2[i], Ki);                X3 = ADD(W3[i], Ki);
      Y0 = HIGH(X0);                      Y1 = HIGH(X1);                   Y2 = HIGH(X2);                      Y3 = HIGH(X3);
      C0 = SHA(C0, A0, X0);               C1 = SHA(C1, A1, X1);            C2 = SHA(C2, A2, X2);               C3 = SHA(C3, A3, X3);
      A0 = SHA(A0, C0, Y0);               A1 = SHA(A1, C1, Y1);            A2 = SHA(A2, C2, Y2);               A3 = SHA(A3, C3, Y3);
    }
    for (j = 1; j < 4; j++) {
      for (i = 0; i < 4; i++) {
        Ki = LOAD(CONST_K + 4 * j + i);
        X0 = MSG1(W0[i], W0[(i + 1) % 4]);        X1 = MSG1(W1[i], W1[(i + 1) % 4]);      X2 = MSG1(W2[i], W2[(i + 1) % 4]);        X3 = MSG1(W3[i], W3[(i + 1) % 4]);
        Y0 = ALIGNR(W0[(i + 3) % 4], W0[(i + 2) % 4]);     Y1 = ALIGNR(W1[(i + 3) % 4], W1[(i + 2) % 4]);   Y2 = ALIGNR(W2[(i + 3) % 4], W2[(i + 2) % 4]);     Y3 = ALIGNR(W3[(i + 3) % 4], W3[(i + 2) % 4]);
        X0 = ADD(X0, Y0);                X1 = ADD(X1, Y1);              X2 = ADD(X2, Y2);                X3 = ADD(X3, Y3);
        W0[i] = MSG2(X0, W0[(i + 3) % 4]);        W1[i] = MSG2(X1, W1[(i + 3) % 4]);      W2[i] = MSG2(X2, W2[(i + 3) % 4]);        W3[i] = MSG2(X3, W3[(i + 3) % 4]);
        X0 = ADD(W0[i], Ki);             X1 = ADD(W1[i], Ki);           X2 = ADD(W2[i], Ki);             X3 = ADD(W3[i], Ki);
        C0 = SHA(C0, A0, X0);            C1 = SHA(C1, A1, X1);          C2 = SHA(C2, A2, X2);            C3 = SHA(C3, A3, X3);
        Y0 = HIGH(X0);                   Y1 = HIGH(X1);                 Y2 = HIGH(X2);                   Y3 = HIGH(X3);
        A0 = SHA(A0, C0, Y0);            A1 = SHA(A1, C1, Y1);          A2 = SHA(A2, C2, Y2);            A3 = SHA(A3, C3, Y3);
//        i1 = i2;
//        i2 = i3;
//        i3 = i;
      }
    }

    A0 = ADD(A0, ABEF0);    A1 = ADD(A1, ABEF1);  A2 = ADD(A2, ABEF2);    A3 = ADD(A3, ABEF3);
    C0 = ADD(C0, CDGH0);    C1 = ADD(C1, CDGH1);  C2 = ADD(C2, CDGH2);    C3 = ADD(C3, CDGH3);
    msg0 += 64;           msg1 += 64;           msg2 += 64;             msg3 += 64;
    num_blocks--;
  }

  X0 = CVHI(A0, C0, 0xB1);  X1 = CVHI(A1, C1, 0xB1);  X2 = CVHI(A2, C2, 0xB1);  X3 = CVHI(A3, C3, 0xB1);
  Y0 = CVLO(A0, C0, 0xB1);  Y1 = CVLO(A1, C1, 0xB1);  Y2 = CVLO(A2, C2, 0xB1);  Y3 = CVLO(A3, C3, 0xB1);

  STORE(state0 + 0, X0);  STORE(state1 + 0, X1);  STORE(state2 + 0, X2);  STORE(state3 + 0, X3);
  STORE(state0 + 1, Y0);  STORE(state1 + 1, Y1);  STORE(state2 + 1, Y2);  STORE(state3 + 1, Y3);
}


void update_shani_8x(
    uint32_t *state0, const uint8_t *msg0,
    uint32_t *state1, const uint8_t *msg1,
    uint32_t *state2, const uint8_t *msg2,
    uint32_t *state3, const uint8_t *msg3,
    uint32_t *state4, const uint8_t *msg4,
    uint32_t *state5, const uint8_t *msg5,
    uint32_t *state6, const uint8_t *msg6,
    uint32_t *state7, const uint8_t *msg7,
    uint32_t num_blocks) {
  const __m128i MASK = _mm_set_epi32(0x0c0d0e0f, 0x08090a0b, 0x04050607, 0x00010203);
  int i, j, i1, i2, i3;
  __m128i Ki;
  __m128i A0, C0, ABEF0, CDGH0, X0, Y0;
  __m128i A1, C1, ABEF1, CDGH1, X1, Y1;
  __m128i A2, C2, ABEF2, CDGH2, X2, Y2;
  __m128i A3, C3, ABEF3, CDGH3, X3, Y3;
  __m128i A4, C4, ABEF4, CDGH4, X4, Y4;
  __m128i A5, C5, ABEF5, CDGH5, X5, Y5;
  __m128i A6, C6, ABEF6, CDGH6, X6, Y6;
  __m128i A7, C7, ABEF7, CDGH7, X7, Y7;

  __m128i W0[4], W1[4], W2[4], W3[4], W4[4], W5[4], W6[4], W7[4];


  X0 = LOAD(state0 + 0);    X1 = LOAD(state1 + 0);    X2 = LOAD(state2 + 0);    X3 = LOAD(state3 + 0);    X4 = LOAD(state4 + 0);    X5 = LOAD(state5 + 0);    X6 = LOAD(state6 + 0);    X7 = LOAD(state7 + 0);
  Y0 = LOAD(state0 + 1);    Y1 = LOAD(state1 + 1);    Y2 = LOAD(state2 + 1);    Y3 = LOAD(state3 + 1);    Y4 = LOAD(state4 + 1);    Y5 = LOAD(state5 + 1);    Y6 = LOAD(state6 + 1);    Y7 = LOAD(state7 + 1);
  A0 = CVLO(X0, Y0, 0x1B);  A1 = CVLO(X1, Y1, 0x1B);  A2 = CVLO(X2, Y2, 0x1B);  A3 = CVLO(X3, Y3, 0x1B);  A4 = CVLO(X4, Y4, 0x1B);  A5 = CVLO(X5, Y5, 0x1B);  A6 = CVLO(X6, Y6, 0x1B);  A7 = CVLO(X7, Y7, 0x1B);
  C0 = CVHI(X0, Y0, 0x1B);  C1 = CVHI(X1, Y1, 0x1B);  C2 = CVHI(X2, Y2, 0x1B);  C3 = CVHI(X3, Y3, 0x1B);  C4 = CVHI(X4, Y4, 0x1B);  C5 = CVHI(X5, Y5, 0x1B);  C6 = CVHI(X6, Y6, 0x1B);  C7 = CVHI(X7, Y7, 0x1B);

  while (num_blocks > 0) {
    ABEF0 = A0;    ABEF1 = A1;  ABEF2 = A2;    ABEF3 = A3;  ABEF4 = A4;    ABEF5 = A5;  ABEF6 = A6;    ABEF7 = A7;
    CDGH0 = C0;    CDGH1 = C1;  CDGH2 = C2;    CDGH3 = C3;  CDGH4 = C4;    CDGH5 = C5;  CDGH6 = C6;    CDGH7 = C7;

    for (i = 0; i < 4; i++) {
      Ki = LOAD(CONST_K + i);
      W0[i] = L2B(LOAD_U(msg0 + i));  W1[i] = L2B(LOAD_U(msg1 + i));  W2[i] = L2B(LOAD_U(msg2 + i));  W3[i] = L2B(LOAD_U(msg3 + i));  W4[i] = L2B(LOAD_U(msg4 + i));  W5[i] = L2B(LOAD_U(msg5 + i));  W6[i] = L2B(LOAD_U(msg6 + i));  W7[i] = L2B(LOAD_U(msg7 + i));
      X0 = ADD(W0[i], Ki);            X1 = ADD(W1[i], Ki);            X2 = ADD(W2[i], Ki);            X3 = ADD(W3[i], Ki);            X4 = ADD(W4[i], Ki);            X5 = ADD(W5[i], Ki);            X6 = ADD(W6[i], Ki);            X7 = ADD(W7[i], Ki);
      Y0 = HIGH(X0);                  Y1 = HIGH(X1);                  Y2 = HIGH(X2);                  Y3 = HIGH(X3);                  Y4 = HIGH(X4);                  Y5 = HIGH(X5);                  Y6 = HIGH(X6);                  Y7 = HIGH(X7);
      C0 = SHA(C0, A0, X0);           C1 = SHA(C1, A1, X1);           C2 = SHA(C2, A2, X2);           C3 = SHA(C3, A3, X3);           C4 = SHA(C4, A4, X4);           C5 = SHA(C5, A5, X5);           C6 = SHA(C6, A6, X6);           C7 = SHA(C7, A7, X7);
      A0 = SHA(A0, C0, Y0);           A1 = SHA(A1, C1, Y1);           A2 = SHA(A2, C2, Y2);           A3 = SHA(A3, C3, Y3);           A4 = SHA(A4, C4, Y4);           A5 = SHA(A5, C5, Y5);           A6 = SHA(A6, C6, Y6);           A7 = SHA(A7, C7, Y7);
    }
    for (j = 1; j < 4; j++) {
      for (i = 0, i1 = 1, i2 = 2, i3 = 3; i < 4; i++) {
        Ki = LOAD(CONST_K + 4 * j + i);
        X0 = MSG1(W0[i], W0[i1]);     X1 = MSG1(W1[i], W1[i1]);     X2 = MSG1(W2[i], W2[i1]);     X3 = MSG1(W3[i], W3[i1]);     X4 = MSG1(W4[i], W4[i1]);     X5 = MSG1(W5[i], W5[i1]);     X6 = MSG1(W6[i], W6[i1]);     X7 = MSG1(W7[i], W7[i1]);
        Y0 = ALIGNR(W0[i3], W0[i2]);  Y1 = ALIGNR(W1[i3], W1[i2]);  Y2 = ALIGNR(W2[i3], W2[i2]);  Y3 = ALIGNR(W3[i3], W3[i2]);  Y4 = ALIGNR(W4[i3], W4[i2]);  Y5 = ALIGNR(W5[i3], W5[i2]);  Y6 = ALIGNR(W6[i3], W6[i2]);  Y7 = ALIGNR(W7[i3], W7[i2]);
        X0 = ADD(X0, Y0);             X1 = ADD(X1, Y1);             X2 = ADD(X2, Y2);             X3 = ADD(X3, Y3);             X4 = ADD(X4, Y4);             X5 = ADD(X5, Y5);             X6 = ADD(X6, Y6);             X7 = ADD(X7, Y7);
        W0[i] = MSG2(X0, W0[i3]);     W1[i] = MSG2(X1, W1[i3]);     W2[i] = MSG2(X2, W2[i3]);     W3[i] = MSG2(X3, W3[i3]);     W4[i] = MSG2(X4, W4[i3]);     W5[i] = MSG2(X5, W5[i3]);     W6[i] = MSG2(X6, W6[i3]);     W7[i] = MSG2(X7, W7[i3]);
        X0 = ADD(W0[i], Ki);          X1 = ADD(W1[i], Ki);          X2 = ADD(W2[i], Ki);          X3 = ADD(W3[i], Ki);          X4 = ADD(W4[i], Ki);          X5 = ADD(W5[i], Ki);          X6 = ADD(W6[i], Ki);          X7 = ADD(W7[i], Ki);
        Y0 = HIGH(X0);                Y1 = HIGH(X1);                Y2 = HIGH(X2);                Y3 = HIGH(X3);                Y4 = HIGH(X4);                Y5 = HIGH(X5);                Y6 = HIGH(X6);                Y7 = HIGH(X7);
        C0 = SHA(C0, A0, X0);         C1 = SHA(C1, A1, X1);         C2 = SHA(C2, A2, X2);         C3 = SHA(C3, A3, X3);         C4 = SHA(C4, A4, X4);         C5 = SHA(C5, A5, X5);         C6 = SHA(C6, A6, X6);         C7 = SHA(C7, A7, X7);
        A0 = SHA(A0, C0, Y0);         A1 = SHA(A1, C1, Y1);         A2 = SHA(A2, C2, Y2);         A3 = SHA(A3, C3, Y3);         A4 = SHA(A4, C4, Y4);         A5 = SHA(A5, C5, Y5);         A6 = SHA(A6, C6, Y6);         A7 = SHA(A7, C7, Y7);
        i1 = i2;
        i2 = i3;
        i3 = i;
      }
    }

      A0 = ADD(A0, ABEF0);    A1 = ADD(A1, ABEF1);  A2 = ADD(A2, ABEF2);    A3 = ADD(A3, ABEF3);    A4 = ADD(A4, ABEF4);    A5 = ADD(A5, ABEF5);  A6 = ADD(A6, ABEF6);    A7 = ADD(A7, ABEF7);
      C0 = ADD(C0, CDGH0);    C1 = ADD(C1, CDGH1);  C2 = ADD(C2, CDGH2);    C3 = ADD(C3, CDGH3);    C4 = ADD(C4, CDGH4);    C5 = ADD(C5, CDGH5);  C6 = ADD(C6, CDGH6);    C7 = ADD(C7, CDGH7);
    msg0 += 64;             msg1 += 64;           msg2 += 64;             msg3 += 64;             msg4 += 64;             msg5 += 64;           msg6 += 64;             msg7 += 64;
    num_blocks--;
  }

  X0 = CVHI(A0, C0, 0xB1);  X1 = CVHI(A1, C1, 0xB1);  X2 = CVHI(A2, C2, 0xB1);  X3 = CVHI(A3, C3, 0xB1);  X4 = CVHI(A4, C4, 0xB1);  X5 = CVHI(A5, C5, 0xB1);  X6 = CVHI(A6, C6, 0xB1);  X7 = CVHI(A7, C7, 0xB1);
  Y0 = CVLO(A0, C0, 0xB1);  Y1 = CVLO(A1, C1, 0xB1);  Y2 = CVLO(A2, C2, 0xB1);  Y3 = CVLO(A3, C3, 0xB1);  Y4 = CVLO(A4, C4, 0xB1);  Y5 = CVLO(A5, C5, 0xB1);  Y6 = CVLO(A6, C6, 0xB1);  Y7 = CVLO(A7, C7, 0xB1);

  STORE(state0 + 0, X0);  STORE(state1 + 0, X1);  STORE(state2 + 0, X2);  STORE(state3 + 0, X3);  STORE(state4 + 0, X4);  STORE(state5 + 0, X5);  STORE(state6 + 0, X6);  STORE(state7 + 0, X7);
  STORE(state0 + 1, Y0);  STORE(state1 + 1, Y1);  STORE(state2 + 1, Y2);  STORE(state3 + 1, Y3);  STORE(state4 + 1, Y4);  STORE(state5 + 1, Y5);  STORE(state6 + 1, Y6);  STORE(state7 + 1, Y7);
}


void update_shani_4x(
    uint32_t *state_0,  const uint8_t *data_0,
    uint32_t *state_1,  const uint8_t *data_1,
    uint32_t *state_2,  const uint8_t *data_2,
    uint32_t *state_3,  const uint8_t *data_3,
    uint32_t num_blocks) {
  const __m128i MASK = _mm_set_epi32(0x0c0d0e0f, 0x08090a0b, 0x04050607, 0x00010203);

  uint8_t i, j;
  __m128i Ki;
  __m128i A0, C0, ABEF0, CDGH0, X0, Y0, W0[4];
  __m128i A1, C1, ABEF1, CDGH1, X1, Y1, W1[4];
  __m128i A2, C2, ABEF2, CDGH2, X2, Y2, W2[4];
  __m128i A3, C3, ABEF3, CDGH3, X3, Y3, W3[4];

  X0 = LOAD(state_0 + 0);
  Y0 = LOAD(state_0 + 1);
  X1 = LOAD(state_1 + 0);
  Y1 = LOAD(state_1 + 1);
  X2 = LOAD(state_2 + 0);
  Y2 = LOAD(state_2 + 1);
  X3 = LOAD(state_3 + 0);
  Y3 = LOAD(state_3 + 1);

  /* DCBA -> ABEF */
  /* HGFE -> CDGH */
  A0 = CVLO(X0, Y0, 0x1B);
  C0 = CVHI(X0, Y0, 0x1B);
  A1 = CVLO(X1, Y1, 0x1B);
  C1 = CVHI(X1, Y1, 0x1B);
  A2 = CVLO(X2, Y2, 0x1B);
  C2 = CVHI(X2, Y2, 0x1B);
  A3 = CVLO(X3, Y3, 0x1B);
  C3 = CVHI(X3, Y3, 0x1B);

  while (num_blocks > 0) {
    ABEF0 = A0;
    CDGH0 = C0;
    ABEF1 = A1;
    CDGH1 = C1;
    ABEF2 = A2;
    CDGH2 = C2;
    ABEF3 = A3;
    CDGH3 = C3;

    for (i = 0; i < 4; i++) {
      Ki = LOAD(CONST_K + i);
      W0[i] = LOAD_U(data_0 + i);
      W1[i] = LOAD_U(data_1 + i);
      W2[i] = LOAD_U(data_2 + i);
      W3[i] = LOAD_U(data_3 + i);
      W0[i] = L2B(W0[i]);
      W1[i] = L2B(W1[i]);
      W2[i] = L2B(W2[i]);
      W3[i] = L2B(W3[i]);
      X0 = ADD(W0[i], Ki);
      X1 = ADD(W1[i], Ki);
      X2 = ADD(W2[i], Ki);
      X3 = ADD(W3[i], Ki);
      Y0 = HIGH(X0);
      Y1 = HIGH(X1);
      Y2 = HIGH(X2);
      Y3 = HIGH(X3);
      C0 = SHA(C0, A0, X0);
      C1 = SHA(C1, A1, X1);
      C2 = SHA(C2, A2, X2);
      C3 = SHA(C3, A3, X3);
      A0 = SHA(A0, C0, Y0);
      A1 = SHA(A1, C1, Y1);
      A2 = SHA(A2, C2, Y2);
      A3 = SHA(A3, C3, Y3);
    }

    for (j = 1; j < 4; j++) {
      for (i = 0; i < 4; i++) {
        Ki = LOAD(CONST_K + 4 * j + i);
        X0 = MSG1(W0[i], W0[(i + 1) % 4]);
        X1 = MSG1(W1[i], W1[(i + 1) % 4]);
        X2 = MSG1(W2[i], W2[(i + 1) % 4]);
        X3 = MSG1(W3[i], W3[(i + 1) % 4]);
        Y0 = ALIGNR(W0[(i + 3) % 4], W0[(i + 2) % 4]);
        Y1 = ALIGNR(W1[(i + 3) % 4], W1[(i + 2) % 4]);
        Y2 = ALIGNR(W2[(i + 3) % 4], W2[(i + 2) % 4]);
        Y3 = ALIGNR(W3[(i + 3) % 4], W3[(i + 2) % 4]);
        X0 = ADD(X0, Y0);
        X1 = ADD(X1, Y1);
        X2 = ADD(X2, Y2);
        X3 = ADD(X3, Y3);
        W0[i] = MSG2(X0, W0[(i + 3) % 4]);
        W1[i] = MSG2(X1, W1[(i + 3) % 4]);
        W2[i] = MSG2(X2, W2[(i + 3) % 4]);
        W3[i] = MSG2(X3, W3[(i + 3) % 4]);
        X0 = ADD(W0[i], Ki);
        X1 = ADD(W1[i], Ki);
        X2 = ADD(W2[i], Ki);
        X3 = ADD(W3[i], Ki);
        C0 = SHA(C0, A0, X0);
        C1 = SHA(C1, A1, X1);
        C2 = SHA(C2, A2, X2);
        C3 = SHA(C3, A3, X3);
        Y0 = HIGH(X0);
        Y1 = HIGH(X1);
        Y2 = HIGH(X2);
        Y3 = HIGH(X3);
        A0 = SHA(A0, C0, Y0);
        A1 = SHA(A1, C1, Y1);
        A2 = SHA(A2, C2, Y2);
        A3 = SHA(A3, C3, Y3);
      }
    }

    A0 = ADD(A0, ABEF0);
    A1 = ADD(A1, ABEF1);
    A2 = ADD(A2, ABEF2);
    A3 = ADD(A3, ABEF3);
    C0 = ADD(C0, CDGH0);
    C1 = ADD(C1, CDGH1);
    C2 = ADD(C2, CDGH2);
    C3 = ADD(C3, CDGH3);

    data_0 += 64;
    data_1 += 64;
    data_2 += 64;
    data_3 += 64;
    num_blocks--;
  }
  /* ABEF -> DCBA */
  /* CDGH -> HGFE */
  X0 = CVHI(A0, C0, 0xB1);
  Y0 = CVLO(A0, C0, 0xB1);
  X1 = CVHI(A1, C1, 0xB1);
  Y1 = CVLO(A1, C1, 0xB1);
  X2 = CVHI(A2, C2, 0xB1);
  Y2 = CVLO(A2, C2, 0xB1);
  X3 = CVHI(A3, C3, 0xB1);
  Y3 = CVLO(A3, C3, 0xB1);

  STORE(state_0 + 0, X0);
  STORE(state_0 + 1, Y0);
  STORE(state_1 + 0, X1);
  STORE(state_1 + 1, Y1);
  STORE(state_2 + 0, X2);
  STORE(state_2 + 1, Y2);
  STORE(state_3 + 0, X3);
  STORE(state_3 + 1, Y3);
}

void __update_shani_8x(
    uint32_t *state_0, const uint8_t *data_0,
    uint32_t *state_1, const uint8_t *data_1,
    uint32_t *state_2, const uint8_t *data_2,
    uint32_t *state_3, const uint8_t *data_3,
    uint32_t *state_4, const uint8_t *data_4,
    uint32_t *state_5, const uint8_t *data_5,
    uint32_t *state_6, const uint8_t *data_6,
    uint32_t *state_7, const uint8_t *data_7,
    uint32_t num_blocks) {
  const __m128i MASK = _mm_set_epi32(0x0c0d0e0f, 0x08090a0b, 0x04050607, 0x00010203);

  int i, j;
  __m128i Ki;
  __m128i A0, C0, ABEF0, CDGH0, X0, Y0, W0[4];
  __m128i A1, C1, ABEF1, CDGH1, X1, Y1, W1[4];
  __m128i A2, C2, ABEF2, CDGH2, X2, Y2, W2[4];
  __m128i A3, C3, ABEF3, CDGH3, X3, Y3, W3[4];
  __m128i A4, C4, ABEF4, CDGH4, X4, Y4, W4[4];
  __m128i A5, C5, ABEF5, CDGH5, X5, Y5, W5[4];
  __m128i A6, C6, ABEF6, CDGH6, X6, Y6, W6[4];
  __m128i A7, C7, ABEF7, CDGH7, X7, Y7, W7[4];

  X0 = LOAD(state_0 + 0);
  Y0 = LOAD(state_0 + 1);
  X1 = LOAD(state_1 + 0);
  Y1 = LOAD(state_1 + 1);
  X2 = LOAD(state_2 + 0);
  Y2 = LOAD(state_2 + 1);
  X3 = LOAD(state_3 + 0);
  Y3 = LOAD(state_3 + 1);
  X4 = LOAD(state_4 + 0);
  Y4 = LOAD(state_4 + 1);
  X5 = LOAD(state_5 + 0);
  Y5 = LOAD(state_5 + 1);
  X6 = LOAD(state_6 + 0);
  Y6 = LOAD(state_6 + 1);
  X7 = LOAD(state_7 + 0);
  Y7 = LOAD(state_7 + 1);

  /* DCBA -> ABEF */
  /* HGFE -> CDGH */
  A0 = CVLO(X0, Y0, 0x1B);
  C0 = CVHI(X0, Y0, 0x1B);
  A1 = CVLO(X1, Y1, 0x1B);
  C1 = CVHI(X1, Y1, 0x1B);
  A2 = CVLO(X2, Y2, 0x1B);
  C2 = CVHI(X2, Y2, 0x1B);
  A3 = CVLO(X3, Y3, 0x1B);
  C3 = CVHI(X3, Y3, 0x1B);
  A4 = CVLO(X4, Y4, 0x1B);
  C4 = CVHI(X4, Y4, 0x1B);
  A5 = CVLO(X5, Y5, 0x1B);
  C5 = CVHI(X5, Y5, 0x1B);
  A6 = CVLO(X6, Y6, 0x1B);
  C6 = CVHI(X6, Y6, 0x1B);
  A7 = CVLO(X7, Y7, 0x1B);
  C7 = CVHI(X7, Y7, 0x1B);

  while (num_blocks > 0) {
    ABEF0 = A0;
    ABEF1 = A1;
    ABEF2 = A2;
    ABEF3 = A3;
    ABEF4 = A4;
    ABEF5 = A5;
    ABEF6 = A6;
    ABEF7 = A7;
    CDGH0 = C0;
    CDGH1 = C1;
    CDGH2 = C2;
    CDGH3 = C3;
    CDGH4 = C4;
    CDGH5 = C5;
    CDGH6 = C6;
    CDGH7 = C7;

    for (i = 0; i < 4; i++) {
      Ki = LOAD(CONST_K + i);
      W0[i] = LOAD_U(data_0 + i);
      W1[i] = LOAD_U(data_1 + i);
      W2[i] = LOAD_U(data_2 + i);
      W3[i] = LOAD_U(data_3 + i);
      W4[i] = LOAD_U(data_4 + i);
      W5[i] = LOAD_U(data_5 + i);
      W6[i] = LOAD_U(data_6 + i);
      W7[i] = LOAD_U(data_7 + i);

      W0[i] = L2B(W0[i]);
      W1[i] = L2B(W1[i]);
      W2[i] = L2B(W2[i]);
      W3[i] = L2B(W3[i]);
      W4[i] = L2B(W4[i]);
      W5[i] = L2B(W5[i]);
      W6[i] = L2B(W6[i]);
      W7[i] = L2B(W7[i]);

      X0 = ADD(W0[i], Ki);
      X1 = ADD(W1[i], Ki);
      X2 = ADD(W2[i], Ki);
      X3 = ADD(W3[i], Ki);
      X4 = ADD(W4[i], Ki);
      X5 = ADD(W5[i], Ki);
      X6 = ADD(W6[i], Ki);
      X7 = ADD(W7[i], Ki);

      Y0 = HIGH(X0);
      Y1 = HIGH(X1);
      Y2 = HIGH(X2);
      Y3 = HIGH(X3);
      Y4 = HIGH(X4);
      Y5 = HIGH(X5);
      Y6 = HIGH(X6);
      Y7 = HIGH(X7);

      C0 = SHA(C0, A0, X0);
      C1 = SHA(C1, A1, X1);
      C2 = SHA(C2, A2, X2);
      C3 = SHA(C3, A3, X3);
      C4 = SHA(C4, A4, X4);
      C5 = SHA(C5, A5, X5);
      C6 = SHA(C6, A6, X6);
      C7 = SHA(C7, A7, X7);

      A0 = SHA(A0, C0, Y0);
      A1 = SHA(A1, C1, Y1);
      A2 = SHA(A2, C2, Y2);
      A3 = SHA(A3, C3, Y3);
      A4 = SHA(A4, C4, Y4);
      A5 = SHA(A5, C5, Y5);
      A6 = SHA(A6, C6, Y6);
      A7 = SHA(A7, C7, Y7);
    }

    for (j = 1; j < 4; j++) {
      for (i = 0; i < 4; i++) {
        Ki = LOAD(CONST_K + 4 * j + i);

        X0 = MSG1(W0[i], W0[(i + 1) % 4]);
        X1 = MSG1(W1[i], W1[(i + 1) % 4]);
        X2 = MSG1(W2[i], W2[(i + 1) % 4]);
        X3 = MSG1(W3[i], W3[(i + 1) % 4]);
        X4 = MSG1(W4[i], W4[(i + 1) % 4]);
        X5 = MSG1(W5[i], W5[(i + 1) % 4]);
        X6 = MSG1(W6[i], W6[(i + 1) % 4]);
        X7 = MSG1(W7[i], W7[(i + 1) % 4]);

        Y0 = ALIGNR(W0[(i + 3) % 4], W0[(i + 2) % 4]);
        Y1 = ALIGNR(W1[(i + 3) % 4], W1[(i + 2) % 4]);
        Y2 = ALIGNR(W2[(i + 3) % 4], W2[(i + 2) % 4]);
        Y3 = ALIGNR(W3[(i + 3) % 4], W3[(i + 2) % 4]);
        Y4 = ALIGNR(W4[(i + 3) % 4], W4[(i + 2) % 4]);
        Y5 = ALIGNR(W5[(i + 3) % 4], W5[(i + 2) % 4]);
        Y6 = ALIGNR(W6[(i + 3) % 4], W6[(i + 2) % 4]);
        Y7 = ALIGNR(W7[(i + 3) % 4], W7[(i + 2) % 4]);

        X0 = ADD(X0, Y0);
        X1 = ADD(X1, Y1);
        X2 = ADD(X2, Y2);
        X3 = ADD(X3, Y3);
        X4 = ADD(X4, Y4);
        X5 = ADD(X5, Y5);
        X6 = ADD(X6, Y6);
        X7 = ADD(X7, Y7);

        W0[i] = MSG2(X0, W0[(i + 3) % 4]);
        W1[i] = MSG2(X1, W1[(i + 3) % 4]);
        W2[i] = MSG2(X2, W2[(i + 3) % 4]);
        W3[i] = MSG2(X3, W3[(i + 3) % 4]);
        W4[i] = MSG2(X4, W4[(i + 3) % 4]);
        W5[i] = MSG2(X5, W5[(i + 3) % 4]);
        W6[i] = MSG2(X6, W6[(i + 3) % 4]);
        W7[i] = MSG2(X7, W7[(i + 3) % 4]);

        X0 = ADD(W0[i], Ki);
        X1 = ADD(W1[i], Ki);
        X2 = ADD(W2[i], Ki);
        X3 = ADD(W3[i], Ki);
        X4 = ADD(W4[i], Ki);
        X5 = ADD(W5[i], Ki);
        X6 = ADD(W6[i], Ki);
        X7 = ADD(W7[i], Ki);

        C0 = SHA(C0, A0, X0);
        C1 = SHA(C1, A1, X1);
        C2 = SHA(C2, A2, X2);
        C3 = SHA(C3, A3, X3);
        C4 = SHA(C4, A4, X4);
        C5 = SHA(C5, A5, X5);
        C6 = SHA(C6, A6, X6);
        C7 = SHA(C7, A7, X7);

        Y0 = HIGH(X0);
        Y1 = HIGH(X1);
        Y2 = HIGH(X2);
        Y3 = HIGH(X3);
        Y4 = HIGH(X4);
        Y5 = HIGH(X5);
        Y6 = HIGH(X6);
        Y7 = HIGH(X7);

        A0 = SHA(A0, C0, Y0);
        A1 = SHA(A1, C1, Y1);
        A2 = SHA(A2, C2, Y2);
        A3 = SHA(A3, C3, Y3);
        A4 = SHA(A4, C4, Y4);
        A5 = SHA(A5, C5, Y5);
        A6 = SHA(A6, C6, Y6);
        A7 = SHA(A7, C7, Y7);
      }
    }

    A0 = ADD(A0, ABEF0);
    A1 = ADD(A1, ABEF1);
    A2 = ADD(A2, ABEF2);
    A3 = ADD(A3, ABEF3);
    A4 = ADD(A4, ABEF4);
    A5 = ADD(A5, ABEF5);
    A6 = ADD(A6, ABEF6);
    A7 = ADD(A7, ABEF7);

    C0 = ADD(C0, CDGH0);
    C1 = ADD(C1, CDGH1);
    C2 = ADD(C2, CDGH2);
    C3 = ADD(C3, CDGH3);
    C4 = ADD(C4, CDGH4);
    C5 = ADD(C5, CDGH5);
    C6 = ADD(C6, CDGH6);
    C7 = ADD(C7, CDGH7);

    data_0 += 64;
    data_1 += 64;
    data_2 += 64;
    data_3 += 64;
    data_4 += 64;
    data_5 += 64;
    data_6 += 64;
    data_7 += 64;
    num_blocks--;
  }
  /* ABEF -> DCBA */
  /* CDGH -> HGFE */
  X0 = CVHI(A0, C0, 0xB1);
  Y0 = CVLO(A0, C0, 0xB1);
  X1 = CVHI(A1, C1, 0xB1);
  Y1 = CVLO(A1, C1, 0xB1);
  X2 = CVHI(A2, C2, 0xB1);
  Y2 = CVLO(A2, C2, 0xB1);
  X3 = CVHI(A3, C3, 0xB1);
  Y3 = CVLO(A3, C3, 0xB1);
  X4 = CVHI(A4, C4, 0xB1);
  Y4 = CVLO(A4, C4, 0xB1);
  X5 = CVHI(A5, C5, 0xB1);
  Y5 = CVLO(A5, C5, 0xB1);
  X6 = CVHI(A6, C6, 0xB1);
  Y6 = CVLO(A6, C6, 0xB1);
  X7 = CVHI(A7, C7, 0xB1);
  Y7 = CVLO(A7, C7, 0xB1);

  STORE(state_0 + 0, X0);
  STORE(state_0 + 1, Y0);
  STORE(state_1 + 0, X1);
  STORE(state_1 + 1, Y1);
  STORE(state_2 + 0, X2);
  STORE(state_2 + 1, Y2);
  STORE(state_3 + 0, X3);
  STORE(state_3 + 1, Y3);
  STORE(state_4 + 0, X4);
  STORE(state_4 + 1, Y4);
  STORE(state_5 + 0, X5);
  STORE(state_5 + 1, Y5);
  STORE(state_6 + 0, X6);
  STORE(state_6 + 1, Y6);
  STORE(state_7 + 0, X7);
  STORE(state_7 + 1, Y7);
}

