#include "shani.h"

#define ZERO_128            _mm_setzero_si128()
#define LOAD_128(X)         _mm_loadu_si128((__m128i*) X)
#define STORE_128(X,Y)      _mm_storeu_si128((__m128i*) X, Y)
#define AND_128(X,Y)        _mm_and_si128(X,Y)
#define ADD_128(X,Y)        _mm_add_epi32(X,Y)
#define XOR_128(X,Y)        _mm_xor_si128(X,Y)
#define OR_128(X,Y)         _mm_or_si128(X,Y)
#define SHL_128(X,Y)        _mm_slli_epi32(X,Y)
#define SHR_128(X,Y)        _mm_srli_epi32(X,Y)
#define SHUF8_128(X,Y)      _mm_shuffle_epi8(X,Y)
#define SET1_32_128(X)	    _mm_set1_epi32(X)
#define BROAD_128(X,Y)	      \
  __asm__ __volatile(         \
    "vpbroadcastd (%1), %0 ;" \
    :/* out  */ "=x" (X)      \
    :/* in   */ "r" (Y)       \
    :/* regs */               \
  );

#define ZERO_256            _mm256_setzero_si256()
#define LOAD_256(X)         _mm256_loadu_si256((__m256i*) X)
#define STORE_256(X,Y)      _mm256_storeu_si256((__m256i*) X, Y)
#define AND_256(X,Y)        _mm256_and_si256(X,Y)
#define ADD_256(X,Y)        _mm256_add_epi32(X,Y)
#define XOR_256(X,Y)        _mm256_xor_si256(X,Y)
#define OR_256(X,Y)         _mm256_or_si256(X,Y)
#define SHL_256(X,Y)        _mm256_slli_epi32(X,Y)
#define SHR_256(X,Y)        _mm256_srli_epi32(X,Y)
#define SHUF8_256(X,Y)      _mm256_shuffle_epi8(X,Y)
#define SET1_32_256(X)	    _mm256_set1_epi32(X)
#define BROAD_256(X,Y)	      \
  __asm__ __volatile(         \
    "vpbroadcastd (%1), %0 ;" \
    :/* out  */ "=x" (X)      \
    :/* in   */ "r" (Y)       \
    :/* regs */               \
  );

#define ZERO_512            _mm512_setzero_si512()
#define LOAD_512(X)         _mm512_loadu_si512((__m512i*) X)
#define STORE_512(X,Y)      _mm512_storeu_si512((__m512i*) X, Y)
#define AND_512(X,Y)        _mm512_and_si512(X,Y)
#define ADD_512(X,Y)        _mm512_add_epi32(X,Y)
#define XOR_512(X,Y)        _mm512_xor_si512(X,Y)
#define OR_512(X,Y)         _mm512_or_si512(X,Y)
#define SHL_512(X,Y)        _mm512_slli_epi32(X,Y)
#define SHR_512(X,Y)        _mm512_srli_epi32(X,Y)
#define SHUF8_512(X,Y)      _mm512_shuffle_epi8(X,Y)
#define SET1_32_512(X)	    _mm512_set1_epi32(X)
#define BROAD_512(X,Y)	      \
  __asm__ __volatile(         \
    "vpbroadcastd (%1), %0 ;" \
    :/* out  */ "=x" (X)      \
    :/* in   */ "r" (Y)       \
    :/* regs */               \
  );

#define BLOCK_SIZE_BYTES (64)
ALIGN const uint32_t big_endian_128[4] = {0x00010203,0x04050607,0x08090a0b,0x0c0d0e0f};
ALIGN const uint32_t big_endian_256[8] = {0x00010203,0x04050607,0x08090a0b,0x0c0d0e0f,
                                          0x00010203,0x04050607,0x08090a0b,0x0c0d0e0f};
ALIGN const uint32_t big_endian_512[16] = {0x00010203,0x04050607,0x08090a0b,0x0c0d0e0f,
                                           0x00010203,0x04050607,0x08090a0b,0x0c0d0e0f,
                                           0x00010203,0x04050607,0x08090a0b,0x0c0d0e0f,
                                           0x00010203,0x04050607,0x08090a0b,0x0c0d0e0f};

#define TRANSPOSE_4WAY(W0, W1, W2, W3)  do{            \
    __m128i a0_b0_a2_b2 = _mm_unpacklo_epi32(W0, W1);  \
    __m128i a1_b1_a3_b3 = _mm_unpackhi_epi32(W0, W1);  \
    __m128i c0_d0_c2_d2 = _mm_unpacklo_epi32(W2, W3);  \
    __m128i c1_d1_c3_d3 = _mm_unpackhi_epi32(W2, W3);  \
    W0 = _mm_unpacklo_epi64(a0_b0_a2_b2, c0_d0_c2_d2); \
    W1 = _mm_unpackhi_epi64(a0_b0_a2_b2, c0_d0_c2_d2); \
    W2 = _mm_unpacklo_epi64(a1_b1_a3_b3, c1_d1_c3_d3); \
    W3 = _mm_unpackhi_epi64(a1_b1_a3_b3, c1_d1_c3_d3); \
}while(0)

#define TRANSPOSE_8WAY(W0, W1, W2, W3, W4, W5, W6, W7)  do{                                                   \
    __m256i a0_b0_c0_d0_a4_b4_c4_d4 = _mm256_permute2x128_si256(W0,W4,0x20);                                  \
    __m256i a1_b1_c1_d1_a5_b5_c5_d5 = _mm256_permute2x128_si256(W1,W5,0x20);                                  \
    __m256i a2_b2_c2_d2_a6_b6_c6_d6 = _mm256_permute2x128_si256(W2,W6,0x20);                                  \
    __m256i a3_b3_c3_d3_a7_b7_c7_d7 = _mm256_permute2x128_si256(W3,W7,0x20);                                  \
                                                                                                              \
    __m256i a0_a1_b0_b1_a4_a5_b4_b5 = _mm256_unpacklo_epi32(a0_b0_c0_d0_a4_b4_c4_d4,a1_b1_c1_d1_a5_b5_c5_d5); \
    __m256i a2_a3_b2_b3_a6_a7_b6_b7 = _mm256_unpacklo_epi32(a2_b2_c2_d2_a6_b6_c6_d6,a3_b3_c3_d3_a7_b7_c7_d7); \
    __m256i c0_c1_d0_d1_c4_c5_d4_d5 = _mm256_unpackhi_epi32(a0_b0_c0_d0_a4_b4_c4_d4,a1_b1_c1_d1_a5_b5_c5_d5); \
    __m256i c2_c3_d2_d3_c6_c7_d6_d7 = _mm256_unpackhi_epi32(a2_b2_c2_d2_a6_b6_c6_d6,a3_b3_c3_d3_a7_b7_c7_d7); \
                                                                                                              \
    __m256i a0_a1_a2_a3_a4_a5_a6_a7 = _mm256_unpacklo_epi64(a0_a1_b0_b1_a4_a5_b4_b5,a2_a3_b2_b3_a6_a7_b6_b7); \
    __m256i b0_b1_b2_b3_b4_b5_b6_b7 = _mm256_unpackhi_epi64(a0_a1_b0_b1_a4_a5_b4_b5,a2_a3_b2_b3_a6_a7_b6_b7); \
    __m256i c0_c1_c2_c3_c4_c5_c6_c7 = _mm256_unpacklo_epi64(c0_c1_d0_d1_c4_c5_d4_d5,c2_c3_d2_d3_c6_c7_d6_d7); \
    __m256i d0_d1_d2_d3_d4_d5_d6_d7 = _mm256_unpackhi_epi64(c0_c1_d0_d1_c4_c5_d4_d5,c2_c3_d2_d3_c6_c7_d6_d7); \
                                                                                                              \
    __m256i e0_f0_g0_h0_e4_f4_g4_h4 = _mm256_permute2x128_si256(W0,W4,0x31);                                  \
    __m256i e1_f1_g1_h1_e5_f5_g5_h5 = _mm256_permute2x128_si256(W1,W5,0x31);                                  \
    __m256i e2_f2_g2_h2_e6_f6_g6_h6 = _mm256_permute2x128_si256(W2,W6,0x31);                                  \
    __m256i e3_f3_g3_h3_e7_f7_g7_h7 = _mm256_permute2x128_si256(W3,W7,0x31);                                  \
                                                                                                              \
    __m256i e0_e1_f0_f1_e4_e5_f4_f5 = _mm256_unpacklo_epi32(e0_f0_g0_h0_e4_f4_g4_h4,e1_f1_g1_h1_e5_f5_g5_h5); \
    __m256i e2_e3_f2_f3_e6_e7_f6_f7 = _mm256_unpacklo_epi32(e2_f2_g2_h2_e6_f6_g6_h6,e3_f3_g3_h3_e7_f7_g7_h7); \
    __m256i g0_g1_h0_h1_g4_g5_h4_h5 = _mm256_unpackhi_epi32(e0_f0_g0_h0_e4_f4_g4_h4,e1_f1_g1_h1_e5_f5_g5_h5); \
    __m256i g2_g3_h2_h3_g6_g7_h6_h7 = _mm256_unpackhi_epi32(e2_f2_g2_h2_e6_f6_g6_h6,e3_f3_g3_h3_e7_f7_g7_h7); \
                                                                                                              \
    __m256i e0_e1_e2_e3_e4_e5_e6_e7 = _mm256_unpacklo_epi64(e0_e1_f0_f1_e4_e5_f4_f5,e2_e3_f2_f3_e6_e7_f6_f7); \
    __m256i f0_f1_f2_f3_f4_f5_f6_f7 = _mm256_unpackhi_epi64(e0_e1_f0_f1_e4_e5_f4_f5,e2_e3_f2_f3_e6_e7_f6_f7); \
    __m256i g0_g1_g2_g3_g4_g5_g6_g7 = _mm256_unpacklo_epi64(g0_g1_h0_h1_g4_g5_h4_h5,g2_g3_h2_h3_g6_g7_h6_h7); \
    __m256i h0_h1_h2_h3_h4_h5_h6_h7 = _mm256_unpackhi_epi64(g0_g1_h0_h1_g4_g5_h4_h5,g2_g3_h2_h3_g6_g7_h6_h7); \
                                                                                                              \
    W0 = a0_a1_a2_a3_a4_a5_a6_a7;                                                                             \
    W1 = b0_b1_b2_b3_b4_b5_b6_b7;                                                                             \
    W2 = c0_c1_c2_c3_c4_c5_c6_c7;                                                                             \
    W3 = d0_d1_d2_d3_d4_d5_d6_d7;                                                                             \
    W4 = e0_e1_e2_e3_e4_e5_e6_e7;                                                                             \
    W5 = f0_f1_f2_f3_f4_f5_f6_f7;                                                                             \
    W6 = g0_g1_g2_g3_g4_g5_g6_g7;                                                                             \
    W7 = h0_h1_h2_h3_h4_h5_h6_h7;                                                                             \
}while(0)


#define TRANSPOSE_16WAY(W0, W1, W2, W3, W4, W5, W6, W7, W8, W9, Wa, Wb, Wc, Wd, We, Wf)  do{                  \
    __m512i a0_b0_c0_d0_a4_b4_c4_d4 = _mm512_shuffle_i64x2(W0,W4,0x20);                                       \
    __m512i a1_b1_c1_d1_a5_b5_c5_d5 = _mm512_shuffle_i64x2(W1,W5,0x20);                                       \
    __m512i a2_b2_c2_d2_a6_b6_c6_d6 = _mm512_shuffle_i64x2(W2,W6,0x20);                                       \
    __m512i a3_b3_c3_d3_a7_b7_c7_d7 = _mm512_shuffle_i64x2(W3,W7,0x20);                                       \
                                                                                                              \
    __m512i a0_a1_b0_b1_a4_a5_b4_b5 = _mm512_unpacklo_epi32(a0_b0_c0_d0_a4_b4_c4_d4,a1_b1_c1_d1_a5_b5_c5_d5); \
    __m512i a2_a3_b2_b3_a6_a7_b6_b7 = _mm512_unpacklo_epi32(a2_b2_c2_d2_a6_b6_c6_d6,a3_b3_c3_d3_a7_b7_c7_d7); \
    __m512i c0_c1_d0_d1_c4_c5_d4_d5 = _mm512_unpackhi_epi32(a0_b0_c0_d0_a4_b4_c4_d4,a1_b1_c1_d1_a5_b5_c5_d5); \
    __m512i c2_c3_d2_d3_c6_c7_d6_d7 = _mm512_unpackhi_epi32(a2_b2_c2_d2_a6_b6_c6_d6,a3_b3_c3_d3_a7_b7_c7_d7); \
                                                                                                              \
    __m512i a0_a1_a2_a3_a4_a5_a6_a7 = _mm512_unpacklo_epi64(a0_a1_b0_b1_a4_a5_b4_b5,a2_a3_b2_b3_a6_a7_b6_b7); \
    __m512i b0_b1_b2_b3_b4_b5_b6_b7 = _mm512_unpackhi_epi64(a0_a1_b0_b1_a4_a5_b4_b5,a2_a3_b2_b3_a6_a7_b6_b7); \
    __m512i c0_c1_c2_c3_c4_c5_c6_c7 = _mm512_unpacklo_epi64(c0_c1_d0_d1_c4_c5_d4_d5,c2_c3_d2_d3_c6_c7_d6_d7); \
    __m512i d0_d1_d2_d3_d4_d5_d6_d7 = _mm512_unpackhi_epi64(c0_c1_d0_d1_c4_c5_d4_d5,c2_c3_d2_d3_c6_c7_d6_d7); \
                                                                                                              \
    __m512i e0_f0_g0_h0_e4_f4_g4_h4 = _mm512_shuffle_i64x2(W0,W4,0x31);                                       \
    __m512i e1_f1_g1_h1_e5_f5_g5_h5 = _mm512_shuffle_i64x2(W1,W5,0x31);                                       \
    __m512i e2_f2_g2_h2_e6_f6_g6_h6 = _mm512_shuffle_i64x2(W2,W6,0x31);                                       \
    __m512i e3_f3_g3_h3_e7_f7_g7_h7 = _mm512_shuffle_i64x2(W3,W7,0x31);                                       \
                                                                                                              \
    __m512i e0_e1_f0_f1_e4_e5_f4_f5 = _mm512_unpacklo_epi32(e0_f0_g0_h0_e4_f4_g4_h4,e1_f1_g1_h1_e5_f5_g5_h5); \
    __m512i e2_e3_f2_f3_e6_e7_f6_f7 = _mm512_unpacklo_epi32(e2_f2_g2_h2_e6_f6_g6_h6,e3_f3_g3_h3_e7_f7_g7_h7); \
    __m512i g0_g1_h0_h1_g4_g5_h4_h5 = _mm512_unpackhi_epi32(e0_f0_g0_h0_e4_f4_g4_h4,e1_f1_g1_h1_e5_f5_g5_h5); \
    __m512i g2_g3_h2_h3_g6_g7_h6_h7 = _mm512_unpackhi_epi32(e2_f2_g2_h2_e6_f6_g6_h6,e3_f3_g3_h3_e7_f7_g7_h7); \
                                                                                                              \
    __m512i e0_e1_e2_e3_e4_e5_e6_e7 = _mm512_unpacklo_epi64(e0_e1_f0_f1_e4_e5_f4_f5,e2_e3_f2_f3_e6_e7_f6_f7); \
    __m512i f0_f1_f2_f3_f4_f5_f6_f7 = _mm512_unpackhi_epi64(e0_e1_f0_f1_e4_e5_f4_f5,e2_e3_f2_f3_e6_e7_f6_f7); \
    __m512i g0_g1_g2_g3_g4_g5_g6_g7 = _mm512_unpacklo_epi64(g0_g1_h0_h1_g4_g5_h4_h5,g2_g3_h2_h3_g6_g7_h6_h7); \
    __m512i h0_h1_h2_h3_h4_h5_h6_h7 = _mm512_unpackhi_epi64(g0_g1_h0_h1_g4_g5_h4_h5,g2_g3_h2_h3_g6_g7_h6_h7); \
                                                                                                              \
    __m512i a8_b8_c8_d8_ac_bc_cc_dc = _mm512_shuffle_i64x2(W8,Wc,0x20);                                       \
    __m512i a9_b9_c9_d9_ad_bd_cd_dd = _mm512_shuffle_i64x2(W9,Wd,0x20);                                       \
    __m512i aa_ba_ca_da_ae_be_ce_de = _mm512_shuffle_i64x2(Wa,We,0x20);                                       \
    __m512i ab_bb_cb_db_af_bf_cf_df = _mm512_shuffle_i64x2(Wb,Wf,0x20);                                       \
                                                                                                              \
    __m512i a8_a9_b8_b9_ac_ad_bc_bd = _mm512_unpacklo_epi32(a8_b8_c8_d8_ac_bc_cc_dc,a9_b9_c9_d9_ad_bd_cd_dd); \
    __m512i aa_ab_ba_bb_ae_af_be_bf = _mm512_unpacklo_epi32(aa_ba_ca_da_ae_be_ce_de,ab_bb_cb_db_af_bf_cf_df); \
    __m512i c8_c9_d8_d9_cc_cd_dc_dd = _mm512_unpackhi_epi32(a8_b8_c8_d8_ac_bc_cc_dc,a9_b9_c9_d9_ad_bd_cd_dd); \
    __m512i ca_cb_da_db_ce_cf_de_df = _mm512_unpackhi_epi32(aa_ba_ca_da_ae_be_ce_de,ab_bb_cb_db_af_bf_cf_df); \
                                                                                                              \
    __m512i a8_a9_aa_ab_ac_ad_ae_af = _mm512_unpacklo_epi64(a8_a9_b8_b9_ac_ad_bc_bd,aa_ab_ba_bb_ae_af_be_bf); \
    __m512i b8_b9_ba_bb_bc_bd_be_bf = _mm512_unpackhi_epi64(a8_a9_b8_b9_ac_ad_bc_bd,aa_ab_ba_bb_ae_af_be_bf); \
    __m512i c8_c9_ca_cb_cc_cd_ce_cf = _mm512_unpacklo_epi64(c8_c9_d8_d9_cc_cd_dc_dd,ca_cb_da_db_ce_cf_de_df); \
    __m512i d8_d9_da_db_dc_dd_de_df = _mm512_unpackhi_epi64(c8_c9_d8_d9_cc_cd_dc_dd,ca_cb_da_db_ce_cf_de_df); \
                                                                                                              \
    __m512i e8_f8_g8_h8_ec_fc_gc_hc = _mm512_shuffle_i64x2(W8,Wc,0x31);                                       \
    __m512i e9_f9_g9_h9_ed_fd_gd_hd = _mm512_shuffle_i64x2(W9,Wd,0x31);                                       \
    __m512i ea_fa_ga_ha_ee_fe_ge_he = _mm512_shuffle_i64x2(Wa,We,0x31);                                       \
    __m512i eb_fb_gb_hb_ef_ff_gf_hf = _mm512_shuffle_i64x2(Wb,Wf,0x31);                                       \
                                                                                                              \
    __m512i e8_e9_f8_f9_ec_ed_fc_fd = _mm512_unpacklo_epi32(e8_f8_g8_h8_ec_fc_gc_hc,e9_f9_g9_h9_ed_fd_gd_hd); \
    __m512i ea_eb_fa_fb_ee_ef_fe_ff = _mm512_unpacklo_epi32(ea_fa_ga_ha_ee_fe_ge_he,eb_fb_gb_hb_ef_ff_gf_hf); \
    __m512i g8_g9_h8_h9_gc_gd_hc_hd = _mm512_unpackhi_epi32(e8_f8_g8_h8_ec_fc_gc_hc,e9_f9_g9_h9_ed_fd_gd_hd); \
    __m512i ga_gb_ha_hb_ge_gf_he_hf = _mm512_unpackhi_epi32(ea_fa_ga_ha_ee_fe_ge_he,eb_fb_gb_hb_ef_ff_gf_hf); \
                                                                                                              \
    __m512i e8_e9_ea_eb_ec_ed_ee_ef = _mm512_unpacklo_epi64(e8_e9_f8_f9_ec_ed_fc_fd,ea_eb_fa_fb_ee_ef_fe_ff); \
    __m512i f8_f9_fa_fb_fc_fd_fe_ff = _mm512_unpackhi_epi64(e8_e9_f8_f9_ec_ed_fc_fd,ea_eb_fa_fb_ee_ef_fe_ff); \
    __m512i g8_g9_ga_gb_gc_gd_ge_gf = _mm512_unpacklo_epi64(g8_g9_h8_h9_gc_gd_hc_hd,ga_gb_ha_hb_ge_gf_he_hf); \
    __m512i h8_h9_ha_hb_hc_hd_he_hf = _mm512_unpackhi_epi64(g8_g9_h8_h9_gc_gd_hc_hd,ga_gb_ha_hb_ge_gf_he_hf); \
                                                                                                              \
    W0 = a0_a1_a2_a3_a4_a5_a6_a7;         W8 = a8_a9_aa_ab_ac_ad_ae_af;                                       \
    W1 = b0_b1_b2_b3_b4_b5_b6_b7;         W9 = b8_b9_ba_bb_bc_bd_be_bf;                                       \
    W2 = c0_c1_c2_c3_c4_c5_c6_c7;         Wa = c8_c9_ca_cb_cc_cd_ce_cf;                                       \
    W3 = d0_d1_d2_d3_d4_d5_d6_d7;         Wb = d8_d9_da_db_dc_dd_de_df;                                       \
    W4 = e0_e1_e2_e3_e4_e5_e6_e7;         Wc = e8_e9_ea_eb_ec_ed_ee_ef;                                       \
    W5 = f0_f1_f2_f3_f4_f5_f6_f7;         Wd = f8_f9_fa_fb_fc_fd_fe_ff;                                       \
    W6 = g0_g1_g2_g3_g4_g5_g6_g7;         We = g8_g9_ga_gb_gc_gd_ge_gf;                                       \
    W7 = h0_h1_h2_h3_h4_h5_h6_h7;         Wf = h8_h9_ha_hb_hc_hd_he_hf;                                       \
}while(0)

static inline void transpose_state_128(__m128i *w) {
  TRANSPOSE_4WAY(w[0x0], w[0x1], w[0x2], w[0x3]);
  TRANSPOSE_4WAY(w[0x4], w[0x5], w[0x6], w[0x7]);
}

static inline void transpose_msg_128(__m128i *w) {
  TRANSPOSE_4WAY(w[0x0], w[0x1], w[0x2], w[0x3]);
  TRANSPOSE_4WAY(w[0x4], w[0x5], w[0x6], w[0x7]);
  TRANSPOSE_4WAY(w[0x8], w[0x9], w[0xa], w[0xb]);
  TRANSPOSE_4WAY(w[0xc], w[0xd], w[0xe], w[0xf]);
}

static inline void transpose_state_256(__m256i *w) {
  TRANSPOSE_8WAY(w[0x0], w[0x1], w[0x2], w[0x3], w[0x4], w[0x5], w[0x6], w[0x7]);
}

static inline void transpose_msg_256(__m256i *w) {
  TRANSPOSE_8WAY(w[0x0], w[0x1], w[0x2], w[0x3], w[0x4], w[0x5], w[0x6], w[0x7]);
  TRANSPOSE_8WAY(w[0x8], w[0x9], w[0xa], w[0xb], w[0xc], w[0xd], w[0xe], w[0xf]);
}

static inline void transpose_state_512(__m512i *w) {
//  TRANSPOSE_16WAY(w[0x0], w[0x1], w[0x2], w[0x3], w[0x4], w[0x5], w[0x6], w[0x7]);
}

static inline void transpose_msg_512(__m512i *w) {
  TRANSPOSE_16WAY(w[0x0], w[0x1], w[0x2], w[0x3], w[0x4], w[0x5], w[0x6], w[0x7],
                  w[0x8], w[0x9], w[0xa], w[0xb], w[0xc], w[0xd], w[0xe], w[0xf]);
}

#define def_initialize(TYPE)                \
static inline void initialize_ ## TYPE(     \
  __m ## TYPE ## i state[8]) {              \
  state[0] = SET1_32_ ## TYPE(0x6a09e667);  \
  state[1] = SET1_32_ ## TYPE(0xbb67ae85);  \
  state[2] = SET1_32_ ## TYPE(0x3c6ef372);  \
  state[3] = SET1_32_ ## TYPE(0xa54ff53a);  \
  state[4] = SET1_32_ ## TYPE(0x510e527f);  \
  state[5] = SET1_32_ ## TYPE(0x9b05688c);  \
  state[6] = SET1_32_ ## TYPE(0x1f83d9ab);  \
  state[7] = SET1_32_ ## TYPE(0x5be0cd19);  \
}

#define def_computeT1(TYPE) \
static inline __m ## TYPE ## i computeT1_ ## TYPE( \
    __m ## TYPE ## i e,     \
    __m ## TYPE ## i f,     \
    __m ## TYPE ## i g,     \
    __m ## TYPE ## i h) {   \
  __m ## TYPE ## i t0, t1, t2, t3, t4, t5, T1; \
  t0 = SHL_ ## TYPE(e, 32 - (6));  \
  t1 = SHL_ ## TYPE(e, 32 - (11)); \
  t2 = SHL_ ## TYPE(e, 32 - (25)); \
  t3 = SHR_ ## TYPE(e, (6));       \
  t4 = SHR_ ## TYPE(e, (11));      \
  t5 = SHR_ ## TYPE(e, (25));      \
  t3 = OR_  ## TYPE(t3, t0);       \
  t0 = XOR_ ## TYPE(f, g);         \
  t4 = OR_  ## TYPE(t4, t1);       \
  t5 = OR_  ## TYPE(t5, t2);       \
  t4 = XOR_ ## TYPE(t3, t4);       \
  t0 = AND_ ## TYPE(t0, e);        \
  t4 = XOR_ ## TYPE(t4, t5);       \
  T1 = ADD_ ## TYPE(h, t4);        \
  t0 = XOR_ ## TYPE(t0, g);        \
  T1 = ADD_ ## TYPE(T1, t0);       \
  return T1;                       \
}

#define def_computeT2(TYPE)        \
static inline __m ## TYPE ## i computeT2_ ## TYPE( \
    __m ## TYPE ## i a,            \
    __m ## TYPE ## i b,            \
    __m ## TYPE ## i c) {          \
  __m ## TYPE ## i s0, s1, s2, s3, s4, s5, T2; \
  s0 = OR_  ## TYPE(b, c);         \
  T2 = AND_ ## TYPE(b, c);         \
  s0 = AND_ ## TYPE(a, s0);        \
  s1 = SHL_ ## TYPE(a, 32 - (2));  \
  s2 = SHL_ ## TYPE(a, 32 - (13)); \
  s3 = SHL_ ## TYPE(a, 32 - (22)); \
  s4 = SHR_ ## TYPE(a, (2));       \
  s5 = SHR_ ## TYPE(a, (13));      \
  s4 = OR_  ## TYPE(s4, s1);       \
  s5 = OR_  ## TYPE(s5, s2);       \
  s1 = SHR_ ## TYPE(a, (22));      \
  s0 = OR_  ## TYPE(T2, s0);       \
  s1 = OR_  ## TYPE(s1, s3);       \
  s4 = XOR_ ## TYPE(s4, s5);       \
  T2 = XOR_ ## TYPE(s4, s1);       \
  T2 = ADD_ ## TYPE(T2, s0);       \
  return T2;                       \
}

#define def_msg_schedule(TYPE)              \
static inline __m ## TYPE ## i msg_schedule_ ## TYPE( \
  __m ## TYPE ## i * W,  uint8_t i) {       \
  __m ## TYPE ## i Wi, t1, t2, t3, t4, t5, t6, t7; \
  t1 = SHL_ ## TYPE(W[i - 2], 32 - (17));   \
  t2 = SHL_ ## TYPE(W[i - 2], 32 - (19));   \
  t3 = SHR_ ## TYPE(W[i - 2], 17);          \
  t4 = SHR_ ## TYPE(W[i - 2], 19);          \
  t7 = OR_  ## TYPE(t1, t3);                \
  t4 = OR_  ## TYPE(t2, t4);                \
  t5 = SHR_ ## TYPE((W[i - 2]), 10);        \
  t7 = XOR_ ## TYPE(t7, t4);                \
  t1 = SHR_ ## TYPE(W[i - 15], (7));        \
  t2 = SHR_ ## TYPE(W[i - 15], (18));       \
  t3 = SHL_ ## TYPE(W[i - 15], 32 - (7));   \
  t4 = SHL_ ## TYPE(W[i - 15], 32 - (18));  \
  t7 = XOR_ ## TYPE(t7, t5);                \
  t6 = OR_  ## TYPE(t1, t3);                \
  t4 = OR_  ## TYPE(t2, t4);                \
  t5 = SHR_ ## TYPE((W[i - 15]), 3);        \
  t6 = XOR_ ## TYPE(t6, t4);                \
  t7 = ADD_ ## TYPE(t7, W[i - 7]);          \
  t6 = XOR_ ## TYPE(t6, t5);                \
  t6 = ADD_ ## TYPE(t6, W[i - 16]);         \
  Wi = ADD_ ## TYPE(t7, t6);                \
  return Wi;                                \
}

#define def_sha256_permutation(TYPE)                            \
static inline void sha256_permutation_ ## TYPE(                 \
  __m ## TYPE ## i *state,                                      \
  __m ## TYPE ## i *message_block) {                            \
  int i;                                                        \
  __m ## TYPE ## i a, b, c, d, e, f, g, h;                      \
  __m ## TYPE ## i T1, T2, Ki;                                  \
  a = state[0];  b = state[1];  c = state[2];  d = state[3];    \
  e = state[4];  f = state[5];  g = state[6];  h = state[7];    \
  for (i = 0; i < 16; i++) {                                    \
    T1 = computeT1_ ## TYPE(e, f, g, h);                        \
    T2 = computeT2_ ## TYPE(a, b, c);                           \
    BROAD_ ## TYPE(Ki, CONST_K + i);                            \
    T1 = ADD_ ## TYPE(T1, ADD_ ## TYPE(Ki, message_block[i]));  \
    h = g;  g = f;  f = e;  e = ADD_ ## TYPE(d, T1);            \
    d = c;  c = b;  b = a;  a = ADD_ ## TYPE(T1, T2);           \
  }                                                             \
  for (i = 16; i < 64; i++) {                                   \
    message_block[i] = msg_schedule_ ## TYPE(message_block,i);  \
    T1 = computeT1_ ## TYPE(e, f, g, h);                        \
    T2 = computeT2_ ## TYPE(a, b, c);                           \
    BROAD_ ## TYPE(Ki, CONST_K + i);                            \
    T1 = ADD_ ## TYPE(T1, ADD_ ## TYPE(Ki, message_block[i]));  \
    h = g;  g = f;  f = e;  e = ADD_ ## TYPE(d, T1);            \
    d = c;  c = b;  b = a;  a = ADD_ ## TYPE(T1, T2);           \
  }                                                             \
  state[0] = ADD_ ## TYPE(state[0], a);  state[1] = ADD_ ## TYPE(state[1], b);  \
  state[2] = ADD_ ## TYPE(state[2], c);  state[3] = ADD_ ## TYPE(state[3], d);  \
  state[4] = ADD_ ## TYPE(state[4], e);  state[5] = ADD_ ## TYPE(state[5], f);  \
  state[6] = ADD_ ## TYPE(state[6], g);  state[7] = ADD_ ## TYPE(state[7], h);  \
}

/**
 * [TODO] Hashing messages of 256 bytes.
 **/
#define def_sha256_vec_256b(NUM,TYPE)  \
void sha256_vec_ ## NUM ## 256b (      \
  uint8_t *message[NUM],               \
  uint8_t *digest[NUM]) {              \
  __m ## TYPE ## i big_endian = LOAD_ ## TYPE(big_endian_ ## TYPE); \
  int msg = 0;                         \
  unsigned int b = 0;                  \
  ALIGN __m ## TYPE ## i state[8];     \
  ALIGN __m ## TYPE ## i block[64];    \
                                       \
  initialize_ ## TYPE(state);          \
  for (msg = 0; msg < 4; msg++) {      \
    for (b = 0; b < ((NUM)/2); b++) {  \
      block[msg+b] = SHUF8_ ## TYPE(LOAD_ ## TYPE(message[msg] + 4*b), big_endian); \
    }                                  \
  }                                    \
  block[8] = SET1_32_ ## TYPE(0x80000000);  \
  for (b = 9; b < 15; b++) {           \
    block[b] = ZERO_ ## TYPE;          \
  }                                    \
  block[15] = SET1_32_ ## TYPE(256);   \
  transpose_state_ ## TYPE(state);     \
  sha256_permutation_ ## TYPE(state, block);  \
  transpose_state_ ## TYPE(state);     \
  for (msg = 0; msg < NUM; msg++) {    \
    for (b = 0; b < ((NUM)/2); b++) {  \
      STORE_ ## TYPE(digest[msg] + b, SHUF8_ ## TYPE(state[msg+4*b], big_endian)); \
    }                                  \
  }                                    \
}


#define sha256_Nw(NUM,TYPE)       \
void sha256_ ## NUM ## w(         \
    uint8_t *message[NUM],        \
    unsigned int message_length,  \
    uint8_t *digest[NUM]) {       \
  int i = 0, msg = 0;\
  unsigned int b = 0;\
  const unsigned int num_blocks = message_length >> 6; \
  const unsigned int remainder_bytes = message_length - (num_blocks << 6);\
  const uint64_t mlen_bits = message_length * 8;\
  ALIGN __m ## TYPE ## i state[8];\
  ALIGN __m ## TYPE ## i block[BLOCK_SIZE_BYTES];\
  __m ## TYPE ## i big_endian = LOAD_ ## TYPE(big_endian_ ## TYPE); \
  ALIGN uint8_t buffer[BLOCK_SIZE_BYTES*NUM] = {0}; \
  initialize_## TYPE (state);\
  for (b = 0; b < num_blocks; b++) { \
    /* Load a 512-bit message_4x */ \
    for (msg = 0; msg < NUM; msg++) {\
      for (i = 0; i < (16/(NUM)); i++) {\
        block[NUM * i + msg] = SHUF8_ ## TYPE(LOAD_ ## TYPE(message[msg] + (16 / (NUM)) * b + i), big_endian);\
      }\
    }\
    transpose_msg_ ## TYPE(block);\
    sha256_permutation_ ## TYPE(state, block);\
  }\
  /* Load a remainder of the message_4x */\
  if (remainder_bytes < 56) { \
    for (msg = 0; msg < NUM; msg++) {\
      for (b = 0; b < remainder_bytes; b++) {\
        buffer[BLOCK_SIZE_BYTES*msg+b] = message[msg][BLOCK_SIZE_BYTES*num_blocks+b];\
      }\
      buffer[BLOCK_SIZE_BYTES*msg+remainder_bytes] = 0x80;\
      for (b = 0; b < 8; b++) {\
        buffer[BLOCK_SIZE_BYTES*(msg+1)-1-b] = (uint8_t)((mlen_bits>>(8*b))&0xFF);\
      }\
    }\
    for (msg = 0; msg < NUM; msg++) {\
      for (i = 0; i < (16/(NUM)); i++) {\
        block[NUM * i + msg ] = SHUF8_ ## TYPE(LOAD_ ## TYPE(buffer + (16 / (NUM)) * msg + i ), big_endian); \
      } \
    }\
    transpose_msg_ ## TYPE(block);\
    sha256_permutation_ ## TYPE(state, block);\
  } else if (remainder_bytes < 64) { \
    /* Load a 512-bit message_4x */\
    for (msg = 0; msg < NUM; msg++) {\
      for (b = 0; b < remainder_bytes; b++) {\
        buffer[BLOCK_SIZE_BYTES*msg+b] = message[msg][BLOCK_SIZE_BYTES*num_blocks+b];\
      }\
      buffer[BLOCK_SIZE_BYTES*msg+remainder_bytes] = 0x80;\
    }\
    for (msg = 0; msg < NUM; msg++) {\
      for (i = 0; i < (16/(NUM)); i++) {\
        block[NUM *i + msg ] = SHUF8_ ## TYPE(LOAD_ ## TYPE(buffer + (16 / (NUM)) * msg + i ), big_endian); \
      }\
    }\
    transpose_msg_ ## TYPE(block);\
    sha256_permutation_ ## TYPE(state, block);\
    for (msg = 0; msg < NUM; msg++) {\
      for (b = 0; b < 56; b++) {\
        buffer[BLOCK_SIZE_BYTES*msg+b] = 0x00;\
      }\
      for (b = 0; b < 8; b++) {\
        buffer[BLOCK_SIZE_BYTES*(msg+1)-1-b] = (uint8_t)((mlen_bits>>(8*b))&0xFF);\
      }\
    }\
    for (msg = 0; msg < NUM; msg++) {\
      for (i = 0; i < (16/(NUM)); i++) {\
        block[NUM * i + msg ] = SHUF8_ ## TYPE(LOAD_ ## TYPE(buffer + (16 / (NUM)) * msg + i ), big_endian); \
      }\
    }\
    transpose_msg_ ## TYPE(block);\
    sha256_permutation_ ## TYPE(state, block);\
  }\
  transpose_state_ ## TYPE(state);\
  for (msg = 0; msg < NUM; msg++) {\
    for (b = 0; b < (8/(NUM)); b++) {\
      STORE_ ## TYPE(digest[msg] + b, SHUF8_ ## TYPE(state[NUM*b+msg], big_endian));\
    }\
  }\
}

#define define_sha256(NUM,TYPE)  \
  def_initialize(TYPE)           \
  def_computeT1(TYPE)            \
  def_computeT2(TYPE)            \
  def_msg_schedule(TYPE)         \
  def_sha256_permutation(TYPE)   \
  /*def_sha256_vec_256b(NUM,TYPE) */ \
  sha256_Nw(NUM,TYPE)

define_sha256(4,128)
define_sha256(8,256)
