/*
 * The MIT License (MIT)
 * Copyright (c) 2016 XMSS Ana Karina De Oliveira (update in 04-2016)
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
 * DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
 * OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE
 * OR OTHER DEALINGS IN THE SOFTWARE.
 */
 
#include <stdlib.h>

void randomNumbers(skXMSS *sk);

void PRG(uIntHash *r, u64 rlen, u8 n, u32 *key32);

void PRG_4way(uIntHash *r, u64 rlen, u8 n, u32 *key32);

void PRG_8way(uIntHash *r, u64 rlen, u8 n, u32 *key32);

void F(u32 *state, u32 *KEY, u32 *M);

void F_4way(__m128i *init, __m128i *KEY128, __m128i *M, __m128i *PADSHA128 );

void F_8way(__m256i *init, __m256i *KEY256, __m256i *M, __m256i *PADSHA256 );

void H(uIntHash out, u32 *KEY, u32 *M );

void H_msg(uIntHash out, u8 *KEY, unsigned int keylen, u8 *M, u8 n);

void RAND_HASH(uIntHash out, uIntHash in1, uIntHash in2, u32 *pub_seed, u32 *ADRS32);

void PRF(u32 *state, u32 *KEY, u32 *M);

void PRF_4way(__m128i init[8], __m128i *KEY, __m128i M[8]);

void PRF_8way(__m256i init[8], __m256i *KEY, __m256i M[8]);

void H_8way(u32_8 *out64, __m256i KEY256[8], __m256i *M, int posit);

void RAND_HASH_8way(u32_8 *out, u32_8 *in, int posit, u32 *pub_seed, u32 ADRS32[8][8]);
