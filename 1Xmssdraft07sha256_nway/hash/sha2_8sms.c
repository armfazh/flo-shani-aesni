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
#include <stdio.h>
#include <stdlib.h>
#include <wmmintrin.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <x86intrin.h>

#ifndef __XOP__
#define _mm256_roti_epi32(x, n)                         \
    _mm256_or_si256 (                                   \
        _mm256_srli_epi32(x, ~n + 1),                   \
        _mm256_slli_epi32(x, 32 + n)                    \
    )                                                \

#endif
//Rot(x, n)=( slli((x),32+(-n)) | srli((x),~(n)+1)) )
//Ch(x,y,z)=(xey)xor(~xez)
//ch(e,f,g)=((((f) ^ (g)) & (e)) ^ (g))
//Maj(x,y,z)=(xey)xor(xez)xor(yez)
//maj(a,b,c) ((((b) | (c)) & (a))|((b) & (c)))
//Sig0=Rot2xorRot13xorRot22
//Sig1=Rot6xorRot11xorRot25
//T1=Sig1(e)+ch(e,f,g)+Kt+Wt+h
//T2=Sig0(a)+maj(a,b,c)
//a=T1+T2;b=a;c=b;d=c;e=d+T1;f=e;g=f;h=g;

void computeT1(__m256i T[8], __m256i *e,__m256i *f,__m256i *g,__m256i *h,  __m256i wt[64], int x){
	// ch=T[0];

	T[6]=_mm256_set1_epi32(K[x]);
	//ROT(T, e);
	T[0]=_mm256_slli_epi32(*e, 32 - (6));
	T[1]=_mm256_slli_epi32(*e, 32 - (11));
	T[2]=_mm256_slli_epi32(*e, 32 - (25));
	T[3]=_mm256_srli_epi32(*e, (6));
	T[4]=_mm256_srli_epi32(*e, (11));
	T[5]=_mm256_srli_epi32(*e, (25));
	T[3]=_mm256_or_si256 (T[3],T[0]);
	T[4]=_mm256_or_si256 (T[4],T[1]);
	T[5]=_mm256_or_si256 (T[5],T[2]);
	T[6]= _mm256_add_epi32 (wt[x],T[6]);
	T[0]= _mm256_xor_si256 (*f,*g);
	T[6]= _mm256_add_epi32 (*h, T[6]);
	T[4]= _mm256_xor_si256 (T[3],T[4]);
	T[0]= _mm256_and_si256 (T[0],*e);
	T[4]= _mm256_xor_si256 (T[4],T[5]);
	T[6]= _mm256_add_epi32 (T[6], T[4]);
	T[0]= _mm256_xor_si256 (T[0],*g);
	T[6]= _mm256_add_epi32 (T[0],T[6]);
}
void computeT2(__m256i T[8], __m256i *a,__m256i *b,__m256i *c){
	//maj=T[0]
	T[0]=_mm256_or_si256 (*b, *c);
	T[7]= _mm256_and_si256 (*b, *c);
	T[0]=_mm256_and_si256 (*a,T[0]);
	T[1]=_mm256_slli_epi32(*a, 32 - (2));
	T[2]=_mm256_slli_epi32(*a, 32 - (13));
	T[3]=_mm256_slli_epi32(*a, 32 - (22));
	T[4]= _mm256_srli_epi32(*a, (2));
	T[5]= _mm256_srli_epi32(*a, (13));
	T[4]=_mm256_or_si256 (T[4],T[1]);
	T[5]=_mm256_or_si256 (T[5],T[2]);
	T[1]= _mm256_srli_epi32(*a, (22));
	T[0]=_mm256_or_si256 (T[7],T[0]);
	T[1]=_mm256_or_si256 (T[1],T[3]);
	T[4]=_mm256_xor_si256 (T[4],T[5]);
	T[7]= _mm256_xor_si256 (T[4],T[1]);
	T[7]= _mm256_add_epi32 (T[7], T[0]);
}

void SHA256_STEPn(__m256i T[8], __m256i *a,__m256i *b,__m256i *c,__m256i *e,__m256i *f,__m256i *g,__m256i *h,__m256i wt[64], int x){
	//T1=T[6],T2=T[7];
	computeT1(T, e,f,g,h,wt,x);
	computeT2(T, a,b,c);
}
//t[6](x)=Rot7xorRot18xorRot[3]
//t[7](x)=Rot17xorRot19xorRot10
//se (t<=15)Wt=Mt
//senão Wt=t[7](W_{t-2})+W_{t-7}+t[6](W_{t-15})+(W_{t-16})
// ROTL32(x, n)   SPH_t[3]2(((x) << (n)) | ((x) >> (32 - (n))))
void SHA256_STEP1(__m256i T[8],__m256i *a,__m256i *b,__m256i *c,__m256i *e,__m256i *f,__m256i *g,__m256i *h,  __m256i wt[64], int x){
	//sig0=t[6], sig1=t[7]
	__m256i t[8];

	t[1]=_mm256_slli_epi32(wt[x-2], 32 - (17));
	t[2]=_mm256_slli_epi32(wt[x-2], 32 - (19));
	t[3]=_mm256_srli_epi32(wt[x-2], 17);
    	t[4]=_mm256_srli_epi32(wt[x-2], 19);
	t[7]=_mm256_or_si256 (t[1],t[3]);
	t[4]=_mm256_or_si256 (t[2],t[4]);
	t[5]=_mm256_srli_epi32 ((wt[x-2]), 10);
	t[7]=_mm256_xor_si256(t[7],t[4]);
	t[1]=_mm256_srli_epi32(wt[x-15], (7));
	t[2]=_mm256_srli_epi32(wt[x-15], (18));
	t[3]=_mm256_slli_epi32(wt[x-15], 32 - (7));
	t[4]=_mm256_slli_epi32(wt[x-15], 32 - (18));
	t[7]=_mm256_xor_si256(t[7],t[5]);
	t[6]=_mm256_or_si256 (t[1],t[3]);
	t[4]=_mm256_or_si256 (t[2],t[4]);
	t[5]=_mm256_srli_epi32 ((wt[x-15]), 3);
	t[6]=_mm256_xor_si256(t[6],t[4]);
	t[7] = _mm256_add_epi32 (t[7], wt[x-7]);
	t[6]=_mm256_xor_si256(t[6],t[5]);
	t[6] = _mm256_add_epi32 (t[6], wt[x-16]);
	wt[x] = _mm256_add_epi32 (t[7],t[6]);
	SHA256_STEPn(T, (a),(b),(c),(e),(f),(g),(h),wt,x);
}

static inline void sha256_8sms (__m256i buffer[16], __m256i init[8])
{
    int i;
    __m256i a, b, c, d, e, f, g, h;
    __m256i wt[64];
    __m256i T[8];

    a = init[0]; e = init[4];
    b = init[1]; f = init[5];
    c = init[2]; g = init[6];
    d = init[3]; h = init[7];
    for(i=0;i<16;i++) wt[i]=buffer[i];

    for(i=0;i<16;i++){
    	SHA256_STEPn(T, &a, &b, &c, &e, &f, &g, &h, wt, i);
	h=g;g=f;f=e;e=_mm256_add_epi32 (d, T[6]);
	d=c;c=b;b=a;a=_mm256_add_epi32 (T[6], T[7]);
    }
    for(i=16;i<64;i++){
	SHA256_STEP1(T, &a, &b, &c, &e, &f, &g, &h, wt, i);
	h=g;g=f;f=e;e=_mm256_add_epi32 (d, T[6]);
	d=c;c=b;b=a;a=_mm256_add_epi32 (T[6], T[7]);
    }

    init[0] = _mm256_add_epi32 (a, init[0]);
    init[1] = _mm256_add_epi32 (b, init[1]);
    init[2] = _mm256_add_epi32 (c, init[2]);
    init[3] = _mm256_add_epi32 (d, init[3]);
    init[4] = _mm256_add_epi32 (e, init[4]);
    init[5] = _mm256_add_epi32 (f, init[5]);
    init[6] = _mm256_add_epi32 (g, init[6]);
    init[7] = _mm256_add_epi32 (h, init[7]);
}

void initialize(__m256i init[8])
{
    init[0] = _mm256_set1_epi32(0x6a09e667);
    init[1] = _mm256_set1_epi32(0xbb67ae85);
    init[2] = _mm256_set1_epi32(0x3c6ef372);
    init[3] = _mm256_set1_epi32(0xa54ff53a);
    init[4] = _mm256_set1_epi32(0x510e527f);
    init[5] = _mm256_set1_epi32(0x9b05688c);
    init[6] = _mm256_set1_epi32(0x1f83d9ab);
    init[7] = _mm256_set1_epi32(0x5be0cd19);
}

void transposta_zip(__m256i w[16])
{

	__m256i a0_b0_c0_d0_a4_b4_c4_d4 = _mm256_permute2x128_si256(w[0],w[4],0x20);
	__m256i a1_b1_c1_d1_a5_b5_c5_d5 = _mm256_permute2x128_si256(w[1],w[5],0x20);
	__m256i a2_b2_c2_d2_a6_b6_c6_d6 = _mm256_permute2x128_si256(w[2],w[6],0x20);
	__m256i a3_b3_c3_d3_a7_b7_c7_d7 = _mm256_permute2x128_si256(w[3],w[7],0x20);

	__m256i a0_a1_b0_b1_a4_a5_b4_b5 = _mm256_unpacklo_epi32(a0_b0_c0_d0_a4_b4_c4_d4,a1_b1_c1_d1_a5_b5_c5_d5);
	__m256i a2_a3_b2_b3_a6_a7_b6_b7 = _mm256_unpacklo_epi32(a2_b2_c2_d2_a6_b6_c6_d6,a3_b3_c3_d3_a7_b7_c7_d7);
	__m256i c0_c1_d0_d1_c4_c5_d4_d5 = _mm256_unpackhi_epi32(a0_b0_c0_d0_a4_b4_c4_d4,a1_b1_c1_d1_a5_b5_c5_d5);
	__m256i c2_c3_d2_d3_c6_c7_d6_d7 = _mm256_unpackhi_epi32(a2_b2_c2_d2_a6_b6_c6_d6,a3_b3_c3_d3_a7_b7_c7_d7);

	__m256i a0_a1_a2_a3_a4_a5_a6_a7 = _mm256_unpacklo_epi64(a0_a1_b0_b1_a4_a5_b4_b5,a2_a3_b2_b3_a6_a7_b6_b7);
	__m256i b0_b1_b2_b3_b4_b5_b6_b7 = _mm256_unpackhi_epi64(a0_a1_b0_b1_a4_a5_b4_b5,a2_a3_b2_b3_a6_a7_b6_b7);
	__m256i c0_c1_c2_c3_c4_c5_c6_c7 = _mm256_unpacklo_epi64(c0_c1_d0_d1_c4_c5_d4_d5,c2_c3_d2_d3_c6_c7_d6_d7);
	__m256i d0_d1_d2_d3_d4_d5_d6_d7 = _mm256_unpackhi_epi64(c0_c1_d0_d1_c4_c5_d4_d5,c2_c3_d2_d3_c6_c7_d6_d7);

	__m256i e0_f0_g0_h0_e4_f4_g4_h4 = _mm256_permute2x128_si256(w[0],w[4],0x31);
	__m256i e1_f1_g1_h1_e5_f5_g5_h5 = _mm256_permute2x128_si256(w[1],w[5],0x31);
	__m256i e2_f2_g2_h2_e6_f6_g6_h6 = _mm256_permute2x128_si256(w[2],w[6],0x31);
	__m256i e3_f3_g3_h3_e7_f7_g7_h7 = _mm256_permute2x128_si256(w[3],w[7],0x31);

	__m256i e0_e1_f0_f1_e4_e5_f4_f5 = _mm256_unpacklo_epi32(e0_f0_g0_h0_e4_f4_g4_h4,e1_f1_g1_h1_e5_f5_g5_h5);
	__m256i e2_e3_f2_f3_e6_e7_f6_f7 = _mm256_unpacklo_epi32(e2_f2_g2_h2_e6_f6_g6_h6,e3_f3_g3_h3_e7_f7_g7_h7);
	__m256i g0_g1_h0_h1_g4_g5_h4_h5 = _mm256_unpackhi_epi32(e0_f0_g0_h0_e4_f4_g4_h4,e1_f1_g1_h1_e5_f5_g5_h5);
	__m256i g2_g3_h2_h3_g6_g7_h6_h7 = _mm256_unpackhi_epi32(e2_f2_g2_h2_e6_f6_g6_h6,e3_f3_g3_h3_e7_f7_g7_h7);

	__m256i e0_e1_e2_e3_e4_e5_e6_e7 = _mm256_unpacklo_epi64(e0_e1_f0_f1_e4_e5_f4_f5,e2_e3_f2_f3_e6_e7_f6_f7);
	__m256i f0_f1_f2_f3_f4_f5_f6_f7 = _mm256_unpackhi_epi64(e0_e1_f0_f1_e4_e5_f4_f5,e2_e3_f2_f3_e6_e7_f6_f7);
	__m256i g0_g1_g2_g3_g4_g5_g6_g7 = _mm256_unpacklo_epi64(g0_g1_h0_h1_g4_g5_h4_h5,g2_g3_h2_h3_g6_g7_h6_h7);
	__m256i h0_h1_h2_h3_h4_h5_h6_h7 = _mm256_unpackhi_epi64(g0_g1_h0_h1_g4_g5_h4_h5,g2_g3_h2_h3_g6_g7_h6_h7);

	w[1]=a0_a1_a2_a3_a4_a5_a6_a7;\
	w[0]=b0_b1_b2_b3_b4_b5_b6_b7;\
	w[3]=c0_c1_c2_c3_c4_c5_c6_c7;\
	w[2]=d0_d1_d2_d3_d4_d5_d6_d7;\
	w[5]=e0_e1_e2_e3_e4_e5_e6_e7;\
	w[4]=f0_f1_f2_f3_f4_f5_f6_f7;\
	w[7]=g0_g1_g2_g3_g4_g5_g6_g7;\
	w[6]=h0_h1_h2_h3_h4_h5_h6_h7;\


}

void transposta_unzip(__m256i w[16])
{

	__m256i a0_b0_c0_d0_a4_b4_c4_d4 = _mm256_permute2x128_si256(w[0],w[4],0x20);
	__m256i a1_b1_c1_d1_a5_b5_c5_d5 = _mm256_permute2x128_si256(w[1],w[5],0x20);
	__m256i a2_b2_c2_d2_a6_b6_c6_d6 = _mm256_permute2x128_si256(w[2],w[6],0x20);
	__m256i a3_b3_c3_d3_a7_b7_c7_d7 = _mm256_permute2x128_si256(w[3],w[7],0x20);

	__m256i a0_a1_b0_b1_a4_a5_b4_b5 = _mm256_unpacklo_epi32(a1_b1_c1_d1_a5_b5_c5_d5,a0_b0_c0_d0_a4_b4_c4_d4);
	__m256i a2_a3_b2_b3_a6_a7_b6_b7 = _mm256_unpacklo_epi32(a3_b3_c3_d3_a7_b7_c7_d7,a2_b2_c2_d2_a6_b6_c6_d6);
	__m256i c0_c1_d0_d1_c4_c5_d4_d5 = _mm256_unpackhi_epi32(a1_b1_c1_d1_a5_b5_c5_d5,a0_b0_c0_d0_a4_b4_c4_d4);
	__m256i c2_c3_d2_d3_c6_c7_d6_d7 = _mm256_unpackhi_epi32(a3_b3_c3_d3_a7_b7_c7_d7,a2_b2_c2_d2_a6_b6_c6_d6);

	__m256i a0_a1_a2_a3_a4_a5_a6_a7 = _mm256_unpacklo_epi64(a0_a1_b0_b1_a4_a5_b4_b5,a2_a3_b2_b3_a6_a7_b6_b7);
	__m256i b0_b1_b2_b3_b4_b5_b6_b7 = _mm256_unpackhi_epi64(a0_a1_b0_b1_a4_a5_b4_b5,a2_a3_b2_b3_a6_a7_b6_b7);
	__m256i c0_c1_c2_c3_c4_c5_c6_c7 = _mm256_unpacklo_epi64(c0_c1_d0_d1_c4_c5_d4_d5,c2_c3_d2_d3_c6_c7_d6_d7);
	__m256i d0_d1_d2_d3_d4_d5_d6_d7 = _mm256_unpackhi_epi64(c0_c1_d0_d1_c4_c5_d4_d5,c2_c3_d2_d3_c6_c7_d6_d7);

	__m256i e0_f0_g0_h0_e4_f4_g4_h4 = _mm256_permute2x128_si256(w[0],w[4],0x31);
	__m256i e1_f1_g1_h1_e5_f5_g5_h5 = _mm256_permute2x128_si256(w[1],w[5],0x31);
	__m256i e2_f2_g2_h2_e6_f6_g6_h6 = _mm256_permute2x128_si256(w[2],w[6],0x31);
	__m256i e3_f3_g3_h3_e7_f7_g7_h7 = _mm256_permute2x128_si256(w[3],w[7],0x31);

	__m256i e0_e1_f0_f1_e4_e5_f4_f5 = _mm256_unpacklo_epi32(e1_f1_g1_h1_e5_f5_g5_h5,e0_f0_g0_h0_e4_f4_g4_h4);
	__m256i e2_e3_f2_f3_e6_e7_f6_f7 = _mm256_unpacklo_epi32(e3_f3_g3_h3_e7_f7_g7_h7,e2_f2_g2_h2_e6_f6_g6_h6);
	__m256i g0_g1_h0_h1_g4_g5_h4_h5 = _mm256_unpackhi_epi32(e1_f1_g1_h1_e5_f5_g5_h5,e0_f0_g0_h0_e4_f4_g4_h4);
	__m256i g2_g3_h2_h3_g6_g7_h6_h7 = _mm256_unpackhi_epi32(e3_f3_g3_h3_e7_f7_g7_h7,e2_f2_g2_h2_e6_f6_g6_h6);

	__m256i e0_e1_e2_e3_e4_e5_e6_e7 = _mm256_unpacklo_epi64(e0_e1_f0_f1_e4_e5_f4_f5,e2_e3_f2_f3_e6_e7_f6_f7);
	__m256i f0_f1_f2_f3_f4_f5_f6_f7 = _mm256_unpackhi_epi64(e0_e1_f0_f1_e4_e5_f4_f5,e2_e3_f2_f3_e6_e7_f6_f7);
	__m256i g0_g1_g2_g3_g4_g5_g6_g7 = _mm256_unpacklo_epi64(g0_g1_h0_h1_g4_g5_h4_h5,g2_g3_h2_h3_g6_g7_h6_h7);
	__m256i h0_h1_h2_h3_h4_h5_h6_h7 = _mm256_unpackhi_epi64(g0_g1_h0_h1_g4_g5_h4_h5,g2_g3_h2_h3_g6_g7_h6_h7);

	w[0]=a0_a1_a2_a3_a4_a5_a6_a7;\
	w[1]=b0_b1_b2_b3_b4_b5_b6_b7;\
	w[2]=c0_c1_c2_c3_c4_c5_c6_c7;\
	w[3]=d0_d1_d2_d3_d4_d5_d6_d7;\
	w[4]=e0_e1_e2_e3_e4_e5_e6_e7;\
	w[5]=f0_f1_f2_f3_f4_f5_f6_f7;\
	w[6]=g0_g1_g2_g3_g4_g5_g6_g7;\
	w[7]=h0_h1_h2_h3_h4_h5_h6_h7;\

}
