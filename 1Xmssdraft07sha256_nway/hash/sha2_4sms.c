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
#include <xmmintrin.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <x86intrin.h>

// ROT32(x, n)  SPH_t[3]2(((x) << (n)) | ((x) >> (32 - (n))))
//Ch(x,y,z)=(xey)xor(~xez)
//CH(a,b,c)    ((((b) ^ (c)) & (a)) ^ (c))
//Maj(x,y,z)=(xey)xor(xez)xor(yez)
//maj(a,b,c) (((b) & (c)) | (((b) | (c)) & (a)))
//Sig0=Rot2xorRot13xorRot22
//Sig1=Rot6xorRot11xorRot25
//T1=Kt+Wt+h+Sig1(e)+ch(e,f,g)
//T2=Sig0(a)+maj(a,b,c)
//a=T1+T2;b=a;c=b;d=c;e=d+T1;f=e;g=f;h=g;

//sig0(x)=t[6]=Rot7xorRot18xorRot3
//sig1(x)=t[7]=Rot17xorRot19xorRot10
//se (t<=15)Wt=Mt
//senão Wt=t[7](W_{t-2})+W_{t-7}+t[6](W_{t-15})+(W_{t-16})
void computeT1_4way(__m128i T[8], __m128i *e,__m128i *f,__m128i *g,__m128i *h,  __m128i wt[64], int x){
	// ch=T[0];

	T[6]=_mm_set1_epi32(K[x]);
	T[6]= _mm_add_epi32 (wt[x],T[6]);
	T[0]=_mm_slli_epi32(*e, 32 - (6));
	T[1]=_mm_slli_epi32(*e, 32 - (11));
	T[2]=_mm_slli_epi32(*e, 32 - (25));
	T[3]=_mm_srli_epi32(*e, (6));
	T[4]=_mm_srli_epi32(*e, (11));
	T[5]=_mm_srli_epi32(*e, (25));
	T[3]=_mm_or_si128 (T[3],T[0]);
	T[0]= _mm_xor_si128 (*f,*g);
	T[4]=_mm_or_si128 (T[4],T[1]);
	T[5]=_mm_or_si128 (T[5],T[2]);
	T[6]= _mm_add_epi32 (*h, T[6]);
	T[4]= _mm_xor_si128 (T[3],T[4]);
	T[0]= _mm_and_si128 (T[0],*e);
	T[4]= _mm_xor_si128 (T[4],T[5]);
	T[6]= _mm_add_epi32 (T[6], T[4]);
	T[0]= _mm_xor_si128 (T[0],*g);
	T[6]= _mm_add_epi32 (T[0],T[6]);
}
void computeT2_4way(__m128i T[8], __m128i *a,__m128i *b,__m128i *c,  __m128i wt[64], int x){
	(void)(wt);
	(void)(x);
	//maj=T[0]
	T[0]=_mm_or_si128 (*b, *c);
	T[7]=_mm_and_si128 (*b, *c);
	T[0]=_mm_and_si128 (*a,T[0]);
	T[1]=_mm_slli_epi32(*a, 32 - (2));
	T[2]=_mm_slli_epi32(*a, 32 - (13));
	T[3]=_mm_slli_epi32(*a, 32 - (22));
	T[4]= _mm_srli_epi32(*a, (2));
	T[5]= _mm_srli_epi32(*a, (13));
	T[4]=_mm_or_si128 (T[4],T[1]);
	T[5]=_mm_or_si128 (T[5],T[2]);
	T[1]= _mm_srli_epi32(*a, (22));
	T[0]=_mm_or_si128 (T[7],T[0]);
	T[1]=_mm_or_si128 (T[1],T[3]);
	T[4]=_mm_xor_si128 (T[4],T[5]);
	T[7]= _mm_xor_si128 (T[4],T[1]);
	T[7]= _mm_add_epi32 (T[7], T[0]);
}

void SHA256_4way_STEPn(__m128i T[8], __m128i *a,__m128i *b,__m128i *c,__m128i *d,__m128i *e,__m128i *f,__m128i *g,__m128i *h,__m128i wt[64], int x){
	(void)(d);
	//T1=T[6],T2=T[7];

	computeT1_4way(T, e,f,g,h,wt,x);
	computeT2_4way(T, a,b,c,wt, x);
}
//t[6](x)=Rot7xorRot18xorRot[3]
//t[7](x)=Rot17xorRot19xorRot10
//se (t<=15)Wt=Mt
//senão Wt=t[7](W_{t-2})+W_{t-7}+t[6](W_{t-15})+(W_{t-16})
// ROTL32(x, n)   SPH_t[3]2(((x) << (n)) | ((x) >> (32 - (n))))
void SHA256_4way_STEP1(__m128i T[8],__m128i *a,__m128i *b,__m128i *c,__m128i *d,__m128i *e,__m128i *f,__m128i *g,__m128i *h,  __m128i wt[64], int x){
	//sig0=t[6], sig1=t[7]
	__m128i t[8];

	t[1]=_mm_slli_epi32(wt[x-2], 32 - (17));
	t[2]=_mm_slli_epi32(wt[x-2], 32 - (19));
	t[3]=_mm_srli_epi32(wt[x-2], 17);
    	t[4]=_mm_srli_epi32(wt[x-2], 19);
	t[7]=_mm_or_si128 (t[1],t[3]);
	t[4]=_mm_or_si128 (t[2],t[4]);
	t[5]=_mm_srli_epi32 ((wt[x-2]), 10);
	t[7]=_mm_xor_si128(t[7],t[4]);
	t[1]=_mm_srli_epi32(wt[x-15], (7));
	t[2]=_mm_srli_epi32(wt[x-15], (18));
	t[3]=_mm_slli_epi32(wt[x-15], 32 - (7));
	t[4]=_mm_slli_epi32(wt[x-15], 32 - (18));
	t[7]=_mm_xor_si128(t[7],t[5]);
	t[6]=_mm_or_si128 (t[1],t[3]);
	t[4]=_mm_or_si128 (t[2],t[4]);
	t[5]=_mm_srli_epi32 ((wt[x-15]), 3);
	t[6]=_mm_xor_si128(t[6],t[4]);
	t[7] = _mm_add_epi32 (t[7], wt[x-7]);
	t[6]=_mm_xor_si128(t[6],t[5]);
	t[6] = _mm_add_epi32 (t[6], wt[x-16]);
	wt[x] = _mm_add_epi32 (t[7],t[6]);
	SHA256_4way_STEPn(T, (a),(b),(c),(d),(e),(f),(g),(h),wt,x);
}

static inline void sha256_4way (__m128i buffer[16], __m128i init[8])
{
    int i;
    __m128i a, b, c, d, e, f, g, h;
    __m128i T[8],wt[64];

    a = init[0]; e = init[4];
    b = init[1]; f = init[5];
    c = init[2]; g = init[6];
    d = init[3]; h = init[7];
    for(i=0;i<16;i++) wt[i]=buffer[i];

    for(i=0;i<16;i++){
    	SHA256_4way_STEPn(T, &a, &b, &c, &d, &e, &f, &g, &h, wt, i);
	h=g;g=f;f=e;e=_mm_add_epi32 (d, T[6]);
	d=c;c=b;b=a;a=_mm_add_epi32 (T[6], T[7]);
    }
    for(i=16;i<64;i++){
	SHA256_4way_STEP1(T, &a, &b, &c, &d, &e, &f, &g, &h, wt, i);
	h=g;g=f;f=e;e=_mm_add_epi32 (d, T[6]);
	d=c;c=b;b=a;a=_mm_add_epi32 (T[6], T[7]);
    }

    init[0] = _mm_add_epi32 (a, init[0]);
    init[1] = _mm_add_epi32 (b, init[1]);
    init[2] = _mm_add_epi32 (c, init[2]);
    init[3] = _mm_add_epi32 (d, init[3]);
    init[4] = _mm_add_epi32 (e, init[4]);
    init[5] = _mm_add_epi32 (f, init[5]);
    init[6] = _mm_add_epi32 (g, init[6]);
    init[7] = _mm_add_epi32 (h, init[7]);
}

void initialize_4way(__m128i init[8])
{
    init[0] = _mm_set1_epi32(0x6a09e667);
    init[1] = _mm_set1_epi32(0xbb67ae85);
    init[2] = _mm_set1_epi32(0x3c6ef372);
    init[3] = _mm_set1_epi32(0xa54ff53a);
    init[4] = _mm_set1_epi32(0x510e527f);
    init[5] = _mm_set1_epi32(0x9b05688c);
    init[6] = _mm_set1_epi32(0x1f83d9ab);
    init[7] = _mm_set1_epi32(0x5be0cd19);
}

static inline void transposta_4way_zip(__m128i w[4])
{
    __m128i a0_b0_a2_b2 = _mm_unpacklo_epi32(w[0],w[1]);
    __m128i a1_b1_a3_b3 = _mm_unpackhi_epi32(w[0],w[1]);

    __m128i c0_d0_c2_d2 = _mm_unpacklo_epi32(w[2],w[3]);
    __m128i c1_d1_c3_d3 = _mm_unpackhi_epi32(w[2],w[3]);

    __m128i a0_b0_c0_d0 = _mm_unpacklo_epi64(a0_b0_a2_b2,c0_d0_c2_d2);
    __m128i a2_b2_c2_d2 = _mm_unpackhi_epi64(a0_b0_a2_b2,c0_d0_c2_d2);

    __m128i a1_b1_c1_d1 = _mm_unpacklo_epi64(a1_b1_a3_b3,c1_d1_c3_d3);
    __m128i a3_b3_c3_d3 = _mm_unpackhi_epi64(a1_b1_a3_b3,c1_d1_c3_d3);

    w[0]=a0_b0_c0_d0;
    w[1]=a1_b1_c1_d1;
    w[2]=a2_b2_c2_d2;
    w[3]=a3_b3_c3_d3;
}

//     for(i=0;i<4;i++) w[i+0] = _mm_load_si128((__m128i*)in[posit+i]+0);
//     for(i=0;i<4;i++) w[i+4] = _mm_load_si128((__m128i*)in[posit+i]+1);
//     transposta_4way_zip(w+0,1);
//     printm128i(w[0]);
//     transposta_4way_zip(w+4,1);

void printm128i(__m128i data){
	uint64_t xz[2];
	u64 w[2];
	int i;

        _mm_store_si128 ((__m128i *) xz, data);
	for (i=0; i<2; i++){
		w[i]=xz[i];
		printf("%llX-",w[i]);
	}
	printf(" ]\n");
}

static inline void crypto_hash4simd(uIntHash *digest64, uIntHash *in, u64 posit)
{
	int i,j;
	__m128i init[8], w[16];
	uint32_t digest[8][8];
	uint32_t buffer[8][8];
	uint32_t __w[16][4] __attribute__ ((aligned (16)));

	for(i=0;i<4;i++){
		//for (j=0; j < 4; j++) printf("%llX-", in[posit+i][j]);	//printf("\n");
		U64TO32B( buffer[i][0], buffer[i][1], in[posit+i][0] );
		U64TO32B( buffer[i][2], buffer[i][3], in[posit+i][1] );
		U64TO32B( buffer[i][4], buffer[i][5], in[posit+i][2] );
		U64TO32B( buffer[i][6], buffer[i][7], in[posit+i][3] );
		//for (j=0; j < 8; j++) printf("%lX-", buffer[i][j]);	//printf("\n");
	}
	for (i=0; i < 8; i++){
	        for (j=0; j < 4; j++) __w[i][j]=(uint32_t)buffer[j][i];
        	w[i] = _mm_load_si128 ((__m128i *) __w[i]);
    	}
	//for (j=0; j < 8; j++) printm128i(w[j]);
	w[8] =_mm_set1_epi32 (0x80000000);
	for (i=9; i < 15; i++) 	   w[i] = _mm_setzero_si128();
	w[15] =_mm_set1_epi32 (256);
	initialize_4way(init);
	sha256_4way(w, init);
	for (i=0; i < 8; i++) _mm_store_si128 ((__m128i *) digest[i], w[i]);
	for (j=0;j<4; j++) for(i=0;i<nRows;i++) digest64[posit+j][i]=U32TO64B(digest[i*2][j], digest[i*2+1][j]) ;
}

static inline void crypto_hashNbits(uIntHash *digest64, uIntHash *in, u64 posit, int N, int total)
{
	int i,j,l;
	__m128i init[8], w[16], Bl[16];
	uint32_t digest[8][8];
	uint32_t buffer[8][16];
	uint32_t __w[16][4] __attribute__ ((aligned (16)));

	initialize_4way(init);
	for(l=0;l<N;l++){
		for(i=0;i<4;i++){
			//for (j=0; j < 4; j++) printf("%llX-", in[posit+i][j]);	//printf("\n");
			U64TO32B( buffer[i][0], buffer[i][1], in[posit+i+(l*8)][0] );
			U64TO32B( buffer[i][2], buffer[i][3], in[posit+i+(l*8)][1] );
			U64TO32B( buffer[i][4], buffer[i][5], in[posit+i+(l*8)][2] );
			U64TO32B( buffer[i][6], buffer[i][7], in[posit+i+(l*8)][3] );

			U64TO32B( buffer[i][8], buffer[i][9],   in[posit+(i+8+(l*8))][0] );
			U64TO32B( buffer[i][10], buffer[i][11], in[posit+(i+8+(l*8))][1] );
			U64TO32B( buffer[i][12], buffer[i][13], in[posit+(i+8+(l*8))][2] );
			U64TO32B( buffer[i][14], buffer[i][15], in[posit+(i+8+(l*8))][3] );
			//for (j=0; j < 8; j++) printf("%lX-", buffer[i][j]);	//printf("\n");
		}
		for (i=0; i < 16; i++){
		        for (j=0; j < 4; j++) __w[i][j]=(uint32_t)buffer[j][i];
	        	Bl[i] = _mm_load_si128 ((__m128i *) __w[i]);
	    	}
		sha256_4way(Bl, init);
	}

	w[0] =_mm_set1_epi32 (0x80000000);
	for (i=0; i < 15; i++) 	   w[i] = _mm_setzero_si128();
	w[15] =_mm_set1_epi32 (total);
	sha256_4way(w, init);
	for (i=0; i < 8; i++) _mm_store_si128 ((__m128i *) digest[i], w[i]);
	for (j=0;j<4; j++) for(i=0;i<nRows;i++) digest64[posit+j][i]=U32TO64B(digest[i*2][j], digest[i*2+1][j]) ;

}

static inline void crypto_hashN2bits(uIntHash *digest64, uIntHash *in, u64 posit, int N, int total)
{
	int i,j,l;
	__m128i init[8], w[16], Bl[16];
	uint32_t digest[8][8];
	uint32_t buffer[8][16];
	uint32_t __w[16][4] __attribute__ ((aligned (16)));

	initialize_4way(init);
	for(l=0;l<N;l++){
		for(i=0;i<4;i++){
			//for (j=0; j < 4; j++) printf("%llX-", in[posit+i][j]);	//printf("\n");
			U64TO32B( buffer[i][0], buffer[i][1], in[0+i+(l%2)][0] );
			U64TO32B( buffer[i][2], buffer[i][3], in[0+i+(l%2)][1] );
			U64TO32B( buffer[i][4], buffer[i][5], in[0+i+(l%2)][2] );
			U64TO32B( buffer[i][6], buffer[i][7], in[0+i+(l%2)][3] );

			U64TO32B( buffer[i][8], buffer[i][9],   in[1+i+(l%2)][0] );
			U64TO32B( buffer[i][10], buffer[i][11], in[1+i+(l%2)][1] );
			U64TO32B( buffer[i][12], buffer[i][13], in[1+i+(l%2)][2] );
			U64TO32B( buffer[i][14], buffer[i][15], in[1+i+(l%2)][3] );
			//for (j=0; j < 8; j++) printf("%lX-", buffer[i][j]);	//printf("\n");
		}
		for (i=0; i < 16; i++){
		        for (j=0; j < 4; j++) __w[i][j]=(uint32_t)buffer[j][i];
	        	Bl[i] = _mm_load_si128 ((__m128i *) __w[i]);
	    	}
		sha256_4way(Bl, init);
	}

	w[0] =_mm_set1_epi32 (0x80000000);
	for (i=0; i < 15; i++) 	   w[i] = _mm_setzero_si128();
	w[15] =_mm_set1_epi32 (total);
	sha256_4way(w, init);
	for (i=0; i < 8; i++) _mm_store_si128 ((__m128i *) digest[i], w[i]);
	for (j=0;j<4; j++) for(i=0;i<nRows;i++) digest64[posit+j][i]=U32TO64B(digest[i*2][j], digest[i*2+1][j]) ;

}
