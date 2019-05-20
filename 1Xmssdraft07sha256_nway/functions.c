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
 
#include "flo-xmss-vec.h"
#include "hash/sha2supercop.h"
#include "functions.h"
#include "hash_address.h"
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#define genRand32(seed){\
	_rdrand32_step(&seed[0]);\
	_rdrand32_step(&seed[1]);\
	_rdrand32_step(&seed[2]);\
	_rdrand32_step(&seed[3]);\
	_rdrand32_step(&seed[4]);\
	_rdrand32_step(&seed[5]);\
	_rdrand32_step(&seed[6]);\
	_rdrand32_step(&seed[7]);\
}
#define genRand64(seed){\
	_rdrand64_step(&seed[0]);\
	_rdrand64_step(&seed[1]);\
	_rdrand64_step(&seed[2]);\
	_rdrand64_step(&seed[3]);\
}

void randomNumbers(skXMSS *sk)
{
	genRand32(sk->sk_seed);
	genRand32(sk->sk_prf);
	genRand32(sk->pub_seed);
}
void PRF2(u64 *out64, u32 *KEY, u32 *M)
{
	u32_16 Bl1={0},Bl2={0};
	u32 state[8];

	Bl1[7]=3;
	for (int i = 0; i < 8; i++){
		Bl1[i+8] = KEY[i];
		Bl2[i] = M[i];
	}
	/* pad SHA2 */
	Bl2[8]=0x80000000;
	Bl2[15]=768;
	//printf("Bl1: ");print_uint32(Bl1, 16);
	//printf("Bl2: ");print_uint32(Bl2, 16);
	sha256_init(state);
	SHA2_ROUND_BODY(Bl1, state);
	SHA2_ROUND_BODY(Bl2, state);
	for(int i=0;i<4;i++) out64[i]=U32TO64(state+(i*2)) ;
}


void PRG(uIntHash *sk, u64 rlen, u8 n, u32 *key32)
{
	u32 counter = 0;
	u64 tmp64[4];
	u32 counter32[8]__attribute__ ((aligned (32)))={0};

	while (counter < rlen) {
		//printf("counter32=%ld\n",counter);
		counter32[7]=counter;
		PRF2(tmp64, key32, counter32);
		//printf("tmp32: ");print_uint32(tmp32, 8);
		memcpy(sk[counter],tmp64,n);
		//printf("prg-sk[%d] ",counter);print_uint32(sk[counter], 8);
	    counter++;
    	//counter32[7]++;
	}

}

void PRG_4way(uIntHash *r, u64 rlen, u8 n, u32 *key32)
{
	u8 i,j,posit,simd4=4;
	u32 counter = 0;
	__m128i out128[8],KEY128[8],counter128[8];
	u32 trans[simd4][8]__attribute__ ((aligned (32)));
	u32 tmp32[8][simd4]__attribute__ ((aligned (32)));
	u32 tmp[8]__attribute__ ((aligned (32)));
	u64 out64[nRows]__attribute__ ((aligned (32)));

	for (i=0; i < nHash-1; i++) 	counter128[i] =_mm_setzero_si128();
	for (i=0; i < nHash; i++)	KEY128[i] =_mm_set1_epi32 (key32[i]);
	while (counter < rlen) {
		posit=counter;
        	for(i=0;i<simd4;i++){
	        	tmp[i]=counter;
			counter++;
		}
		counter128[nHash-1]=_mm_load_si128 ((__m128i*)tmp);
		PRF_4way(out128, KEY128, counter128);
		for(i=0;i<nHash;i++) _mm_storeu_si128 ((__m128i *) tmp32[i], out128[i]);
		//transpose
		for (i=0; (i<simd4) ; i++){
		  for(j=0;j<nHash;j++)
			trans[i][j]=tmp32[j][i];
		}
		for (i=0; ((i<simd4) && ((posit+i)<rlen)); i++){
			memcpy(tmp,trans[i],n);
			for(j=0;j<nRows;j++) out64[j]=U32TO64(tmp+(j*2)) ;
			memcpy(r[posit+i],out64,n);
		}
    }
}

void PRG_8way(uIntHash *r, u64 rlen, u8 n, u32 *key32)
{
	u8 i,posit;
	u32 counter = 0;
	__m256i out256[8],KEY256[8],counter256[8];
	u32 trans[8][8]__attribute__ ((aligned (32)));
	u32 tmp32[8][8]__attribute__ ((aligned (32)));
	u32 tmp[simd]__attribute__ ((aligned (32)));
	u64 out64[nRows]__attribute__ ((aligned (32)));

	for (i=0; i < nHash-1; i++) 	counter256[i] =_mm256_setzero_si256();
	for (i=0; i < nHash; i++)	KEY256[i] =_mm256_set1_epi32 (key32[i]);
	while (counter < rlen) {
		posit=counter;
        	for(i=0;i<simd;i++){
	        	tmp[i]=counter;
			counter++;
		}
		counter256[nHash-1]=_mm256_load_si256 ((__m256i*)tmp);
		PRF_8way(out256, KEY256, counter256);
		for(i=0;i<nHash;i++) _mm256_storeu_si256 ((__m256i *) tmp32[i], out256[i]);
		/*transpose */
		for (i=0; (i<simd) ; i++){
		  for(int j=0;j<nHash;j++)
			trans[i][j]=tmp32[j][i];
		}
		for (i=0; ((i<simd) && (posit+i<rlen)); i++){
			memcpy(tmp,trans[i],n);
			for(int j=0;j<nRows;j++) out64[j]=U32TO64(tmp+(j*2)) ;
			memcpy(r[posit+i],out64,n);
		}
    }
}

void F(u32 *state, u32 *KEY, u32 *M)
{
	u32_16 Bl1={0},Bl2={0};

	for (int i = 0; i < 8; i++){
		Bl1[i+8] = KEY[i];
		Bl2[i] = M[i];
	}
	/* pad SHA2 */
	Bl2[8]=0x80000000;
	Bl2[15]=768;
	sha256_init(state);
	SHA2_ROUND_BODY(Bl1, state);
	SHA2_ROUND_BODY(Bl2, state);
}

/* gen 4 internal nodes at the same time */
void F_4way(__m128i *init, __m128i *KEY128, __m128i *M, __m128i *PADSHA128 ){
	__m128i Bl1[16],Bl2[16];

	/* prepare blocks SHA2 */
	for(u8 i=0;i<8;i++){
		Bl1[i] =_mm_setzero_si128();
		Bl1[i+8] =KEY128[i];
		Bl2[i] = M[i];
		Bl2[i+8] = PADSHA128[i];
	}
	/*initialize sha2 */
	initialize_4way(init);
	/* rounds SHA2 */
	sha256_4way(Bl1, init);
	sha256_4way(Bl2, init);
}

/* gen 8 internal nodes at the same time */
void F_8way(__m256i *init, __m256i *KEY256, __m256i *M, __m256i *PADSHA256 ){
	__m256i Bl1[16],Bl2[16];

	/* prepare blocks SHA2 */
	for(u8 i=0;i<8;i++){
		Bl1[i] =_mm256_setzero_si256();
		Bl1[i+8] =KEY256[i];
		Bl2[i] = M[i];
		Bl2[i+8] = PADSHA256[i];
	}
	/*initialize sha2 */
	initialize(init);
	/* rounds SHA2 */
	sha256_8sms(Bl1, init);
	sha256_8sms(Bl2, init);
}

void H(uIntHash out, u32 *KEY, u32 *M )
{
	u8 i;
	u32 Bl1[16]={0},Pad[16]={0};///messages to 512-bit and 256-bit hash
	u32_8 state;

	// prepare blocks SHA2
	Bl1[7]=1;
	for(i=0;i<8;i++){
		Bl1[i+8]=KEY[i];
	}
	/* pad SHA2 */
	Pad[0]=0x80000000;
	Pad[15]=1024;//add the size of the last message block
	/* initialize SHA2 */
	sha256_init(state);
	/* rounds SHA2 */
	SHA2_ROUND_BODY(Bl1, state);
	SHA2_ROUND_BODY(M, state);
	SHA2_ROUND_BODY(Pad, state);
	//printf("state "); print_uint32(state, 8);
	for(i=0;i<4;i++) out[i]=U32TO64(state+(i*2)) ;

}

/* Implemts H_msg */
void H_msg(uIntHash out, u8 *KEY, unsigned int keylen, u8 *M, u8 n)
{
	u8 i;
	u8 msglen=strlen((const char *)(M));
	unsigned char buf[msglen + keylen+n];

	for (i=0; i < keylen; i++) {
		buf[i] = KEY[i];
	}
	for (i=0; i < msglen; i++) {
		buf[keylen+i] = M[i];
	}
	SHA2_256(buf, msglen + keylen , out);
}

/* Implements PRF */
void PRF(u32 *state, u32 *KEY, u32 *M)
{
	u32_16 Bl1={0},Bl2={0};

	Bl1[7]=3;
	for (int i = 0; i < 8; i++){
		Bl1[i+8] = KEY[i];
		Bl2[i] = M[i];
	}
	/* pad SHA2 */
	Bl2[8]=0x80000000;
	Bl2[15]=768;
	//printf("Bl1: ");print_uint32(Bl1, 16);
	sha256_init(state);
	SHA2_ROUND_BODY(Bl1, state);
	SHA2_ROUND_BODY(Bl2, state);
}

void PRF_4way(__m128i init[8], __m128i *KEY, __m128i M[8])
{
	u8 i;
	__m128i Bl1[16],Bl2[16];

	/* prepare blocks SHA2 */
	for(i=0;i<7;i++) Bl1[i] =_mm_setzero_si128();
	Bl1[7] =_mm_set1_epi32(3);
	for(i=0;i<8;i++) Bl1[i+8] =KEY[i];
	for(i=0;i<8;i++) Bl2[i] = M[i];
	/* pad SHA2 */
	Bl2[8] =_mm_set1_epi32 (0x80000000);
	for (i=9; i < 15; i++) 	   Bl2[i] =_mm_setzero_si128();
	Bl2[15] =_mm_set1_epi32 (768);
	/*initialize sha2 */
	initialize_4way(init);
	/* rounds SHA2 */
	sha256_4way(Bl1, init);
	sha256_4way(Bl2, init);
}

void PRF_8way(__m256i init[8], __m256i *KEY, __m256i M[8])
{
	u8 i;
	__m256i Bl1[16],Bl2[16];

	/* prepare blocks SHA2 */
	for(i=0;i<7;i++) Bl1[i] =_mm256_setzero_si256();
	Bl1[7] =_mm256_set1_epi32(3);
	for(i=0;i<8;i++) Bl1[i+8] =KEY[i];
	for(i=0;i<8;i++) Bl2[i] = M[i];
	/* pad SHA2 */
	Bl2[8] =_mm256_set1_epi32 (0x80000000);
	for (i=9; i < 15; i++) 	   Bl2[i] =_mm256_setzero_si256();
	Bl2[15] =_mm256_set1_epi32 (768);
	/*initialize sha2 */
	initialize(init);
	/* rounds SHA2 */
	sha256_8sms(Bl1, init);
	sha256_8sms(Bl2, init);
}


void RAND_HASH(uIntHash out, uIntHash in1, uIntHash in2, u32 *pub_seed, u32 *ADRS32)
{
	u32_8 KEY;
	u32_8 BM_0,BM_1,LEFT, RIGHT;
	u32_16 M;
	u8 j;

	SET_KEY_AND_MASK32(ADRS32, 0);
	PRF(KEY, pub_seed, ADRS32);
	//printf("KEY= ");print_uint32(KEY, 8);
	SET_KEY_AND_MASK32(ADRS32, 1);
	PRF(BM_0, pub_seed, ADRS32);
	SET_KEY_AND_MASK32(ADRS32, 2);
	PRF(BM_1, pub_seed, ADRS32);
	U64TO32( LEFT+(0), in1[0] );U64TO32( LEFT+(2), in1[1] );
	U64TO32( LEFT+(4), in1[2] );U64TO32( LEFT+(6), in1[3] );
	U64TO32( RIGHT+(0), in2[0] );U64TO32( RIGHT+(2), in2[1] );
	U64TO32( RIGHT+(4), in2[2] );U64TO32( RIGHT+(6), in2[3] );
	for(j=0;j<nHash;j++){
		M[j]= (LEFT[j]  ^ BM_0[j]);
		M[j+8]=(RIGHT[j] ^ BM_1[j]);
	}
	H(out, KEY, M);
}

void H32(u32 *state, u32 *KEY, u32 *M )
{
	u8 i;
	u32 Bl1[16]={0},Pad[16]={0};///messages to 512-bit and 256-bit hash

	// prepare blocks SHA2
	Bl1[7]=1;
	for(i=0;i<8;i++)
		Bl1[i+8]=KEY[i];
	/* pad SHA2 */
	Pad[0]=0x80000000;
	Pad[15]=1024;//add the size of the last message block
	/* initialize SHA2 */
	sha256_init(state);
	/* rounds SHA2 */
	SHA2_ROUND_BODY(Bl1, state);
	SHA2_ROUND_BODY(M, state);
	SHA2_ROUND_BODY(Pad, state);
}

void RAND_HASH32(u32 *out, u32 *LEFT, u32 *RIGHT, u32 *pub_seed, u32 *ADRS32)
{
	u32_8 KEY;
	u32_8 BM_0,BM_1;
	u32_16 M;
	u8 j;

	SET_KEY_AND_MASK32(ADRS32, 0);
	PRF(KEY, pub_seed, ADRS32);
	//printf("KEY= ");print_uint32(KEY, 8);
	SET_KEY_AND_MASK32(ADRS32, 1);
	PRF(BM_0, pub_seed, ADRS32);
	SET_KEY_AND_MASK32(ADRS32, 2);
	PRF(BM_1, pub_seed, ADRS32);
//	for(i=0;i<8;i++) LEFT[i]=in1[i];
//	for(i=0;i<8;i++) RIGHT[i]=in2[i] );
	for(j=0;j<nHash;j++){
		M[j]= (LEFT[j]  ^ BM_0[j]);
		M[j+8]=(RIGHT[j] ^ BM_1[j]);
	}
	H32(out, KEY, M);
}

void H_4way(u32_8 *out32, __m128i KEY128[8], __m128i *M, int posit)
{
	u8 i,j;
	u32_8 digest32[8],tmp[8];
	__m128i init[8], Bl1[16],PAD128[16];

	/* prepare block 1 SHA2 */
	for(i=0;i<7;i++) Bl1[i] =_mm_setzero_si128();
	Bl1[7]=_mm_set1_epi32(1);
	for(i=0;i<8;i++) Bl1[i+8] =KEY128[i];
	/* pad SHA2 */
	PAD128[0] =_mm_set1_epi32 (0x80000000);
	for (i=1; i < 15; i++) 	   PAD128[i] =_mm_setzero_si128();
	PAD128[15] =_mm_set1_epi32 (1024);
	/*initialize sha2 */
	initialize_4way(init);
	/* rounds SHA2 */
	sha256_4way(Bl1, init);
	sha256_4way(M, init);
	sha256_4way(PAD128, init);
	for(i=0;i<8;i++)
		_mm_storeu_si128 ((__m128i *) digest32[i], init[i]);
	for(i=0;i<simd;i++)
		for(j=0;j<8;j++)	tmp[i][j]=(uint32_t)digest32[j][i];
	for (i=0; i < simd; i++)
		for (j=0; j < nHash; j++)
			out32[(posit/2)+i][j]=tmp[i][j] ;
}


void H_8way(u32_8 *out32, __m256i KEY256[8], __m256i *M, int posit)
{
	u8 i,j;
	u32_8 digest32[8],tmp[8];
	__m256i init[8], Bl1[16],PAD256[16];

	/* prepare block 1 SHA2 */
	for(i=0;i<7;i++) Bl1[i] =_mm256_setzero_si256();
	Bl1[7]=_mm256_set1_epi32(1);
	for(i=0;i<8;i++) Bl1[i+8] =KEY256[i];
	/* pad SHA2 */
	PAD256[0] =_mm256_set1_epi32 (0x80000000);
	for (i=1; i < 15; i++) 	   PAD256[i] =_mm256_setzero_si256();
	PAD256[15] =_mm256_set1_epi32 (1024);
	/*initialize sha2 */
	initialize(init);
	/* rounds SHA2 */
	sha256_8sms(Bl1, init);
	sha256_8sms(M, init);
	sha256_8sms(PAD256, init);
	for(i=0;i<8;i++)
		_mm256_storeu_si256 ((__m256i *) digest32[i], init[i]);
	for(i=0;i<8;i++)
		for(j=0;j<8;j++)	tmp[i][j]=(uint32_t)digest32[j][i];
	for (i=0; i < 8; i++)
		for (j=0; j < 8; j++)
			out32[(posit/2)+i][j]=tmp[i][j] ;
}
#ifdef XMSS_SHA2_8x
void RAND_HASH_nway(u32_8 *out, u32_8 *in, int posit, u32 *pub_seed, u32 ADRS32[simd][8])
{
	u8 i,j,simd2=8;
	__m256i KEY256[8],PUBSEED256[8],M256[16];
	u32_8 LEFT[simd2], RIGHT[simd2],tmp[8];
	__m256i BM256_0[8],BM256_1[8],LEFT256[8], RIGHT256[8],ADRS256[8];

	/* transpose ADRS32 */
	for(i=0;i<8;i++){
		for(j=0;j<simd2;j++)	tmp[i][j]=(uint32_t)ADRS32[j][i];
		ADRS256[i]=_mm256_load_si256 ((__m256i*)tmp[i]);
	}
	/* set PUBSEED256 */
	for(j=0;j<nHash;j++)
		PUBSEED256[j] =_mm256_set1_epi32(pub_seed[j]);
	SET_KEY_AND_MASK256(ADRS256,_mm256_set1_epi32(0));
	PRF_8way(KEY256, PUBSEED256, ADRS256);
	SET_KEY_AND_MASK256(ADRS256,_mm256_set1_epi32(1));
	PRF_8way(BM256_0, PUBSEED256, ADRS256);
	SET_KEY_AND_MASK256(ADRS256,_mm256_set1_epi32(2));
	PRF_8way(BM256_1, PUBSEED256, ADRS256);
	/* LEFT and RIGHT are nodes in the tree */
	for(i=0;i<8;i++)
		for(j=0;j<8;j++){
			LEFT[i][j]= in[(i*2)+posit][j];
			RIGHT[i][j]= in[(i*2)+posit+1][j];
		}
	/* transpose LEFT and RIGHT */
	for(i=0;i<8;i++){
		for(j=0;j<8;j++)	tmp[i][j]=(uint32_t)LEFT[j][i];
		LEFT256[i]=_mm256_load_si256 ((__m256i*)tmp[i]);
		for(j=0;j<8;j++)	tmp[i][j]=(uint32_t)RIGHT[j][i];
		RIGHT256[i]=_mm256_load_si256 ((__m256i*)tmp[i]);
	}
	for(i=0;i<nHash;i++){
		M256[i]=_mm256_xor_si256(LEFT256[i],BM256_0[i]);
		M256[i+8]=_mm256_xor_si256(RIGHT256[i],BM256_1[i]);
	}
	//for (i=0; i < 8; i++){printf("M256[%d]= ",i); print_m256i(M256[i]);}
	H_8way(out, KEY256, M256, posit);
}
#else
void RAND_HASH_nway(u32_8 *out, u32_8 *in, int posit, u32 *pub_seed, u32 ADRS32[simd][8])
{
	u8 i,j,simd2=4;
	__m128i KEY128[8],PUBSEED128[8],M128[16];
	u32_8 LEFT[simd2], RIGHT[simd2],tmp[8];
	__m128i BM128_0[8],BM128_1[8],LEFT128[8], RIGHT128[8],ADRS128[8];

	/* transpose ADRS32 */
	for(i=0;i<8;i++){
		for(j=0;j<simd2;j++)	tmp[i][j]=(uint32_t)ADRS32[j][i];
		ADRS128[i]=_mm_load_si128 ((__m128i*)tmp[i]);
	}
	/* set PUBSEED128 */
	for(j=0;j<nHash;j++)
		PUBSEED128[j] =_mm_set1_epi32(pub_seed[j]);
	SET_KEY_AND_MASK128(ADRS128,_mm_set1_epi32(0));
	PRF_4way(KEY128, PUBSEED128, ADRS128);
	SET_KEY_AND_MASK128(ADRS128,_mm_set1_epi32(1));
	PRF_4way(BM128_0, PUBSEED128, ADRS128);
	SET_KEY_AND_MASK128(ADRS128,_mm_set1_epi32(2));
	PRF_4way(BM128_1, PUBSEED128, ADRS128);
	/* LEFT and RIGHT are nodes in the tree */
	for(i=0;i<simd2;i++)
		for(j=0;j<nHash;j++){
			LEFT[i][j]= in[(i*2)+posit][j];
			RIGHT[i][j]= in[(i*2)+posit+1][j];
		}
	/* transpose LEFT and RIGHT */
	for(i=0;i<8;i++){
		for(j=0;j<simd2;j++)	tmp[i][j]=(uint32_t)LEFT[j][i];
		LEFT128[i]=_mm_load_si128 ((__m128i*)tmp[i]);
		for(j=0;j<simd2;j++)	tmp[i][j]=(uint32_t)RIGHT[j][i];
		RIGHT128[i]=_mm_load_si128 ((__m128i*)tmp[i]);
	}
	for(i=0;i<nHash;i++){
		M128[i]=_mm_xor_si128(LEFT128[i],BM128_0[i]);
		M128[i+8]=_mm_xor_si128(RIGHT128[i],BM128_1[i]);
	}
	//for (i=0; i < 8; i++){printf("M128[%d]= ",i); print_m128i(M128[i]);}
	H_4way(out, KEY128, M128, posit);
}
#endif
