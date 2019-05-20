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
#ifndef PROJECT_XMSS_VEC_H
#define PROJECT_XMSS_VEC_H

#ifdef __cplusplus
extern "C" {
#endif

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <sys/time.h>
#include <time.h>
#include <immintrin.h>
#include <omp.h>
#include <inttypes.h>
#include <stdint.h>
#include <unistd.h>

// fixed
#define hTree 19
#define RDRand 0
#define block 64
#define nThreads 1
#define int16 65535
#define teto(p) ((int)(p/2))+(p%2)
#define true 1
#define false 0

// It changes
#define HASH SHA256
#define nHash 8
#define nRows 4
#define chashbitlen 256
#define Blocks 512

#ifdef XMSS_SHA2_8x
  #define simd 8
#endif
#ifdef XMSS_SHA2_4x
  #define simd 4
#endif
#ifdef XMSS_SHA2_1x
  #define simd 1
#endif


//typedef opaque bytestring32[32];
typedef unsigned long long u64;
typedef uint32_t u32;
typedef unsigned char u8;
typedef u64 uInt256[nRows] __attribute__ ((aligned (32)));
typedef u64 uInt512[nRows*2] __attribute__ ((aligned (32)));
typedef u32 u32_4[4] __attribute__ ((aligned (32)));
typedef u32 u32_8[8] __attribute__ ((aligned (32)));
typedef u32 u32_16[16] __attribute__ ((aligned (32)));
typedef uint32_t uInt256_32[nRows*2] __attribute__ ((aligned (32)));
typedef uint32_t uInt512_32[nRows*4] __attribute__ ((aligned (32)));
typedef u32_8 uBitMask32[2];

#define U8TO32(p)					\
  (((uint32_t)((p)[0]) << 24) | ((uint32_t)((p)[1]) << 16) |	\
   ((uint32_t)((p)[2]) <<  8) | ((uint32_t)((p)[3])      ))
#define U8TO64(p) \
  (((u64)U8TO32(p) << 32) | (u64)U8TO32((p) + 4))
#define U32TO8(p, v) \
  { (p)[0] = ((u8)((v >>  24) & 0xFF)); (p)[1] = ((u8) ( (v >> 16) & 0xFF)); \
  (p)[2] = ((u8)((v >> 8) & 0xFF));   (p)[3] = ((u8) ( (v >>  0) & 0xFF)); }
#define U64TO8(p, v) \
    U32TO8((p),     (u32)((v) >> 32));	\
    U32TO8((p) + 4, (u32)((v)      ));
#define U32TO64B(p0,p1)					\
  (((u64)(p0) << 32) | ((u64)(p1)))
#define U64TO32B(p0,p1, v) \
    p0 = (u32) ((v)>>32); p1 = (u32) (v);
#define U64TO32(p, v) \
    (p)[0] = (u32) ((v)>>32); (p)[1] = (u32) (v);
#define U32TO64(p)					\
  (((u64)((p)[0]) << 32) | ((u64)((p)[1])))

// It change
typedef uInt256 uIntHash;

struct noTree {
	uIntHash hash;
	u8 height;
	u64 numNo;
};

struct noStack {
	struct noTree *no;
	struct noStack *next;
};
typedef struct noStack rStack;
typedef struct noTree rTree;

struct noTree32 {
	uIntHash hash;
	u8 height;
	u64 numNo;
};
typedef struct noTree32 rTree32;
typedef struct {
	u8 n;
	u8 w;
	u8 logw;
	u8 len1;
	u8 len2;
	u8 len;
	u8 keysize;
}wots_params;

typedef struct{
	wots_params wots_par;
	u8 n;
	u8 h;
	u8 k;
} xmss_params;

struct pathAuth {
	rTree *Auth;
	rTree Retain[hTree][3];
	rTree *Keep;
	rTree *TreeHASH;
	u64 *TreeHASHh;
	u8 *TreeHASHiStack;
	rTree TreeHASHstack[hTree][hTree];
	u8 *ind;
};
typedef struct pathAuth bds_state;
struct publicKey {
	u32_8 root;
	u32_8 pub_seed;
};
typedef struct publicKey pkXMSS;
struct privateKey {
	u32 idx;
	u32_8 sk_seed;
	u32_8 sk_prf;
	u32_8 root;
	u32_8 pub_seed;
};
typedef struct privateKey skXMSS;

struct signature {
	u32 idx_sig;
	u32_8 r;
	uIntHash *sig_ots;
	uIntHash *auth;
};
typedef struct signature sigXMSS;

struct vetdSigWinternitz {
    int idx;
    u64 e;
};
typedef struct vetdSigWinternitz dSigWin;

void printnchar(unsigned char *bloco, int n);
void print_uint32(uint32_t *data, int n);
void print_m256i(__m256i data);
void printnBlocosDe64(u64 *bloco, int n);
uint64_t Rdtsc();
double getTime();
void printNo(rTree *no);
void printNo2(rTree no);


/*********** alloc and dealloc functions ********************************************/
#define alloc(sig,path,pkx,l,H,hLtree,W,i)	\
	sig= (sigXMSS *) _mm_malloc(sizeof(sigXMSS),32);\
	sig->sig_ots = (uIntHash *) _mm_malloc(((l)+simd) * sizeof (uIntHash),32);\
	sig->auth = (uIntHash *) _mm_malloc((H) * sizeof (uIntHash),32);\
	sig->idx_sig=0; \
	path=(bds_state *) _mm_malloc (sizeof(bds_state),32);\
	path->Auth = (rTree *) _mm_malloc((H) * sizeof (rTree),32);\
	path->TreeHASH = (rTree *) _mm_malloc((H) * sizeof (rTree),32);\
	path->TreeHASHh = (u64 *) _mm_malloc((H-1) * sizeof (u64),32);\
	path->TreeHASHiStack=(u8 *) _mm_malloc((H-1) * sizeof (u8),32);\
	path->Keep = (rTree *) _mm_malloc((H) * sizeof (rTree),32);\
	pkx=(pkXMSS *) _mm_malloc (sizeof(pkXMSS),32);\
	path->ind=(u8 *) _mm_malloc((H) * sizeof (u8 ),32);\
	for(i=0;i<=h-2;i++) path->ind[i]=0;\
	for(i=0;i<(H-1);i++){\
		path->TreeHASHh[i]=0;\
		path->TreeHASHiStack[i]=0;\
	}

#define dealloc(params,sig,path,pkx)	\
	_mm_free(sig->sig_ots); _mm_free(sig->auth);	\
	_mm_free(sig);	\
	_mm_free(path->Auth); _mm_free(path->TreeHASH);	\
	_mm_free(path->TreeHASHh); _mm_free(path->TreeHASHiStack);\
	_mm_free(path->Keep);\
	_mm_free(path);	\
	_mm_free(pkx);

#define computeHeight(nLeafs,i,h)	\
  	h=0;i=nLeafs;	\
  	while(i>1){		\
  		i>>=1;	\
  		h++;		\
  	}			\
  	if(nLeafs%2) h=h+1;


void XMSS_setParams(xmss_params *params, int n, int h, int k, int w);
void XMSS_keyGen(pkXMSS *pkx, skXMSS *sk, bds_state *path, const xmss_params *params);
void XMSS_sign(skXMSS sk, sigXMSS *sig, unsigned char *message, bds_state *path, pkXMSS *pkx, u32 s, const xmss_params *params);
int XMSS_verify(unsigned char *message, sigXMSS *sig, pkXMSS *pkx, const xmss_params *params);


#ifdef __cplusplus
}
#endif

#endif  // PROJECT_XMSS_VEC_H
