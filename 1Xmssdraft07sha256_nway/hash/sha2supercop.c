/* $Id: sha2.c 227 2010-06-16 17:28:38Z tp $ */
/*
 * SHA-224 / SHA-256 implementation.
 *
 * ==========================(LICENSE BEGIN)============================
 *
 * Copyright (c) 2007-2010  Projet RNRT SAPHIR
 * 
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 * 
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 * ===========================(LICENSE END)=============================
 *
 * @author   Thomas Pornin <thomas.pornin@cryptolog.com>
*/

#include "sph_sha2.h"

uint32_t convert_msb(uint64_t i){
	uint32_t msb;
	i = i & 0xFFFF0000;
	i >>= 32;
	msb = i & 0x0000FFFF;
	return (msb);
}

uint32_t convert_lsb(uint64_t i){
	uint32_t lsb;
	lsb = i & 0x0000FFFF;
	return (lsb);
}

#if SPH_SMALL_FOOTPRINT && !defined SPH_SMALL_FOOTPRINT_SHA2
#define SPH_SMALL_FOOTPRINT_SHA2   1
#endif

#define CH(X, Y, Z)    ((((Y) ^ (Z)) & (X)) ^ (Z))
#define MAJ(X, Y, Z)   (((Y) & (Z)) | (((Y) | (Z)) & (X)))

#define ROTR    SPH_ROTR32
#define SPH_T32(x)    ((x) & SPH_C32(0xFFFFFFFF))
#define SPH_ROTL32(x, n)   SPH_T32(((x) << (n)) | ((x) >> (32 - (n))))
#define SPH_ROTR32(x, n)   SPH_ROTL32(x, (32 - (n)))

#define BSG2_0(x)      (ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22))
#define BSG2_1(x)      (ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25))
#define SSG2_0(x)      (ROTR(x, 7) ^ ROTR(x, 18) ^ SPH_T32((x) >> 3))
#define SSG2_1(x)      (ROTR(x, 17) ^ ROTR(x, 19) ^ SPH_T32((x) >> 10))

static const sph_u32 H256[8] = {
	SPH_C32(0x6A09E667), SPH_C32(0xBB67AE85), SPH_C32(0x3C6EF372),
	SPH_C32(0xA54FF53A), SPH_C32(0x510E527F), SPH_C32(0x9B05688C),
	SPH_C32(0x1F83D9AB), SPH_C32(0x5BE0CD19)
};

static const sph_u32 K[64] = {
	SPH_C32(0x428A2F98), SPH_C32(0x71374491),
	SPH_C32(0xB5C0FBCF), SPH_C32(0xE9B5DBA5),
	SPH_C32(0x3956C25B), SPH_C32(0x59F111F1),
	SPH_C32(0x923F82A4), SPH_C32(0xAB1C5ED5),
	SPH_C32(0xD807AA98), SPH_C32(0x12835B01),
	SPH_C32(0x243185BE), SPH_C32(0x550C7DC3),
	SPH_C32(0x72BE5D74), SPH_C32(0x80DEB1FE),
	SPH_C32(0x9BDC06A7), SPH_C32(0xC19BF174),
	SPH_C32(0xE49B69C1), SPH_C32(0xEFBE4786),
	SPH_C32(0x0FC19DC6), SPH_C32(0x240CA1CC),
	SPH_C32(0x2DE92C6F), SPH_C32(0x4A7484AA),
	SPH_C32(0x5CB0A9DC), SPH_C32(0x76F988DA),
	SPH_C32(0x983E5152), SPH_C32(0xA831C66D),
	SPH_C32(0xB00327C8), SPH_C32(0xBF597FC7),
	SPH_C32(0xC6E00BF3), SPH_C32(0xD5A79147),
	SPH_C32(0x06CA6351), SPH_C32(0x14292967),
	SPH_C32(0x27B70A85), SPH_C32(0x2E1B2138),
	SPH_C32(0x4D2C6DFC), SPH_C32(0x53380D13),
	SPH_C32(0x650A7354), SPH_C32(0x766A0ABB),
	SPH_C32(0x81C2C92E), SPH_C32(0x92722C85),
	SPH_C32(0xA2BFE8A1), SPH_C32(0xA81A664B),
	SPH_C32(0xC24B8B70), SPH_C32(0xC76C51A3),
	SPH_C32(0xD192E819), SPH_C32(0xD6990624),
	SPH_C32(0xF40E3585), SPH_C32(0x106AA070),
	SPH_C32(0x19A4C116), SPH_C32(0x1E376C08),
	SPH_C32(0x2748774C), SPH_C32(0x34B0BCB5),
	SPH_C32(0x391C0CB3), SPH_C32(0x4ED8AA4A),
	SPH_C32(0x5B9CCA4F), SPH_C32(0x682E6FF3),
	SPH_C32(0x748F82EE), SPH_C32(0x78A5636F),
	SPH_C32(0x84C87814), SPH_C32(0x8CC70208),
	SPH_C32(0x90BEFFFA), SPH_C32(0xA4506CEB),
	SPH_C32(0xBEF9A3F7), SPH_C32(0xC67178F2)
};

#define SHA2_MEXP1(in, pc)   do { \
		W[pc] = in[pc]; \
	} while (0)

#define SHA2_MEXP2(in, pc)   do { \
		W[(pc) & 0x0F] = SPH_T32(SSG2_1(W[((pc) - 2) & 0x0F]) \
			+ W[((pc) - 7) & 0x0F] \
			+ SSG2_0(W[((pc) - 15) & 0x0F]) + W[(pc) & 0x0F]); \
	} while (0)

#define SHA2_STEPn(n, a, b, c, d, e, f, g, h, in, pc)   do { \
		sph_u32 t1, t2; \
		SHA2_MEXP ## n(in, pc); \
		t1 = SPH_T32(h + BSG2_1(e) + CH(e, f, g) \
			+ K[pcount + (pc)] + W[(pc) & 0x0F]); \
		t2 = SPH_T32(BSG2_0(a) + MAJ(a, b, c)); \
		d = SPH_T32(d + t1); \
		h = SPH_T32(t1 + t2); \
	} while (0)

#define SHA2_STEP1(a, b, c, d, e, f, g, h, in, pc) \
	SHA2_STEPn(1, a, b, c, d, e, f, g, h, in, pc)
#define SHA2_STEP2(a, b, c, d, e, f, g, h, in, pc) \
	SHA2_STEPn(2, a, b, c, d, e, f, g, h, in, pc)

#define SHA2_ROUND_BODY(in, r)   do { \
		sph_u32 A, B, C, D, E, F, G, H; \
		sph_u32 W[16]; \
		unsigned pcount; \
 \
		A = (r)[0]; \
		B = (r)[1]; \
		C = (r)[2]; \
		D = (r)[3]; \
		E = (r)[4]; \
		F = (r)[5]; \
		G = (r)[6]; \
		H = (r)[7]; \
		pcount = 0; \
		SHA2_STEP1(A, B, C, D, E, F, G, H, in,  0); \
		SHA2_STEP1(H, A, B, C, D, E, F, G, in,  1); \
		SHA2_STEP1(G, H, A, B, C, D, E, F, in,  2); \
		SHA2_STEP1(F, G, H, A, B, C, D, E, in,  3); \
		SHA2_STEP1(E, F, G, H, A, B, C, D, in,  4); \
		SHA2_STEP1(D, E, F, G, H, A, B, C, in,  5); \
		SHA2_STEP1(C, D, E, F, G, H, A, B, in,  6); \
		SHA2_STEP1(B, C, D, E, F, G, H, A, in,  7); \
		SHA2_STEP1(A, B, C, D, E, F, G, H, in,  8); \
		SHA2_STEP1(H, A, B, C, D, E, F, G, in,  9); \
		SHA2_STEP1(G, H, A, B, C, D, E, F, in, 10); \
		SHA2_STEP1(F, G, H, A, B, C, D, E, in, 11); \
		SHA2_STEP1(E, F, G, H, A, B, C, D, in, 12); \
		SHA2_STEP1(D, E, F, G, H, A, B, C, in, 13); \
		SHA2_STEP1(C, D, E, F, G, H, A, B, in, 14); \
		SHA2_STEP1(B, C, D, E, F, G, H, A, in, 15); \
		for (pcount = 16; pcount < 64; pcount += 16) { \
			SHA2_STEP2(A, B, C, D, E, F, G, H, in,  0); \
			SHA2_STEP2(H, A, B, C, D, E, F, G, in,  1); \
			SHA2_STEP2(G, H, A, B, C, D, E, F, in,  2); \
			SHA2_STEP2(F, G, H, A, B, C, D, E, in,  3); \
			SHA2_STEP2(E, F, G, H, A, B, C, D, in,  4); \
			SHA2_STEP2(D, E, F, G, H, A, B, C, in,  5); \
			SHA2_STEP2(C, D, E, F, G, H, A, B, in,  6); \
			SHA2_STEP2(B, C, D, E, F, G, H, A, in,  7); \
			SHA2_STEP2(A, B, C, D, E, F, G, H, in,  8); \
			SHA2_STEP2(H, A, B, C, D, E, F, G, in,  9); \
			SHA2_STEP2(G, H, A, B, C, D, E, F, in, 10); \
			SHA2_STEP2(F, G, H, A, B, C, D, E, in, 11); \
			SHA2_STEP2(E, F, G, H, A, B, C, D, in, 12); \
			SHA2_STEP2(D, E, F, G, H, A, B, C, in, 13); \
			SHA2_STEP2(C, D, E, F, G, H, A, B, in, 14); \
			SHA2_STEP2(B, C, D, E, F, G, H, A, in, 15); \
		} \
		(r)[0] = SPH_T32((r)[0] + A); \
		(r)[1] = SPH_T32((r)[1] + B); \
		(r)[2] = SPH_T32((r)[2] + C); \
		(r)[3] = SPH_T32((r)[3] + D); \
		(r)[4] = SPH_T32((r)[4] + E); \
		(r)[5] = SPH_T32((r)[5] + F); \
		(r)[6] = SPH_T32((r)[6] + G); \
		(r)[7] = SPH_T32((r)[7] + H); \
	} while (0)

#define SHA2_MEXP1b(in, W, pc)   do { \
		W[pc] = in[pc]; \
	} while (0)


#define SHA2_MEXP2b(in, W, pc)   do { \
		W[pc] = SPH_T32( SSG2_1(W[pc - 2])+W[pc-7] \
			+ SSG2_0(W[(pc) - 15 ]) + W[(pc)-16]); \
	} while (0)


#define SHA2_STEPnb(a, b, c, d, e, f, g, h, W, pc)   do { \
		sph_u32 t1, t2; \
		t1 = SPH_T32(h + BSG2_1(e) + CH(e, f, g) \
			+ W[pcount + (pc)]); \
		t2 = SPH_T32(BSG2_0(a) + MAJ(a, b, c)); \
		d = SPH_T32(d + t1); \
		h = SPH_T32(t1 + t2); \
	} while (0)

#define SHA2_ROUND_BODYb(in, r)   do { \
		sph_u32 A, B, C, D, E, F, G, H; \
		unsigned pcount; \
 \
		A = (r)[0]; \
		B = (r)[1]; \
		C = (r)[2]; \
		D = (r)[3]; \
		E = (r)[4]; \
		F = (r)[5]; \
		G = (r)[6]; \
		H = (r)[7]; \
		pcount = 0; \
		for (pcount = 0; pcount < 64; pcount += 16) { \
			SHA2_STEPnb(A, B, C, D, E, F, G, H, in,  0); \
			SHA2_STEPnb(H, A, B, C, D, E, F, G, in,  1); \
			SHA2_STEPnb(G, H, A, B, C, D, E, F, in,  2); \
			SHA2_STEPnb(F, G, H, A, B, C, D, E, in,  3); \
			SHA2_STEPnb(E, F, G, H, A, B, C, D, in,  4); \
			SHA2_STEPnb(D, E, F, G, H, A, B, C, in,  5); \
			SHA2_STEPnb(C, D, E, F, G, H, A, B, in,  6); \
			SHA2_STEPnb(B, C, D, E, F, G, H, A, in,  7); \
			SHA2_STEPnb(A, B, C, D, E, F, G, H, in,  8); \
			SHA2_STEPnb(H, A, B, C, D, E, F, G, in,  9); \
			SHA2_STEPnb(G, H, A, B, C, D, E, F, in, 10); \
			SHA2_STEPnb(F, G, H, A, B, C, D, E, in, 11); \
			SHA2_STEPnb(E, F, G, H, A, B, C, D, in, 12); \
			SHA2_STEPnb(D, E, F, G, H, A, B, C, in, 13); \
			SHA2_STEPnb(C, D, E, F, G, H, A, B, in, 14); \
			SHA2_STEPnb(B, C, D, E, F, G, H, A, in, 15); \
		} \
		(r)[0] = SPH_T32((r)[0] + A); \
		(r)[1] = SPH_T32((r)[1] + B); \
		(r)[2] = SPH_T32((r)[2] + C); \
		(r)[3] = SPH_T32((r)[3] + D); \
		(r)[4] = SPH_T32((r)[4] + E); \
		(r)[5] = SPH_T32((r)[5] + F); \
		(r)[6] = SPH_T32((r)[6] + G); \
		(r)[7] = SPH_T32((r)[7] + H); \
	} while (0)


void sha256_init(u32 state[8]){
	int i;
	for(i=0;i<8;i++) state[i]=H256[i];
}
void addBitsClose(unsigned char *texto, u32 inlen, u32_16 *blocs)
{
	u32 i=0;
	int blocCurrent=0, nCurrent=0, posCurrent=0;
	u32 temp;
	u64 bitfrase;

        bitfrase = inlen * 8;
	blocs[0][0] = 0;
	//printf("texto=%X \n",texto[0]);
	while(i<inlen)	
	{
		temp = texto[i++];
		temp <<= ( (3-posCurrent) * 8);
		blocs[blocCurrent][nCurrent]+= temp;
		if ((posCurrent) == 3){
			nCurrent ++;
			if (nCurrent==16){
				nCurrent = 0;
				blocCurrent ++;
			}
			blocs[blocCurrent][nCurrent]=0;
		}
		posCurrent = (posCurrent +1) % 4;
	}
        //printf("posição i=%d,numCorrente=%d,bitfrase=%d\n",i,nCurrent,bitfrase);
	temp = 0x80;
	temp <<= ((3-posCurrent) * 8);
	//qtdzeros = ((4-posCurrent) * 8)-1;
	blocs[blocCurrent][nCurrent]+= temp;
	nCurrent ++;
	if (nCurrent >=15){
		for (i=nCurrent; i< 16; i++)blocs[blocCurrent][i] = 0;
		blocCurrent ++;
		nCurrent = 0;
	}
	for (i = nCurrent; i< 14; i++) blocs[blocCurrent][i] = 0;
	blocs [blocCurrent][14] = convert_msb (bitfrase);
	blocs [blocCurrent][15] = convert_lsb (bitfrase);
}

void crypto_hash(uIntHash out, unsigned char *message)
{
	int i, qtdBlocs;
	u32 state[8];
        u32 inlen=strlen((char *)message);
	qtdBlocs=((inlen*8)+1+64)/512+1;
	u32_16 blocs[64];

	addBitsClose(message,inlen,(u32_16 *)blocs);
	sha256_init(state);
	for(i=0; i<qtdBlocs; i++){
		 printf("blocs: ");print_uint32(blocs[i], 16);
		 SHA2_ROUND_BODY(blocs[i], state);
	}
	for(int i=0;i<nRows;i++) out[i]=U32TO64(state+(i*2)) ;
}

void SHA2_256_char(const u8 *message, u32 inlen, unsigned char *out)
{
	int i, qtdBlocs;
	u32 state[8];
	qtdBlocs=(((inlen*8)+1+64)/512)+1;
	u32_16 blocs[64];

	//printf("qtdBlocs=%d\n",qtdBlocs);
	addBitsClose((u8 *)message,inlen, (u32_16 *)blocs);
	sha256_init(state);
	for(i=0; i<qtdBlocs; i++){
		//printf("blocs: ");print_uint32(blocs[i], 16);
		SHA2_ROUND_BODY(blocs[i], state);
	}
	//printf("state: ");print_uint32(state, 8);
	for(int i=0;i<(nRows*2);i++) U32TO8(out+(4*i), state[i]);
}

void SHA2_256(unsigned char *message, u32 inlen, uIntHash out)
{
	int i, qtdBlocs;
	u32 state[8];
	qtdBlocs=(((inlen*8)+1+64)/512)+1;
	u32_16 blocs[64];

	//printf("inlen=%d, qtdBlocs=%d\n",inlen, qtdBlocs);
	addBitsClose(message,inlen, (u32_16 *)blocs);
	sha256_init(state);
	for(i=0; i<qtdBlocs; i++){
		//printf("blocs: ");print_uint32(blocs[i], 16);
		SHA2_ROUND_BODY(blocs[i], state);
	}
	//printf("state: ");print_uint32(state, 8);
	for(int i=0;i<nRows;i++) out[i]=U32TO64(state+(i*2));
}

void SHA2_256_hmac(u32 *in,u32 inlen, u32 *out)
{
	int i, posit;
	u32 state[8];
	u32 bloc1[16];

	posit=(inlen-64)/4;
	//printf("posit=%d \n", posit);
	sha256_init(state);
	memcpy(bloc1,in,64);
	//printf("bloc1: ");print_uint32(bloc1, 16);
	SHA2_ROUND_BODY(bloc1, state);
	memcpy(bloc1,in+16,32);
	bloc1[posit]=0x80000000;
	for(i=posit+1;i<15;i++) bloc1[i]=0;
	bloc1[15]=inlen*8;
	//printf("bloc1: ");print_uint32(bloc1, 16);
	SHA2_ROUND_BODY(bloc1, state);
	//printf("state: ");print_uint32(state, 8);
	for(i=0;i<(nRows*2);i++) out[i]=state[i];
}

void SHA2_256_u32(unsigned char *message, u32 inlen, u32 *out)
{
	int i, qtdBlocs;
	u32 state[8];
	qtdBlocs=(((inlen*8)+1+64)/512)+1;
	u32_16 blocs[64];

	//printf("inlen=%d, qtdBlocs=%d\n",inlen, qtdBlocs);
	addBitsClose(message,inlen, (u32_16 *)blocs);
	sha256_init(state);
	for(i=0; i<qtdBlocs; i++){
		//printf("blocs: ");print_uint32(blocs[i], 16);
		SHA2_ROUND_BODY(blocs[i], state);
	}
	//printf("state: ");print_uint32(state, 8);
	for(int i=0;i<(nRows*2);i++) out[i]=state[i];
}
void crypto_hashComputeWSHA2(u32 e[16], sph_u32 W2[64]){
	u8 pc;

	for(pc=0;pc<16;pc++) 
		SHA2_MEXP1b(e, W2, pc); 
	for (pc = 16; pc < 64; pc ++)
		SHA2_MEXP2b(e, W2, pc);
	for(pc=0;pc<64;pc++)		
		W2[pc]=W2[pc]+K[pc];
}

void crypto_hash256(uIntHash out, uIntHash in)
{
	int i;
	uint32_t e[16]={0};//messages to 256-bit and 256-bit hash
	u32 state[8];
	sph_u32 W[64];

	U64TO32( e+(0), in[0] );
	U64TO32( e+(2), in[1] );
	U64TO32( e+(4), in[2] );
	U64TO32( e+(6), in[3] );
	e[8]=0x80000000;
	e[15]=256;
	sha256_init(state);
	//SHA2_ROUND_BODY(e, state);
	crypto_hashComputeWSHA2(e, W);
	SHA2_ROUND_BODYb(W, state);
	for(i=0;i<4;i++) out[i]=U32TO64(state+(i*2)) ;
}

void crypto_hash2xb(uIntHash out, uInt512 in )
{
	u8 i;
	u32 e1[16],e2[16]={0};///messages to 512-bit and 256-bit hash
	u32 state[8];

	U64TO32( e1+(0), in[0] );U64TO32( e1+(2), in[1] );
	U64TO32( e1+(4), in[2] );U64TO32( e1+(6), in[3] );
	U64TO32( e1+(8), in[4] );U64TO32( e1+(10), in[5] );
	U64TO32( e1+(12), in[6] );U64TO32( e1+(14), in[7] );
	e2[0]=0x80000000;
	e2[15]=512;//add the size of the last message block
	sha256_init(state);
	SHA2_ROUND_BODY(e1, state);
	SHA2_ROUND_BODY(e2, state);
	for(i=0;i<4;i++) out[i]=U32TO64(state+(i*2)) ;
}
  

