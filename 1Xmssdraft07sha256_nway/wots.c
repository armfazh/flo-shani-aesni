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
 
#include "treehash.h"
//set parameter Winternitz
void WOTS_setParams(wots_params *params, int n, int w)
{
  params->n = n;
  params->w = w;
  params->logw = (int) log2(w);
  params->len1 = (int) ceil(((8*n) / params->logw));
  params->len2 = (int) floor(log2(params->len1*(w-1)) / params->logw) + 1;
  params->len = params->len1 + params->len2;
  params->keysize = params->len*params->n;
  printf("p->len1=%d, p->l2=%d, p->len=%d \n",params->len1,params->len2,params->len);
}

void base_w(dSigWin *basew, uIntHash X, const xmss_params *params){
	u8 l = params->wots_par.len;
	u8 w = params->wots_par.w;
	u8 in=0;
	u8 out =0;
	u64 total=0;
	u8 bits=0;
	u8 consumed=0;
	u32 csum=0;

	u8 lgw=log2(w);
	//convert message to base w
	for(consumed=0;consumed < params->wots_par.len1; consumed++){
		if(bits==0){
			total=X[in];
			in++;
			bits+=64;
		}
		bits-=lgw;
		basew[out].idx=out;
		basew[out].e=(total>>bits & (w -1));
		out++;
	}
	//compute checksum
	for(consumed=0;consumed < params->wots_par.len1; consumed++)
		csum=csum+((w)-1-basew[consumed].e);
	//convert csum to base w
	out=l-1;
	bits=(lgw * params->wots_par.len2);
	while(bits>=(lgw)){
	    basew[out].e=csum&(w -1);
   		basew[out].idx=out;
		csum>>=lgw;
		bits=bits-lgw;
		out--;
	}
}

//chain(out, in, ini, end, posicaoInicial);
#ifdef XMSS_SHA2_8x
static inline void chain(uIntHash *out64, uIntHash *in, int ini, int s, int posit, u8 n, u32 *pub_seed, u32 ADRS32[8][8])
{
	u8 i,j,nr,simd2=8;
	u32 tmp2[8][8];
	__m256i M[8], PADSHA256[8], PUBSEED256[8], BM256[8],KEY256[8],ADRS256[8];
	__m256i zero_32=_mm256_set1_epi32(0);
	__m256i one_32=_mm256_set1_epi32(1);

	if(s==0){
		for(i=0;i<8;i++) memcpy(out64[posit+i],in[posit+i],n);
	}else{
		for(i=0;i<8;i++) M[i] = _mm256_load_si256((__m256i*)in[posit+i]);
		transposta_zip(M);
		// pad SHA2
		PADSHA256[0] =_mm256_set1_epi32 (0x80000000);
		for (j=1; j < 7; j++) 	   PADSHA256[j] = _mm256_setzero_si256();
		PADSHA256[7] =_mm256_set1_epi32 (768);
		// transpose ADRS32
		for(i=0;i<8;i++){
			for(j=0;j<simd2;j++)	tmp2[i][j]=(uint32_t)ADRS32[j][i];
			ADRS256[i]=_mm256_load_si256 ((__m256i*)tmp2[i]);
		}
		// set PUBSEED256
		for(j=0;j<simd2;j++)
			PUBSEED256[j] =_mm256_set1_epi32(pub_seed[j]);
		// compute chain
		for(nr=ini;nr<s;nr++){
			SET_HASH_ADDRESS256(ADRS256, nr);
			SET_KEY_AND_MASK256(ADRS256,zero_32);
			PRF_8way(KEY256, PUBSEED256,ADRS256);
			SET_KEY_AND_MASK256(ADRS256,one_32);
			PRF_8way(BM256, PUBSEED256,ADRS256);
		   	for(i=0;i<nHash;i++)	M[i]=_mm256_xor_si256(M[i],BM256[i]);
			//F_8way(KEY,M XOR BM)
			F_8way(M, KEY256, M, PADSHA256 );
		}
		transposta_unzip(M);
		for (i=0; i < 8; i++) _mm256_store_si256 ((__m256i *) out64[posit+i], M[i]);
	}
}
#endif
#ifdef XMSS_SHA2_4x
void chain(uIntHash *out64, uIntHash *in, int ini, int s,int posit, u8 n, u32 *pub_seed, u32 ADRS32[4][8])
{
	u8 i,j,nr,simd4=4;
	u32 tmp2[8][4],tmp[4][8];
	__m128i M[8], PADSHA128[8], PUBSEED128[8], BM128[8],KEY128[8],ADRS128[8];
	__m128i zero_32=_mm_set1_epi32(0);
	__m128i one_32=_mm_set1_epi32(1);

	if(s==0){
		for(i=0;i<4;i++) memcpy(out64[posit+i],in[posit+i],n);
	}else{
		for(i=0;i<simd4;i++){
			U64TO32( tmp[i]+(0), in[posit+i][0] );
			U64TO32( tmp[i]+(2), in[posit+i][1] );
			U64TO32( tmp[i]+(4), in[posit+i][2] );
			U64TO32( tmp[i]+(6), in[posit+i][3] );
		}
		//printf("in: ");for(i=0;i<simd4;i++) printnBlocosDe64(in[posit+i], nRows);
		//transposta
		for (i=0; i < nHash; i++){
		        for (j=0; j < simd4; j++) tmp2[i][j]=(uint32_t)tmp[j][i];
        		M[i] = _mm_load_si128 ((__m128i *) tmp2[i]);
			//printf("tmp2-in ");print_uint32(tmp2[i], 4);
			//printf("M[i]-in ");print_m128i(M[i]);
    		}
		// pad SHA2
		PADSHA128[0] =_mm_set1_epi32 (0x80000000);
		for (j=1; j < 7; j++) 	   PADSHA128[j] = _mm_setzero_si128();
		PADSHA128[7] =_mm_set1_epi32(768);
		// transpose ADRS32
		for(i=0;i<nHash;i++){
			for(j=0;j<simd4;j++) tmp2[i][j]=(uint32_t)ADRS32[j][i];
			ADRS128[i]=_mm_load_si128 ((__m128i *)tmp2[i]);
		}
		// set PUBSEED256
		for(j=0;j<8;j++)
			PUBSEED128[j] =_mm_set1_epi32(pub_seed[j]);
		// compute chain
		for(nr=ini;nr<s;nr++){
			SET_HASH_ADDRESS128(ADRS128, nr);
			SET_KEY_AND_MASK128(ADRS128,zero_32);
			PRF_4way(KEY128, PUBSEED128,ADRS128);
			SET_KEY_AND_MASK128(ADRS128,one_32);
			PRF_4way(BM128, PUBSEED128,ADRS128);
			//printf("BM128: ");for(i=0;i<8;i++) print_m128i(BM128[i]);
		   	for(i=0;i<nHash;i++){
				//tmpM[i]=M[i];
				//printf("M[i]-nr=%d: ",nr);print_m128i(M[i]);
				M[i]=_mm_xor_si128(M[i],BM128[i]);
				//printf("M[i] apos xor ");print_m128i(tmpM[i]);

			}
			//F_8way(KEY,M XOR BM)
			F_4way(M, KEY128, M, PADSHA128 );
		}
		//transposta_unzip(M);
		for (i=0; i < nHash; i++)
			_mm_store_si128 ((__m128i *) tmp2[i], M[i]);
		for (j=0;j<simd4; j++)
			for(i=0;i<nRows;i++)
				out64[posit+j][i]=U32TO64B(tmp2[i*2][j], tmp2[i*2+1][j]) ;
	}
}
#endif
#ifdef XMSS_SHA2_1x
void chain(uIntHash *out64, uIntHash *in, int ini, int s,int posit, u8 n, u32 *pub_seed, u32 ADRS32[8][8])
{
	uint8_t i,nr;
	u32 M[8]={0};
	u32 KEY[8];
	u32 BM[8];

	if(s==0){
		memcpy(out64[posit],in[posit],n);
	}else{
		U64TO32( M+(0), in[posit][0] );
		U64TO32( M+(2), in[posit][1] );
		U64TO32( M+(4), in[posit][2] );
		U64TO32( M+(6), in[posit][3] );
		/* compute chain */
		for(nr=ini;nr<s;nr++){
			SET_HASH_ADDRESS32(ADRS32[0], nr);
   			SET_KEY_AND_MASK32(ADRS32[0],0);
			PRF(KEY, pub_seed, ADRS32[0]);
			//printf("nr=%d, KEY: ", nr);print_uint32(KEY, 8);
			SET_KEY_AND_MASK32(ADRS32[0],1);
			PRF(BM, pub_seed, ADRS32[0]);
			//F(KEY,M XOR BM)
			for (i = 0; i < 8; i++) M[i]=M[i]^BM[i];
			F(M, KEY, M);
		}
		for(i=0;i<nRows;i++) out64[posit][i]=U32TO64(M+(i*2));
	}
	//printf("out64= ");printnBlocosDe64(out64[posit], nRows);
}
#endif

#ifdef XMSS_SHA2_8x
static void expand_seed(uIntHash *outseeds, u32 *inseed, const xmss_params *params)
{
	u8 n = params->n;
	PRG_8way(outseeds, params->wots_par.len, n, inseed);
}
#endif
#ifdef XMSS_SHA2_4x
static void expand_seed(uIntHash *outseeds, u32 *inseed, const xmss_params *params)
{
	u8 n = params->n;
	PRG_4way(outseeds, params->wots_par.len, n, inseed);
}
#endif
#ifdef XMSS_SHA2_1x
static void expand_seed(uIntHash *outseeds, u32 *inseed, const xmss_params *params)
{
	u8 n = params->n;
	PRG(outseeds, params->wots_par.len, n, inseed);
	//for(int j=0;j<8;j++) {printf("outseeds[%d]= ",j);printnBlocosDe64(outseeds[j], nRows);}
}
#endif
static void getWOTS_SK(u32 *SK, u32 *sk_seed, u32 *addr32)
{
	SET_CHAIN_ADDRESS32(addr32,0);
	SET_HASH_ADDRESS32(addr32,0);
	SET_KEY_AND_MASK32(addr32,0);
	//printf("bytes(");  printf("addr32): ");print_uint32(addr32, 8);
	PRF(SK, sk_seed, addr32);
}

//compute one Merkle leaf
void WOTS_genPK(uIntHash *pk, u32 *sk_seed, const xmss_params *params, u32 *pub_seed, u32 *ots_addr32)
{
	u8 i, j, l = params->wots_par.len;//,simd4=4;
	u8 n = params->n;
	u8 w = params->wots_par.w;
	uIntHash tmp_sk[l+simd] __attribute__ ((aligned (32)));
	u32 SK[8];
	u32 ADRS32[simd][8];

	for(j=0;j<simd;j++)	memcpy(ADRS32[j],ots_addr32,32);
	getWOTS_SK(SK, sk_seed, ots_addr32);
	//printf("SK: ");print_uint32(SK, 8);
   	expand_seed(tmp_sk, SK, params);
	//for(j=0;j<l;j++) {printf("sk[%d]= ",j);printnBlocosDe64(tmp_sk[j], nRows);}
	for(i=0;i<l;i+=simd){
		for(j=0;j<simd;j++){
			SET_CHAIN_ADDRESS32(ADRS32[j], (i+j));
		}
		chain(pk, tmp_sk, 0, (w-1), i, n, pub_seed, ADRS32);
	}
	memcpy(ots_addr32,ADRS32[simd-1],32);
	//for(j=0;j<l;j++) {printf("pk[%d]= ",j);printnBlocosDe64(pk[j], nRows);}
}

//WOTS signature generation
void WOTS_sign(sigXMSS *sig, uIntHash msg_h, u32 *SK, u32 s, const xmss_params *params, u32 *pub_seed, u32 *ots_addr32) {
	u8 l = params->wots_par.len;
	u8 n = params->n;
	dSigWin msg[l+(simd)] __attribute__ ((aligned (32)));
	uIntHash tmp_sk[l+simd] __attribute__ ((aligned (32)));
	uIntHash tempSig[simd] __attribute__ ((aligned (32)));
	u8 i, j, ini, eCurr, x=0;

	u32 ADRS32[simd][8];
	for(j=0;j<simd;j++)	memcpy(ADRS32[j],ots_addr32,32);
	sig->idx_sig=s;
	base_w(msg, msg_h, params);	//compute d according message bits
	//printf("msg "); for(i=0;i<l;i++) printf("%lld ",msg[i].e);printf("\n");
	//for(i=0;i<l;i++) msg[i].e=params->wots_par.w-1;
	insertion_sort(msg, l); //ordena os valores de d para aplicação da função f em paralelo
	expand_seed(tmp_sk, SK, params);
	//for(j=0;j<8;j++) {printf("sk[%d]= ",j);printnBlocosDe64(tmp_sk[j], nRows);}
	while(x<l){
		eCurr=msg[x].e;
		i=0;
		ini=x;
		while(i<simd && x<(l) && msg[x].e==eCurr){
		    SET_CHAIN_ADDRESS32(ADRS32[i], msg[x].idx);
		    memcpy(tempSig[i],tmp_sk[msg[x].idx],n);
		    i++;x++;
		}
		chain(tempSig, tempSig, 0, eCurr,0, n, pub_seed, ADRS32);
		for(j=0;j<i;j++){
			memcpy(sig->sig_ots[msg[ini].idx],tempSig[j],n);
			ini++;
		}
	}
	//for(j=0;j<l;j++) {printf("sig[%d]= ",j);printnBlocosDe64(sig->sig_ots[j], nRows);}
}
//verifica conforme o algoritmo WOTS
void WOTS_pkFromSig(uIntHash *pk_ots, sigXMSS *sig, uIntHash msg_h, const xmss_params *params,u32 *pub_seed, u32 *ots_addr32) {
	u8 l = params->wots_par.len;
	u8 w = params->wots_par.w;
	u8 n = params->n;
	dSigWin msg[l+simd] __attribute__ ((aligned (32)));
	uIntHash tempSig[simd] __attribute__ ((aligned (32)));
	u8 i, j, ini, eCurr, x=0;

	u32 ADRS32[simd][8];
	for(j=0;j<simd;j++)	memcpy(ADRS32[j],ots_addr32,32);
	base_w(msg, msg_h, params);//compute d according message bits
	//for(i=0;i<l;i++) msg[i].e=params->wots_par.w-1;
	insertion_sort(msg, l); //ordena os valores de d para aplicação da função f em paralelo
	while(x<(l)){
		eCurr=msg[x].e;
		i=0;
		ini=x;
		while(i<simd && x<l && msg[x].e==eCurr){
		    SET_CHAIN_ADDRESS32(ADRS32[i], msg[x].idx);
		    memcpy(tempSig[i],sig->sig_ots[msg[x].idx],n);
		    i++;x++;
		}
		chain(tempSig, tempSig, eCurr,w-1, 0, n, pub_seed, ADRS32);
		for(j=0;j<i;j++){
			memcpy(pk_ots[msg[ini].idx],tempSig[j],n);
			ini++;
		}
	}
	//for(j=0;j<l;j++) {printf("pk2[%d]= ",j);printnBlocosDe64(pk_ots[j], nRows);}
}
