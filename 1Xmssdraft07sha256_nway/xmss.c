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
#include "hash_address.h"

#include "xmssBib.c"
#include "functions.c"
#include "wots.c"
#include "treehash.c"
#include "treetraversal.c"

void buildAuth(skXMSS sk, bds_state *path, u32 s, const xmss_params *params, u32 *pub_seed, u32 *ADRS32);
// set parameter xmss
void XMSS_setParams(xmss_params *params, int n, int h, int k, int w)
{
  params->h = h;
  params->n = n;
  params->k = k;
  wots_params wots_par;
  WOTS_setParams(&wots_par, n, w);
  params->wots_par = wots_par;
}

//generate Keys XMSS
void XMSS_keyGen(pkXMSS *pkx, skXMSS *sk, bds_state *path, const xmss_params *params)
{
	u32 ADRS32[8]  __attribute__ ((aligned (32))) = {0};
	u8 n = params->n;
	uIntHash root;
	// Set idx = 0
	sk->idx=0;
	// generates random values ​​for SK_SEED (n byte), SK_PRF (m byte), and PUB_SEED (n byte)
	randomNumbers(sk);
	/*int i;
	for(i=0;i<8;i++) sk->sk_seed[i]=0x01010101;
	for(i=0;i<8;i++) sk->pub_seed[i]=0x01010101;
        for(i=0;i<8;i++) sk->sk_prf[i]=0x01010101;*/
	memcpy(pkx->pub_seed,sk->pub_seed,n);
	treeHash_setup(root, sk->sk_seed, &(*path), params, pkx->pub_seed, ADRS32);
	U64TO32B(sk->root[0],sk->root[1], root[0]);
	U64TO32B(sk->root[2],sk->root[3], root[1]);
	U64TO32B(sk->root[4],sk->root[5], root[2]);
	U64TO32B(sk->root[6],sk->root[7], root[3]);
	memcpy(pkx->root,sk->root,n);
}
void treeSig(skXMSS sk, sigXMSS *sig, uIntHash msg_h, bds_state *path, pkXMSS *pkx, u32 s, const xmss_params *params,u32 *ADRS32 )
{
	u8 j,n = params->n;
  	u32 SEED[8]__attribute__ ((aligned (32)));
  	u32 ots_addr32[8]  __attribute__ ((aligned (32))) = {0};

	// Prepare Address for sign
	SET_TYPE32(ots_addr32, 0);
	SET_OTS_ADDRESS32(ots_addr32, sig->idx_sig);
	// Compute seed for sign
	getWOTS_SK(SEED, sk.sk_seed, ots_addr32);
	//Sign  WOTS signature
  	WOTS_sign(sig, msg_h, SEED, s, params, pkx->pub_seed, ots_addr32);
  	for(j=0;j<(params->h);j++)
  		memcpy(sig->auth[j],path->Auth[j].hash,n);
  	buildAuth(sk, &(*path), s, params, pkx->pub_seed, ADRS32);
}

void XMSS_sign(skXMSS sk, sigXMSS *sig, unsigned char *message, bds_state *path, pkXMSS *pkx, u32 s, const xmss_params *params)
{
	u8 i, n = params->n;
  	uIntHash msg_h;
    	u32 r[8]__attribute__ ((aligned (32)));
	u32 IDX_SIG[8]__attribute__ ((aligned (32)))={0};
  	u32 ADRS32[8] __attribute__ ((aligned (32))) = {0};
  	unsigned char hash_key[4*n]__attribute__ ((aligned (32)));
	unsigned char tmp_bytes[32]__attribute__ ((aligned (32)));

	sk.idx=s;
	sig->idx_sig=sk.idx;
  	// Compute pseudorandom key
	IDX_SIG[7]=sk.idx;
  	PRF(r, sk.sk_prf, IDX_SIG);
	for(i = 0; i < 8; i++) sig->r[i] = r[i];
  	// Concatenate hash_key (tobyte(2,n)||r||getRoot(SK)||tobyte(idx_sig,n))
	memset(hash_key, 0, n);
  	hash_key[n-1] = 2;
	for(i=0;i<8;i++) U32TO8(tmp_bytes+(i*4), r[i]);
  	memcpy(hash_key+n, tmp_bytes, n);
	for(i=0;i<8;i++) U32TO8(tmp_bytes+(i*4), sk.root[i]);
  	memcpy(hash_key+(2*n), tmp_bytes, n);
	// index as 32 bytes string
	for(i=0;i<8;i++) U32TO8(tmp_bytes+(i*4), IDX_SIG[i]);
  	memcpy(hash_key+(3*n), tmp_bytes, n);
	//printf("hash_key "); for(i=0; i<(128); i++) printf("%X", hash_key[i]);
  	// Compute message digest
  	H_msg(msg_h, hash_key, (4*n), message,n);
	//printf("msg_h ");for(int j=0;j<4;j++) printf("%lX ",msg_h[j]); printf("\n");
	treeSig(sk, sig, msg_h, &(*path), pkx, s, params, ADRS32 );
}


void XMSS_rootFromSig(uIntHash node, uIntHash msg_h, sigXMSS *sig, pkXMSS *pkx, const xmss_params *params)
{
  	u32 k, cond;
	u8 l = params->wots_par.len;
  	u32 ots_addr32[8] __attribute__ ((aligned (32))) = {0};
  	u32 ltree_addr32[8]__attribute__ ((aligned (32)))={0};
  	u32 node_addr32[8]__attribute__ ((aligned (32)))={0};
	uIntHash pk_ots[l+simd] __attribute__ ((aligned (32)));

	// Prepare Address for verify
	SET_TYPE32(ots_addr32, 0);
	SET_TYPE32(ltree_addr32, 1);
	memcpy(node_addr32, ltree_addr32, 32);
	SET_TYPE32(node_addr32, 2);
	SET_OTS_ADDRESS32(ots_addr32, sig->idx_sig);
	SET_LTREE_ADDRESS32(ltree_addr32, sig->idx_sig);

	// Verify WOTS signature
	WOTS_pkFromSig(pk_ots, sig, msg_h, params,pkx->pub_seed,ots_addr32);
	ltree(node,pk_ots, params, pkx->pub_seed, ltree_addr32);
	//printf("node ");printnBlocosDe64(node, nRows);
	u64 idx=sig->idx_sig;
	for(k=0;k<(params->h);k++){
		cond = (int) sig->idx_sig/(1<<k);
		cond=cond%2;
		SET_NODE_TREE_HEIGHT32(node_addr32, k);
		if(cond==0){
			SET_NODE_TREE_INDEX32(node_addr32, (idx/2));
			RAND_HASH(node,node,sig->auth[k],pkx->pub_seed,node_addr32);
		}else{
        	SET_NODE_TREE_INDEX32(node_addr32, (idx/2));
			RAND_HASH(node, sig->auth[k],node,pkx->pub_seed,node_addr32);
		}
		idx=idx/2;
	}
}

//verify public Key
int XMSS_verify(unsigned char *message, sigXMSS *sig, pkXMSS *pkx, const xmss_params *params)
{
	int check;
	uIntHash node, msg_h;
	u8 i,n = params->n;
	u32 IDX_SIG[8]__attribute__ ((aligned (32)))={0};
	u32 root[8]__attribute__ ((aligned (32)))={0};
  	unsigned char hash_key[4*n]__attribute__ ((aligned (32)));
	unsigned char tmp_bytes[32]__attribute__ ((aligned (32)));

  	// Concatenate hash_key (tobyte(2,n)||r||getRoot(SK)||tobyte(idx_sig,n))
	memset(hash_key, 0, n);
  	hash_key[n-1] = 2;
	IDX_SIG[7]=sig->idx_sig;
	for(i=0;i<8;i++) U32TO8(tmp_bytes+(i*4), sig->r[i]);
  	memcpy(hash_key+n, tmp_bytes, n);
	for(i=0;i<8;i++) U32TO8(tmp_bytes+(i*4), pkx->root[i]);
  	memcpy(hash_key+(2*n), tmp_bytes, n);
	// index as 32 bytes string
	for(i=0;i<8;i++) U32TO8(tmp_bytes+(i*4), IDX_SIG[i]);
  	memcpy(hash_key+(3*n), tmp_bytes, n);
  	// Compute message digest
  	H_msg(msg_h, hash_key, (4*n), message,n);

	XMSS_rootFromSig(node, msg_h, sig, pkx,params);

  	/*	printf("The public key is: \n");
	printnBlocosDe64(publicKey, nRows);
	printf("Temp PK is:");
	printnBlocosDe64(node, nRows);*/
	U64TO32B(root[0],root[1], node[0]);
	U64TO32B(root[2],root[3], node[1]);
	U64TO32B(root[4],root[5], node[2]);
	U64TO32B(root[6],root[7], node[3]);
 	check=memcmp(root,pkx->root,sizeof(pkx->root));

	return check;
}
