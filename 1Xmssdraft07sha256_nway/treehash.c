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
//empilha na árvore de Merkle um nó gerado conforme algoritmo treehash
//usado somente no processo de geração de chaves do esquema XMSS
void treeHash_setup(uIntHash root, u32 *sk_seed, bds_state *path, const xmss_params *params, u32 *pub_seed, u32 *ADRS32) {
	rTree in, top;
	u8 iStack=0,qtdAutP=0;
	uIntHash leaf;
	u8 h=params->h, K=params->k,n=params->n;
	u8 i,h_k=h-K,l = params->wots_par.len;
	u64 j,idx,temp,leafs=1<<h;
	rTree StackAux[h+1] __attribute__ ((aligned (32)));
	uIntHash pk[l+7] __attribute__ ((aligned (32)));
	u32 ots_addr32[8]__attribute__ ((aligned (32)))={0};
	u32 ltree_addr32[8]__attribute__ ((aligned (32)))={0};
	u32 node_addr32[8]__attribute__ ((aligned (32)))={0};

	memcpy(ots_addr32, ADRS32, 32);
	SET_TYPE32(ots_addr32, 0);
	memcpy(ltree_addr32, ADRS32, 32);
	SET_TYPE32(ltree_addr32, 1);
	memcpy(node_addr32, ltree_addr32, 32);
	SET_TYPE32(node_addr32, 2);

	for(idx=0;idx<leafs;idx++){
	   in.numNo=idx;
	   in.height = 0;
	   SET_OTS_ADDRESS32(ots_addr32, idx);
	   //printf("ots_addr32: ");print_uint32(ots_addr32, 8);
	   WOTS_genPK(pk, sk_seed, params, pub_seed, ots_addr32);
	   SET_LTREE_ADDRESS32(ltree_addr32, idx);
	   ltree(leaf, pk, params, pub_seed, ltree_addr32);
	   //printf("leaf=%lld - ", idx);printnBlocosDe64(leaf, nRows);
	   memcpy(in.hash, leaf,n);
	   while((iStack)!=0 && (in.height == (StackAux[(iStack)-1].height)))
	   {
		if(in.numNo==1){
			path->Auth[(qtdAutP)]=in;
			(qtdAutP)++;
		}else if(in.height<=(h_k-1)&&(in.numNo)==3){
			path->TreeHASH[in.height]=in;
		}else{
		   for(i=h_k;i<=(h-2);i++)
			if(in.height==i){
				temp=(1<<(h-i-1))-2;
				for(j=0;j<=temp;j++)
					if(in.numNo==(2*j+3)){
					   path->Retain[in.height][j]=in;
					}
			}
		}
		top = StackAux[(iStack)-1];
		(iStack)--;
		SET_NODE_TREE_HEIGHT32(node_addr32, (top.height));
		SET_NODE_TREE_INDEX32(node_addr32, (top.numNo/2));
		//printf("in.numNo=%d, node_addr32 ",top.numNo);print_uint32(node_addr32, 4);
		RAND_HASH(in.hash, top.hash,in.hash,pub_seed,node_addr32);
		in.height=(in.height)+1;
		in.numNo = (in.numNo)/2;
	   }
	   StackAux[(iStack)]=in;
	   iStack++;
	}
	memcpy(root,StackAux[0].hash,n);
}
//empilha na árvore de Merkle um nó gerado conforme algoritmo treehash
//usado no processo de assinatura
void treeHash_update(uIntHash nY, u32 numNo, bds_state *path, u8 h, u8 n, u32 *pub_seed, u32 *node_addr32) {
	rTree in, top;
	in.numNo=numNo;
	in.height = 0;
	memcpy(in.hash, nY,n);
	while((path->TreeHASHiStack[h])!=0 && (in.height == (path->TreeHASHstack[h][(path->TreeHASHiStack[h])-1].height)))
	{
		top = path->TreeHASHstack[h][(path->TreeHASHiStack[h])-1];
		(path->TreeHASHiStack[h])--;
		SET_NODE_TREE_HEIGHT32(node_addr32, (top.height));
		SET_NODE_TREE_INDEX32(node_addr32, (top.numNo/2));
		RAND_HASH(in.hash, top.hash,in.hash,pub_seed,node_addr32);
		in.height=(in.height)+1;
		in.numNo = (in.numNo)/2;
	}
	path->TreeHASHstack[h][(path->TreeHASHiStack[h])]=in;
	(path->TreeHASHiStack[h])++;
}

//function L-tree
//gen simd internal nodes at the same time using AVX2
void ltree(uIntHash leaf, uIntHash *pk, const xmss_params *params, u32 *pub_seed, u32 *ltree_addr32){
	u8 l = params->wots_par.len;//,simd2=8;
	u8 n = params->n;
	u32_8 vet[2][l] __attribute__ ((aligned (32)));
	u8 i,h,total,atual=0,next=1,x,idx,hLtree;
	u32 ADRS32[simd][8]__attribute__ ((aligned (32)));

	for(i=0;i<l;i++)
		memcpy(vet[atual][i],pk[i],n);
	total=l;
	computeHeight(l,i,hLtree);
	for(i=0;i<simd;i++) memcpy(ADRS32[i],ltree_addr32,32);
	for(h=0;h<hLtree;h++){
		x=0; idx=0;
		for(i=0;i<simd;i++) SET_LTREE_TREE_HEIGHT32(ADRS32[i], h);
		//if has (2*simd) nodes then gen simd nodes at the same time with SHA2-AVX2
		while((x+simd*2)<=total && simd>1){
			for(i=0;i<simd;i++)
				SET_LTREE_TREE_INDEX32(ADRS32[i], (idx+i));
			RAND_HASH_nway(vet[next], vet[atual], x, pub_seed, ADRS32);
			x+=(simd*2);idx+=(simd);
		}
		//if not has (2*simd) nodes then gen only 1 node
		while((x+1) < total){
			SET_LTREE_TREE_INDEX32(ADRS32[0], idx);
			RAND_HASH32(vet[next][x/2], vet[atual][x], vet[atual][x+1], pub_seed, ADRS32[0]);
			x+=2;idx++;
		}
		//if exist 1 only node then it is shifted a higher level on the tree
		if(x<total)
			memcpy(vet[next][x/2],vet[atual][x],n);
		atual=1-atual;
		next=1-next;
		total=total/2+(total%2);
	}
	//memcpy(leaf,(uIntHash)(vet[atual][0]),n);
	for(i=0;i<4;i++) leaf[i]=U32TO64(vet[atual][0]+(i*2)) ;
	//printf("leaf ");printnBlocosDe64(leaf, nRows);

}
