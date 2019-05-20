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
 
//Algorithm by Merkle Tree Traversal Revisited
#include "flo-xmss-vec.h"
//gen the next authentication path
void buildAuth(skXMSS sk, bds_state *path, u32 s, const xmss_params *params, u32 *pub_seed, u32 *ADRS32)
{
	u8 i,j,Tau=0,min, numUpdate;
	u8 K=params->k;
	u8 h=params->h;
	u8 n=params->n;
	u8 l = params->wots_par.len;
	u64 startnode, leafIni, z, potNos;
	uIntHash pk[l+7] __attribute__ ((aligned (32)));
	uIntHash leaf;
	u32 ots_addr32[8]={0};
	u32 ltree_addr32[8]={0};
	u32 node_addr32[8]={0};

	memcpy(ots_addr32, ADRS32, 32);
	SET_TYPE32(ots_addr32, 0);
	memcpy(ltree_addr32, ADRS32, 32);
	SET_TYPE32(ltree_addr32, 1);
	memcpy(node_addr32, ltree_addr32, 32);
	SET_TYPE32(node_addr32, 2);

	potNos=1<<h;
	if(s%2!=0){ //Tau!=0
		z=s;
		while ((z%2)){
			z=z/2;
			Tau=Tau+1;
		}
	}
	z=1<<(Tau+1);
	if(((s/z)%2==0) && (Tau < (h-1))){
		memcpy(path->Keep[Tau].hash,path->Auth[Tau].hash,n);
		path->Keep[Tau].height=path->Auth[Tau].height;
		path->Keep[Tau].numNo=path->Auth[Tau].numNo;
	}
	if(Tau==0){
		path->Auth[0].numNo=s;
		SET_OTS_ADDRESS32(ots_addr32, s);
		WOTS_genPK(pk, sk.sk_seed, params, pub_seed, ots_addr32);
		SET_LTREE_ADDRESS32(ltree_addr32, s);
	   	ltree(leaf, pk, params, pub_seed, ltree_addr32);
		memcpy(path->Auth[0].hash, leaf,n);
		path->Auth[0].height=0;
	}else if(Tau<h){
        	SET_NODE_TREE_HEIGHT32(node_addr32, (Tau-1));
        	SET_NODE_TREE_INDEX32(node_addr32, ((path->Keep[(Tau-1)].numNo)/2));
		RAND_HASH(path->Auth[Tau].hash, path->Auth[(Tau-1)].hash,path->Keep[(Tau-1)].hash,pub_seed,node_addr32);
		path->Auth[Tau].numNo=(path->Auth[Tau-1].numNo)/2;
		path->Auth[Tau].height=Tau;
		for(i=0;i<=(Tau-1);i++){
			if(i<=(h-K-1)){
				path->Auth[i]=path->TreeHASH[i];
			}else{ //if(i>(h-K-1))
				path->Auth[i]=path->Retain[i][path->ind[i]];
				path->ind[i]++;
			}
		}
		min=Tau-1;
		if((h-K-1)<min) min=h-K-1;
		for(i=0;i<=(min);i++){
			startnode=(s + 1 + 3*(1<<i));
			if(startnode<potNos){
				path->TreeHASHh[i] = startnode;
			}
		}
	}
	j=0;
	numUpdate = 0;
	while(j<=(h-K-1) && numUpdate <(h-K)/2){	//one update for height
		if(path->TreeHASHh[j]!=0){
			min=j;
			leafIni=path->TreeHASHh[min];
   			SET_OTS_ADDRESS32(ots_addr32, leafIni);
			WOTS_genPK(pk, sk.sk_seed, params,pub_seed, ots_addr32);
			SET_LTREE_ADDRESS32(ltree_addr32, leafIni);
			ltree(leaf, pk, params, pub_seed, ltree_addr32);
			treeHash_update(leaf, leafIni, &(*path), min, n, pub_seed, node_addr32);
			path->TreeHASHh[min]++;
			if(path->TreeHASHstack[min][0].height==min){
				path->TreeHASH[min] = path->TreeHASHstack[min][0];
				path->TreeHASHh[min]=0;
				path->TreeHASHiStack[min]=0;
			}
			numUpdate++;
		}else j++;
	}
}
