/* XMSS Ana Karina update in 06-2017 */
/*XMSS draft-ver05*/

#include <flo-xmss-vec.h>
#include <flo-cpuid.h>
#include <flo-random.h>
#include <stdio.h>
#include "clocks.h"

/* para executar ./xmss... arg1 arg2 ag3 arg4 (arg1=altura da árvore, arg2=parâmetro W, arg3=nSig=num de Assinaturas) */
int main( int argc, char * argv [] ) {
	u64 s, nLeafs;
	u8 i, h, K,check;
	u8 W=16, n=32,hLtree;
	pkXMSS *pkx;
	skXMSS sk;
	bds_state *path;
	sigXMSS *sig;

	//set parameters
	if(argc!=3){ printf("Usage: h w\n"); return 0;}
	h= atoi(argv[1]); W= atoi(argv[2]);
	nLeafs=1<<h;
	//nSig=nLeafs-1;
	if((h%2)!=0) K=3; //k treetraversal
	else K=2;
	xmss_params p;
  	xmss_params *params = &p;
  	XMSS_setParams(params, n, h,K, W);
	//params->wots_par.len1=6;params->wots_par.len2=2;params->wots_par.len=8;
	int l = params->wots_par.len;
	computeHeight(l,i,hLtree);
	alloc(sig,path,pkx,l,h,hLtree,W,i);
	printf("The height of the tree is:%d, nLeafs is:%lld, simd=%d,w=%d\n",h, nLeafs,simd,W);

	double t_start, t_finish, t1;
	u64 st,ft1;
	/* key generation */
	t_start = getTime();
	st = Rdtsc();
		XMSS_keyGen(&(*pkx), &sk, &(*path), params);
	ft1 = Rdtsc()-st;
	t_finish = getTime(); t1=t_finish-t_start;
	printf("The public key is:");print_uint32(pkx->root, 8);

	double t2,t3;
	u64 ft2,ft3;
	t2=0; ft2=0; t3=0;ft3=0;
	unsigned char *message2;
	message2=(unsigned char *)"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
	u64 nSig=nLeafs-1;

	printf("== Start of Benchmark ===\n");
	printf("Number of signatures computed is:%lld\n",s);
	printf("Time to comput keys(X,Y)   is: \t\t%.6f ms ::: %lld: Cycles \n",t1*1000, ft1);
	printf("Time all to sign           is: \t\t%.6f ms ::: %lld: Cycles \n",(t2)/s*1000, (ft2)/s);
	printf("Time all to check          is: \t\t%.6f ms ::: %lld: Cycles \n",(t3)/s*1000, (ft3)/s);
	printf("------------------------------------------------------------------------------\n");

//	unsigned long BENCH=50;
	oper_second(while(0),XMSS_sign,XMSS_sign(sk, sig, message2, &(*path), pkx, i, params));
	oper_second(while(0),XMSS_verif,check=XMSS_verify(message2, sig, pkx,params));
	// CLOCKS(XMSS_sign(sk, sig, message2, &(*path), pkx, j_bench, params));
	// CLOCKS(check=XMSS_verify(message2, sig, pkx,params));

printf("== End of Benchmark =====\n");
	/*Deallocate vectors */
	dealloc(params,sig,path,pkx);

	return 0;
}
