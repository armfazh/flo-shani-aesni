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
#include "hash/sha2supercop.c"
#include "hash/sha2_8sms.c"
#include "hash/sha2_4sms.c"

double getTime()
{
	struct timeval tv;
	gettimeofday(&tv,0);
	return tv.tv_sec + tv.tv_usec/1e6;
}
uint64_t Rdtsc()
{
    union
    {
        uint64_t x64;
        struct
        {
            uint32_t lo;
            uint32_t hi;
        };
    } time;

    __asm__ __volatile__ ( "rdtsc\n" : "=a" (time.lo), "=d" (time.hi) );

    return time.x64;
}

#define cpyVet(a,b) 	\
  a[0]=b[0];		\
  a[1]=b[1];		\
  a[2]=b[2];		\
  a[3]=b[3];

#define cpy256Result(result1,result2,j,top,in,bitMask,height)	\
	result1[j]=_mm256_load_si256((__m256i*) top); \
	result2[j]=_mm256_load_si256((__m256i*) in); \
	result1[j]=_mm256_xor_si256(result1[j],_mm256_loadu_si256((__m256i*) (bitMask[height])));		\
	result2[j]=_mm256_xor_si256(result2[j],_mm256_loadu_si256((__m256i*) (bitMask[height+1])));

//-------------------------------------------------------------------------------------------------------------------------
void insertion_sort(dSigWin *valor, int largura)
{
	int i, j;
	dSigWin tmp;

	for(i=1; i<largura; i++){
		j=i;
		while(j>0 && valor[j-1].e > valor[j].e){
			tmp=valor[j];
        		valor[j] = valor[j-1];
			valor[j-1]=tmp;
			j--;
       		}
	}
}

//-------------------------------------------------------------------------------------------------------------------------
void printnchar(unsigned char *bloco, int n){
	int i;

	for(i=0; i<n; i++) {
    		printf("%X-", bloco[i]);
	}
	printf("\n");
}

void printnBlocosDe64(u64 *bloco, int n){
	int i;

	for(i=0; i<n; i++) {
    		printf("%llX", bloco[i]);
	}
	printf("\n");
}

void print_uint64_t(char *sz, uint64_t *data){
	u64 w[2] __attribute__ ((aligned (16)));
	int i;

	printf("\n%s [ ",sz);
	for (i=0; i<2; i++){
		w[i]=data[i];
		printf(" %llX  ",w[i]);
	}
	printf(" ]\n");
}
void print_uint32(uint32_t *data, int n){
	unsigned long int w[2] __attribute__ ((aligned (16)));
	int i;

	printf(" [ ");
	for (i=0; i<n; i++){
		w[i]=data[i];
		printf(" %lX-",w[i]);
	}
	printf(" ]\n");
}
void print_m256i(__m256i data){
	uint64_t xz[4] __attribute__ ((aligned (16)));
	u64 A[4] __attribute__ ((aligned (16)));
	int i;

        _mm256_store_si256 ((__m256i *) xz, data);
	for (i=0; i<4; i++){
		A[i]=xz[i];
		printf("%llX-",A[i]);
	}
	printf(" \n");
}
/*void print_m128i(__m128i data){
	u32 xz[4] __attribute__ ((aligned (16)));
	u32 A[4] __attribute__ ((aligned (16)));
	int i;

        _mm_store_si128 ((__m128i *) xz, data);
	for (i=0; i<4; i++){
		A[i]=xz[i];
		printf("%lX-",A[i]);
	}
	printf(" \n");
}*/

void printNo(rTree *no)
{
	if (no !=NULL)
	{
		printf(" height- %d; numNo =%lld e hash=; \n ", no->height, no->numNo);
		for(int i=0; i<nRows; ++i) printf("%02llX", no->hash[i]);
	}
	printf("\n");
}
void printNo2(rTree no)
{
	{
		printf(" height- %d; numNo =%lld e hash=; \n ", no.height, no.numNo);
		for(int i=0; i<nRows; ++i) printf("%02llX", no.hash[i]);
	}
	printf("\n");
}
