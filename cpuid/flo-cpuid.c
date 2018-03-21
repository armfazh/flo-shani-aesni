/**
 * Copyright (c) 2017 Armando Faz <armfazh@ic.unicamp.br>.
 * Institute of Computing.
 * University of Campinas, Brazil.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation, version 2 or greater.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
*/
#include <stdio.h>
#include <stdint.h>
#include <cpuid.h>
#include <openssl/objects.h>

#define my_cpuid(ra,rb,rc,rd) __asm volatile \
(    \
	"mov %0, %%eax      \n"\
	"mov %1, %%ebx      \n"\
	"mov %2, %%ecx      \n"\
	"mov %3, %%edx      \n"\
	"cpuid      \n"\
	"mov %%eax, %0      \n"\
	"mov %%ebx, %1      \n"\
	"mov %%ecx, %2      \n"\
	"mov %%edx, %3      \n"\
:"+r" (ra), "+r" (rb), "+r" (rc), "+r" (rd)\
: : "%eax", "%ebx", "%ecx", "%edx")

#define test_capability(REG,CAP) \
 printf("%-12s: [%s]\n",#CAP,( (REG & CAP) != 0 )?"Yes":"No");

#define supports_capability(REG,CAP)  ( (REG & CAP) != 0 )

//#ifndef bit_BMI
//#define bit_BMI	(1 << 3)
//#endif
//
//#ifndef bit_AVX2
//#define bit_AVX2	(1 << 5)
//#endif
//
//#ifndef bit_BMI2
//#define bit_BMI2	(1 << 8)
//#endif
//
//#ifndef bit_ADX
//#define bit_ADX	(1 << 19)
//#endif
//
//#ifndef bit_SSE4_1
//#define bit_SSE4_1	(1 << 19)
//#endif
//
//#ifndef bit_SSE4_2
//#define bit_SSE4_2	(1 << 20)
//#endif


void machine_info()
{
  printf("=== Environment Information ====\n");
  printf("Program compiled with: %s\n",__VERSION__);
  unsigned int eax, ebx, ecx, edx;

  eax = 1;
  ebx = 0;
  ecx = 0;
  edx = 0;
  my_cpuid(eax, ebx, ecx, edx);

  test_capability(edx, bit_CMOV);
  test_capability(edx, bit_SSE);
  test_capability(edx, bit_SSE2);
  test_capability(ecx, bit_SSE3);
  test_capability(ecx, bit_SSSE3);
  test_capability(ecx, bit_SSE4_1);
  test_capability(ecx, bit_SSE4_2);
  test_capability(ecx, bit_AVX);

  eax = 7;
  ebx = 0;
  ecx = 0;
  edx = 0;
  my_cpuid(eax, ebx, ecx, edx);
  test_capability(ebx, bit_AVX2);
  test_capability(ebx, bit_BMI);
  test_capability(ebx, bit_BMI2);
  test_capability(ebx, bit_ADX);
  test_capability(ebx, bit_SHA);

}

void openssl_version()
{
  printf("OpenSSL version: %s\n", OPENSSL_VERSION_TEXT);
}

int hasSHANI()
{
  unsigned int eax, ebx, ecx, edx;
  eax = 7;
  ebx = 0;
  ecx = 0;
  edx = 0;
  my_cpuid(eax, ebx, ecx, edx);
  return supports_capability(ebx, bit_SHA);
}

void disableSHANI()
{
  if( OPENSSL_VERSION_NUMBER <0x10002FFF) {
    extern unsigned long *OPENSSL_ia32cap_loc(void);
    uint64_t *c = OPENSSL_ia32cap_loc();
    c[1] &= ~0x20000000;
  }
}

void openssl_caps()
{
#if 0 

  printf("OpenSSL version: %s\n", SSLeay_version(SSLEAY_VERSION));
  printf("compiled with: %s\n", SSLeay_version(SSLEAY_CFLAGS));
  printf("built on: %s\n", SSLeay_version(SSLEAY_BUILT_ON));
  printf("located on: %s\n", SSLeay_version(SSLEAY_DIR));
  FIPS_mode_set(1);
  printf("OpenSSL FIPS: %s\n", FIPS_mode() ? "On" : "Off");
  uint64_t caps2[4]={0};
  uint64_t caps3[4]={0};
  uint64_t *caps = caps2;
  uint64_t *c = OPENSSL_ia32cap_loc();
  caps3[0] = OPENSSL_ia32_cpuid(caps3);
  printf("%lx %lx %lx \n", *c ,caps[0],caps3[0]);
  printf("%lx %lx %lx \n", *(c+1) ,caps[1],caps3[1]);
  printf("AES-NI    supported: [%s]\n", *c & ((uint64_t) 1 << 57) ? "yes" : "no");
  printf("PCLMULQDQ supported: [%s]\n", *c & ((uint64_t) 1 << 33) ? "yes" : "no");

  //Disabel AES-NI and PCLMULQDQ
  *c &= ~0x200000200000000;

  printf("AES-NI    supported: [%s]\n", *c & ((uint64_t) 1 << 57) ? "yes" : "no");
  printf("PCLMULQDQ supported: [%s]\n", *c & ((uint64_t) 1 << 33) ? "yes" : "no");

//    int i;
//    for(i=0;i<64;i++)
//    {
//        printf("%d  supported: [%s]\n",i, caps3[0] & ((uint64_t) 1 << i) ? "yes" : "no");
//    }
//    for(i=0;i<64;i++)
//    {
//        printf("%d  supported: [%s]\n",i, caps[1] & ((uint64_t) 1 << i) ? "yes" : "no");
//    }
#endif 
}
