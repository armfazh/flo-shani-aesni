#ifndef AEGIS_H
#define AEGIS_H

#ifdef __cplusplus
extern "C"{
#endif

#include <stdint.h>
#include <immintrin.h>

#define ALIGN_BYTES 32
#ifdef __INTEL_COMPILER
#define ALIGN __declspec(align(ALIGN_BYTES))
#else
#define ALIGN __attribute__ ((aligned (ALIGN_BYTES)))
#endif

int crypto_aead_encrypt_opt(
		unsigned char *c, uint64_t *clen,
		unsigned char *m, uint64_t mlen,
		unsigned char *ad, uint64_t adlen,
		unsigned char *npub,
		unsigned char *k);

int crypto_aead_encrypt(
		unsigned char *c, uint64_t *clen,
		const unsigned char *m, uint64_t mlen,
		const unsigned char *ad, uint64_t adlen,
		const unsigned char *npub,
		const unsigned char *k
);

int crypto_aead_decrypt(
		unsigned char *m, uint64_t *mlen,
		unsigned char *nsec,
		const unsigned char *c, uint64_t clen,
		const unsigned char *ad, uint64_t adlen,
		const unsigned char *npub,
		const unsigned char *k
);

#ifdef __cplusplus
}
#endif

#endif /* AEGIS_H */
