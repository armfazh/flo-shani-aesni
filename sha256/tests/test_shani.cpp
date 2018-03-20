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
#include <gtest/gtest.h>
#include <prng/flo-random.h>
#include <openssl/sha.h>
#include <shani.h>

#define TEST_TIMES 1000

#define SHA256_DigestSize 32
typedef uint8_t Digest[SHA256_DigestSize];

static std::ostream &operator<<(std::ostream &os, const Digest &d) {
  int i = 0;
  for (i = 0; i < SHA256_DigestSize; i++) {
    os << std::setbase(16) << std::setfill('0') << std::setw(2)
       << static_cast<int>(d[i]);
  }
  return os << std::endl;
}

TEST(SHA256, ZERO_LENGHT) {
  unsigned long mlen = 2;
  uint8_t digest0[32];
  uint8_t digest1[32];
  uint8_t *message0 = (uint8_t *) _mm_malloc(mlen, ALIGN_BYTES);
  uint8_t *message1 = (uint8_t *) _mm_malloc(mlen, ALIGN_BYTES);

  SHA256(message0, 0, digest0);
  sha256_update_shani(message1, 0, digest1);
  ASSERT_EQ(memcmp(digest0, digest1, SHA256_DigestSize), 0)
                << "want: " << digest0
                << "get:  " << digest1;
  _mm_free(message0);
  _mm_free(message1);
}

TEST(SHA256, ONE_BLOCK) {
  unsigned long mlen = rand() % 56;
  uint8_t digest0[32];
  uint8_t digest1[32];
  uint8_t *message0 = (uint8_t *) _mm_malloc(mlen, ALIGN_BYTES);
  uint8_t *message1 = (uint8_t *) _mm_malloc(mlen, ALIGN_BYTES);
  int k = 0;
  do {
    random_bytes(message0, mlen);
    memcpy(message1, message0, mlen);

    SHA256(message0, mlen, digest0);
    sha256_update_shani(message1, mlen, digest1);
    k++;
    ASSERT_EQ(memcmp(digest0, digest1, SHA256_DigestSize), 0)
                  << "want: " << digest0
                  << "get:  " << digest1;
  } while (k < TEST_TIMES);

  _mm_free(message0);
  _mm_free(message1);
}

TEST(SHA256, TWO_BLOCKS) {
  unsigned long mlen = rand() % 120;
  uint8_t digest0[32];
  uint8_t digest1[32];
  uint8_t *message0 = (uint8_t *) _mm_malloc(mlen, ALIGN_BYTES);
  uint8_t *message1 = (uint8_t *) _mm_malloc(mlen, ALIGN_BYTES);
  int k = 0;
  do {
    random_bytes(message0, mlen);
    memcpy(message1, message0, mlen);

    SHA256(message0, mlen, digest0);
    sha256_update_shani(message1, mlen, digest1);
    k++;
    ASSERT_EQ(memcmp(digest0, digest1, SHA256_DigestSize), 0)
                  << "want: " << digest0
                  << "get:  " << digest1;
  } while (k < TEST_TIMES);

  _mm_free(message0);
  _mm_free(message1);
}

TEST(SHA256, LARGE) {
  int k = 0;
  uint8_t digest0[32];
  uint8_t digest1[32];
  uint8_t *message0=NULL;
  uint8_t *message1=NULL;
  unsigned long mlen = 0;

  do {
    mlen = rand()%(1<<16);
    message0 = (uint8_t *) _mm_malloc(mlen, ALIGN_BYTES);
    message1 = (uint8_t *) _mm_malloc(mlen, ALIGN_BYTES);

    random_bytes(message0, mlen);
    memcpy(message1, message0, mlen);

    SHA256(message0, mlen, digest0);
    sha256_update_shani(message1, mlen, digest1);
    k++;
    ASSERT_EQ(memcmp(digest0, digest1, SHA256_DigestSize), 0)
                  << "want: " << digest0
                  << "get:  " << digest1;
    _mm_free(message0);
    _mm_free(message1);
  } while (k < TEST_TIMES);
}
