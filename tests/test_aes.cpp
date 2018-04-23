/*
 * The MIT License (MIT)
 * Copyright (c) 2018 Armando Faz
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
 * DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
 * OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE
 * OR OTHER DEALINGS IN THE SOFTWARE.
 */
#include <gtest/gtest.h>
#include <openssl/evp.h>
#include <flo-random.h>
#include <flo-aesni.h>

#define TEST_TIMES 1000

static std::string print_ostream(uint8_t *data, int len) {
  int i = 0;
  std::stringstream stream;
  for (i = 0; i < len; i++) {
    stream << std::setbase(16) << std::setfill('0') << std::setw(2)
           << static_cast<int>(data[i]);
  }
  stream << std::endl;
  return stream.str();
}

typedef void (*AES_CTR_Implementation)(
    const unsigned char *in,
    unsigned char *out,
    const unsigned char *ivec,
    unsigned long length,
    const unsigned char *key,
    const int number_of_rounds);

class AES_PIPE : public ::testing::TestWithParam<AES_CTR_Implementation> {
  //  virtual void SetUp() { printf("starting \n"); }
  //  virtual void TearDown() {printf("ending \n");  }
};

TEST_P(AES_PIPE, ONE_BLOCK) {
  const AES_CTR_Implementation aes_ctr = GetParam();
  uint8_t key[AES_128_Bytes];
  uint8_t key_sched[AES_128_Bytes * (AES_128_Rounds + 1)];
  uint8_t iv[AES_BlockSize_Bits / 8];
  EVP_CIPHER_CTX *ctx = NULL;
  uint8_t *plaintext = NULL;
  uint8_t *ciphertext0 = NULL;
  uint8_t *ciphertext1 = NULL;
  int plaintext_len;
  int ciphertext_len;
  int len;
  int count = 0;

  /* Create and initialise the context */
  ctx = EVP_CIPHER_CTX_new();
  plaintext_len = 16;
  plaintext = (uint8_t *) _mm_malloc(plaintext_len, ALIGN_BYTES);
  ciphertext0 = (uint8_t *) _mm_malloc(plaintext_len + (AES_BlockSize_Bits / 8), ALIGN_BYTES);
  ciphertext1 = (uint8_t *) _mm_malloc(plaintext_len + (AES_BlockSize_Bits / 8), ALIGN_BYTES);

  do {
    random_bytes(plaintext, plaintext_len);
    random_bytes(key, sizeof(key));
    random_bytes(iv, sizeof(iv));

    /* Encrypting with OpenSSL */
    EVP_EncryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, key, iv);
    EVP_EncryptUpdate(ctx, ciphertext0, &len, plaintext, plaintext_len);
    ciphertext_len = len;
    EVP_EncryptFinal_ex(ctx, ciphertext0 + len, &len);
    ciphertext_len += len;

    /* Encrypting with flo-aesni */
    AES_128_Key_Expansion(key, key_sched);
    aes_ctr(plaintext, ciphertext1, iv, plaintext_len, key_sched, AES_128_Rounds);

    count++;
    ASSERT_EQ(memcmp(ciphertext0, ciphertext1, ciphertext_len), 0)
                  << "Key:   " << print_ostream(key, sizeof(key))
                  << "IV:    " << print_ostream(iv, sizeof(iv))
                  << "input: " << print_ostream(plaintext, plaintext_len)
                  << "get:   " << print_ostream(ciphertext1, ciphertext_len)
                  << "want:  " << print_ostream(ciphertext0, ciphertext_len);

  } while (count < TEST_TIMES);
  _mm_free(plaintext);
  _mm_free(ciphertext0);
  _mm_free(ciphertext1);
  EVP_CIPHER_CTX_free(ctx);
  EXPECT_EQ(count, TEST_TIMES) << "passed: " << count << "/" << TEST_TIMES
                               << std::endl;

}

TEST_P(AES_PIPE, MANY_BLOCKS) {
  const AES_CTR_Implementation aes_ctr = GetParam();
  uint8_t key[AES_128_Bytes];
  uint8_t key_sched[AES_128_Bytes * (AES_128_Rounds + 1)];
  uint8_t iv[AES_BlockSize_Bits / 8];
  EVP_CIPHER_CTX *ctx = NULL;
  uint8_t *plaintext = NULL;
  uint8_t *ciphertext0 = NULL;
  uint8_t *ciphertext1 = NULL;
  int plaintext_len;
  int ciphertext_len;
  int count = 0;
  int len;

  /* Create and initialise the context */
  ctx = EVP_CIPHER_CTX_new();

  do {
    random_bytes(reinterpret_cast<uint8_t *>(&plaintext_len), sizeof(plaintext_len));
    plaintext_len &= (1 << 20) - 1;
    plaintext = (uint8_t *) _mm_malloc(plaintext_len, ALIGN_BYTES);
    ciphertext0 = (uint8_t *) _mm_malloc(plaintext_len + (AES_BlockSize_Bits / 8), ALIGN_BYTES);
    ciphertext1 = (uint8_t *) _mm_malloc(plaintext_len + (AES_BlockSize_Bits / 8), ALIGN_BYTES);
    random_bytes(plaintext, plaintext_len);
    random_bytes(key, sizeof(key));
    random_bytes(iv, sizeof(iv));

    /* Encrypting with OpenSSL */
    EVP_EncryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, key, iv);
    EVP_EncryptUpdate(ctx, ciphertext0, &len, plaintext, plaintext_len);
    ciphertext_len = len;
    EVP_EncryptFinal_ex(ctx, ciphertext0 + len, &len);
    ciphertext_len += len;

    /* Encrypting with flo-aesni */
    AES_128_Key_Expansion(key, key_sched);
    aes_ctr(plaintext, ciphertext1, iv, plaintext_len, key_sched, AES_128_Rounds);

    count++;
    ASSERT_EQ(memcmp(ciphertext0, ciphertext1, ciphertext_len), 0)
                  << "Key:   " << print_ostream(key, sizeof(key))
                  << "IV:    " << print_ostream(iv, sizeof(iv))
                  << "input: " << print_ostream(plaintext, plaintext_len)
                  << "get:   " << print_ostream(ciphertext1, ciphertext_len)
                  << "want:  " << print_ostream(ciphertext0, ciphertext_len);
    _mm_free(plaintext);
    _mm_free(ciphertext0);
    _mm_free(ciphertext1);
  } while (count < TEST_TIMES);
  EVP_CIPHER_CTX_free(ctx);
  EXPECT_EQ(count, TEST_TIMES) << "passed: " << count << "/" << TEST_TIMES
                               << std::endl;
}

INSTANTIATE_TEST_CASE_P(AES128, AES_PIPE, ::testing::Values(
    AES_CTR_encrypt,
    AES_CTR_encrypt_pipe2,
    AES_CTR_encrypt_pipe4,
    AES_CTR_encrypt_pipe8));
