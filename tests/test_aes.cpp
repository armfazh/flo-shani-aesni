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

static std::string print_ostream(uint8_t *data, size_t len) {
  size_t i = 0;
  std::stringstream stream;
  for (i = 0; i < len; i++) {
    stream << std::setbase(16) << std::setfill('0') << std::setw(2)
           << static_cast<int>(data[i]);
  }
  stream << std::endl;
  return stream.str();
}

class AES_PIPE : public ::testing::TestWithParam<std::pair<AES_CTR_Implementation, AES_CIPHER_ID> > {
  //  virtual void SetUp() { printf("starting \n"); }
  //  virtual void TearDown() {printf("ending \n");  }
};

TEST_P(AES_PIPE, ONE_BLOCK) {
  std::pair<AES_CTR_Implementation, AES_CIPHER_ID> _params_ = GetParam();
  const AES_CTR_Implementation aes_ctr = _params_.first;
  const AES_CIPHER_ID aes_id = _params_.second;

  EVP_CIPHER_CTX *ctx = NULL;
  uint8_t *key = NULL;
  uint8_t *iv = NULL;
  uint8_t *key_sched = NULL;
  uint8_t *plaintext = NULL;
  uint8_t *ciphertext0 = NULL;
  uint8_t *ciphertext1 = NULL;
  size_t plaintext_len;
  size_t ciphertext_len;
  int len;
  int count = 0;

  /* Create and initialise the context */
  ctx = EVP_CIPHER_CTX_new();
  const EVP_CIPHER *cipher = NULL;
  switch (aes_id) {
    case AES_128:cipher = EVP_aes_128_ctr();
      break;
    case AES_192:cipher = EVP_aes_192_ctr();
      break;
    case AES_256:cipher = EVP_aes_256_ctr();
      break;
    default:cipher = NULL;
  }
  plaintext_len = 16;
  key = (uint8_t *) _mm_malloc(aes_id / 8, ALIGN_BYTES);
  iv = (uint8_t *) _mm_malloc(AES_BlockSize / 8, ALIGN_BYTES);
  plaintext = (uint8_t *) _mm_malloc(plaintext_len, ALIGN_BYTES);
  ciphertext0 = (uint8_t *) _mm_malloc(plaintext_len, ALIGN_BYTES);
  ciphertext1 = (uint8_t *) _mm_malloc(plaintext_len, ALIGN_BYTES);

  do {
    random_bytes(plaintext, plaintext_len);
    random_bytes(key, aes_id / 8);
    random_bytes(iv, AES_BlockSize / 8);

    /* Encrypting with OpenSSL */
    EVP_EncryptInit_ex(ctx, cipher, NULL, key, iv);
    EVP_EncryptUpdate(ctx, ciphertext0, &len, plaintext, (int) plaintext_len);
    ciphertext_len = (size_t) len;
    EVP_EncryptFinal_ex(ctx, ciphertext0 + len, &len);
    ciphertext_len += (size_t) len;
    ASSERT_EQ(ciphertext_len, plaintext_len)
                  << "get:  " << ciphertext_len
                  << "want: " << plaintext_len;

    /* Encrypting with flo-aesni */
    key_sched = AES_Key_Expansion(key, aes_id);
    aes_ctr(plaintext, ciphertext1, iv, plaintext_len, key_sched, aes_id);

    count++;
    ASSERT_EQ(memcmp(ciphertext0, ciphertext1, ciphertext_len), 0)
                  << "Key:   " << print_ostream(key, aes_id / 8)
                  << "IV:    " << print_ostream(iv, AES_BlockSize / 8)
                  << "input: " << print_ostream(plaintext, plaintext_len)
                  << "get:   " << print_ostream(ciphertext1, ciphertext_len)
                  << "want:  " << print_ostream(ciphertext0, ciphertext_len);

  } while (count < TEST_TIMES);
  _mm_free(key);
  _mm_free(iv);
  _mm_free(key_sched);
  _mm_free(plaintext);
  _mm_free(ciphertext0);
  _mm_free(ciphertext1);
  EVP_CIPHER_CTX_free(ctx);
  EXPECT_EQ(count, TEST_TIMES) << "passed: " << count << "/" << TEST_TIMES
                               << std::endl;
}

TEST_P(AES_PIPE, MANY_BLOCKS) {
  std::pair<AES_CTR_Implementation, AES_CIPHER_ID> _params_ = GetParam();
  const AES_CTR_Implementation aes_ctr = _params_.first;
  const AES_CIPHER_ID aes_id = _params_.second;

  EVP_CIPHER_CTX *ctx = NULL;
  uint8_t *key = NULL;
  uint8_t *iv = NULL;
  uint8_t *key_sched = NULL;
  uint8_t *plaintext = NULL;
  uint8_t *ciphertext0 = NULL;
  uint8_t *ciphertext1 = NULL;
  size_t plaintext_len;
  size_t ciphertext_len;
  int count = 0;
  int len;

  /* Create and initialise the context */
  ctx = EVP_CIPHER_CTX_new();
  const EVP_CIPHER *cipher;
  switch (aes_id) {
    case AES_128:cipher = EVP_aes_128_ctr();
      break;
    case AES_192:cipher = EVP_aes_192_ctr();
      break;
    case AES_256:cipher = EVP_aes_256_ctr();
      break;
    default:cipher = NULL;
  }

  key = (uint8_t *) _mm_malloc(aes_id / 8, ALIGN_BYTES);
  iv = (uint8_t *) _mm_malloc(AES_BlockSize / 8, ALIGN_BYTES);
  do {
    random_bytes(reinterpret_cast<uint8_t *>(&plaintext_len), sizeof(plaintext_len));
    plaintext_len &= 0xfffff;
    plaintext = (uint8_t *) _mm_malloc(plaintext_len, ALIGN_BYTES);
    ciphertext0 = (uint8_t *) _mm_malloc(plaintext_len, ALIGN_BYTES);
    ciphertext1 = (uint8_t *) _mm_malloc(plaintext_len, ALIGN_BYTES);
    random_bytes(plaintext, plaintext_len);
    random_bytes(key, aes_id / 8);
    random_bytes(iv, AES_BlockSize / 8);

    /* Encrypting with OpenSSL */
    EVP_EncryptInit_ex(ctx, cipher, NULL, key, iv);
    EVP_EncryptUpdate(ctx, ciphertext0, &len, plaintext, (int) plaintext_len);
    ciphertext_len = (size_t) len;
    EVP_EncryptFinal_ex(ctx, ciphertext0 + len, &len);
    ciphertext_len += (size_t) len;
    ASSERT_EQ(ciphertext_len, plaintext_len)
                  << "get:  " << ciphertext_len
                  << "want: " << plaintext_len;

    /* Encrypting with flo-aesni */
    key_sched = AES_Key_Expansion(key, aes_id);
    aes_ctr(plaintext, ciphertext1, iv, plaintext_len, key_sched, aes_id);

    count++;
    ASSERT_EQ(memcmp(ciphertext0, ciphertext1, ciphertext_len), 0)
                  << "Key:   " << print_ostream(key, aes_id / 8)
                  << "IV:    " << print_ostream(iv, AES_BlockSize / 8)
                  << "input: " << print_ostream(plaintext, plaintext_len)
                  << "get:   " << print_ostream(ciphertext1, ciphertext_len)
                  << "want:  " << print_ostream(ciphertext0, ciphertext_len);
    _mm_free(plaintext);
    _mm_free(ciphertext0);
    _mm_free(ciphertext1);
  } while (count < TEST_TIMES);
  _mm_free(key);
  _mm_free(iv);
  EVP_CIPHER_CTX_free(ctx);
  EXPECT_EQ(count, TEST_TIMES) << "passed: " << count << "/" << TEST_TIMES
                               << std::endl;
}

INSTANTIATE_TEST_CASE_P(AES, AES_PIPE, ::testing::Values(
    std::make_pair(AES_128_CTR_encrypt, AES_128)
//    ,
//    std::make_pair(AES_CTR_encrypt_pipe2, AES_128),
//    std::make_pair(AES_CTR_encrypt_pipe4, AES_128),
//    std::make_pair(AES_CTR_encrypt_pipe8, AES_128))
));
