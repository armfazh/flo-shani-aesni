#include "flo-aesni.h"

#define XOR        _mm_xor_si128
#define AESENC     _mm_aesenc_si128
#define AESENCLAST _mm_aesenclast_si128
#define AESDEC     _mm_aesdec_si128
#define AESDECLAST _mm_aesdeclast_si128

static inline __m128i AES_128_ASSIST(__m128i temp1, __m128i temp2) {
  __m128i temp3;
  temp2 = _mm_shuffle_epi32(temp2, 0xff);
  temp3 = _mm_slli_si128(temp1, 0x4);
  temp1 = XOR(temp1, temp3);
  temp3 = _mm_slli_si128(temp3, 0x4);
  temp1 = XOR(temp1, temp3);
  temp3 = _mm_slli_si128(temp3, 0x4);
  temp1 = XOR(temp1, temp3);
  temp1 = XOR(temp1, temp2);
  return temp1;
}

void AES_128_Key_Expansion(const unsigned char *userkey, unsigned char *key) {
  __m128i temp1, temp2;
  __m128i *Key_Schedule = (__m128i *) key;
  temp1 = _mm_loadu_si128((__m128i *) userkey);
  Key_Schedule[0] = temp1;
  temp2 = _mm_aeskeygenassist_si128(temp1, 0x1);
  temp1 = AES_128_ASSIST(temp1, temp2);
  Key_Schedule[1] = temp1;
  temp2 = _mm_aeskeygenassist_si128(temp1, 0x2);
  temp1 = AES_128_ASSIST(temp1, temp2);
  Key_Schedule[2] = temp1;
  temp2 = _mm_aeskeygenassist_si128(temp1, 0x4);
  temp1 = AES_128_ASSIST(temp1, temp2);
  Key_Schedule[3] = temp1;
  temp2 = _mm_aeskeygenassist_si128(temp1, 0x8);
  temp1 = AES_128_ASSIST(temp1, temp2);
  Key_Schedule[4] = temp1;
  temp2 = _mm_aeskeygenassist_si128(temp1, 0x10);
  temp1 = AES_128_ASSIST(temp1, temp2);
  Key_Schedule[5] = temp1;
  temp2 = _mm_aeskeygenassist_si128(temp1, 0x20);
  temp1 = AES_128_ASSIST(temp1, temp2);
  Key_Schedule[6] = temp1;
  temp2 = _mm_aeskeygenassist_si128(temp1, 0x40);
  temp1 = AES_128_ASSIST(temp1, temp2);
  Key_Schedule[7] = temp1;
  temp2 = _mm_aeskeygenassist_si128(temp1, 0x80);
  temp1 = AES_128_ASSIST(temp1, temp2);
  Key_Schedule[8] = temp1;
  temp2 = _mm_aeskeygenassist_si128(temp1, 0x1b);
  temp1 = AES_128_ASSIST(temp1, temp2);
  Key_Schedule[9] = temp1;
  temp2 = _mm_aeskeygenassist_si128(temp1, 0x36);
  temp1 = AES_128_ASSIST(temp1, temp2);
  Key_Schedule[10] = temp1;
}

void AES_CBC_encrypt(
    const unsigned char *in,
    unsigned char *out,
    unsigned char ivec[16],
    unsigned long length,
    unsigned char *key,
    const int number_of_rounds) {
  __m128i feedback, data;
  int j;
  unsigned long i;
  if (length % 16)
    length = length / 16 + 1;
  else
    length /= 16;
  feedback = _mm_loadu_si128((__m128i *) ivec);
  for (i = 0; i < length; i++) {
    data = _mm_loadu_si128(&((__m128i *) in)[i]);
    feedback = XOR(data, feedback);
    feedback = XOR(feedback, ((__m128i *) key)[0]);
    for (j = 1; j < number_of_rounds; j++) {
      feedback = AESENC(feedback, ((__m128i *) key)[j]);
    }
    feedback = AESENCLAST(feedback, ((__m128i *) key)[j]);
    _mm_storeu_si128(&((__m128i *) out)[i], feedback);
  }
}

void AES_CBC_decrypt(
    const unsigned char *in,
    unsigned char *out,
    unsigned char ivec[16],
    unsigned long length,
    unsigned char *key,
    const int number_of_rounds) {
  __m128i data, feedback, last_in;
  int j;
  unsigned long i;
  if (length % 16) {
    length = length / 16 + 1;
  } else {
    length /= 16;
  }
  feedback = _mm_loadu_si128((__m128i *) ivec);
  for (i = 0; i < length; i++) {
    last_in = _mm_loadu_si128(&((__m128i *) in)[i]);
    data = XOR(last_in, ((__m128i *) key)[0]);
    for (j = 1; j < number_of_rounds; j++) {
      data = AESDEC(data, ((__m128i *) key)[j]);
    }
    data = AESDECLAST(data, ((__m128i *) key)[j]);
    data = XOR(data, feedback);
    _mm_storeu_si128(&((__m128i *) out)[i], data);
    feedback = last_in;
  }
}

void AES_CBC_decrypt_pipe2(
    const unsigned char *in,
    unsigned char *out,
    unsigned char *ivec,
    unsigned long length,
    unsigned char *key_schedule,
    const unsigned int nr) {
  __m128i data1, data2;
  __m128i feedback1, feedback2, last_in;
  unsigned long j;
  unsigned int i;
  if (length % 16) {
    length = length / 16 + 1;
  } else { length /= 16; }
  feedback1 = _mm_loadu_si128((__m128i *) ivec);
  for (i = 0; i < length / 2; i++) {
    data1 = _mm_loadu_si128(&((__m128i *) in)[i * 4 + 0]);
    data2 = _mm_loadu_si128(&((__m128i *) in)[i * 4 + 1]);
    feedback2 = data1;
    last_in = data2;
    data1 = XOR(data1, ((__m128i *) key_schedule)[0]);
    data2 = XOR(data2, ((__m128i *) key_schedule)[0]);

    for (j = 1; j < nr; j++) {
      data1 = AESDEC(data1, ((__m128i *) key_schedule)[j]);
      data2 = AESDEC(data2, ((__m128i *) key_schedule)[j]);
    }

    data1 = AESDECLAST(data1, ((__m128i *) key_schedule)[j]);
    data2 = AESDECLAST(data2, ((__m128i *) key_schedule)[j]);

    data1 = XOR(data1, feedback1);
    data2 = XOR(data2, feedback2);

    _mm_storeu_si128(&((__m128i *) out)[i * 4 + 0], data1);
    _mm_storeu_si128(&((__m128i *) out)[i * 4 + 1], data2);
    feedback1 = last_in;
  }
  for (j = i * 2; j < length; j++) {
    data1 = _mm_loadu_si128(&((__m128i *) in)[j]);
    last_in = data1;
    data1 = XOR(data1, ((__m128i *) key_schedule)[0]);
    for (i = 1; i < nr; i++) {
      data1 = AESDEC(data1, ((__m128i *) key_schedule)[i]);
    }
    data1 = AESDECLAST(data1, ((__m128i *) key_schedule)[i]);
    data1 = XOR(data1, feedback1);
    _mm_storeu_si128(&((__m128i *) out)[j], data1);
    feedback1 = last_in;
  }
}

void AES_CBC_decrypt_pipe4(
    const unsigned char *in,
    unsigned char *out,
    unsigned char *ivec,
    unsigned long length,
    unsigned char *key_schedule,
    const unsigned int nr) {
  __m128i data1, data2, data3, data4;
  __m128i feedback1, feedback2, feedback3, feedback4, last_in;
  unsigned long j;
  unsigned int i;
  if (length % 16) {
    length = length / 16 + 1;
  } else { length /= 16; }
  feedback1 = _mm_loadu_si128((__m128i *) ivec);
  for (i = 0; i < length / 4; i++) {
    data1 = _mm_loadu_si128(&((__m128i *) in)[i * 4 + 0]);
    data2 = _mm_loadu_si128(&((__m128i *) in)[i * 4 + 1]);
    data3 = _mm_loadu_si128(&((__m128i *) in)[i * 4 + 2]);
    data4 = _mm_loadu_si128(&((__m128i *) in)[i * 4 + 3]);
    feedback2 = data1;
    feedback3 = data2;
    feedback4 = data3;
    last_in = data4;
    data1 = XOR(data1, ((__m128i *) key_schedule)[0]);
    data2 = XOR(data2, ((__m128i *) key_schedule)[0]);
    data3 = XOR(data3, ((__m128i *) key_schedule)[0]);
    data4 = XOR(data4, ((__m128i *) key_schedule)[0]);

    for (j = 1; j < nr; j++) {
      data1 = AESDEC(data1, ((__m128i *) key_schedule)[j]);
      data2 = AESDEC(data2, ((__m128i *) key_schedule)[j]);
      data3 = AESDEC(data3, ((__m128i *) key_schedule)[j]);
      data4 = AESDEC(data4, ((__m128i *) key_schedule)[j]);
    }

    data1 = AESDECLAST(data1, ((__m128i *) key_schedule)[j]);
    data2 = AESDECLAST(data2, ((__m128i *) key_schedule)[j]);
    data3 = AESDECLAST(data3, ((__m128i *) key_schedule)[j]);
    data4 = AESDECLAST(data4, ((__m128i *) key_schedule)[j]);

    data1 = XOR(data1, feedback1);
    data2 = XOR(data2, feedback2);
    data3 = XOR(data3, feedback3);
    data4 = XOR(data4, feedback4);

    _mm_storeu_si128(&((__m128i *) out)[i * 4 + 0], data1);
    _mm_storeu_si128(&((__m128i *) out)[i * 4 + 1], data2);
    _mm_storeu_si128(&((__m128i *) out)[i * 4 + 2], data3);
    _mm_storeu_si128(&((__m128i *) out)[i * 4 + 3], data4);
    feedback1 = last_in;
  }
  for (j = i * 4; j < length; j++) {
    data1 = _mm_loadu_si128(&((__m128i *) in)[j]);
    last_in = data1;
    data1 = XOR(data1, ((__m128i *) key_schedule)[0]);
    for (i = 1; i < nr; i++) {
      data1 = AESDEC(data1, ((__m128i *) key_schedule)[i]);
    }
    data1 = AESDECLAST(data1, ((__m128i *) key_schedule)[i]);
    data1 = XOR(data1, feedback1);
    _mm_storeu_si128(&((__m128i *) out)[j], data1);
    feedback1 = last_in;
  }
}

void AES_CBC_decrypt_pipe8(
    const unsigned char *in,
    unsigned char *out,
    unsigned char ivec[16],
    unsigned long length,
    unsigned char *key_schedule,
    const unsigned int nr) {
  __m128i data1, data2, data3, data4, data5, data6, data7, data8;
  __m128i feedback1, feedback2, feedback3, feedback4, feedback5, feedback6, feedback7, feedback8, last_in;
  unsigned long j;
  unsigned int i;
  if (length % 16) {
    length = length / 16 + 1;
  } else { length /= 16; }
  feedback1 = _mm_loadu_si128((__m128i *) ivec);
  for (i = 0; i < length / 8; i++) {
    data1 = _mm_loadu_si128(&((__m128i *) in)[i * 4 + 0]);
    data2 = _mm_loadu_si128(&((__m128i *) in)[i * 4 + 1]);
    data3 = _mm_loadu_si128(&((__m128i *) in)[i * 4 + 2]);
    data4 = _mm_loadu_si128(&((__m128i *) in)[i * 4 + 3]);
    data5 = _mm_loadu_si128(&((__m128i *) in)[i * 4 + 4]);
    data6 = _mm_loadu_si128(&((__m128i *) in)[i * 4 + 5]);
    data7 = _mm_loadu_si128(&((__m128i *) in)[i * 4 + 6]);
    data8 = _mm_loadu_si128(&((__m128i *) in)[i * 4 + 7]);
    feedback2 = data1;
    feedback3 = data2;
    feedback4 = data3;
    feedback5 = data4;
    feedback6 = data5;
    feedback7 = data6;
    feedback8 = data7;
    last_in = data8;
    data1 = XOR(data1, ((__m128i *) key_schedule)[0]);
    data2 = XOR(data2, ((__m128i *) key_schedule)[0]);
    data3 = XOR(data3, ((__m128i *) key_schedule)[0]);
    data4 = XOR(data4, ((__m128i *) key_schedule)[0]);
    data5 = XOR(data5, ((__m128i *) key_schedule)[0]);
    data6 = XOR(data6, ((__m128i *) key_schedule)[0]);
    data7 = XOR(data7, ((__m128i *) key_schedule)[0]);
    data8 = XOR(data8, ((__m128i *) key_schedule)[0]);

    for (j = 1; j < nr; j++) {
      data1 = AESDEC(data1, ((__m128i *) key_schedule)[j]);
      data2 = AESDEC(data2, ((__m128i *) key_schedule)[j]);
      data3 = AESDEC(data3, ((__m128i *) key_schedule)[j]);
      data4 = AESDEC(data4, ((__m128i *) key_schedule)[j]);
      data5 = AESDEC(data5, ((__m128i *) key_schedule)[j]);
      data6 = AESDEC(data6, ((__m128i *) key_schedule)[j]);
      data7 = AESDEC(data7, ((__m128i *) key_schedule)[j]);
      data8 = AESDEC(data8, ((__m128i *) key_schedule)[j]);
    }

    data1 = AESDECLAST(data1, ((__m128i *) key_schedule)[j]);
    data2 = AESDECLAST(data2, ((__m128i *) key_schedule)[j]);
    data3 = AESDECLAST(data3, ((__m128i *) key_schedule)[j]);
    data4 = AESDECLAST(data4, ((__m128i *) key_schedule)[j]);
    data5 = AESDECLAST(data5, ((__m128i *) key_schedule)[j]);
    data6 = AESDECLAST(data6, ((__m128i *) key_schedule)[j]);
    data7 = AESDECLAST(data7, ((__m128i *) key_schedule)[j]);
    data8 = AESDECLAST(data8, ((__m128i *) key_schedule)[j]);

    data1 = XOR(data1, feedback1);
    data2 = XOR(data2, feedback2);
    data3 = XOR(data3, feedback3);
    data4 = XOR(data4, feedback4);
    data5 = XOR(data5, feedback5);
    data6 = XOR(data6, feedback6);
    data7 = XOR(data7, feedback7);
    data8 = XOR(data8, feedback8);

    _mm_storeu_si128(&((__m128i *) out)[i * 4 + 0], data1);
    _mm_storeu_si128(&((__m128i *) out)[i * 4 + 1], data2);
    _mm_storeu_si128(&((__m128i *) out)[i * 4 + 2], data3);
    _mm_storeu_si128(&((__m128i *) out)[i * 4 + 3], data4);
    _mm_storeu_si128(&((__m128i *) out)[i * 4 + 4], data5);
    _mm_storeu_si128(&((__m128i *) out)[i * 4 + 5], data6);
    _mm_storeu_si128(&((__m128i *) out)[i * 4 + 6], data7);
    _mm_storeu_si128(&((__m128i *) out)[i * 4 + 7], data8);
    feedback1 = last_in;
  }
  for (j = i * 8; j < length; j++) {
    data1 = _mm_loadu_si128(&((__m128i *) in)[j]);
    last_in = data1;
    data1 = XOR(data1, ((__m128i *) key_schedule)[0]);
    for (i = 1; i < nr; i++) {
      data1 = AESDEC(data1, ((__m128i *) key_schedule)[i]);
    }
    data1 = AESDECLAST(data1, ((__m128i *) key_schedule)[i]);
    data1 = XOR(data1, feedback1);
    _mm_storeu_si128(&((__m128i *) out)[j], data1);
    feedback1 = last_in;
  }
}

void AES_CBC_encrypt_2w(
    const unsigned char **in,
    unsigned char **out,
    unsigned char **ivec,
    unsigned long length,
    const unsigned char *key,
    const int nr) {
  __m128i feedback0, data0;
  __m128i feedback1, data1;
  int j;
  unsigned long i;
  if (length % 16) {
    length = length / 16 + 1;
  } else { length /= 16; }
  feedback0 = _mm_loadu_si128((__m128i *) (ivec[0]));
  feedback1 = _mm_loadu_si128((__m128i *) (ivec[1]));
  for (i = 0; i < length; i++) {
    data0 = _mm_loadu_si128(&((__m128i *) (in[0]))[i]);
    data1 = _mm_loadu_si128(&((__m128i *) (in[1]))[i]);
    feedback0 = XOR(data0, feedback0);
    feedback1 = XOR(data1, feedback1);
    feedback0 = XOR(feedback0, ((__m128i *) key)[0]);
    feedback1 = XOR(feedback1, ((__m128i *) key)[0]);
    for (j = 1; j < nr; j++) {
      feedback0 = AESENC(feedback0, ((__m128i *) key)[j]);
      feedback1 = AESENC(feedback1, ((__m128i *) key)[j]);
    }
    feedback0 = AESENCLAST(feedback0, ((__m128i *) key)[j]);
    feedback1 = AESENCLAST(feedback1, ((__m128i *) key)[j]);
    _mm_storeu_si128(&((__m128i *) (out[0]))[i], feedback0);
    _mm_storeu_si128(&((__m128i *) (out[1]))[i], feedback1);
  }
}

void AES_CBC_encrypt_4w(
    const unsigned char **in,
    unsigned char **out,
    unsigned char **ivec,
    unsigned long length,
    const unsigned char *key,
    const int nr) {
  __m128i feedback0, data0;
  __m128i feedback1, data1;
  __m128i feedback2, data2;
  __m128i feedback3, data3;
  int j;
  unsigned long i;
  if (length % 16) {
    length = length / 16 + 1;
  } else { length /= 16; }
  feedback0 = _mm_loadu_si128((__m128i *) (ivec[0]));
  feedback1 = _mm_loadu_si128((__m128i *) (ivec[1]));
  feedback2 = _mm_loadu_si128((__m128i *) (ivec[2]));
  feedback3 = _mm_loadu_si128((__m128i *) (ivec[3]));
  for (i = 0; i < length; i++) {
    data0 = _mm_loadu_si128(&((__m128i *) (in[0]))[i]);
    data1 = _mm_loadu_si128(&((__m128i *) (in[1]))[i]);
    data2 = _mm_loadu_si128(&((__m128i *) (in[2]))[i]);
    data3 = _mm_loadu_si128(&((__m128i *) (in[3]))[i]);
    feedback0 = XOR(data0, feedback0);
    feedback1 = XOR(data1, feedback1);
    feedback2 = XOR(data2, feedback2);
    feedback3 = XOR(data3, feedback3);
    feedback0 = XOR(feedback0, ((__m128i *) key)[0]);
    feedback1 = XOR(feedback1, ((__m128i *) key)[0]);
    feedback2 = XOR(feedback2, ((__m128i *) key)[0]);
    feedback3 = XOR(feedback3, ((__m128i *) key)[0]);
    for (j = 1; j < nr; j++) {
      feedback0 = AESENC(feedback0, ((__m128i *) key)[j]);
      feedback1 = AESENC(feedback1, ((__m128i *) key)[j]);
      feedback2 = AESENC(feedback2, ((__m128i *) key)[j]);
      feedback3 = AESENC(feedback3, ((__m128i *) key)[j]);
    }
    feedback0 = AESENCLAST(feedback0, ((__m128i *) key)[j]);
    feedback1 = AESENCLAST(feedback1, ((__m128i *) key)[j]);
    feedback2 = AESENCLAST(feedback2, ((__m128i *) key)[j]);
    feedback3 = AESENCLAST(feedback3, ((__m128i *) key)[j]);
    _mm_storeu_si128(&((__m128i *) (out[0]))[i], feedback0);
    _mm_storeu_si128(&((__m128i *) (out[1]))[i], feedback1);
    _mm_storeu_si128(&((__m128i *) (out[2]))[i], feedback2);
    _mm_storeu_si128(&((__m128i *) (out[3]))[i], feedback3);
  }

}

void AES_CBC_encrypt_6w(
    const unsigned char **in,
    unsigned char **out,
    unsigned char **ivec,
    unsigned long length,
    const unsigned char *key,
    const int nr) {
  __m128i feedback0, data0;
  __m128i feedback1, data1;
  __m128i feedback2, data2;
  __m128i feedback3, data3;
  __m128i feedback4, data4;
  __m128i feedback5, data5;
  int j;
  unsigned long i;
  if (length % 16) {
    length = length / 16 + 1;
  } else {
    length /= 16;
  }
  feedback0 = _mm_loadu_si128((__m128i *) (ivec[0]));
  feedback1 = _mm_loadu_si128((__m128i *) (ivec[1]));
  feedback2 = _mm_loadu_si128((__m128i *) (ivec[2]));
  feedback3 = _mm_loadu_si128((__m128i *) (ivec[3]));
  feedback4 = _mm_loadu_si128((__m128i *) (ivec[4]));
  feedback5 = _mm_loadu_si128((__m128i *) (ivec[5]));
  for (i = 0; i < length; i++) {
    data0 = _mm_loadu_si128(&((__m128i *) (in[0]))[i]);
    data1 = _mm_loadu_si128(&((__m128i *) (in[1]))[i]);
    data2 = _mm_loadu_si128(&((__m128i *) (in[2]))[i]);
    data3 = _mm_loadu_si128(&((__m128i *) (in[3]))[i]);
    data4 = _mm_loadu_si128(&((__m128i *) (in[4]))[i]);
    data5 = _mm_loadu_si128(&((__m128i *) (in[5]))[i]);
    feedback0 = XOR(data0, feedback0);
    feedback1 = XOR(data1, feedback1);
    feedback2 = XOR(data2, feedback2);
    feedback3 = XOR(data3, feedback3);
    feedback4 = XOR(data4, feedback4);
    feedback5 = XOR(data5, feedback5);
    feedback0 = XOR(feedback0, ((__m128i *) key)[0]);
    feedback1 = XOR(feedback1, ((__m128i *) key)[0]);
    feedback2 = XOR(feedback2, ((__m128i *) key)[0]);
    feedback3 = XOR(feedback3, ((__m128i *) key)[0]);
    feedback4 = XOR(feedback4, ((__m128i *) key)[0]);
    feedback5 = XOR(feedback5, ((__m128i *) key)[0]);
    for (j = 1; j < nr; j++) {
      feedback0 = AESENC(feedback0, ((__m128i *) key)[j]);
      feedback1 = AESENC(feedback1, ((__m128i *) key)[j]);
      feedback2 = AESENC(feedback2, ((__m128i *) key)[j]);
      feedback3 = AESENC(feedback3, ((__m128i *) key)[j]);
      feedback4 = AESENC(feedback4, ((__m128i *) key)[j]);
      feedback5 = AESENC(feedback5, ((__m128i *) key)[j]);
    }
    feedback0 = AESENCLAST(feedback0, ((__m128i *) key)[j]);
    feedback1 = AESENCLAST(feedback1, ((__m128i *) key)[j]);
    feedback2 = AESENCLAST(feedback2, ((__m128i *) key)[j]);
    feedback3 = AESENCLAST(feedback3, ((__m128i *) key)[j]);
    feedback4 = AESENCLAST(feedback4, ((__m128i *) key)[j]);
    feedback5 = AESENCLAST(feedback5, ((__m128i *) key)[j]);
    _mm_storeu_si128(&((__m128i *) (out[0]))[i], feedback0);
    _mm_storeu_si128(&((__m128i *) (out[1]))[i], feedback1);
    _mm_storeu_si128(&((__m128i *) (out[2]))[i], feedback2);
    _mm_storeu_si128(&((__m128i *) (out[3]))[i], feedback3);
    _mm_storeu_si128(&((__m128i *) (out[4]))[i], feedback4);
    _mm_storeu_si128(&((__m128i *) (out[5]))[i], feedback5);
  }
}

void AES_CBC_encrypt_8w(
    const unsigned char **in,
    unsigned char **out,
    unsigned char **ivec,
    unsigned long length,
    const unsigned char *key,
    const int nr) {
  __m128i feedback0, data0;
  __m128i feedback1, data1;
  __m128i feedback2, data2;
  __m128i feedback3, data3;
  __m128i feedback4, data4;
  __m128i feedback5, data5;
  __m128i feedback6, data6;
  __m128i feedback7, data7;
  int j;
  unsigned long i;
  if (length % 16) {
    length = length / 16 + 1;
  } else { length /= 16; }
  feedback0 = _mm_loadu_si128((__m128i *) (ivec[0]));
  feedback1 = _mm_loadu_si128((__m128i *) (ivec[1]));
  feedback2 = _mm_loadu_si128((__m128i *) (ivec[2]));
  feedback3 = _mm_loadu_si128((__m128i *) (ivec[3]));
  feedback4 = _mm_loadu_si128((__m128i *) (ivec[4]));
  feedback5 = _mm_loadu_si128((__m128i *) (ivec[5]));
  feedback6 = _mm_loadu_si128((__m128i *) (ivec[6]));
  feedback7 = _mm_loadu_si128((__m128i *) (ivec[7]));
  for (i = 0; i < length; i++) {
    data0 = _mm_loadu_si128(&((__m128i *) (in[0]))[i]);
    data1 = _mm_loadu_si128(&((__m128i *) (in[1]))[i]);
    data2 = _mm_loadu_si128(&((__m128i *) (in[2]))[i]);
    data3 = _mm_loadu_si128(&((__m128i *) (in[3]))[i]);
    data4 = _mm_loadu_si128(&((__m128i *) (in[4]))[i]);
    data5 = _mm_loadu_si128(&((__m128i *) (in[5]))[i]);
    data6 = _mm_loadu_si128(&((__m128i *) (in[6]))[i]);
    data7 = _mm_loadu_si128(&((__m128i *) (in[7]))[i]);
    feedback0 = XOR(data0, feedback0);
    feedback1 = XOR(data1, feedback1);
    feedback2 = XOR(data2, feedback2);
    feedback3 = XOR(data3, feedback3);
    feedback4 = XOR(data4, feedback4);
    feedback5 = XOR(data5, feedback5);
    feedback6 = XOR(data6, feedback6);
    feedback7 = XOR(data7, feedback7);
    feedback0 = XOR(feedback0, ((__m128i *) key)[0]);
    feedback1 = XOR(feedback1, ((__m128i *) key)[0]);
    feedback2 = XOR(feedback2, ((__m128i *) key)[0]);
    feedback3 = XOR(feedback3, ((__m128i *) key)[0]);
    feedback4 = XOR(feedback4, ((__m128i *) key)[0]);
    feedback5 = XOR(feedback5, ((__m128i *) key)[0]);
    feedback6 = XOR(feedback6, ((__m128i *) key)[0]);
    feedback7 = XOR(feedback7, ((__m128i *) key)[0]);
    for (j = 1; j < nr; j++) {
      feedback0 = AESENC(feedback0, ((__m128i *) key)[j]);
      feedback1 = AESENC(feedback1, ((__m128i *) key)[j]);
      feedback2 = AESENC(feedback2, ((__m128i *) key)[j]);
      feedback3 = AESENC(feedback3, ((__m128i *) key)[j]);
      feedback4 = AESENC(feedback4, ((__m128i *) key)[j]);
      feedback5 = AESENC(feedback5, ((__m128i *) key)[j]);
      feedback6 = AESENC(feedback6, ((__m128i *) key)[j]);
      feedback7 = AESENC(feedback7, ((__m128i *) key)[j]);
    }
    feedback0 = AESENCLAST(feedback0, ((__m128i *) key)[j]);
    feedback1 = AESENCLAST(feedback1, ((__m128i *) key)[j]);
    feedback2 = AESENCLAST(feedback2, ((__m128i *) key)[j]);
    feedback3 = AESENCLAST(feedback3, ((__m128i *) key)[j]);
    feedback4 = AESENCLAST(feedback4, ((__m128i *) key)[j]);
    feedback5 = AESENCLAST(feedback5, ((__m128i *) key)[j]);
    feedback6 = AESENCLAST(feedback6, ((__m128i *) key)[j]);
    feedback7 = AESENCLAST(feedback7, ((__m128i *) key)[j]);
    _mm_storeu_si128(&((__m128i *) (out[0]))[i], feedback0);
    _mm_storeu_si128(&((__m128i *) (out[1]))[i], feedback1);
    _mm_storeu_si128(&((__m128i *) (out[2]))[i], feedback2);
    _mm_storeu_si128(&((__m128i *) (out[3]))[i], feedback3);
    _mm_storeu_si128(&((__m128i *) (out[4]))[i], feedback4);
    _mm_storeu_si128(&((__m128i *) (out[5]))[i], feedback5);
    _mm_storeu_si128(&((__m128i *) (out[6]))[i], feedback6);
    _mm_storeu_si128(&((__m128i *) (out[7]))[i], feedback7);
  }

}

void AES_CTR_encrypt(
    const unsigned char *in,
    unsigned char *out,
    const unsigned char ivec[8],
    const unsigned char nonce[4],
    unsigned long length,
    const unsigned char *key,
    const int number_of_rounds) {
  __m128i ctr_block, tmp, ONE, BSWAP_EPI64;
  int j;
  unsigned long i;
  if (length % 16)
    length = length / 16 + 1;
  else
    length /= 16;
  ONE = _mm_set_epi32(0, 1, 0, 0);
  BSWAP_EPI64 = _mm_setr_epi8(7, 6, 5, 4, 3, 2, 1, 0, 15, 14, 13, 12, 11, 10, 9, 8);
  ctr_block = _mm_setzero_si128();
  ctr_block = _mm_insert_epi64(ctr_block, *(long long *) ivec, 1);
  ctr_block = _mm_insert_epi32(ctr_block, *(long *) nonce, 1);
  ctr_block = _mm_srli_si128(ctr_block, 4);
  ctr_block = _mm_shuffle_epi8(ctr_block, BSWAP_EPI64);
  ctr_block = _mm_add_epi64(ctr_block, ONE);

  for (i = 0; i < length; i++) {
    tmp = _mm_shuffle_epi8(ctr_block, BSWAP_EPI64);
    ctr_block = _mm_add_epi64(ctr_block, ONE);
    tmp = XOR(tmp, ((__m128i *) key)[0]);
    for (j = 1; j < number_of_rounds; j++) {
      tmp = AESENC(tmp, ((__m128i *) key)[j]);
    };
    tmp = AESENCLAST(tmp, ((__m128i *) key)[j]);
    tmp = XOR(tmp, _mm_loadu_si128(&((__m128i *) in)[i]));
    _mm_storeu_si128(&((__m128i *) out)[i], tmp);
  }
}

void AES_CTR_encrypt_pipe2(
    const unsigned char *in,
    unsigned char *out,
    const unsigned char ivec[8],
    const unsigned char nonce[4],
    unsigned long length,
    const unsigned char *key,
    const int number_of_rounds) {
  __m128i ctr_block, ONE, BSWAP_EPI64;
  __m128i tmp0;
  __m128i tmp1;
  int j;
  unsigned long i;
  if (length % 16)
    length = length / 16 + 1;
  else
    length /= 16;
  ONE = _mm_set_epi32(0, 1, 0, 0);
  BSWAP_EPI64 = _mm_setr_epi8(7, 6, 5, 4, 3, 2, 1, 0, 15, 14, 13, 12, 11, 10, 9, 8);
  ctr_block = _mm_setzero_si128();
  ctr_block = _mm_insert_epi64(ctr_block, *(long long *) ivec, 1);
  ctr_block = _mm_insert_epi32(ctr_block, *(long *) nonce, 1);
  ctr_block = _mm_srli_si128(ctr_block, 4);
  ctr_block = _mm_shuffle_epi8(ctr_block, BSWAP_EPI64);
  ctr_block = _mm_add_epi64(ctr_block, ONE);

  for (i = 0; i < length / 4; i++) {
    tmp0 = _mm_shuffle_epi8(ctr_block, BSWAP_EPI64);
    ctr_block = _mm_add_epi64(ctr_block, ONE);
    tmp1 = _mm_shuffle_epi8(ctr_block, BSWAP_EPI64);
    ctr_block = _mm_add_epi64(ctr_block, ONE);

    tmp0 = XOR(tmp0, ((__m128i *) key)[0]);
    tmp1 = XOR(tmp1, ((__m128i *) key)[0]);
    for (j = 1; j < number_of_rounds; j++) {
      tmp0 = AESENC(tmp0, ((__m128i *) key)[j]);
      tmp1 = AESENC(tmp1, ((__m128i *) key)[j]);
    };
    tmp0 = AESENCLAST(tmp0, ((__m128i *) key)[j]);
    tmp1 = AESENCLAST(tmp1, ((__m128i *) key)[j]);
    tmp0 = XOR(tmp0, _mm_loadu_si128(&((__m128i *) in)[2 * i + 0]));
    tmp1 = XOR(tmp1, _mm_loadu_si128(&((__m128i *) in)[2 * i + 1]));
    _mm_storeu_si128(&((__m128i *) out)[2 * i + 0], tmp0);
    _mm_storeu_si128(&((__m128i *) out)[2 * i + 1], tmp1);
  }
  __m128i tmp;
  for (i = 2 * i; i < length; i++) {
    tmp = _mm_shuffle_epi8(ctr_block, BSWAP_EPI64);
    ctr_block = _mm_add_epi64(ctr_block, ONE);
    tmp = XOR(tmp, ((__m128i *) key)[0]);
    for (j = 1; j < number_of_rounds; j++) {
      tmp = AESENC(tmp, ((__m128i *) key)[j]);
    };
    tmp = AESENCLAST(tmp, ((__m128i *) key)[j]);
    tmp = XOR(tmp, _mm_loadu_si128(&((__m128i *) in)[i]));
    _mm_storeu_si128(&((__m128i *) out)[i], tmp);
  }
}

void AES_CTR_encrypt_pipe4(
    const unsigned char *in,
    unsigned char *out,
    const unsigned char ivec[8],
    const unsigned char nonce[4],
    unsigned long length,
    const unsigned char *key,
    const int number_of_rounds) {
  __m128i ctr_block, ONE, BSWAP_EPI64;
  __m128i tmp0;
  __m128i tmp1;
  __m128i tmp2;
  __m128i tmp3;
  int j;
  unsigned long i;
  if (length % 16)
    length = length / 16 + 1;
  else
    length /= 16;
  ONE = _mm_set_epi32(0, 1, 0, 0);
  BSWAP_EPI64 = _mm_setr_epi8(7, 6, 5, 4, 3, 2, 1, 0, 15, 14, 13, 12, 11, 10, 9, 8);
  ctr_block = _mm_setzero_si128();
  ctr_block = _mm_insert_epi64(ctr_block, *(long long *) ivec, 1);
  ctr_block = _mm_insert_epi32(ctr_block, *(long *) nonce, 1);
  ctr_block = _mm_srli_si128(ctr_block, 4);
  ctr_block = _mm_shuffle_epi8(ctr_block, BSWAP_EPI64);
  ctr_block = _mm_add_epi64(ctr_block, ONE);

  for (i = 0; i < length / 4; i++) {
    tmp0 = _mm_shuffle_epi8(ctr_block, BSWAP_EPI64);
    ctr_block = _mm_add_epi64(ctr_block, ONE);
    tmp1 = _mm_shuffle_epi8(ctr_block, BSWAP_EPI64);
    ctr_block = _mm_add_epi64(ctr_block, ONE);
    tmp2 = _mm_shuffle_epi8(ctr_block, BSWAP_EPI64);
    ctr_block = _mm_add_epi64(ctr_block, ONE);
    tmp3 = _mm_shuffle_epi8(ctr_block, BSWAP_EPI64);
    ctr_block = _mm_add_epi64(ctr_block, ONE);

    tmp0 = XOR(tmp0, ((__m128i *) key)[0]);
    tmp1 = XOR(tmp1, ((__m128i *) key)[0]);
    tmp2 = XOR(tmp2, ((__m128i *) key)[0]);
    tmp3 = XOR(tmp3, ((__m128i *) key)[0]);
    for (j = 1; j < number_of_rounds; j++) {
      tmp0 = AESENC(tmp0, ((__m128i *) key)[j]);
      tmp1 = AESENC(tmp1, ((__m128i *) key)[j]);
      tmp2 = AESENC(tmp2, ((__m128i *) key)[j]);
      tmp3 = AESENC(tmp3, ((__m128i *) key)[j]);
    };
    tmp0 = AESENCLAST(tmp0, ((__m128i *) key)[j]);
    tmp1 = AESENCLAST(tmp1, ((__m128i *) key)[j]);
    tmp2 = AESENCLAST(tmp2, ((__m128i *) key)[j]);
    tmp3 = AESENCLAST(tmp3, ((__m128i *) key)[j]);
    tmp0 = XOR(tmp0, _mm_loadu_si128(&((__m128i *) in)[2 * i + 0]));
    tmp1 = XOR(tmp1, _mm_loadu_si128(&((__m128i *) in)[2 * i + 1]));
    tmp2 = XOR(tmp2, _mm_loadu_si128(&((__m128i *) in)[2 * i + 2]));
    tmp3 = XOR(tmp3, _mm_loadu_si128(&((__m128i *) in)[2 * i + 3]));
    _mm_storeu_si128(&((__m128i *) out)[2 * i + 0], tmp0);
    _mm_storeu_si128(&((__m128i *) out)[2 * i + 1], tmp1);
    _mm_storeu_si128(&((__m128i *) out)[2 * i + 2], tmp2);
    _mm_storeu_si128(&((__m128i *) out)[2 * i + 3], tmp3);
  }
  __m128i tmp;
  for (i = 4 * i; i < length; i++) {
    tmp = _mm_shuffle_epi8(ctr_block, BSWAP_EPI64);
    ctr_block = _mm_add_epi64(ctr_block, ONE);
    tmp = XOR(tmp, ((__m128i *) key)[0]);
    for (j = 1; j < number_of_rounds; j++) {
      tmp = AESENC(tmp, ((__m128i *) key)[j]);
    };
    tmp = AESENCLAST(tmp, ((__m128i *) key)[j]);
    tmp = XOR(tmp, _mm_loadu_si128(&((__m128i *) in)[i]));
    _mm_storeu_si128(&((__m128i *) out)[i], tmp);
  }
}

void AES_CTR_encrypt_pipe8(
    const unsigned char *in,
    unsigned char *out,
    const unsigned char ivec[8],
    const unsigned char nonce[4],
    unsigned long length,
    const unsigned char *key,
    const int number_of_rounds) {
  __m128i ctr_block, ONE, BSWAP_EPI64;
  __m128i tmp0;
  __m128i tmp1;
  __m128i tmp2;
  __m128i tmp3;
  __m128i tmp4;
  __m128i tmp5;
  __m128i tmp6;
  __m128i tmp7;
  int j;
  unsigned long i;
  if (length % 16)
    length = length / 16 + 1;
  else
    length /= 16;
  ONE = _mm_set_epi32(0, 1, 0, 0);
  BSWAP_EPI64 = _mm_setr_epi8(7, 6, 5, 4, 3, 2, 1, 0, 15, 14, 13, 12, 11, 10, 9, 8);
  ctr_block = _mm_setzero_si128();
  ctr_block = _mm_insert_epi64(ctr_block, *(long long *) ivec, 1);
  ctr_block = _mm_insert_epi32(ctr_block, *(long *) nonce, 1);
  ctr_block = _mm_srli_si128(ctr_block, 4);
  ctr_block = _mm_shuffle_epi8(ctr_block, BSWAP_EPI64);
  ctr_block = _mm_add_epi64(ctr_block, ONE);

  for (i = 0; i < length / 8; i++) {
    tmp0 = _mm_shuffle_epi8(ctr_block, BSWAP_EPI64);
    ctr_block = _mm_add_epi64(ctr_block, ONE);
    tmp1 = _mm_shuffle_epi8(ctr_block, BSWAP_EPI64);
    ctr_block = _mm_add_epi64(ctr_block, ONE);
    tmp2 = _mm_shuffle_epi8(ctr_block, BSWAP_EPI64);
    ctr_block = _mm_add_epi64(ctr_block, ONE);
    tmp3 = _mm_shuffle_epi8(ctr_block, BSWAP_EPI64);
    ctr_block = _mm_add_epi64(ctr_block, ONE);
    tmp4 = _mm_shuffle_epi8(ctr_block, BSWAP_EPI64);
    ctr_block = _mm_add_epi64(ctr_block, ONE);
    tmp5 = _mm_shuffle_epi8(ctr_block, BSWAP_EPI64);
    ctr_block = _mm_add_epi64(ctr_block, ONE);
    tmp6 = _mm_shuffle_epi8(ctr_block, BSWAP_EPI64);
    ctr_block = _mm_add_epi64(ctr_block, ONE);
    tmp7 = _mm_shuffle_epi8(ctr_block, BSWAP_EPI64);
    ctr_block = _mm_add_epi64(ctr_block, ONE);

    tmp0 = XOR(tmp0, ((__m128i *) key)[0]);
    tmp1 = XOR(tmp1, ((__m128i *) key)[0]);
    tmp2 = XOR(tmp2, ((__m128i *) key)[0]);
    tmp3 = XOR(tmp3, ((__m128i *) key)[0]);
    tmp4 = XOR(tmp4, ((__m128i *) key)[0]);
    tmp5 = XOR(tmp5, ((__m128i *) key)[0]);
    tmp6 = XOR(tmp6, ((__m128i *) key)[0]);
    tmp7 = XOR(tmp7, ((__m128i *) key)[0]);
    for (j = 1; j < number_of_rounds; j++) {
      tmp0 = AESENC(tmp0, ((__m128i *) key)[j]);
      tmp1 = AESENC(tmp1, ((__m128i *) key)[j]);
      tmp2 = AESENC(tmp2, ((__m128i *) key)[j]);
      tmp3 = AESENC(tmp3, ((__m128i *) key)[j]);
      tmp4 = AESENC(tmp4, ((__m128i *) key)[j]);
      tmp5 = AESENC(tmp5, ((__m128i *) key)[j]);
      tmp6 = AESENC(tmp6, ((__m128i *) key)[j]);
      tmp7 = AESENC(tmp7, ((__m128i *) key)[j]);
    };
    tmp0 = AESENCLAST(tmp0, ((__m128i *) key)[j]);
    tmp1 = AESENCLAST(tmp1, ((__m128i *) key)[j]);
    tmp2 = AESENCLAST(tmp2, ((__m128i *) key)[j]);
    tmp3 = AESENCLAST(tmp3, ((__m128i *) key)[j]);
    tmp4 = AESENCLAST(tmp4, ((__m128i *) key)[j]);
    tmp5 = AESENCLAST(tmp5, ((__m128i *) key)[j]);
    tmp6 = AESENCLAST(tmp6, ((__m128i *) key)[j]);
    tmp7 = AESENCLAST(tmp7, ((__m128i *) key)[j]);
    tmp0 = XOR(tmp0, _mm_loadu_si128(&((__m128i *) in)[2 * i + 0]));
    tmp1 = XOR(tmp1, _mm_loadu_si128(&((__m128i *) in)[2 * i + 1]));
    tmp2 = XOR(tmp2, _mm_loadu_si128(&((__m128i *) in)[2 * i + 2]));
    tmp3 = XOR(tmp3, _mm_loadu_si128(&((__m128i *) in)[2 * i + 3]));
    tmp4 = XOR(tmp4, _mm_loadu_si128(&((__m128i *) in)[2 * i + 3]));
    tmp5 = XOR(tmp5, _mm_loadu_si128(&((__m128i *) in)[2 * i + 3]));
    tmp6 = XOR(tmp6, _mm_loadu_si128(&((__m128i *) in)[2 * i + 3]));
    tmp7 = XOR(tmp7, _mm_loadu_si128(&((__m128i *) in)[2 * i + 3]));
    _mm_storeu_si128(&((__m128i *) out)[2 * i + 0], tmp0);
    _mm_storeu_si128(&((__m128i *) out)[2 * i + 1], tmp1);
    _mm_storeu_si128(&((__m128i *) out)[2 * i + 2], tmp2);
    _mm_storeu_si128(&((__m128i *) out)[2 * i + 3], tmp3);
    _mm_storeu_si128(&((__m128i *) out)[2 * i + 4], tmp4);
    _mm_storeu_si128(&((__m128i *) out)[2 * i + 5], tmp5);
    _mm_storeu_si128(&((__m128i *) out)[2 * i + 6], tmp6);
    _mm_storeu_si128(&((__m128i *) out)[2 * i + 7], tmp7);
  }
  __m128i tmp;
  for (i = 8 * i; i < length; i++) {
    tmp = _mm_shuffle_epi8(ctr_block, BSWAP_EPI64);
    ctr_block = _mm_add_epi64(ctr_block, ONE);
    tmp = XOR(tmp, ((__m128i *) key)[0]);
    for (j = 1; j < number_of_rounds; j++) {
      tmp = AESENC(tmp, ((__m128i *) key)[j]);
    };
    tmp = AESENCLAST(tmp, ((__m128i *) key)[j]);
    tmp = XOR(tmp, _mm_loadu_si128(&((__m128i *) in)[i]));
    _mm_storeu_si128(&((__m128i *) out)[i], tmp);
  }
}
