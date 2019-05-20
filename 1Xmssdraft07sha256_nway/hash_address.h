/*
Ana Karina D S Oliveira
based in version hash_address.h 20160217 by
Andreas Hülsing
Joost Rijneveld
Public domain.
*/


#define SET_LAYER_ADDRESS32(a, v) {\
  a[0] = v ;}
  
#define SET_TREE_ADDRESS32(a, v) {\
  a[2] = (v & 0xFFFFFFFF);\
  a[1] = (v >> 32) & 0xFFFFFFFF;}

#define SET_TYPE32(a, v){\
  a[3] = v;\
  a[4] = 0;a[5] = 0; a[6] = 0; a[7] = 0; }

#define SET_KEY_AND_MASK32(a, b){\
 a[7] = b;}

#define SET_KEY_AND_MASK128(a, b){\
 a[7] = b;}

#define SET_KEY_AND_MASK256(a, b){\
 a[7] = b;}

/* wots */

#define SET_OTS_ADDRESS32(a, v) {\
  a[4] = v ;}

#define SET_CHAIN_ADDRESS32(a, v) {\
  a[5] = v ;}

#define SET_HASH_ADDRESS32(a, v) {\
  a[6] = v ;}

#define SET_HASH_ADDRESS128(a, v) {\
  a[6] = _mm_and_si128(_mm_set1_epi32(v), _mm_set1_epi32(0xFFFFFFFF));}

#define SET_HASH_ADDRESS256(a, v) {\
  a[6] = _mm256_and_si256(_mm256_set1_epi32(v), _mm256_set1_epi32(0xFFFFFFFF));}

/* ltree */

#define SET_LTREE_ADDRESS32(a, v) {\
  a[4] = v ;}

#define SET_LTREE_TREE_HEIGHT32(a, v) {\
  a[5] = v ;}

#define SET_LTREE_TREE_INDEX32(a, v) {\
  a[6] = v ;}

/* tree */

#define SET_NODE_TREE_HEIGHT32(a, v) {\
  a[5] = v ;}

#define SET_NODE_TREE_INDEX32(a, v) {\
  a[6] = v ;}


