/*
 * This software is Copyright © 2004 bartavelle, <bartavelle at bandecon.com>, and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without modification, are permitted. 
 * 
 * Minor changes by David Luyer <david at luyer.net> to
 * use a modified (faster) version of Solar Designer's
 * md5 implementation.
 *
 * More improvement by 
 * Balázs Bucsay - earthquake at rycon.hu - http://www.rycon.hu/ 
 * (2times faster, but it's only works up to 54characters)
 *
 * Added in SSE2 (and MMX) support from md5-mmx.S by
 * Jim Fougeron - jfoug at cox dot net
 * (1.5 to 3.5x faster, depending upon core type).  
 * Done in blocks of 64 hashs per 'run' (to avoid 
 * fseek() slowdown issues in wordlist.c code
 *
 */

#include <string.h>

#include "arch.h"
#include "misc.h"
#include "common.h"
#include "formats.h"

#ifdef MMX_COEF
#include "md5.h"
#else
#if ARCH_LITTLE_ENDIAN
#define MD5_out MD5_out_eq
#else
#define MD5_out MD5_bitswapped_out_eq
#endif
typedef unsigned int MD5_u32plus;
extern void MD5_Go_eq(unsigned char *data, unsigned int len, int index);
extern void MD5_Go2_eq(unsigned char *data, unsigned int len, int index);
#endif

#define FORMAT_LABEL		"raw-md5"
#define FORMAT_NAME			"Raw MD5"
#ifdef MMX_COEF
#if (MMX_COEF == 2)
#define ALGORITHM_NAME		"raw-md5 MMX 32x2"
#else
#define ALGORITHM_NAME		"raw-md5 SSE2 16x4"
#endif
#else
#define ALGORITHM_NAME		"raw-md5 64x1"
#endif

#ifdef MMX_TYPE
#define BENCHMARK_COMMENT	MMX_TYPE
#else
#define BENCHMARK_COMMENT		""
#endif
#define BENCHMARK_LENGTH		-1

#ifdef MMX_COEF
#define PLAINTEXT_LENGTH		53
#else
// NOTE, when we use 'generic' md5 to do this, we can process up to 
// 96 byte passwords.  However, in the 'native' mode, 53 byte is max :(
#define PLAINTEXT_LENGTH		53
#endif
#define CIPHERTEXT_LENGTH		32

#define BINARY_SIZE				16
#define SALT_SIZE				0

#ifdef MMX_COEF
#if MMX_COEF==2
#define BLOCK_LOOPS 32
#else
#define BLOCK_LOOPS 16
#endif
#define MIN_KEYS_PER_CRYPT	MMX_COEF*BLOCK_LOOPS
#define MAX_KEYS_PER_CRYPT	MMX_COEF*BLOCK_LOOPS
#define GETPOS(i, index)		( (index)*4 + ((i) & (0xffffffff-3) )*MMX_COEF + ((i)&3) )
#else
#define MIN_KEYS_PER_CRYPT	1
#define MAX_KEYS_PER_CRYPT	64
extern ARCH_WORD_32 MD5_out[MAX_KEYS_PER_CRYPT];
extern char MD5_tmp[MAX_KEYS_PER_CRYPT][CIPHERTEXT_LENGTH + 1];
#endif

static struct fmt_tests rawmd5_tests[] = {
	{"5a105e8b9d40e1329780d62ea2265d8a", "test1"},
	{"ad0234829205b9033196ba818f7a872b", "test2"},
	{"8ad8757baa8564dc136c1e07507f4a98", "test3"},
	{"86985e105f79b95d6bc918fb45ec7727", "test4"},
	{"378e2c4a07968da2eca692320136433d", "thatsworking"},
	{NULL}
};

#ifdef MMX_COEF
/* Cygwin would not guarantee the alignment if these were declared static */
#define saved_key rawMD5_saved_key
#define crypt_key rawMD5_crypt_key
char saved_key[BLOCK_LOOPS][64*MMX_COEF] __attribute__ ((aligned(16)));
unsigned char crypt_key[BLOCK_LOOPS][BINARY_SIZE*MMX_COEF] __attribute__ ((aligned(16)));
static unsigned long total_len[BLOCK_LOOPS];
static char out[64 + 1];
#else
static char saved_key[MAX_KEYS_PER_CRYPT][PLAINTEXT_LENGTH + 1 + 128 /* MD5 scratch space */];
static unsigned int saved_key_len[MAX_KEYS_PER_CRYPT];
#endif

static int valid(char *ciphertext)
{
	int i;

	if (strlen(ciphertext) != CIPHERTEXT_LENGTH) return 0;
	for (i = 0; i < CIPHERTEXT_LENGTH; i++){
		if (!(  (('0' <= ciphertext[i])&&(ciphertext[i] <= '9')) ||
					(('a' <= ciphertext[i])&&(ciphertext[i] <= 'f'))  ))
			return 0;
	}
	return 1;
}

static void rawmd5_set_key(char *key, int index)
{
#ifdef MMX_COEF
	unsigned int i, len, cnt;
	unsigned int idx = ( ((unsigned)index)>>(MMX_COEF>>1));
	ARCH_WORD_32 *pi = (ARCH_WORD_32 *)key;
	ARCH_WORD_32 *po = &((ARCH_WORD_32 *)(&(saved_key[idx])))[index&(MMX_COEF-1)];
	len = strlen(key);
	if(index==0)
	{
		memset(saved_key, 0, sizeof(saved_key));
		memset(total_len, 0, sizeof(total_len));
	}

	cnt = len>>2;
	for (i = 0; i < cnt; ++i)
	{
		*po = *pi++;
		po += MMX_COEF;
	}
	for(i=cnt<<2;i<len;i++)
		saved_key[idx][GETPOS(i, index&(MMX_COEF-1))] = key[i];
	saved_key[idx][GETPOS(i, index&(MMX_COEF-1))] = 0x80;
	total_len[idx] += ( len << ( ( (32/MMX_COEF) * (index&(MMX_COEF-1)) ) ));

//	{
//		int i;
//		printf ("key=%s index=%d  total_len=%X\n", key, index, total_len[idx]);
//		for (i = 0; i < 64; ++i)
//		{
//			printf ("%02X ", (unsigned char)saved_key[idx][i]);
//			if (i % 16 == 15)
//				printf ("\n");
//		}
//	}

#else
	strnzcpy(saved_key[index], key, PLAINTEXT_LENGTH+1);
	saved_key_len[index] = strlen(saved_key[index]);
#endif
}

static char *rawmd5_get_key(int index) {
#ifdef MMX_COEF
	unsigned int i,s;
	unsigned int idx = ( ((unsigned)index)>>(MMX_COEF>>1));
	
	s = (total_len[idx] >> (((32/MMX_COEF)*(index&(MMX_COEF-1))))) & 0xff;
	for(i=0;i<s;i++)
		out[i] = saved_key[idx][ GETPOS(i, index&(MMX_COEF-1)) ];
	out[i] = 0;
	return (char*)out;
#else
	saved_key[index][saved_key_len[index]] = '\0';
	return saved_key[index];
#endif
}

static int rawmd5_cmp_all(void *binary, int count)
{
#ifdef MMX_COEF
	unsigned int i, j;
	unsigned int cnt = ( ((unsigned)count+MMX_COEF-1)>>(MMX_COEF>>1));
	for (j = 0; j < cnt; ++j)
	{
		int SomethingGood = 1;
		i = 0;
		while(i < (BINARY_SIZE/4) )
		{
			if (
				( ((unsigned long *)binary)[i] != ((unsigned long *)&(crypt_key[j]))[i*MMX_COEF])
				&& ( ((unsigned long *)binary)[i] != ((unsigned long *)&(crypt_key[j]))[i*MMX_COEF+1])
#if (MMX_COEF > 3)
				&& ( ((unsigned long *)binary)[i] != ((unsigned long *)&(crypt_key[j]))[i*MMX_COEF+2])
				&& ( ((unsigned long *)binary)[i] != ((unsigned long *)&(crypt_key[j]))[i*MMX_COEF+3])
#endif
				)
			{
				SomethingGood = 0;
				break;
			}
			++i;
		}
		if (SomethingGood)
			return 1;
	}
	return 0;
#else
	unsigned int i;

	for (i = 0; i < count; i++) {
		if (!(*((unsigned int*)binary) - *((unsigned int*)&MD5_out[i])))
			return 1;
	}

	return 0;
#endif
}

static int rawmd5_cmp_one(void *binary, int index) 
{
#ifdef MMX_COEF
	unsigned int idx = ( ((unsigned)index)>>(MMX_COEF>>1));
	return((((ARCH_WORD_32 *)binary)[0] == ((ARCH_WORD_32 *)&(crypt_key[idx]))[0*MMX_COEF+(index&(MMX_COEF-1))]) &&
		     (((ARCH_WORD_32 *)binary)[1] == ((ARCH_WORD_32 *)&(crypt_key[idx]))[1*MMX_COEF+(index&(MMX_COEF-1))])
#if (MMX_COEF > 3)
		     &&
		     (((ARCH_WORD_32 *)binary)[2] == ((ARCH_WORD_32 *)&(crypt_key[idx]))[2*MMX_COEF+(index&(MMX_COEF-1))]) &&
		     (((ARCH_WORD_32 *)binary)[3] == ((ARCH_WORD_32 *)&(crypt_key[idx]))[3*MMX_COEF+(index&(MMX_COEF-1))])
#endif
		);
#else
	return (!(*((unsigned int*)binary) - (unsigned int)MD5_out[index]));
#endif
}

static int rawmd5_cmp_exact(char *source, int index)
{
#ifdef MMX_COEF
	return 1;
#else
    MD5_Go2_eq((unsigned char *)saved_key[index], saved_key_len[index], index);
    return !memcmp(source, MD5_tmp[index], CIPHERTEXT_LENGTH);
#endif
}

static void rawmd5_crypt_all(int count) {
  // get plaintext input in saved_key put it into ciphertext crypt_key
#ifdef MMX_COEF
	unsigned int cnt = ( ((unsigned)count+MMX_COEF-1)>>(MMX_COEF>>1));
	unsigned i;
	for (i = 0; i < cnt; ++i)
		mdfivemmx((unsigned char*)&(crypt_key[i]), (unsigned char*)&(saved_key[i]), total_len[i]);
#else
	unsigned int i;

	for (i = 0; i < count; i++)
		MD5_Go_eq((unsigned char *)saved_key[i], saved_key_len[i], i);
#endif
}

static int rawmd5_binary_hash_0(void * binary) { return ((ARCH_WORD_32 *)binary)[0] & 0xf; }
static int rawmd5_binary_hash_1(void * binary) { return ((ARCH_WORD_32 *)binary)[0] & 0xff; }
static int rawmd5_binary_hash_2(void * binary) { return ((ARCH_WORD_32 *)binary)[0] & 0xfff; }
static int rawmd5_binary_hash_3(void * binary) { return ((ARCH_WORD_32 *)binary)[0] & 0xffff; }
static int rawmd5_binary_hash_4(void * binary) { return ((ARCH_WORD_32 *)binary)[0] & 0xfffff; }

int rawmd5_get_hash_0(int index)
{
#ifdef MMX_COEF
	unsigned int idx = ( ((unsigned)index)>>(MMX_COEF>>1));
	return ((ARCH_WORD_32 *)&(crypt_key[idx]))[index&(MMX_COEF-1)] & 0xf;
#else
	return MD5_out[index] & 0xF;
#endif
}

int rawmd5_get_hash_1(int index)
{
#ifdef MMX_COEF
	unsigned int idx = ( ((unsigned)index)>>(MMX_COEF>>1));
	return ((ARCH_WORD_32 *)&(crypt_key[idx]))[index&(MMX_COEF-1)] & 0xff;
#else
	return MD5_out[index] & 0xFF;
#endif
}

int rawmd5_get_hash_2(int index)
{
#ifdef MMX_COEF
	unsigned int idx = ( ((unsigned)index)>>(MMX_COEF>>1));
	return ((ARCH_WORD_32 *)&(crypt_key[idx]))[index&(MMX_COEF-1)] & 0xfff;
#else
	return MD5_out[index] & 0xFFF;
#endif
}

int rawmd5_get_hash_3(int index)
{
#ifdef MMX_COEF
	unsigned int idx = ( ((unsigned)index)>>(MMX_COEF>>1));
	return ((ARCH_WORD_32 *)&(crypt_key[idx]))[index&(MMX_COEF-1)] & 0xffff;
#else
	return MD5_out[index] & 0xFFFF;
#endif
}
int rawmd5_get_hash_4(int index)
{
#ifdef MMX_COEF
	unsigned int idx = ( ((unsigned)index)>>(MMX_COEF>>1));
	return ((ARCH_WORD_32 *)&(crypt_key[idx]))[index&(MMX_COEF-1)] & 0xfffff;
#else
	return MD5_out[index] & 0xFFFFF;
#endif
}


static void *rawmd5_binary(char *ciphertext)
{
	static char realcipher[BINARY_SIZE];
	int i;

	for(i=0;i<BINARY_SIZE;i++)
	{
		realcipher[i] = atoi16[ARCH_INDEX(ciphertext[i*2])]*16 + atoi16[ARCH_INDEX(ciphertext[i*2+1])];
	}
	return (void *)realcipher;
}

struct fmt_main fmt_rawMD5go = 
{
	{
		FORMAT_LABEL,
		FORMAT_NAME,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		PLAINTEXT_LENGTH,
		BINARY_SIZE,
		SALT_SIZE,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT,
		rawmd5_tests
	}, {
		fmt_default_init,
		valid,
		fmt_default_split,
		rawmd5_binary,
		fmt_default_salt,
		{
			rawmd5_binary_hash_0,
			rawmd5_binary_hash_1,
			rawmd5_binary_hash_2,
			rawmd5_binary_hash_3,
			rawmd5_binary_hash_4
		},
		fmt_default_salt_hash,
		fmt_default_set_salt,
		rawmd5_set_key,
		rawmd5_get_key,
		fmt_default_clear_keys,
		rawmd5_crypt_all,
		{
			rawmd5_get_hash_0,
			rawmd5_get_hash_1,
			rawmd5_get_hash_2,
			rawmd5_get_hash_3,
			rawmd5_get_hash_4
		},
		rawmd5_cmp_all,
		rawmd5_cmp_one,
		rawmd5_cmp_exact
	}
};
