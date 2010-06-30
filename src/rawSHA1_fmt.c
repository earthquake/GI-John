/*
 * Copyright (c) 2004 bartavelle
 * bartavelle at bandecon.com
 *
 * Simple MD5 hashes cracker
 * It uses the Solar Designer's md5 implementation
 * 
 */

#include <string.h>

#include "arch.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "sha.h"

#define FORMAT_LABEL			"raw-sha1"
#define FORMAT_NAME			"Raw SHA-1"
#ifdef MMX_COEF
#if (MMX_COEF == 2)
#define ALGORITHM_NAME			"raw-sha1 MMX"
#else
#define ALGORITHM_NAME			"raw-sha1 SSE2"
#endif
#else
#define ALGORITHM_NAME			"raw-sha1"
#endif

#ifdef MMX_TYPE
#define BENCHMARK_COMMENT		MMX_TYPE
#else
#define BENCHMARK_COMMENT		""
#endif
#define BENCHMARK_LENGTH		-1

#define PLAINTEXT_LENGTH		32
#define CIPHERTEXT_LENGTH		40

#define BINARY_SIZE			20
#define SALT_SIZE			0

#ifdef MMX_COEF
#define MIN_KEYS_PER_CRYPT		MMX_COEF
#define MAX_KEYS_PER_CRYPT		MMX_COEF
//#define GETPOS(i, index)		( (index)*4 + ((i)& (0xffffffff-3) )*MMX_COEF + ((i)&3) ) //std getpos
#define GETPOS(i, index)		( (index)*4 + ((i)& (0xffffffff-3) )*MMX_COEF + (3-((i)&3)) ) //for endianity conversion
#else
#define MIN_KEYS_PER_CRYPT		1
#define MAX_KEYS_PER_CRYPT		1
#endif

static struct fmt_tests rawsha1_tests[] = {
	{"A9993E364706816ABA3E25717850C26C9CD0D89D", "abc"},
	{"2fbf0eba37de1d1d633bc1ed943b907f9b360d4c", "azertyuiop1"},
	{"f879f8090e92232ed07092ebed6dc6170457a21d", "azertyuiop2"},
	{"1813c12f25e64931f3833b26e999e26e81f9ad24", "azertyuiop3"},
	{NULL}
};

#ifdef MMX_COEF
/* Cygwin would not guarantee the alignment if these were declared static */
#define saved_key rawSHA1_saved_key
#define crypt_key rawSHA1_crypt_key
char saved_key[80*4*MMX_COEF] __attribute__ ((aligned(16)));
char crypt_key[BINARY_SIZE*MMX_COEF] __attribute__ ((aligned(16)));
static unsigned long total_len;
static unsigned char out[PLAINTEXT_LENGTH + 1];
#else
static char saved_key[PLAINTEXT_LENGTH + 1];
static ARCH_WORD_32 crypt_key[BINARY_SIZE / 4];
static SHA_CTX ctx;
#endif

static int valid(char *ciphertext)
{
	int i;

	if (strlen(ciphertext) != CIPHERTEXT_LENGTH) return 0;
	for (i = 0; i < CIPHERTEXT_LENGTH; i++){
		if (!(  (('0' <= ciphertext[i])&&(ciphertext[i] <= '9')) ||
					(('a' <= ciphertext[i])&&(ciphertext[i] <= 'f'))  
					|| (('A' <= ciphertext[i])&&(ciphertext[i] <= 'F'))))
			return 0;
	}
	return 1;
}

static void rawsha1_set_salt(void *salt) { }

static void rawsha1_init(void)
{
#ifdef MMX_COEF
	memset(saved_key, 0, sizeof(saved_key));
#endif
}

static void rawsha1_set_key(char *key, int index) {
#ifdef MMX_COEF
	int len;
	int i;
	
	if(index==0)
	{
		total_len = 0;
		memset(saved_key, 0, sizeof(saved_key));
	}
	len = strlen(key);
	if(len>PLAINTEXT_LENGTH)
		len = PLAINTEXT_LENGTH;

	total_len += len << ( ( (32/MMX_COEF) * index ) );
	for(i=0;i<len;i++)
		saved_key[GETPOS(i, index)] = key[i];

	saved_key[GETPOS(i, index)] = 0x80;
#else
	strnzcpy(saved_key, key, PLAINTEXT_LENGTH+1);
#endif
}

static char *rawsha1_get_key(int index) {
#ifdef MMX_COEF
	unsigned int i,s;
	
	s = (total_len >> (((32/MMX_COEF)*(index)))) & 0xff;
	for(i=0;i<s;i++)
		out[i] = saved_key[ GETPOS(i, index) ];
	out[i] = 0;
	return (char *) out;
#else
	return saved_key;
#endif
}

static int rawsha1_cmp_all(void *binary, int count) { 
#ifdef MMX_COEF
	int i=0;
	while(i< (BINARY_SIZE/4) )
	{
		if (
			( ((unsigned long *)binary)[i] != ((unsigned long *)crypt_key)[i*MMX_COEF])
			&& ( ((unsigned long *)binary)[i] != ((unsigned long *)crypt_key)[i*MMX_COEF+1])
#if (MMX_COEF > 3)
			&& ( ((unsigned long *)binary)[i] != ((unsigned long *)crypt_key)[i*MMX_COEF+2])
			&& ( ((unsigned long *)binary)[i] != ((unsigned long *)crypt_key)[i*MMX_COEF+3])
#endif
		)
			return 0;
		i++;
	}
	return 1;
#else
	return !memcmp(binary, crypt_key, BINARY_SIZE);
#endif
}

static int rawsha1_cmp_exact(char *source, int count){
  return (1);
}

static int rawsha1_cmp_one(void * binary, int index)
{
#ifdef MMX_COEF
	int i = 0;
	for(i=0;i<(BINARY_SIZE/4);i++)
		if ( ((unsigned long *)binary)[i] != ((unsigned long *)crypt_key)[i*MMX_COEF+index] )
			return 0;
	return 1;
#else
	return rawsha1_cmp_all(binary, index);
#endif
}

static void rawsha1_crypt_all(int count) {  
  // get plaintext input in saved_key put it into ciphertext crypt_key
#ifdef MMX_COEF
	shammx((unsigned char *) crypt_key, (unsigned char *) saved_key, total_len);
#else
	SHA1_Init( &ctx );
	SHA1_Update( &ctx, (unsigned char *) saved_key, strlen( saved_key ) );
	SHA1_Final( (unsigned char *) crypt_key, &ctx);
#endif
  
}

static void * rawsha1_binary(char *ciphertext) 
{
	static char realcipher[BINARY_SIZE];
	int i;
	
	for(i=0;i<BINARY_SIZE;i++)
	{
		realcipher[i] = atoi16[ARCH_INDEX(ciphertext[i*2])]*16 + atoi16[ARCH_INDEX(ciphertext[i*2+1])];
	}
	return (void *)realcipher;
}

static int binary_hash_0(void *binary)
{
	return ((ARCH_WORD_32 *)binary)[0] & 0xF;
}

static int binary_hash_1(void *binary)
{
	return ((ARCH_WORD_32 *)binary)[0] & 0xFF;
}

static int binary_hash_2(void *binary)
{
	return ((ARCH_WORD_32 *)binary)[0] & 0xFFF;
}

static int get_hash_0(int index)
{
	return ((ARCH_WORD_32 *)crypt_key)[index] & 0xF;
}

static int get_hash_1(int index)
{
	return ((ARCH_WORD_32 *)crypt_key)[index] & 0xFF;
}

static int get_hash_2(int index)
{
	return ((ARCH_WORD_32 *)crypt_key)[index] & 0xFFF;
}

struct fmt_main fmt_rawSHA1 = {
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
		rawsha1_tests
	}, {
		rawsha1_init,
		valid,
		fmt_default_split,
		rawsha1_binary,
		fmt_default_salt,
		{
			binary_hash_0,
			binary_hash_1,
			binary_hash_2,
			NULL,
			NULL
		},
		fmt_default_salt_hash,
		rawsha1_set_salt,
		rawsha1_set_key,
		rawsha1_get_key,
		fmt_default_clear_keys,
		rawsha1_crypt_all,
		{
			get_hash_0,
			get_hash_1,
			get_hash_2,
			NULL,
			NULL
		},
		rawsha1_cmp_all,
		rawsha1_cmp_one,
		rawsha1_cmp_exact
	}
};
