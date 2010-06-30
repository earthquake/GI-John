/*
 * Copyright (c) 2004 bartavelle
 * bartavelle at bandecon.com
 *
 * Modified by Mathieu Perrin (mathieu at tpfh.org) 09/06
 * Microsoft MS-SQL05 password cracker
 * 
 */

#include <string.h>

#include "arch.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "sha.h"

#define FORMAT_LABEL			"mssql05"
#define FORMAT_NAME			"MS-SQL05"
#ifdef MMX_COEF
#if (MMX_COEF == 2)
#define ALGORITHM_NAME			"ms-sql05 MMX"
#else
#define ALGORITHM_NAME			"ms-sql05 SSE2"
#endif
#else
#define ALGORITHM_NAME			"ms-sql05"
#endif

#ifdef MMX_TYPE
#define BENCHMARK_COMMENT		MMX_TYPE
#else
#define BENCHMARK_COMMENT		""
#endif
#define BENCHMARK_LENGTH		0

#define PLAINTEXT_LENGTH		20
#define CIPHERTEXT_LENGTH		54

#define BINARY_SIZE			20
#define SALT_SIZE			4

#ifdef MMX_COEF
#define MIN_KEYS_PER_CRYPT		MMX_COEF
#define MAX_KEYS_PER_CRYPT		MMX_COEF
//#define GETPOS(i, index)		( (index)*4 + ((i)& (0xffffffff-3) )*MMX_COEF + ((i)&3) ) //std getpos
#define GETPOS(i, index)		( (index)*4 + ((i)& (0xffffffff-3) )*MMX_COEF + (3-((i)&3)) ) //for endianity conversion
#else
#define MIN_KEYS_PER_CRYPT		1
#define MAX_KEYS_PER_CRYPT		1
#endif

//microsoft unicode ...
#if ARCH_LITTLE_ENDIAN
#define ENDIAN_SHIFT_L
#define ENDIAN_SHIFT_R
#else
#define ENDIAN_SHIFT_L  << 8
#define ENDIAN_SHIFT_R  >> 8
#endif

static struct fmt_tests mssql05_tests[] = {
	{"0x01004086CEB6BF932BC4151A1AF1F13CD17301D70816A8886908", "toto"},
	{"0x01004086CEB60ED526885801C23B366965586A43D3DEAC6DD3FD", "titi"},
	{NULL}
};

static unsigned char cursalt[SALT_SIZE];

#ifdef MMX_COEF
/* Cygwin would not guarantee the alignment if these were declared static */
#define saved_key mssql05_saved_key
#define crypt_key mssql05_crypt_key
char saved_key[80*4*MMX_COEF] __attribute__ ((aligned(16)));
char crypt_key[BINARY_SIZE*MMX_COEF] __attribute__ ((aligned(16)));
static unsigned long total_len;
static unsigned char out[PLAINTEXT_LENGTH + 1];
#else
static unsigned char saved_key[PLAINTEXT_LENGTH*2 + 1];
static ARCH_WORD_32 crypt_key[BINARY_SIZE / 4];
static SHA_CTX ctx;
static unsigned int key_length;
#endif

static int valid(char *ciphertext)
{
	int i;

	if (strlen(ciphertext) != CIPHERTEXT_LENGTH) return 0;
	if(memcmp(ciphertext, "0x0100", 6))
		return 0;
	for (i = 6; i < CIPHERTEXT_LENGTH; i++){
		if (!(  (('0' <= ciphertext[i])&&(ciphertext[i] <= '9')) ||
					(('a' <= ciphertext[i])&&(ciphertext[i] <= 'f'))  
					|| (('A' <= ciphertext[i])&&(ciphertext[i] <= 'F'))))
			return 0;
	}
	return 1;
}

static void mssql05_set_salt(void *salt)
{
	memcpy(cursalt, salt, SALT_SIZE);
}

static void * mssql05_get_salt(char * ciphertext)
{
	static unsigned char out2[SALT_SIZE];
	int l;

	for(l=0;l<SALT_SIZE;l++)
	{
		out2[l] = atoi16[ARCH_INDEX(ciphertext[l*2+6])]*16 
			+ atoi16[ARCH_INDEX(ciphertext[l*2+7])];
	}

	return out2;
}


static void mssql05_init(void)
{
#ifdef MMX_COEF
	memset(saved_key, 0, sizeof(saved_key));
#endif
}

static void mssql05_set_key(char *key, int index) {
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

	total_len += (len*2) << ( ( (32/MMX_COEF) * index ) );
	for(i=0;i<len;i++)
	{
		saved_key[GETPOS((i*2), index)] = key[i];
		saved_key[GETPOS((i*2+1), index)] = 0;
	}
#else
	key_length = 0;
	while( (((unsigned short *)saved_key)[key_length] = key[key_length] ENDIAN_SHIFT_L ))
		key_length++;
#endif
}

static char *mssql05_get_key(int index) {
#ifdef MMX_COEF
	unsigned int i,s;
	
	s = (total_len >> (((32/MMX_COEF)*(index)))) & 0xff;
	s = (s-4)/2;
	for(i=0;i<s;i++)
		out[i] = saved_key[ GETPOS(i*2, index) ];
	out[i] = 0;
	return (char *) out;
#else
	static char retkey[PLAINTEXT_LENGTH];
	int i;
	
	memset(retkey, 0, PLAINTEXT_LENGTH);
	for(i=0;i<key_length;i++)
		retkey[i] = ((unsigned short *)saved_key)[i] ENDIAN_SHIFT_R;
	return retkey;
#endif
}

static int mssql05_cmp_all(void *binary, int index) { 
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

static int mssql05_cmp_exact(char *source, int count){
  return (1);
}

static int mssql05_cmp_one(void * binary, int index)
{
#ifdef MMX_COEF
	int i = 0;
	for(i=0;i<(BINARY_SIZE/4);i++)
		if ( ((unsigned long *)binary)[i] != ((unsigned long *)crypt_key)[i*MMX_COEF+index] )
			return 0;
	return 1;
#else
	return mssql05_cmp_all(binary, index);
#endif
}

static void mssql05_crypt_all(int count) {
  // get plaintext input in saved_key put it into ciphertext crypt_key
#ifdef MMX_COEF
	unsigned i, index;
	for (index = 0; index < count; ++index)
	{
		unsigned len = (total_len >> ((32/MMX_COEF)*index)) & 0xFF;
		for(i=0;i<SALT_SIZE;i++)
			saved_key[GETPOS((len+i), index)] = cursalt[i];
		saved_key[GETPOS((len+SALT_SIZE) , index)] = 0x80;
		total_len += (SALT_SIZE) << ( ( (32/MMX_COEF) * index ) );
	}
	shammx((unsigned char *) crypt_key, (unsigned char *) saved_key, total_len);
#else
	memcpy(saved_key+key_length*2, cursalt, SALT_SIZE);
	SHA1_Init( &ctx );
	SHA1_Update( &ctx, saved_key, key_length*2+SALT_SIZE );
	SHA1_Final( (unsigned char *) crypt_key, &ctx);
#endif
  
}

static void * mssql05_binary(char *ciphertext) 
{
	static char realcipher[BINARY_SIZE];
	int i;
	
	for(i=0;i<BINARY_SIZE;i++)
	{
		realcipher[i] = atoi16[ARCH_INDEX(ciphertext[i*2+14])]*16 + atoi16[ARCH_INDEX(ciphertext[i*2+15])];
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

struct fmt_main fmt_mssql05 = {
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
		FMT_8_BIT,
		mssql05_tests
	}, {
		mssql05_init,
		valid,
		fmt_default_split,
		mssql05_binary,
		mssql05_get_salt,
		{
			binary_hash_0,
			binary_hash_1,
			binary_hash_2,
			NULL,
			NULL
		},
		fmt_default_salt_hash,
		mssql05_set_salt,
		mssql05_set_key,
		mssql05_get_key,
		fmt_default_clear_keys,
		mssql05_crypt_all,
		{
			get_hash_0,
			get_hash_1,
			get_hash_2,
			NULL,
			NULL
		},
		mssql05_cmp_all,
		mssql05_cmp_one,
		mssql05_cmp_exact
	}
};
