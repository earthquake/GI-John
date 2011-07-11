/*
 * This software is Copyright © 2004 bartavelle, <bartavelle at bandecon.com>, and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without modification, are permitted. 
 *
 * microsoft MS SQL cracker
 * 
 */

#include <string.h>

#include "arch.h"
#include "misc.h"
#include "params.h"
#include "common.h"
#include "formats.h"
#include "sha.h"

#define FORMAT_LABEL			"mssql"
#define FORMAT_NAME			"MS-SQL"
#ifdef MMX_COEF
#if (MMX_COEF == 2)
#define ALGORITHM_NAME			"ms-sql MMX"
#else
#define ALGORITHM_NAME			"ms-sql SSE2"
#endif
#else
#define ALGORITHM_NAME			"ms-sql"
#endif

#ifdef MMX_TYPE
#define BENCHMARK_COMMENT		MMX_TYPE
#else
#define BENCHMARK_COMMENT		""
#endif
#define BENCHMARK_LENGTH		0

#define PLAINTEXT_LENGTH		20
#define CIPHERTEXT_LENGTH		94

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

static struct fmt_tests mssql_tests[] = {
	{"0x0100A607BA7C54A24D17B565C59F1743776A10250F581D482DA8B6D6261460D3F53B279CC6913CE747006A2E3254", "FOO"},
	{"0x01000508513EADDF6DB7DDD270CCA288BF097F2FF69CC2DB74FBB9644D6901764F999BAB9ECB80DE578D92E3F80D", "BAR"},
	{"0x01008408C523CF06DCB237835D701C165E68F9460580132E28ED8BC558D22CEDF8801F4503468A80F9C52A12C0A3", "CANARD"},
	{"0x0100BF088517935FC9183FE39FDEC77539FD5CB52BA5F5761881E5B9638641A79DBF0F1501647EC941F3355440A2", "LAPIN"},
	{NULL}
};

static unsigned char cursalt[SALT_SIZE];

#ifdef MMX_COEF
/* Cygwin would not guarantee the alignment if these were declared static */
#define saved_key mssql_saved_key
#define crypt_key mssql_crypt_key
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

static void mssql_set_salt(void *salt)
{
	memcpy(cursalt, salt, SALT_SIZE);
}

static void * mssql_get_salt(char * ciphertext)
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

static inline unsigned char upper(unsigned char c)
{
	if( (c>='a') && (c<='z'))
		return c+'A'-'a';
	return c;
}

static void mssql_init(void)
{
#ifdef MMX_COEF
	memset(saved_key, 0, 64*MMX_COEF);
#endif
}

static void mssql_set_key(char *key, int index) {
#ifdef MMX_COEF
	int len;
	int i;
	
	if(index==0)
	{
		total_len = 0;
		memset(saved_key, 0, 64*MMX_COEF);
	}
	len = strlen(key);
	if(len>PLAINTEXT_LENGTH)
		len = PLAINTEXT_LENGTH;

	total_len += (len*2) << ( ( (32/MMX_COEF) * index ) );
	for(i=0;i<len;i++)
	{
		saved_key[GETPOS((i*2), index)] = upper(key[i]);
		saved_key[GETPOS((i*2+1), index)] = 0;
	}
#else
	key_length = 0;
	while( (((unsigned short *)saved_key)[key_length] = upper(key[key_length]) ENDIAN_SHIFT_L ))
		key_length++;
#endif
}

static char *mssql_get_key(int index) {
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

static int mssql_cmp_all(void *binary, int index) { 
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

static int mssql_cmp_exact(char *source, int count){
  return (1);
}

static int mssql_cmp_one(void * binary, int index)
{
#ifdef MMX_COEF
	int i = 0;
	for(i=0;i<(BINARY_SIZE/4);i++)
		if ( ((unsigned long *)binary)[i] != ((unsigned long *)crypt_key)[i*MMX_COEF+index] )
			return 0;
	return 1;
#else
	return mssql_cmp_all(binary, index);
#endif
}

static void mssql_crypt_all(int count) {
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
	shammx( (unsigned char *) crypt_key, (unsigned char *) saved_key, total_len);
#else
	memcpy(saved_key+key_length*2, cursalt, SALT_SIZE);
	SHA1_Init( &ctx );
	SHA1_Update( &ctx, saved_key, key_length*2+SALT_SIZE );
	SHA1_Final( (unsigned char *) crypt_key, &ctx);
#endif
  
}

static void * mssql_binary(char *ciphertext) 
{
	static char realcipher[BINARY_SIZE];
	int i;
	
	for(i=0;i<BINARY_SIZE;i++)
	{
		realcipher[i] = atoi16[ARCH_INDEX(ciphertext[i*2+54])]*16 + atoi16[ARCH_INDEX(ciphertext[i*2+55])];
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

static int binary_hash_3(void *binary)
{
	return ((ARCH_WORD_32 *)binary)[0] & 0xFFFF;
}

static int binary_hash_4(void *binary)
{
	return ((ARCH_WORD_32 *)binary)[0] & 0xFFFFF;
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

static int get_hash_3(int index)
{
	return ((ARCH_WORD_32 *)crypt_key)[index] & 0xFFFF;
}

static int get_hash_4(int index)
{
	return ((ARCH_WORD_32 *)crypt_key)[index] & 0xFFFFF;
}

static int salt_hash(void *salt)
{
	return *((ARCH_WORD_32 *)salt) & (SALT_HASH_SIZE - 1);
}

struct fmt_main fmt_mssql = {
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
		mssql_tests
	}, {
		mssql_init,
		valid,
		fmt_default_split,
		mssql_binary,
		mssql_get_salt,
		{
			binary_hash_0,
			binary_hash_1,
			binary_hash_2,
			binary_hash_3,
			binary_hash_4
		},
		salt_hash,
		mssql_set_salt,
		mssql_set_key,
		mssql_get_key,
		fmt_default_clear_keys,
		mssql_crypt_all,
		{
			get_hash_0,
			get_hash_1,
			get_hash_2,
			get_hash_3,
			get_hash_4
		},
		mssql_cmp_all,
		mssql_cmp_one,
		mssql_cmp_exact
	}
};
