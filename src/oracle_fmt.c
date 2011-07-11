/*
 * Copyright (c) 2004 Simon Marechal
 * simon.marechal at thales-security.com
 */

#include <string.h>
#include <openssl/des.h>

#include "arch.h"
#include "misc.h"
#include "common.h"
#include "formats.h"

#define FORMAT_LABEL			"oracle"
#define FORMAT_NAME			"Oracle"
#define ALGORITHM_NAME			"oracle"

#define BENCHMARK_COMMENT		""
#define BENCHMARK_LENGTH		-1

#define PLAINTEXT_LENGTH		120

#define BINARY_SIZE			8
#define SALT_SIZE			(32 + 2)
#define CIPHERTEXT_LENGTH		16

#define MIN_KEYS_PER_CRYPT		1
#define MAX_KEYS_PER_CRYPT		1

static struct fmt_tests oracle_tests[] = {
	{"O$SYSTEM#9EEDFA0AD26C6D52", "THALES" },
	{"O$SIMON#4F8BC1809CB2AF77", "A"},
	{"O$SIMON#183D72325548EF11", "THALES2" },
	{"O$SIMON#C4EB3152E17F24A4", "TST" },
	{"O$BOB#b02c8e79ed2e7f46", "LAPIN" },
	{"O$BOB#6bb4e95898c88011", "LAPINE" },
	{"O$BOB#cdc6b483874b875b", "GLOUGLOU" },
	{"O$BOB#ef1f9139db2d5279", "GLOUGLOUTER" },
	{"O$BOB#c0ee5107c9a080c1", "AZERTYUIOP" },
	{"O$BOB#99e8b231d33772f9", "CANARDWC" },
	{"O$BOB#da3224126a67c8ed", "COUCOU_COUCOU" },
	{"O$BOB#ec8147abb3373d53", "LONG_MOT_DE_PASSE_OUI" },
	{NULL}
};

#if ARCH_LITTLE_ENDIAN
#define ENDIAN_SHIFT_L  << 8
#define ENDIAN_SHIFT_R  >> 8
#else
#define ENDIAN_SHIFT_L
#define ENDIAN_SHIFT_R
#endif

static ARCH_WORD_32 crypt_key[2];

static unsigned short cur_salt[SALT_SIZE / 2 + PLAINTEXT_LENGTH];
static unsigned short cur_key[PLAINTEXT_LENGTH + 1];

static DES_key_schedule desschedule1;
static DES_key_schedule desschedule2;

static int salt_length;
static int key_length;

static int valid(char *ciphertext)
{
	int i;
	int l;

	/*
	 * 2 cases
	 * 1 - it comes from the disk, and does not have O$ + salt
	 * 2 - it comes from memory, and has got O$ + salt + # + blah
	 */

	if (!memcmp(ciphertext, "O$", 2))
	{
		l = strlen(ciphertext) - CIPHERTEXT_LENGTH;
		if(ciphertext[l-1]!='#')
			return 0;
	}
	else
	{
		if(strlen(ciphertext)!=CIPHERTEXT_LENGTH)
			return 0;
		l = 0;
	}
	for (i = l; i < l + CIPHERTEXT_LENGTH; i++){
		if (!(  (('0' <= ciphertext[i])&&(ciphertext[i] <= '9')) ||
			(('a' <= ciphertext[i])&&(ciphertext[i] <= 'f'))
			|| (('A' <= ciphertext[i])&&(ciphertext[i] <= 'F'))))
			return 0;
	}
	
	return 1;
}

static void oracle_init(void)
{
	unsigned char deskey[8];

	deskey[0] = 0x01;
	deskey[1] = 0x23;
	deskey[2] = 0x45;
	deskey[3] = 0x67;
	deskey[4] = 0x89;
	deskey[5] = 0xab;
	deskey[6] = 0xcd;
	deskey[7] = 0xef;

	DES_set_key((DES_cblock *)deskey, &desschedule1);
}

static inline unsigned char upper(unsigned char c)
{
	if( (c>='a') && (c<='z'))
		return c+'A'-'a';
	return c;
}

static void oracle_set_salt(void *salt) {
	salt_length = *(unsigned short *)salt;
	memcpy(cur_salt, (char *)salt+2, salt_length);
}

static void oracle_set_key(char *key, int index) {
	key_length = 0;
	while( (cur_key[key_length] = upper(key[key_length]) ENDIAN_SHIFT_L ))
		key_length++;
	key_length <<= 1;
}

static char *oracle_get_key(int index) {
	static unsigned char out[PLAINTEXT_LENGTH + 1];
	unsigned int i;
	for(i=0;i<key_length>>1;i++)
		out[i] = cur_key[i] ENDIAN_SHIFT_R;
	out[i] = 0;
	return (char *) out;
}

static void oracle_crypt_all(int count)
{
	unsigned char buf[sizeof(cur_salt)];
	unsigned int l;

	l = salt_length + key_length;
	crypt_key[0] = 0;
	crypt_key[1] = 0;
	memcpy((char *)cur_salt + salt_length, cur_key, key_length);
	DES_ncbc_encrypt((unsigned char *)cur_salt, buf, l, &desschedule1, (DES_cblock *) crypt_key, DES_ENCRYPT);
	DES_set_key((DES_cblock *)crypt_key, &desschedule2);
	crypt_key[0] = 0;
	crypt_key[1] = 0;
	DES_ncbc_encrypt((unsigned char *)cur_salt, buf, l, &desschedule2, (DES_cblock *) crypt_key, DES_ENCRYPT);
}

static void * oracle_binary(char *ciphertext)
{
	static unsigned char out3[BINARY_SIZE];
	int l;
	int i;
	l = strlen(ciphertext) - CIPHERTEXT_LENGTH;
	for(i=0;i<BINARY_SIZE;i++)
	{
		out3[i] = atoi16[ARCH_INDEX(ciphertext[i*2+l])]*16
			+ atoi16[ARCH_INDEX(ciphertext[i*2+l+1])];
	}
	return out3;
}

static void * oracle_get_salt(char * ciphertext)
{
	static unsigned short out[SALT_SIZE / 2];
	unsigned char salt[SALT_SIZE + 1];
	int l;

	l = 2;
	while( ciphertext[l] && (ciphertext[l]!='#') )
	{
		salt[l-2] = ciphertext[l];
		l++;
		if (l-2 >= SALT_SIZE-2) break;
	}
	salt[l-2] = 0;

	l = 0;
	while ((out[l+1] = upper(salt[l]) ENDIAN_SHIFT_L))
		l++;
	out[0] = l*2;

	return out;
}

static int binary_hash1(void * binary) { return (((ARCH_WORD_32 *)binary)[0] & 0xf); }
static int binary_hash2(void * binary) { return (((ARCH_WORD_32 *)binary)[0] & 0xff); }
static int binary_hash3(void * binary) { return (((ARCH_WORD_32 *)binary)[0] & 0xfff); }

static int get_hash1(int index) { return crypt_key[0] & 0xf; }
static int get_hash2(int index) { return crypt_key[0] & 0xff; }
static int get_hash3(int index) { return crypt_key[0] & 0xfff; }

static int oracle_cmp_all(void *binary, int index) {
	return !memcmp(binary, crypt_key, sizeof(crypt_key));
}

static int oracle_cmp_exact(char *source, int count) {
	return 1;
}

struct fmt_main fmt_oracle = {
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
		oracle_tests
	}, {
		oracle_init,
		valid,
		fmt_default_split,
		oracle_binary,
		oracle_get_salt,
		{
			binary_hash1,
			binary_hash2,
			binary_hash3,
			NULL,
			NULL
		},
		fmt_default_salt_hash,
		oracle_set_salt,
		oracle_set_key,
		oracle_get_key,
		fmt_default_clear_keys,
		oracle_crypt_all,
		{
			get_hash1,
			get_hash2,
			get_hash3,
			NULL,
			NULL
		},
		oracle_cmp_all,
		oracle_cmp_all,
		oracle_cmp_exact
	}
};
