/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 2008 by Solar Designer
 */

#include <string.h>
#include <openssl/sha.h>

#include "arch.h"
#include "params.h"
#include "common.h"
#include "formats.h"

#define FORMAT_LABEL			"xsha"
#define FORMAT_NAME			"Mac OS X 10.4+ salted SHA-1"
#define ALGORITHM_NAME			"32/" ARCH_BITS_STR

#define BENCHMARK_COMMENT		""
#define BENCHMARK_LENGTH		0

#define PLAINTEXT_LENGTH		51
#define CIPHERTEXT_LENGTH		48

#define BINARY_SIZE			20
#define SALT_SIZE			4

#define MIN_KEYS_PER_CRYPT		1
#define MAX_KEYS_PER_CRYPT		1

static struct fmt_tests tests[] = {
	{"12345678F9083C7F66F46A0A102E4CC17EC08C8AF120571B", "abc"},
	{"12345678EB8844BFAF2A8CBDD587A37EF8D4A290680D5818", "azertyuiop1"},
	{"3234C32AAA335FD20E3F95870E5851BDBE942B79CE4FDD92", "azertyuiop2"},
	{"01295B67659E95F32931CEDB3BA50289E2826AF3D5A1422F", "apple"},
	{"0E6A48F765D0FFFFF6247FA80D748E615F91DD0C7431E4D9", "macintosh"},
	{"A320163F1E6DB42C3949F7E232888ACC7DB7A0A17E493DBA", "test"},
	{NULL}
};

static char saved_key[PLAINTEXT_LENGTH + 1];
static int saved_key_length;
static ARCH_WORD_32 saved_salt;
static SHA_CTX ctx;
static ARCH_WORD_32 crypt_out[5];

static int valid(char *ciphertext)
{
	char *pos;

	/* Require uppercase hex digits (assume ASCII) */
	pos = ciphertext;
	while (atoi16[ARCH_INDEX(*pos)] != 0x7F && *pos < 'a')
		pos++;
	return !*pos && pos - ciphertext == CIPHERTEXT_LENGTH;
}

static void *get_binary(char *ciphertext)
{
	static unsigned char out[BINARY_SIZE];
	char *p;
	int i;

	p = ciphertext + 8;
	for (i = 0; i < sizeof(out); i++) {
		out[i] =
		    (atoi16[ARCH_INDEX(*p)] << 4) |
		    atoi16[ARCH_INDEX(p[1])];
		p += 2;
	}

	return out;
}

static void *salt(char *ciphertext)
{
	static unsigned char out[SALT_SIZE];
	char *p;
	int i;

	p = ciphertext;
	for (i = 0; i < sizeof(out); i++) {
		out[i] =
		    (atoi16[ARCH_INDEX(*p)] << 4) |
		    atoi16[ARCH_INDEX(p[1])];
		p += 2;
	}

	return out;
}

static int binary_hash_0(void *binary)
{
	return *(ARCH_WORD_32 *)binary & 0xF;
}

static int binary_hash_1(void *binary)
{
	return *(ARCH_WORD_32 *)binary & 0xFF;
}

static int binary_hash_2(void *binary)
{
	return *(ARCH_WORD_32 *)binary & 0xFFF;
}

static int binary_hash_3(void *binary)
{
	return *(ARCH_WORD_32 *)binary & 0xFFFF;
}

static int binary_hash_4(void *binary)
{
	return *(ARCH_WORD_32 *)binary & 0xFFFFF;
}

static int get_hash_0(int index)
{
	return crypt_out[0] & 0xF;
}

static int get_hash_1(int index)
{
	return crypt_out[0] & 0xFF;
}

static int get_hash_2(int index)
{
	return crypt_out[0] & 0xFFF;
}

static int get_hash_3(int index)
{
	return crypt_out[0] & 0xFFFF;
}

static int get_hash_4(int index)
{
	return crypt_out[0] & 0xFFFFF;
}

static int salt_hash(void *salt)
{
	return *(ARCH_WORD_32 *)salt & 0x3FF;
}

static void set_salt(void *salt)
{
	saved_salt = *(ARCH_WORD_32 *)salt;
}

static void set_key(char *key, int index)
{
	saved_key_length = strlen(key);
	if (saved_key_length > PLAINTEXT_LENGTH)
		saved_key_length = PLAINTEXT_LENGTH;
	memcpy(saved_key, key, saved_key_length);
}

static char *get_key(int index)
{
	saved_key[saved_key_length] = 0;
	return saved_key;
}

static void crypt_all(int count)
{
	SHA1_Init(&ctx);
	SHA1_Update(&ctx, &saved_salt, SALT_SIZE);
	SHA1_Update(&ctx, saved_key, saved_key_length);
	SHA1_Final((unsigned char *)crypt_out, &ctx);
}

static int cmp_all(void *binary, int count)
{
	return !memcmp(binary, crypt_out, BINARY_SIZE);
}

static int cmp_exact(char *source, int index)
{
	return 1;
}

struct fmt_main fmt_XSHA = {
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
		tests
	}, {
		fmt_default_init,
		valid,
		fmt_default_split,
		get_binary,
		salt,
		{
			binary_hash_0,
			binary_hash_1,
			binary_hash_2,
			binary_hash_3,
			binary_hash_4
		},
		salt_hash,
		set_salt,
		set_key,
		get_key,
		fmt_default_clear_keys,
		crypt_all,
		{
			get_hash_0,
			get_hash_1,
			get_hash_2,
			get_hash_3,
			get_hash_4
		},
		cmp_all,
		cmp_all,
		cmp_exact
	}
};
