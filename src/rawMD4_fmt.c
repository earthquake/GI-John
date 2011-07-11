/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 2010 by Solar Designer
 */

#include <string.h>

#include "arch.h"
#include "params.h"
#include "common.h"
#include "formats.h"
#include "md4.h"

#define FORMAT_LABEL			"raw-md4"
#define FORMAT_NAME			"Raw MD4"
#define ALGORITHM_NAME			"32/" ARCH_BITS_STR

#define BENCHMARK_COMMENT		""
#define BENCHMARK_LENGTH		-1

#define PLAINTEXT_LENGTH		125
#define CIPHERTEXT_LENGTH		32

#define BINARY_SIZE			16
#define SALT_SIZE			0

#define MIN_KEYS_PER_CRYPT		1
#define MAX_KEYS_PER_CRYPT		1

static struct fmt_tests tests[] = {
	{"8a9d093f14f8701df17732b2bb182c74", "password"},
	{"$MD4$8a9d093f14f8701df17732b2bb182c74", "password"},
	{NULL}
};

static int saved_key_length;
static char saved_key[PLAINTEXT_LENGTH + 1];
static MD4_CTX ctx;
static ARCH_WORD_32 crypt_out[4];

static int valid(char *ciphertext)
{
	char *p, *q;

	p = ciphertext;
	if (!strncmp(p, "$MD4$", 5))
		p += 5;

	q = p;
	while (atoi16[ARCH_INDEX(*q)] != 0x7F) {
		if (*q >= 'A' && *q <= 'F') /* support lowercase only */
			return 0;
		q++;
	}
	return !*q && q - p == CIPHERTEXT_LENGTH;
}

static char *split(char *ciphertext, int index)
{
	static char out[5 + CIPHERTEXT_LENGTH + 1];

	if (!strncmp(ciphertext, "$MD4$", 5))
		return ciphertext;

	memcpy(out, "$MD4$", 5);
	memcpy(out + 5, ciphertext, CIPHERTEXT_LENGTH + 1);
	return out;
}

static void *get_binary(char *ciphertext)
{
	static unsigned char out[BINARY_SIZE];
	char *p;
	int i;

	p = ciphertext + 5;
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
	MD4_Init(&ctx);
	MD4_Update(&ctx, saved_key, saved_key_length);
	MD4_Final((unsigned char *)crypt_out, &ctx);
}

static int cmp_all(void *binary, int count)
{
	return !memcmp(binary, crypt_out, BINARY_SIZE);
}

static int cmp_exact(char *source, int index)
{
	return 1;
}

struct fmt_main fmt_rawMD4 = {
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
		split,
		get_binary,
		fmt_default_salt,
		{
			binary_hash_0,
			binary_hash_1,
			binary_hash_2,
			binary_hash_3,
			binary_hash_4
		},
		fmt_default_salt_hash,
		fmt_default_set_salt,
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
