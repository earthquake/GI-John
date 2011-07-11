/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-2001,2005,2010 by Solar Designer
 */

#include <string.h>

#include "arch.h"
#include "misc.h"
#include "memory.h"
#include "DES_bs.h"
#include "common.h"
#include "formats.h"

#define FORMAT_LABEL			"lm"
#define FORMAT_NAME			"LM DES"

#define BENCHMARK_COMMENT		""
#define BENCHMARK_LENGTH		-1

#define PLAINTEXT_LENGTH		7
#define CIPHERTEXT_LENGTH		32

#define LM_EMPTY			"aad3b435b51404ee"

static struct fmt_tests tests[] = {
	{"$LM$a9c604d244c4e99d", "AAAAAA"},
	{"$LM$cbc501a4d2227783", "AAAAAAA"},
	{"$LM$3466c2b0487fe39a", "CRACKPO"},
	{"$LM$dbc5e5cba8028091", "IMPUNIT"},
	{LM_EMPTY LM_EMPTY, ""},
	{"$LM$73cc402bd3e79175", "SCLEROS"},
	{"$LM$5ecd9236d21095ce", "YOKOHAM"},
	{"$LM$A5E6066DE61C3E35", "ZZZZZZZ"}, /* uppercase encoding */
	{"$LM$1FB363feB834C12D", "ZZZZZZ"}, /* mixed case encoding */
	{NULL}
};

#define ALGORITHM_NAME			DES_BS_ALGORITHM_NAME

#define BINARY_SIZE			ARCH_SIZE
#define SALT_SIZE			0

#define MIN_KEYS_PER_CRYPT		DES_BS_DEPTH
#define MAX_KEYS_PER_CRYPT		DES_BS_DEPTH

static void init(void)
{
	DES_bs_init(1);
}

static int valid(char *ciphertext)
{
	char *pos;
	char lower[CIPHERTEXT_LENGTH - 16 + 1];

	for (pos = ciphertext; atoi16[ARCH_INDEX(*pos)] != 0x7F; pos++);
	if (!*pos && pos - ciphertext == CIPHERTEXT_LENGTH) {
		strcpy(lower, &ciphertext[16]);
		strlwr(lower);
		if (strcmp(lower, LM_EMPTY))
			return 2;
		else
			return 1;
	}

	if (strncmp(ciphertext, "$LM$", 4)) return 0;

	for (pos = &ciphertext[4]; atoi16[ARCH_INDEX(*pos)] != 0x7F; pos++);
	if (*pos || pos - ciphertext != 20) return 0;

	return 1;
}

static char *split(char *ciphertext, int index)
{
	static char out[21];

/* We don't just "return ciphertext" for already split hashes since we may
 * need to convert hashes stored by older versions of John to all-lowercase. */
	if (!strncmp(ciphertext, "$LM$", 4))
		ciphertext += 4;

	out[0] = '$';
	out[1] = 'L';
	out[2] = 'M';
	out[3] = '$';

	if (index)
		memcpy(&out[4], &ciphertext[16], 16);
	else
		memcpy(&out[4], ciphertext, 16);

	out[20] = 0;

	strlwr(&out[4]);

	return out;
}

static void *get_binary(char *ciphertext)
{
	return DES_bs_get_binary_LM(ciphertext + 4);
}

static int binary_hash_0(void *binary)
{
	return *(ARCH_WORD *)binary & 0xF;
}

static int binary_hash_1(void *binary)
{
	return *(ARCH_WORD *)binary & 0xFF;
}

static int binary_hash_2(void *binary)
{
	return *(ARCH_WORD *)binary & 0xFFF;
}

static int binary_hash_3(void *binary)
{
	return *(ARCH_WORD *)binary & 0xFFFF;
}

static int binary_hash_4(void *binary)
{
	return *(ARCH_WORD *)binary & 0xFFFFF;
}

static int get_hash_0(int index)
{
	return DES_bs_get_hash(index, 4);
}

static int get_hash_1(int index)
{
	return DES_bs_get_hash(index, 8);
}

static int get_hash_2(int index)
{
	return DES_bs_get_hash(index, 12);
}

static int get_hash_3(int index)
{
	return DES_bs_get_hash(index, 16);
}

static int get_hash_4(int index)
{
	return DES_bs_get_hash(index, 20);
}

static int cmp_all(void *binary, int count)
{
	return DES_bs_cmp_all((ARCH_WORD *)binary);
}

static int cmp_one(void *binary, int index)
{
	return DES_bs_cmp_one((ARCH_WORD *)binary, 32, index);
}

static int cmp_exact(char *source, int index)
{
	return DES_bs_cmp_one(get_binary(source), 64, index);
}

static char *get_key(int index)
{
#if !DES_BS_VECTOR && ARCH_BITS >= 64
	return (char *)DES_bs_all.E.extras.keys[index];
#else
	return (char *)DES_bs_all.keys[index];
#endif
}

struct fmt_main fmt_LM = {
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
		FMT_8_BIT | FMT_BS | FMT_SPLIT_UNIFIES_CASE,
		tests
	}, {
		init,
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
		DES_bs_set_key_LM,
		get_key,
		DES_bs_clear_keys_LM,
		(void (*)(int))DES_bs_crypt_LM,
		{
			get_hash_0,
			get_hash_1,
			get_hash_2,
			get_hash_3,
			get_hash_4
		},
		cmp_all,
		cmp_one,
		cmp_exact
	}
};
