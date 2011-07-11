/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-2001,2010 by Solar Designer
 */

#include <string.h>

#include "arch.h"
#include "DES_std.h"
#include "common.h"
#include "formats.h"

#define FORMAT_LABEL			"des"
#define FORMAT_NAME			"Traditional DES"

#define BENCHMARK_COMMENT		""
#define BENCHMARK_LENGTH		0

#define PLAINTEXT_LENGTH		8
#define CIPHERTEXT_LENGTH_1		13
#define CIPHERTEXT_LENGTH_2		24

static struct fmt_tests tests[] = {
	{"CCNf8Sbh3HDfQ", "U*U*U*U*"},
	{"CCX.K.MFy4Ois", "U*U***U"},
	{"CC4rMpbg9AMZ.", "U*U***U*"},
	{"XXxzOu6maQKqQ", "*U*U*U*U"},
	{"SDbsugeBiC58A", ""},
	{NULL}
};

#if DES_BS

#include "DES_bs.h"

#define ALGORITHM_NAME			DES_BS_ALGORITHM_NAME

#define BINARY_SIZE			ARCH_SIZE
#define SALT_SIZE			ARCH_SIZE

#define MIN_KEYS_PER_CRYPT		DES_BS_DEPTH
#define MAX_KEYS_PER_CRYPT		DES_BS_DEPTH

#else

#define ALGORITHM_NAME			DES_STD_ALGORITHM_NAME

#define BINARY_SIZE			ARCH_SIZE
#define SALT_SIZE			ARCH_SIZE

#define MIN_KEYS_PER_CRYPT		0x40
#if DES_128K
#define MAX_KEYS_PER_CRYPT		0x100
#else
#define MAX_KEYS_PER_CRYPT		0x80
#endif

static struct {
	union {
		double dummy;
		struct {
			DES_KS KS;
			DES_binary binary;
		} data;
	} aligned;
	char key[PLAINTEXT_LENGTH];
} buffer[MAX_KEYS_PER_CRYPT];

#endif

#if DES_BS

static void init(void)
{
	DES_bs_init(0);
}

#endif

static int valid(char *ciphertext)
{
	char *pos;

	if (!ciphertext[0] || !ciphertext[1]) return 0;

	for (pos = &ciphertext[2]; atoi64[ARCH_INDEX(*pos)] != 0x7F; pos++);
	if (*pos && *pos != ',') return 0;

	if (atoi64[ARCH_INDEX(*(pos - 1))] & 3) return 0;

	switch (pos - ciphertext) {
	case CIPHERTEXT_LENGTH_1:
		return 1;

	case CIPHERTEXT_LENGTH_2:
		if (atoi64[ARCH_INDEX(ciphertext[12])] & 3) return 0;
		return 2;

	default:
		return 0;
	}
}

static char *split(char *ciphertext, int index)
{
	static char out[14];

	if (index) {
		memcpy(out, &ciphertext[2], 2);
		memcpy(&out[2], &ciphertext[13], 11);
	} else
		memcpy(out, ciphertext, 13);

	out[13] = 0;
	return out;
}

static void *salt(char *ciphertext)
{
	static ARCH_WORD out;

#if DES_BS
	out = DES_raw_get_salt(ciphertext);
#else
	out = DES_std_get_salt(ciphertext);
#endif

	return &out;
}

#if DES_BS

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

static int salt_hash(void *salt)
{
	return *(ARCH_WORD *)salt & 0x3FF;
}

static void set_salt(void *salt)
{
	DES_bs_set_salt(*(ARCH_WORD *)salt);
}

static void crypt_all(int count)
{
	DES_bs_expand_keys();
	DES_bs_crypt_25();
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
	return DES_bs_cmp_one(DES_bs_get_binary(source), 64, index);
}

#else

static int binary_hash_0(void *binary)
{
	return DES_STD_HASH_0(*(ARCH_WORD *)binary);
}

static int binary_hash_1(void *binary)
{
	return DES_STD_HASH_1(*(ARCH_WORD *)binary);
}

static int binary_hash_2(void *binary)
{
	return DES_STD_HASH_2(*(ARCH_WORD *)binary);
}

#define binary_hash_3 NULL
#define binary_hash_4 NULL

static int get_hash_0(int index)
{
	return DES_STD_HASH_0(buffer[index].aligned.data.binary[0]);
}

static int get_hash_1(int index)
{
	ARCH_WORD binary;

	binary = buffer[index].aligned.data.binary[0];
	return DES_STD_HASH_1(binary);
}

static int get_hash_2(int index)
{
	ARCH_WORD binary;

	binary = buffer[index].aligned.data.binary[0];
	return DES_STD_HASH_2(binary);
}

#define get_hash_3 NULL
#define get_hash_4 NULL

static int salt_hash(void *salt)
{
	return DES_STD_HASH_2(*(ARCH_WORD *)salt) & 0x3FF;
}

static void set_salt(void *salt)
{
	DES_std_set_salt(*(ARCH_WORD *)salt);
}

static void crypt_all(int count)
{
	int index;

	for (index = 0; index < count; index++)
		DES_std_crypt(buffer[index].aligned.data.KS,
			buffer[index].aligned.data.binary);
}

static int cmp_all(void *binary, int count)
{
	int index;

	for (index = 0; index < count; index++)
	if (*(unsigned ARCH_WORD *)binary ==
	    (buffer[index].aligned.data.binary[0] & DES_BINARY_MASK))
		return 1;

	return 0;
}

static int cmp_one(void *binary, int index)
{
	return *(unsigned ARCH_WORD *)binary ==
		(buffer[index].aligned.data.binary[0] & DES_BINARY_MASK);
}

static int cmp_exact(char *source, int index)
{
	ARCH_WORD *binary;
	int word;

	binary = DES_std_get_binary(source);

	for (word = 0; word < 16 / DES_SIZE; word++)
	if ((unsigned ARCH_WORD)binary[word] !=
	    (buffer[index].aligned.data.binary[word] & DES_BINARY_MASK))
		return 0;

	return 1;
}

#endif

#if !DES_BS
static void set_key(char *key, int index)
{
	DES_std_set_key(key);
	memcpy(buffer[index].aligned.data.KS, DES_KS_current, sizeof(DES_KS));
	memcpy(buffer[index].key, key, PLAINTEXT_LENGTH);
}
#endif

static char *get_key(int index)
{
	static char out[PLAINTEXT_LENGTH + 1];

#if DES_BS
	memcpy(out, DES_bs_all.keys[index], PLAINTEXT_LENGTH);
#else
	memcpy(out, buffer[index].key, PLAINTEXT_LENGTH);
#endif
	out[PLAINTEXT_LENGTH] = 0;

	return out;
}

struct fmt_main fmt_DES = {
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
#if DES_BS
		FMT_CASE | FMT_BS,
#else
		FMT_CASE,
#endif
		tests
	}, {
#if DES_BS
		init,
#else
		DES_std_init,
#endif
		valid,
		split,
		(void *(*)(char *))
#if DES_BS
			DES_bs_get_binary,
#else
			DES_std_get_binary,
#endif
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
#if DES_BS
		DES_bs_set_key,
#else
		set_key,
#endif
		get_key,
#if DES_BS
		DES_bs_clear_keys,
#else
		fmt_default_clear_keys,
#endif
		crypt_all,
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
