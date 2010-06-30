/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-2001,2010 by Solar Designer
 */

#include <string.h>

#include "arch.h"
#include "misc.h"
#include "DES_std.h"
#include "common.h"
#include "formats.h"

#define FORMAT_LABEL			"bsdi"
#define FORMAT_NAME			"BSDI DES"

#define BENCHMARK_COMMENT		" (x725)"
#define BENCHMARK_LENGTH		0

#define PLAINTEXT_LENGTH		64
#define CIPHERTEXT_LENGTH		20

static struct fmt_tests tests[] = {
	{"_J9..CCCCXBrJUJV154M", "U*U*U*U*"},
	{"_J9..CCCCXUhOBTXzaiE", "U*U***U"},
	{"_J9..CCCC4gQ.mB/PffM", "U*U***U*"},
	{"_J9..XXXXvlzQGqpPPdk", "*U*U*U*U"},
	{"_J9..XXXXsqM/YSSP..Y", "*U*U*U*U*"},
	{"_J9..XXXXVL7qJCnku0I", "*U*U*U*U*U*U*U*U"},
	{"_J9..XXXXAj8cFbP5scI", "*U*U*U*U*U*U*U*U*"},
	{"_J9..SDizh.vll5VED9g", "ab1234567"},
	{"_J9..SDizRjWQ/zePPHc", "cr1234567"},
	{"_J9..SDizxmRI1GjnQuE", "zxyDPWgydbQjgq"},
	{"_K9..SaltNrQgIYUAeoY", "726 even"},
	{"_J9..SDSD5YGyRCr4W4c", ""},
	{NULL}
};

#if DES_BS

#include "DES_bs.h"

#define ALGORITHM_NAME			DES_BS_ALGORITHM_NAME

#define BINARY_SIZE			ARCH_SIZE
#define SALT_SIZE			(ARCH_SIZE * 2)

#define MIN_KEYS_PER_CRYPT		DES_BS_DEPTH
#define MAX_KEYS_PER_CRYPT		DES_BS_DEPTH

#else

#define ALGORITHM_NAME			DES_STD_ALGORITHM_NAME

#define BINARY_SIZE			ARCH_SIZE
#define SALT_SIZE			(ARCH_SIZE * 2)

#define MIN_KEYS_PER_CRYPT		4
#define MAX_KEYS_PER_CRYPT		8

ARCH_WORD saved_salt, current_salt;

#endif

static int saved_count;

static struct {
#if !DES_BS
	union {
		double dummy;
		struct {
			DES_KS KS;
			DES_binary binary;
		} data;
	} aligned;
#endif
	char key[PLAINTEXT_LENGTH];
} buffer[MAX_KEYS_PER_CRYPT];

static void init(void)
{
	DES_std_init();

#if DES_BS
	DES_bs_init(0);

	DES_std_set_salt(0);
	DES_count = 1;
#else
	current_salt = -1;
#endif
}

static int valid(char *ciphertext)
{
	char *pos;

	if (ciphertext[0] != '_') return 0;

	for (pos = &ciphertext[1]; pos < &ciphertext[9]; pos++)
	if (!*pos) return 0;

	for (pos = &ciphertext[9]; atoi64[ARCH_INDEX(*pos)] != 0x7F; pos++);
	if (*pos || pos - ciphertext != CIPHERTEXT_LENGTH) return 0;

	if (atoi64[ARCH_INDEX(*(pos - 1))] & 3) return 0;

	return 1;
}

static void *salt(char *ciphertext)
{
	static ARCH_WORD out[2];

#if DES_BS
	out[0] = DES_raw_get_salt(ciphertext);
#else
	out[0] = DES_std_get_salt(ciphertext);
#endif
	out[1] = DES_raw_get_count(ciphertext);

	return out;
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
	saved_count = ((ARCH_WORD *)salt)[1];
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
	saved_salt = *(ARCH_WORD*)salt;
	saved_count = ((ARCH_WORD *)salt)[1];
}

#endif

static void set_key(char *key, int index)
{
	char *ptr, *chr;
	int pos, word;
	unsigned ARCH_WORD block[2];
	union {
		double dummy;
		DES_binary binary;
	} aligned;
	char chars[8];
#if DES_BS
	char *final = key;
#endif

	DES_std_set_key(key);

	for (pos = 0, ptr = key; pos < 8 && *ptr; pos++, ptr++);
	block[1] = block[0] = 0;

	while (*ptr) {
		ptr -= 8;
		for (word = 0; word < 2; word++)
		for (pos = 0; pos < 4; pos++)
			block[word] ^= (ARCH_WORD)*ptr++ << (1 + (pos << 3));

#if !DES_BS
		if (current_salt)
			DES_std_set_salt(current_salt = 0);
		DES_count = 1;
#endif

		DES_std_set_block(block[0], block[1]);
		DES_std_crypt(DES_KS_current, aligned.binary);
		DES_std_get_block(aligned.binary, block);

		chr = chars;
		for (word = 0; word < 2; word++)
		for (pos = 0; pos < 4; pos++) {
			*chr++ = 0x80 |
				((block[word] >> (1 + (pos << 3))) ^ *ptr);
			if (*ptr) ptr++;
		}

#if DES_BS
		final = chars;
		if (*ptr)
#endif
			DES_raw_set_key(chars);
	}

#if DES_BS
	DES_bs_set_key(final, index);
#else
	memcpy(buffer[index].aligned.data.KS, DES_KS_current, sizeof(DES_KS));
#endif
	strnfcpy(buffer[index].key, key, PLAINTEXT_LENGTH);
}

static char *get_key(int index)
{
	static char out[PLAINTEXT_LENGTH + 1];

	return strnzcpy(out, buffer[index].key, PLAINTEXT_LENGTH + 1);
}

#if DES_BS

static void crypt_all(int count)
{
	DES_bs_expand_keys();
	DES_bs_crypt(saved_count);
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

static void crypt_all(int count)
{
	int index;

	if (current_salt != saved_salt)
		DES_std_set_salt(current_salt = saved_salt);

	memset(DES_IV, 0, sizeof(DES_IV));
	DES_count = saved_count;

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

struct fmt_main fmt_BSDI = {
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
		init,
		valid,
		fmt_default_split,
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
		set_key,
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
