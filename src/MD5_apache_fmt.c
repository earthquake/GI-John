/*
    Modified by Sun-Zero <sun-zero at freemail.hu>
    2004. 07. 26. 

    Now, its work with md5 hash of apache.
    The original john patch came from 
    http://lists.jammed.com/pen-test/2001/11/0134.html by
    Kostas Evangelinos (kos at bastard.net)
*/

/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-2001 by Solar Designer
 */

#include <string.h>

#include "arch.h"
#include "misc.h"
#include "MD5_std.h"
#include "common.h"
#include "formats.h"

#define FORMAT_LABEL			"md5a"
#define FORMAT_NAME			"Apache MD5"

#define BENCHMARK_COMMENT		""
#define BENCHMARK_LENGTH		-1

#define PLAINTEXT_LENGTH		15
#define CIPHERTEXT_LENGTH		22

#define BINARY_SIZE			4
#define SALT_SIZE			8

#define MIN_KEYS_PER_CRYPT		MD5_N
#define MAX_KEYS_PER_CRYPT		MD5_N


static struct fmt_tests tests[] = {
	{"$apr1$Q6ZYh...$RV6ft2bZ8j.NGrxLYaJt9.", "test"},
	{"$apr1$rBXqc...$NlXxN9myBOk95T0AyLAsJ0", "john"},
	{"$apr1$Grpld/..$qp5GyjwM2dnA5Cdej9b411", "the"},
	{"$apr1$GBx.D/..$yfVeeYFCIiEXInfRhBRpy/", "ripper"},
	{NULL}
};

static char saved_key[MD5_N][PLAINTEXT_LENGTH + 1];

static int valid(char *ciphertext)
{
	char *pos, *start;

	if (strncmp(ciphertext, "$apr1$", 6)) return 0;

        /* magic string */
        start = &ciphertext[1];
	for (pos = start; *pos && *pos != '$'; pos++);
    		if (!*pos || pos < start+1 || pos > start+MD5_MAGIC_LENGTH+1) 
		    return 0;

        /* salt */
        start = ++pos;
        for (pos = start; *pos && *pos != '$'; pos++);
    	    if (!*pos || pos < start || pos > start+8) 
		return 0;


	start = ++pos;
	while (atoi64[ARCH_INDEX(*pos)] != 0x7F) pos++;
	if (*pos || pos - start != CIPHERTEXT_LENGTH) return 0;

	if (atoi64[ARCH_INDEX(*(pos - 1))] & 0x3C) return 0;

	return 1;
}

static int binary_hash_0(void *binary)
{
	return *(MD5_word *)binary & 0xF;
}

static int binary_hash_1(void *binary)
{
	return *(MD5_word *)binary & 0xFF;
}

static int binary_hash_2(void *binary)
{
	return *(MD5_word *)binary & 0xFFF;
}

static int get_hash_0(int index)
{
	return MD5_out[index][0] & 0xF;
}

static int get_hash_1(int index)
{
	return MD5_out[index][0] & 0xFF;
}

static int get_hash_2(int index)
{
	return MD5_out[index][0] & 0xFFF;
}

static int salt_hash(void *salt)
{
	return
		((int)atoi64[ARCH_INDEX(((char *)salt)[0])] |
		((int)atoi64[ARCH_INDEX(((char *)salt)[1])] << 6)) & 0x3FF;
}

static void set_key(char *key, int index)
{
	MD5_std_set_key(key, index);

	strnfcpy(saved_key[index], key, PLAINTEXT_LENGTH);
}

static char *get_key(int index)
{
	saved_key[index][PLAINTEXT_LENGTH] = 0;

	return saved_key[index];
}

static int cmp_all(void *binary, int index)
{
#if MD5_X2
	return *(MD5_word *)binary == MD5_out[0][0] ||
		*(MD5_word *)binary == MD5_out[1][0];
#else
	return *(MD5_word *)binary == MD5_out[0][0];
#endif
}

static int cmp_exact(char *source, int index)
{
	return !memcmp(MD5_std_get_binary(source, MD5_TYPE_APACHE), MD5_out[index],
	    sizeof(MD5_binary));
}


static void crypt_all(int count) {
	MD5_std_crypt(MD5_TYPE_APACHE);
}

static void *get_salt(char *ciphertext) {
	return MD5_std_get_salt(ciphertext, MD5_TYPE_APACHE);
}

static void *get_binary(char *ciphertext) {
	return MD5_std_get_binary(ciphertext, MD5_TYPE_APACHE);
}

struct fmt_main fmt_MD5_apache = {
	{
		FORMAT_LABEL,
		FORMAT_NAME,
		MD5_ALGORITHM_NAME,
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
		MD5_std_init,
		valid,
		fmt_default_split,
		get_binary,		//(void *(*)(char *))MD5_std_get_binary,
		get_salt,  		//(void *(*)(char *))MD5_std_get_salt,
		{
			binary_hash_0,
			binary_hash_1,
			binary_hash_2,
			NULL,
			NULL
		},
		salt_hash,
		(void (*)(void *))MD5_std_set_salt,
		set_key,
		get_key,
		fmt_default_clear_keys,
		crypt_all,		//(void (*)(int))MD5_std_crypt,
		{
			get_hash_0,
			get_hash_1,
			get_hash_2,
			NULL,
			NULL
		},
		cmp_all,
		cmp_all,
		cmp_exact
	}
};
