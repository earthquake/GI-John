/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-2001,2008,2010 by Solar Designer
 */

/*
 * OpenBSD-style Blowfish-based password hash implementation.
 */

#ifndef _JOHN_BF_STD_H
#define _JOHN_BF_STD_H

#include "arch.h"
#include "common.h"

typedef ARCH_WORD_32 BF_word;

/*
 * Binary salt type, also keeps the number of rounds.
 */
typedef BF_word BF_salt[4 + 1];

/*
 * Binary ciphertext type.
 */
typedef BF_word BF_binary[6];

#if BF_X2
#define BF_Nmin				2
#else
#define BF_Nmin				1
#endif

#if defined(_OPENMP) && !BF_ASM
#define BF_cpt				3
#define BF_mt				96
#define BF_N				(BF_Nmin * BF_mt)
#else
#define BF_mt				1
#define BF_N				BF_Nmin
#endif

/*
 * BF_std_crypt() output buffer.
 */
extern BF_binary BF_out[BF_N];

/*
 * ASCII to binary conversion table, for use in BF_fmt.valid().
 */
extern unsigned char BF_atoi64[0x80];

#if BF_X2
#define BF_ALGORITHM_NAME		"32/" ARCH_BITS_STR " X2"
#else
#define BF_ALGORITHM_NAME		"32/" ARCH_BITS_STR
#endif

/*
 * Sets a key for BF_std_crypt().
 */
extern void BF_std_set_key(char *key, int index);

/*
 * Main hashing routine, sets first two words of BF_out
 * (or all words in an OpenMP-enabled build).
 */
extern void BF_std_crypt(BF_salt salt, int n);

#if BF_mt == 1
/*
 * Calculates the rest of BF_out, for exact comparison.
 */
extern void BF_std_crypt_exact(int index);
#endif

/*
 * Returns the salt for BF_std_crypt().
 */
extern BF_word *BF_std_get_salt(char *ciphertext);

/*
 * Converts an ASCII ciphertext to binary.
 */
extern BF_word *BF_std_get_binary(char *ciphertext);

#endif
