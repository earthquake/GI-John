/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 2003,2006,2008,2010 by Solar Designer
 *
 * ...with a trivial change in the jumbo patch, by Alain Espinosa.
 */

/*
 * Architecture specific parameters for x86-64.
 */

#ifndef _JOHN_ARCH_H
#define _JOHN_ARCH_H

#define ARCH_WORD			long
#define ARCH_SIZE			8
#define ARCH_BITS			64
#define ARCH_BITS_LOG			6
#define ARCH_BITS_STR			"64"
#define ARCH_LITTLE_ENDIAN		1
#define ARCH_INT_GT_32			0
#define ARCH_ALLOWS_UNALIGNED		1
#define ARCH_INDEX(x)			((unsigned int)(unsigned char)(x))

#define OS_TIMER			1
#define OS_FLOCK			1

#define CPU_DETECT			0

#define DES_ASM				0
#define DES_128K			0
#define DES_X2				0
#define DES_MASK			1
#define DES_SCALE			1
#define DES_EXTB			1
#define DES_COPY			0
#if defined(__SSE2__) && \
    ((__GNUC__ == 4 && __GNUC_MINOR__ >= 4) || __GNUC__ > 4)
#define DES_BS_ASM			0
#if 1
#define DES_BS_VECTOR			2
#define DES_BS_ALGORITHM_NAME		"128/128 BS SSE2-16"
#elif 0
#define DES_BS_VECTOR			3
#define DES_BS_VECTOR_SIZE		4
#define DES_BS_ALGORITHM_NAME		"128/128 BS SSE2-16 + 64/64 BS MMX"
#elif 0
#define DES_BS_NO_MMX
#define DES_BS_VECTOR			3
#define DES_BS_VECTOR_SIZE		4
#define DES_BS_ALGORITHM_NAME		"128/128 BS SSE2-16 + 64/64 BS"
#else
#define DES_BS_VECTOR			4
#define DES_BS_ALGORITHM_NAME		"128/128 BS SSE2-16 + 64/64 BS MMX + 64/64 BS"
#endif
#else
#define DES_BS_ASM			1
#define DES_BS_VECTOR			2
#define DES_BS_ALGORITHM_NAME		"128/128 BS SSE2-16"
#endif
#define DES_BS				1
#define DES_BS_EXPAND			1

#define MD5_ASM				0
#define MD5_X2				1
#define MD5_IMM				1

#define BF_ASM				0
#define BF_SCALE			1
#define BF_X2				1

#define NT_X86_64

#endif
