/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-2002,2005,2006,2008,2010,2011 by Solar Designer
 *
 * ...with changes in the jumbo patch for mingw and MSC, by JimF.
 * ...and introduction of MMX_TYPE and MMX_COEF by Simon Marechal.
 * ...and NT_SSE2 by Alain Espinosa.
 */

/*
 * Architecture specific parameters for x86 with SSE2.
 */

#ifndef _JOHN_ARCH_H
#define _JOHN_ARCH_H

#define ARCH_WORD			long
#define ARCH_SIZE			4
#define ARCH_BITS			32
#define ARCH_BITS_LOG			5
#define ARCH_BITS_STR			"32"
#define ARCH_LITTLE_ENDIAN		1
#define ARCH_INT_GT_32			0
#define ARCH_ALLOWS_UNALIGNED		1
#define ARCH_INDEX(x)			((unsigned int)(unsigned char)(x))

#if defined(__CYGWIN32__) || defined(__BEOS__) || defined(__MINGW32__) || defined(_MSC_VER)
#define OS_TIMER			0
#else
#define OS_TIMER			1
#endif
#define OS_FLOCK			1

#if defined (_MSC_VER)
#define CPU_DETECT			0
#else
#define CPU_DETECT			1
#endif
#define CPU_REQ				1
#define CPU_NAME			"SSE2"
#ifndef CPU_FALLBACK
#define CPU_FALLBACK			0
#endif
#if CPU_FALLBACK
#define CPU_FALLBACK_BINARY		"john-non-sse"
#endif

#define DES_ASM				1
#define DES_128K			0
#define DES_X2				1
#define DES_MASK			1
#define DES_SCALE			0
#define DES_EXTB			0
#define DES_COPY			1
#define DES_STD_ALGORITHM_NAME		"48/64 4K MMX"
#define DES_BS				1
#if defined(__AVX__) && defined(__GNUC__)
/* Require gcc for AVX because DES_bs_all is aligned in a gcc-specific way */
#define DES_BS_ASM			0
#if 1
#define DES_BS_VECTOR			8
#if defined(__XOP__) && defined(__GNUC__)
/* Require gcc for 256-bit XOP because of __builtin_ia32_vpcmov_v8sf256() */
#undef DES_BS
#define DES_BS				3
#define DES_BS_ALGORITHM_NAME		"256/256 BS XOP"
#else
#define DES_BS_ALGORITHM_NAME		"256/256 BS AVX"
#endif
#else
#define DES_BS_VECTOR			4
#ifdef __XOP__
#undef DES_BS
#define DES_BS				3
#define DES_BS_ALGORITHM_NAME		"128/256 BS XOP"
#else
#define DES_BS_ALGORITHM_NAME		"128/256 BS AVX"
#endif
#endif
#elif defined(__SSE2__) && 0
#define DES_BS_ASM			0
#if 1
#define DES_BS_VECTOR			4
#define DES_BS_ALGORITHM_NAME		"128/128 BS SSE2"
#elif 0
#define DES_BS_VECTOR			6
#define DES_BS_VECTOR_SIZE		8
#define DES_BS_ALGORITHM_NAME		"128/128 BS SSE2 + 64/64 BS MMX"
#elif 0
#define DES_BS_VECTOR			5
#define DES_BS_VECTOR_SIZE		8
#define DES_BS_ALGORITHM_NAME		"128/128 BS SSE2 + 32/32 BS"
#else
#define DES_BS_VECTOR			7
#define DES_BS_VECTOR_SIZE		8
#define DES_BS_ALGORITHM_NAME		"128/128 BS SSE2 + 64/64 BS MMX + 32/32 BS"
#endif
#else
#define DES_BS_ASM			1
#define DES_BS_VECTOR			4
#define DES_BS_ALGORITHM_NAME		"128/128 BS SSE2"
#endif
#define DES_BS_EXPAND			1

#define MD5_ASM				1
#define MD5_X2				0
#define MD5_IMM				1

#ifdef _OPENMP
#define BF_ASM				0
#define BF_X2				1
#else
#define BF_ASM				1
#define BF_X2				0
#endif
#define BF_SCALE			1

#define MMX_TYPE			" SSE2"
#define MMX_COEF			4

#define NT_SSE2

#endif
