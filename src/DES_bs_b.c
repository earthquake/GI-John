/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-2001,2003,2010 by Solar Designer
 */

#include "arch.h"

#if !DES_BS_ASM
#include "DES_bs.h"

#if defined(__ALTIVEC__) && DES_BS_DEPTH == 128
#undef DES_BS_VECTOR

#ifdef __linux__
#include <altivec.h>
#endif

typedef vector signed int vtype;

#define vst(dst, ofs, src) \
	vec_st((src), (ofs) * sizeof(DES_bs_vector), &(dst))

#define vxorf(a, b) \
	vec_xor((a), (b))

#define vnot(dst, a) \
	(dst) = vec_nor((a), (a))
#define vand(dst, a, b) \
	(dst) = vec_and((a), (b))
#define vor(dst, a, b) \
	(dst) = vec_or((a), (b))
#define vandn(dst, a, b) \
	(dst) = vec_andc((a), (b))
#define vxorn(dst, a, b) \
	(dst) = vec_xor((a), (b)); \
	(dst) = vec_nor((dst), (dst))
#define vnor(dst, a, b) \
	(dst) = vec_nor((a), (b))
#define vsel(dst, a, b, c) \
	(dst) = vec_sel((a), (b), (c))

#elif defined(__ALTIVEC__) && \
    ((ARCH_BITS == 64 && DES_BS_DEPTH == 192) || \
    (ARCH_BITS == 32 && DES_BS_DEPTH == 160))
#undef DES_BS_VECTOR

#ifdef __linux__
#include <altivec.h>
#endif

typedef struct {
	vector signed int f;
	ARCH_WORD g;
} vtype;

#define vst(dst, ofs, src) \
	vec_st((src).f, (ofs) * sizeof(DES_bs_vector), &((vtype *)&(dst))->f); \
	((vtype *)((DES_bs_vector *)&(dst) + (ofs)))->g = (src).g

#define vxor(dst, a, b) \
	(dst).f = vec_xor((a).f, (b).f); \
	(dst).g = (a).g ^ (b).g

#define vnot(dst, a) \
	(dst).f = vec_nor((a).f, (a).f); \
	(dst).g = ~(a).g
#define vand(dst, a, b) \
	(dst).f = vec_and((a).f, (b).f); \
	(dst).g = (a).g & (b).g
#define vor(dst, a, b) \
	(dst).f = vec_or((a).f, (b).f); \
	(dst).g = (a).g | (b).g
#define vandn(dst, a, b) \
	(dst).f = vec_andc((a).f, (b).f); \
	(dst).g = (a).g & ~(b).g
#define vxorn(dst, a, b) \
	(dst).f = vec_xor((a).f, (b).f); \
	(dst).f = vec_nor((dst).f, (dst).f); \
	(dst).g = ~((a).g ^ (b).g)
#define vnor(dst, a, b) \
	(dst).f = vec_nor((a).f, (b).f); \
	(dst).g = ~((a).g | (b).g)
#define vsel(dst, a, b, c) \
	(dst).f = vec_sel((a).f, (b).f, (c).f); \
	(dst).g = (((a).g & ~(c).g) ^ ((b).g & (c).g))

#elif defined(__ALTIVEC__) && DES_BS_DEPTH == 256
#undef DES_BS_VECTOR

#ifdef __linux__
#include <altivec.h>
#endif

typedef struct {
	vector signed int f, g;
} vtype;

#define vst(dst, ofs, src) \
	vec_st((src).f, (ofs) * sizeof(DES_bs_vector), &((vtype *)&(dst))->f); \
	vec_st((src).g, (ofs) * sizeof(DES_bs_vector), &((vtype *)&(dst))->g)

#define vxor(dst, a, b) \
	(dst).f = vec_xor((a).f, (b).f); \
	(dst).g = vec_xor((a).g, (b).g)

#define vnot(dst, a) \
	(dst).f = vec_nor((a).f, (a).f); \
	(dst).g = vec_nor((a).g, (a).g)
#define vand(dst, a, b) \
	(dst).f = vec_and((a).f, (b).f); \
	(dst).g = vec_and((a).g, (b).g)
#define vor(dst, a, b) \
	(dst).f = vec_or((a).f, (b).f); \
	(dst).g = vec_or((a).g, (b).g)
#define vandn(dst, a, b) \
	(dst).f = vec_andc((a).f, (b).f); \
	(dst).g = vec_andc((a).g, (b).g)
#define vxorn(dst, a, b) \
	(dst).f = vec_xor((a).f, (b).f); \
	(dst).g = vec_xor((a).g, (b).g); \
	(dst).f = vec_nor((dst).f, (dst).f); \
	(dst).g = vec_nor((dst).g, (dst).g)
#define vnor(dst, a, b) \
	(dst).f = vec_nor((a).f, (b).f); \
	(dst).g = vec_nor((a).g, (b).g)
#define vsel(dst, a, b, c) \
	(dst).f = vec_sel((a).f, (b).f, (c).f); \
	(dst).g = vec_sel((a).g, (b).g, (c).g)

#elif defined(__SSE2__) && DES_BS_DEPTH == 128
#undef DES_BS_VECTOR

#ifdef __GNUC__
#warning Notice: with recent versions of gcc, we are currently using SSE2 intrinsics instead of the supplied SSE2 assembly code.  This choice is made in the x86-*.h file.
#endif

#include <emmintrin.h>

typedef __m128i vtype;

#define vst(dst, ofs, src) \
	_mm_store_si128((vtype *)((DES_bs_vector *)&(dst) + (ofs)), (src))

#define vxorf(a, b) \
	_mm_xor_si128((a), (b))

#define vnot(dst, a) \
	(dst) = _mm_xor_si128((a), *(vtype *)&DES_bs_all.ones)
#define vand(dst, a, b) \
	(dst) = _mm_and_si128((a), (b))
#define vor(dst, a, b) \
	(dst) = _mm_or_si128((a), (b))
#define vandn(dst, a, b) \
	(dst) = _mm_andnot_si128((b), (a))
#define vxorn(dst, a, b) \
	(dst) = _mm_xor_si128(_mm_xor_si128((a), (b)), \
	    *(vtype *)&DES_bs_all.ones)

#elif defined(__SSE2__) && defined(__MMX__) && DES_BS_DEPTH == 192 && \
    !defined(DES_BS_NO_MMX)
#undef DES_BS_VECTOR

#include <emmintrin.h>
#include <mmintrin.h>

typedef struct {
	__m128i f;
	__m64 g;
} vtype;

#define vst(dst, ofs, src) \
	_mm_store_si128(&((vtype *)((DES_bs_vector *)&(dst) + (ofs)))->f, \
	    (src).f); \
	((vtype *)((DES_bs_vector *)&(dst) + (ofs)))->g = (src).g

#define vxor(dst, a, b) \
	(dst).f = _mm_xor_si128((a).f, (b).f); \
	(dst).g = _mm_xor_si64((a).g, (b).g)

#define vnot(dst, a) \
	(dst).f = _mm_xor_si128((a).f, ((vtype *)&DES_bs_all.ones)->f); \
	(dst).g = _mm_xor_si64((a).g, ((vtype *)&DES_bs_all.ones)->g)
#define vand(dst, a, b) \
	(dst).f = _mm_and_si128((a).f, (b).f); \
	(dst).g = _mm_and_si64((a).g, (b).g)
#define vor(dst, a, b) \
	(dst).f = _mm_or_si128((a).f, (b).f); \
	(dst).g = _mm_or_si64((a).g, (b).g)
#define vandn(dst, a, b) \
	(dst).f = _mm_andnot_si128((b).f, (a).f); \
	(dst).g = _mm_andnot_si64((b).g, (a).g)
#define vxorn(dst, a, b) \
	(dst).f = _mm_xor_si128(_mm_xor_si128((a).f, (b).f), \
	    (*(vtype *)&DES_bs_all.ones).f); \
	(dst).g = _mm_xor_si64(_mm_xor_si64((a).g, (b).g), \
	    (*(vtype *)&DES_bs_all.ones).g);

#elif defined(__SSE2__) && \
    ((ARCH_BITS == 64 && DES_BS_DEPTH == 192) || \
    (ARCH_BITS == 32 && DES_BS_DEPTH == 160))
#undef DES_BS_VECTOR

#include <emmintrin.h>

typedef struct {
	__m128i f;
	ARCH_WORD g;
} vtype;

#define vst(dst, ofs, src) \
	_mm_store_si128(&((vtype *)((DES_bs_vector *)&(dst) + (ofs)))->f, \
	    (src).f); \
	((vtype *)((DES_bs_vector *)&(dst) + (ofs)))->g = (src).g

#define vxor(dst, a, b) \
	(dst).f = _mm_xor_si128((a).f, (b).f); \
	(dst).g = (a).g ^ (b).g

#define vnot(dst, a) \
	(dst).f = _mm_xor_si128((a).f, ((vtype *)&DES_bs_all.ones)->f); \
	(dst).g = ~(a).g
#define vand(dst, a, b) \
	(dst).f = _mm_and_si128((a).f, (b).f); \
	(dst).g = (a).g & (b).g
#define vor(dst, a, b) \
	(dst).f = _mm_or_si128((a).f, (b).f); \
	(dst).g = (a).g | (b).g
#define vandn(dst, a, b) \
	(dst).f = _mm_andnot_si128((b).f, (a).f); \
	(dst).g = (a).g & ~(b).g
#define vxorn(dst, a, b) \
	(dst).f = _mm_xor_si128(_mm_xor_si128((a).f, (b).f), \
	    (*(vtype *)&DES_bs_all.ones).f); \
	(dst).g = ~((a).g ^ (b).g)

#elif defined(__SSE2__) && defined(__MMX__) && \
    ((ARCH_BITS == 64 && DES_BS_DEPTH == 256) || \
    (ARCH_BITS == 32 && DES_BS_DEPTH == 224))
#undef DES_BS_VECTOR

#include <emmintrin.h>
#include <mmintrin.h>

typedef struct {
	__m128i f;
	__m64 g;
	ARCH_WORD h;
} vtype;

#define vst(dst, ofs, src) \
	_mm_store_si128(&((vtype *)((DES_bs_vector *)&(dst) + (ofs)))->f, \
	    (src).f); \
	((vtype *)((DES_bs_vector *)&(dst) + (ofs)))->g = (src).g; \
	((vtype *)((DES_bs_vector *)&(dst) + (ofs)))->h = (src).h

#define vxor(dst, a, b) \
	(dst).f = _mm_xor_si128((a).f, (b).f); \
	(dst).g = _mm_xor_si64((a).g, (b).g); \
	(dst).h = (a).h ^ (b).h

#define vnot(dst, a) \
	(dst).f = _mm_xor_si128((a).f, ((vtype *)&DES_bs_all.ones)->f); \
	(dst).g = _mm_xor_si64((a).g, ((vtype *)&DES_bs_all.ones)->g); \
	(dst).h = ~(a).h
#define vand(dst, a, b) \
	(dst).f = _mm_and_si128((a).f, (b).f); \
	(dst).g = _mm_and_si64((a).g, (b).g); \
	(dst).h = (a).h & (b).h
#define vor(dst, a, b) \
	(dst).f = _mm_or_si128((a).f, (b).f); \
	(dst).g = _mm_or_si64((a).g, (b).g); \
	(dst).h = (a).h | (b).h
#define vandn(dst, a, b) \
	(dst).f = _mm_andnot_si128((b).f, (a).f); \
	(dst).g = _mm_andnot_si64((b).g, (a).g); \
	(dst).h = (a).h & ~(b).h
#define vxorn(dst, a, b) \
	(dst).f = _mm_xor_si128(_mm_xor_si128((a).f, (b).f), \
	    (*(vtype *)&DES_bs_all.ones).f); \
	(dst).g = _mm_xor_si64(_mm_xor_si64((a).g, (b).g), \
	    (*(vtype *)&DES_bs_all.ones).g); \
	(dst).h = ~((a).h ^ (b).h)

#elif defined(__MMX__) && ARCH_BITS != 64 && DES_BS_DEPTH == 64
#undef DES_BS_VECTOR

#include <mmintrin.h>

typedef __m64 vtype;

#define vxorf(a, b) \
	_mm_xor_si64((a), (b))

#define vnot(dst, a) \
	(dst) = _mm_xor_si64((a), *(vtype *)&DES_bs_all.ones)
#define vand(dst, a, b) \
	(dst) = _mm_and_si64((a), (b))
#define vor(dst, a, b) \
	(dst) = _mm_or_si64((a), (b))
#define vandn(dst, a, b) \
	(dst) = _mm_andnot_si64((b), (a))
#define vxorn(dst, a, b) \
	(dst) = _mm_xor_si64(_mm_xor_si64((a), (b)), \
	    *(vtype *)&DES_bs_all.ones)

#elif defined(__MMX__) && ARCH_BITS == 32 && DES_BS_DEPTH == 96
#undef DES_BS_VECTOR

#include <mmintrin.h>

typedef struct {
	__m64 f;
	ARCH_WORD g;
} vtype;

#define vst(dst, ofs, src) \
	((vtype *)((DES_bs_vector *)&(dst) + (ofs)))->f = (src).f; \
	((vtype *)((DES_bs_vector *)&(dst) + (ofs)))->g = (src).g

#define vxor(dst, a, b) \
	(dst).f = _mm_xor_si64((a).f, (b).f); \
	(dst).g = (a).g ^ (b).g

#define vnot(dst, a) \
	(dst).f = _mm_xor_si64((a).f, ((vtype *)&DES_bs_all.ones)->f); \
	(dst).g = ~(a).g
#define vand(dst, a, b) \
	(dst).f = _mm_and_si64((a).f, (b).f); \
	(dst).g = (a).g & (b).g
#define vor(dst, a, b) \
	(dst).f = _mm_or_si64((a).f, (b).f); \
	(dst).g = (a).g | (b).g
#define vandn(dst, a, b) \
	(dst).f = _mm_andnot_si64((b).f, (a).f); \
	(dst).g = (a).g & ~(b).g
#define vxorn(dst, a, b) \
	(dst).f = _mm_xor_si64(_mm_xor_si64((a).f, (b).f), \
	    (*(vtype *)&DES_bs_all.ones).f); \
	(dst).g = ~((a).g ^ (b).g)

#else

typedef ARCH_WORD vtype;

#define zero				0
#define ones				~(vtype)0

#define vxorf(a, b) \
	((a) ^ (b))

#define vnot(dst, a) \
	(dst) = ~(a)
#define vand(dst, a, b) \
	(dst) = (a) & (b)
#define vor(dst, a, b) \
	(dst) = (a) | (b)
#define vandn(dst, a, b) \
	(dst) = (a) & ~(b)
#define vxorn(dst, a, b) \
	(dst) = ~((a) ^ (b))

#endif

#ifndef vst
#define vst(dst, ofs, src) \
	*((vtype *)((DES_bs_vector *)&(dst) + (ofs))) = (src)
#endif

#if !defined(vxor) && defined(vxorf)
#define vxor(dst, a, b) \
	(dst) = vxorf((a), (b))
#endif
#if !defined(vxorf) && defined(vxor)
/*
 * This requires gcc's "Statement Exprs" extension (also supported by a number
 * of other C compilers).
 */
#define vxorf(a, b) \
	({ vtype tmp; vxor(tmp, (a), (b)); tmp; })
#endif

#ifdef __GNUC__
#if __GNUC__ > 3 || (__GNUC__ == 3 && __GNUC_MINOR__ >= 1)
#define MAYBE_INLINE __attribute__((always_inline))
#else
#define MAYBE_INLINE __inline__
#endif
#else
#define MAYBE_INLINE
#endif

/* Include the S-boxes here so that the compiler can inline them */
#if DES_BS == 3
#include "sboxes-s.c"
#elif DES_BS == 2
#include "sboxes.c"
#else
#include "nonstd.c"
#endif

#define b				DES_bs_all.B
#define e				DES_bs_all.E.E

#ifndef DES_BS_VECTOR
#define DES_BS_VECTOR			0
#endif

#if DES_BS_VECTOR
#define kd				[depth]
#define bd				[depth]
#define ed				[depth]
#define for_each_depth() \
	for (depth = 0; depth < DES_BS_VECTOR; depth++)
#else
#if DES_BS_EXPAND
#define kd
#else
#define kd				[0]
#endif
#define bd
#define ed				[0]
#define for_each_depth()
#endif

#define DES_bs_clear_block_8(i) \
	for_each_depth() { \
		vst(b[i] bd, 0, zero); \
		vst(b[i] bd, 1, zero); \
		vst(b[i] bd, 2, zero); \
		vst(b[i] bd, 3, zero); \
		vst(b[i] bd, 4, zero); \
		vst(b[i] bd, 5, zero); \
		vst(b[i] bd, 6, zero); \
		vst(b[i] bd, 7, zero); \
	}

#define DES_bs_clear_block() \
	DES_bs_clear_block_8(0); \
	DES_bs_clear_block_8(8); \
	DES_bs_clear_block_8(16); \
	DES_bs_clear_block_8(24); \
	DES_bs_clear_block_8(32); \
	DES_bs_clear_block_8(40); \
	DES_bs_clear_block_8(48); \
	DES_bs_clear_block_8(56);

#define DES_bs_set_block_8(i, v0, v1, v2, v3, v4, v5, v6, v7) \
	for_each_depth() { \
		vst(b[i] bd, 0, v0); \
		vst(b[i] bd, 1, v1); \
		vst(b[i] bd, 2, v2); \
		vst(b[i] bd, 3, v3); \
		vst(b[i] bd, 4, v4); \
		vst(b[i] bd, 5, v5); \
		vst(b[i] bd, 6, v6); \
		vst(b[i] bd, 7, v7); \
	}

#define x(p) vxorf(*(vtype *)&e[p] ed, *(vtype *)&k[p] kd)
#define y(p, q) vxorf(*(vtype *)&b[p] bd, *(vtype *)&k[q] kd)
#define z(r) ((vtype *)&b[r] bd)

void DES_bs_crypt(int count)
{
#if DES_BS_EXPAND
	DES_bs_vector *k;
#else
	ARCH_WORD **k;
#endif
	int iterations, rounds_and_swapped;
#if DES_BS_VECTOR
	int depth;
#endif

#ifndef zero
	vtype zero;
/* This may produce an "uninitialized" warning */
	vxor(zero, zero, zero);
#endif

	DES_bs_clear_block();

#if DES_BS_EXPAND
	k = DES_bs_all.KS.v;
#else
	k = DES_bs_all.KS.p;
#endif
	rounds_and_swapped = 8;
	iterations = count;

start:
	for_each_depth()
	s1(x(0), x(1), x(2), x(3), x(4), x(5),
		z(40), z(48), z(54), z(62));
	for_each_depth()
	s2(x(6), x(7), x(8), x(9), x(10), x(11),
		z(44), z(59), z(33), z(49));
	for_each_depth()
	s3(x(12), x(13), x(14), x(15), x(16), x(17),
		z(55), z(47), z(61), z(37));
	for_each_depth()
	s4(x(18), x(19), x(20), x(21), x(22), x(23),
		z(57), z(51), z(41), z(32));
	for_each_depth()
	s5(x(24), x(25), x(26), x(27), x(28), x(29),
		z(39), z(45), z(56), z(34));
	for_each_depth()
	s6(x(30), x(31), x(32), x(33), x(34), x(35),
		z(35), z(60), z(42), z(50));
	for_each_depth()
	s7(x(36), x(37), x(38), x(39), x(40), x(41),
		z(63), z(43), z(53), z(38));
	for_each_depth()
	s8(x(42), x(43), x(44), x(45), x(46), x(47),
		z(36), z(58), z(46), z(52));

	if (rounds_and_swapped == 0x100) goto next;

swap:
	for_each_depth()
	s1(x(48), x(49), x(50), x(51), x(52), x(53),
		z(8), z(16), z(22), z(30));
	for_each_depth()
	s2(x(54), x(55), x(56), x(57), x(58), x(59),
		z(12), z(27), z(1), z(17));
	for_each_depth()
	s3(x(60), x(61), x(62), x(63), x(64), x(65),
		z(23), z(15), z(29), z(5));
	for_each_depth()
	s4(x(66), x(67), x(68), x(69), x(70), x(71),
		z(25), z(19), z(9), z(0));
	for_each_depth()
	s5(x(72), x(73), x(74), x(75), x(76), x(77),
		z(7), z(13), z(24), z(2));
	for_each_depth()
	s6(x(78), x(79), x(80), x(81), x(82), x(83),
		z(3), z(28), z(10), z(18));
	for_each_depth()
	s7(x(84), x(85), x(86), x(87), x(88), x(89),
		z(31), z(11), z(21), z(6));
	for_each_depth()
	s8(x(90), x(91), x(92), x(93), x(94), x(95),
		z(4), z(26), z(14), z(20));

	k += 96;

	if (--rounds_and_swapped) goto start;
	k -= (0x300 + 48);
	rounds_and_swapped = 0x108;
	if (--iterations) goto swap;
	return;

next:
	k -= (0x300 - 48);
	rounds_and_swapped = 8;
	if (--iterations) goto start;
}

void DES_bs_crypt_25(void)
{
#if DES_BS_EXPAND
	DES_bs_vector *k;
#else
	ARCH_WORD **k;
#endif
	int iterations, rounds_and_swapped;
#if DES_BS_VECTOR
	int depth;
#endif

#ifndef zero
	vtype zero;
/* This may produce an "uninitialized" warning */
	vxor(zero, zero, zero);
#endif

	DES_bs_clear_block();

#if DES_BS_EXPAND
	k = DES_bs_all.KS.v;
#else
	k = DES_bs_all.KS.p;
#endif
	rounds_and_swapped = 8;
	iterations = 25;

start:
	for_each_depth()
	s1(x(0), x(1), x(2), x(3), x(4), x(5),
		z(40), z(48), z(54), z(62));
	for_each_depth()
	s2(x(6), x(7), x(8), x(9), x(10), x(11),
		z(44), z(59), z(33), z(49));
	for_each_depth()
	s3(y(7, 12), y(8, 13), y(9, 14),
		y(10, 15), y(11, 16), y(12, 17),
		z(55), z(47), z(61), z(37));
	for_each_depth()
	s4(y(11, 18), y(12, 19), y(13, 20),
		y(14, 21), y(15, 22), y(16, 23),
		z(57), z(51), z(41), z(32));
	for_each_depth()
	s5(x(24), x(25), x(26), x(27), x(28), x(29),
		z(39), z(45), z(56), z(34));
	for_each_depth()
	s6(x(30), x(31), x(32), x(33), x(34), x(35),
		z(35), z(60), z(42), z(50));
	for_each_depth()
	s7(y(23, 36), y(24, 37), y(25, 38),
		y(26, 39), y(27, 40), y(28, 41),
		z(63), z(43), z(53), z(38));
	for_each_depth()
	s8(y(27, 42), y(28, 43), y(29, 44),
		y(30, 45), y(31, 46), y(0, 47),
		z(36), z(58), z(46), z(52));

	if (rounds_and_swapped == 0x100) goto next;

swap:
	for_each_depth()
	s1(x(48), x(49), x(50), x(51), x(52), x(53),
		z(8), z(16), z(22), z(30));
	for_each_depth()
	s2(x(54), x(55), x(56), x(57), x(58), x(59),
		z(12), z(27), z(1), z(17));
	for_each_depth()
	s3(y(39, 60), y(40, 61), y(41, 62),
		y(42, 63), y(43, 64), y(44, 65),
		z(23), z(15), z(29), z(5));
	for_each_depth()
	s4(y(43, 66), y(44, 67), y(45, 68),
		y(46, 69), y(47, 70), y(48, 71),
		z(25), z(19), z(9), z(0));
	for_each_depth()
	s5(x(72), x(73), x(74), x(75), x(76), x(77),
		z(7), z(13), z(24), z(2));
	for_each_depth()
	s6(x(78), x(79), x(80), x(81), x(82), x(83),
		z(3), z(28), z(10), z(18));
	for_each_depth()
	s7(y(55, 84), y(56, 85), y(57, 86),
		y(58, 87), y(59, 88), y(60, 89),
		z(31), z(11), z(21), z(6));
	for_each_depth()
	s8(y(59, 90), y(60, 91), y(61, 92),
		y(62, 93), y(63, 94), y(32, 95),
		z(4), z(26), z(14), z(20));

	k += 96;

	if (--rounds_and_swapped) goto start;
	k -= (0x300 + 48);
	rounds_and_swapped = 0x108;
	if (--iterations) goto swap;
	return;

next:
	k -= (0x300 - 48);
	rounds_and_swapped = 8;
	iterations--;
	goto start;
}

#undef x

#undef kd
#if DES_BS_VECTOR
#define kd				[depth]
#else
#define kd				[0]
#endif

void DES_bs_crypt_LM(void)
{
	ARCH_WORD **k;
	int rounds;
#if DES_BS_VECTOR
	int depth;
#endif

#ifndef zero
	vtype zero, ones;
/* This may produce an "uninitialized" warning */
	vxor(zero, zero, zero);
	vnot(ones, zero);
#endif

	DES_bs_set_block_8(0, zero, zero, zero, zero, zero, zero, zero, zero);
	DES_bs_set_block_8(8, ones, ones, ones, zero, ones, zero, zero, zero);
	DES_bs_set_block_8(16, zero, zero, zero, zero, zero, zero, zero, ones);
	DES_bs_set_block_8(24, zero, zero, ones, zero, zero, ones, ones, ones);
	DES_bs_set_block_8(32, zero, zero, zero, ones, zero, ones, ones, ones);
	DES_bs_set_block_8(40, zero, zero, zero, zero, zero, ones, zero, zero);
	DES_bs_set_block_8(48, ones, ones, zero, zero, zero, zero, ones, zero);
	DES_bs_set_block_8(56, ones, zero, ones, zero, ones, ones, ones, ones);

	k = DES_bs_all.KS.p;
	rounds = 8;

	do {
		for_each_depth()
		s1(y(31, 0), y(0, 1), y(1, 2),
			y(2, 3), y(3, 4), y(4, 5),
			z(40), z(48), z(54), z(62));
		for_each_depth()
		s2(y(3, 6), y(4, 7), y(5, 8),
			y(6, 9), y(7, 10), y(8, 11),
			z(44), z(59), z(33), z(49));
		for_each_depth()
		s3(y(7, 12), y(8, 13), y(9, 14),
			y(10, 15), y(11, 16), y(12, 17),
			z(55), z(47), z(61), z(37));
		for_each_depth()
		s4(y(11, 18), y(12, 19), y(13, 20),
			y(14, 21), y(15, 22), y(16, 23),
			z(57), z(51), z(41), z(32));
		for_each_depth()
		s5(y(15, 24), y(16, 25), y(17, 26),
			y(18, 27), y(19, 28), y(20, 29),
			z(39), z(45), z(56), z(34));
		for_each_depth()
		s6(y(19, 30), y(20, 31), y(21, 32),
			y(22, 33), y(23, 34), y(24, 35),
			z(35), z(60), z(42), z(50));
		for_each_depth()
		s7(y(23, 36), y(24, 37), y(25, 38),
			y(26, 39), y(27, 40), y(28, 41),
			z(63), z(43), z(53), z(38));
		for_each_depth()
		s8(y(27, 42), y(28, 43), y(29, 44),
			y(30, 45), y(31, 46), y(0, 47),
			z(36), z(58), z(46), z(52));

		for_each_depth()
		s1(y(63, 48), y(32, 49), y(33, 50),
			y(34, 51), y(35, 52), y(36, 53),
			z(8), z(16), z(22), z(30));
		for_each_depth()
		s2(y(35, 54), y(36, 55), y(37, 56),
			y(38, 57), y(39, 58), y(40, 59),
			z(12), z(27), z(1), z(17));
		for_each_depth()
		s3(y(39, 60), y(40, 61), y(41, 62),
			y(42, 63), y(43, 64), y(44, 65),
			z(23), z(15), z(29), z(5));
		for_each_depth()
		s4(y(43, 66), y(44, 67), y(45, 68),
			y(46, 69), y(47, 70), y(48, 71),
			z(25), z(19), z(9), z(0));
		for_each_depth()
		s5(y(47, 72), y(48, 73), y(49, 74),
			y(50, 75), y(51, 76), y(52, 77),
			z(7), z(13), z(24), z(2));
		for_each_depth()
		s6(y(51, 78), y(52, 79), y(53, 80),
			y(54, 81), y(55, 82), y(56, 83),
			z(3), z(28), z(10), z(18));
		for_each_depth()
		s7(y(55, 84), y(56, 85), y(57, 86),
			y(58, 87), y(59, 88), y(60, 89),
			z(31), z(11), z(21), z(6));
		for_each_depth()
		s8(y(59, 90), y(60, 91), y(61, 92),
			y(62, 93), y(63, 94), y(32, 95),
			z(4), z(26), z(14), z(20));

		k += 96;
	} while (--rounds);
}
#endif
