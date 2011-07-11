/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-2001,2003,2006,2011 by Solar Designer
 *
 * This implementation of FreeBSD-style MD5-based crypt(3) password hashing
 * supports passwords of up to 15 characters long only since this lets us use a
 * significantly faster algorithm. -- SD
 */

#include <string.h>

#include "arch.h"
#include "common.h"
#include "MD5_std.h"

MD5_std_combined CC_CACHE_ALIGN MD5_std_all;

#if !MD5_IMM
static MD5_data MD5_data_init = {
	{
		0xd76aa477, 0xf8fa0bcc, 0xbcdb4dd9, 0xb18b7a77,
		0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
		0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
		0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
		0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
		0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
		0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
		0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
		0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
		0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
		0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
		0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
		0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
		0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
		0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
		0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
	}, {
		0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476
	}, {
		0x77777777, 0x00ff00ff
	}
};
#endif

#if !MD5_ASM

#define S11				7
#define S12				12
#define S13				17
#define S14				22
#define S21				5
#define S22				9
#define S23				14
#define S24				20
#define S31				4
#define S32				11
#define S33				16
#define S34				23
#define S41				6
#define S42				10
#define S43				15
#define S44				21

#if MD5_IMM

/*
 * Using immediate values is good for CISC.
 */

#define AC1				0xd76aa477
#define AC2pCd				0xf8fa0bcc
#define AC3pCc				0xbcdb4dd9
#define AC4pCb				0xb18b7a77
#define AC5				0xf57c0faf
#define AC6				0x4787c62a
#define AC7				0xa8304613
#define AC8				0xfd469501
#define AC9				0x698098d8
#define AC10				0x8b44f7af
#define AC11				0xffff5bb1
#define AC12				0x895cd7be
#define AC13				0x6b901122
#define AC14				0xfd987193
#define AC15				0xa679438e
#define AC16				0x49b40821
#define AC17				0xf61e2562
#define AC18				0xc040b340
#define AC19				0x265e5a51
#define AC20				0xe9b6c7aa
#define AC21				0xd62f105d
#define AC22				0x02441453
#define AC23				0xd8a1e681
#define AC24				0xe7d3fbc8
#define AC25				0x21e1cde6
#define AC26				0xc33707d6
#define AC27				0xf4d50d87
#define AC28				0x455a14ed
#define AC29				0xa9e3e905
#define AC30				0xfcefa3f8
#define AC31				0x676f02d9
#define AC32				0x8d2a4c8a
#define AC33				0xfffa3942
#define AC34				0x8771f681
#define AC35				0x6d9d6122
#define AC36				0xfde5380c
#define AC37				0xa4beea44
#define AC38				0x4bdecfa9
#define AC39				0xf6bb4b60
#define AC40				0xbebfbc70
#define AC41				0x289b7ec6
#define AC42				0xeaa127fa
#define AC43				0xd4ef3085
#define AC44				0x04881d05
#define AC45				0xd9d4d039
#define AC46				0xe6db99e5
#define AC47				0x1fa27cf8
#define AC48				0xc4ac5665
#define AC49				0xf4292244
#define AC50				0x432aff97
#define AC51				0xab9423a7
#define AC52				0xfc93a039
#define AC53				0x655b59c3
#define AC54				0x8f0ccc92
#define AC55				0xffeff47d
#define AC56				0x85845dd1
#define AC57				0x6fa87e4f
#define AC58				0xfe2ce6e0
#define AC59				0xa3014314
#define AC60				0x4e0811a1
#define AC61				0xf7537e82
#define AC62				0xbd3af235
#define AC63				0x2ad7d2bb
#define AC64				0xeb86d391

#define Ca				0x67452301
#define Cb				0xefcdab89
#define Cc				0x98badcfe
#define Cd				0x10325476

#define MASK1				0x77777777

#define OOFFOOFF			0x00ff00ff

#else

/*
 * If we used immediate values on RISC with 32-bit instruction size, it would
 * take about twice more instructions to load all the values.
 */

#define MD5_AC				MD5_std_all.data.AC
#define AC1				MD5_AC[0]
#define AC2pCd				MD5_AC[1]
#define AC3pCc				MD5_AC[2]
#define AC4pCb				MD5_AC[3]
#define AC5				MD5_AC[4]
#define AC6				MD5_AC[5]
#define AC7				MD5_AC[6]
#define AC8				MD5_AC[7]
#define AC9				MD5_AC[8]
#define AC10				MD5_AC[9]
#define AC11				MD5_AC[10]
#define AC12				MD5_AC[11]
#define AC13				MD5_AC[12]
#define AC14				MD5_AC[13]
#define AC15				MD5_AC[14]
#define AC16				MD5_AC[15]
#define AC17				MD5_AC[16]
#define AC18				MD5_AC[17]
#define AC19				MD5_AC[18]
#define AC20				MD5_AC[19]
#define AC21				MD5_AC[20]
#define AC22				MD5_AC[21]
#define AC23				MD5_AC[22]
#define AC24				MD5_AC[23]
#define AC25				MD5_AC[24]
#define AC26				MD5_AC[25]
#define AC27				MD5_AC[26]
#define AC28				MD5_AC[27]
#define AC29				MD5_AC[28]
#define AC30				MD5_AC[29]
#define AC31				MD5_AC[30]
#define AC32				MD5_AC[31]
#define AC33				MD5_AC[32]
#define AC34				MD5_AC[33]
#define AC35				MD5_AC[34]
#define AC36				MD5_AC[35]
#define AC37				MD5_AC[36]
#define AC38				MD5_AC[37]
#define AC39				MD5_AC[38]
#define AC40				MD5_AC[39]
#define AC41				MD5_AC[40]
#define AC42				MD5_AC[41]
#define AC43				MD5_AC[42]
#define AC44				MD5_AC[43]
#define AC45				MD5_AC[44]
#define AC46				MD5_AC[45]
#define AC47				MD5_AC[46]
#define AC48				MD5_AC[47]
#define AC49				MD5_AC[48]
#define AC50				MD5_AC[49]
#define AC51				MD5_AC[50]
#define AC52				MD5_AC[51]
#define AC53				MD5_AC[52]
#define AC54				MD5_AC[53]
#define AC55				MD5_AC[54]
#define AC56				MD5_AC[55]
#define AC57				MD5_AC[56]
#define AC58				MD5_AC[57]
#define AC59				MD5_AC[58]
#define AC60				MD5_AC[59]
#define AC61				MD5_AC[60]
#define AC62				MD5_AC[61]
#define AC63				MD5_AC[62]
#define AC64				MD5_AC[63]

#define MD5_IV				MD5_std_all.data.IV
#define Ca				MD5_IV[0]
#define Cb				MD5_IV[1]
#define Cc				MD5_IV[2]
#define Cd				MD5_IV[3]

#define MASK1				MD5_std_all.data.masks[0]

#define OOFFOOFF			MD5_std_all.data.masks[1]

#endif

/*
 * F, G, H and I are basic MD5 functions.
 */
#define F(x, y, z)			((z) ^ ((x) & ((y) ^ (z))))
#define G(x, y, z)			((y) ^ ((z) & ((x) ^ (y))))
#define H(x, y, z)			((x) ^ (y) ^ (z))
#define I(x, y, z)			((y) ^ ((x) | ~(z)))

/*
 * ROTATE_LEFT rotates x left n bits.
 */
#define ROTATE_LEFT(x, n) \
	(x) = (((x) << (n)) | ((MD5_word)(x) >> (32 - (n))))

/*
 * FF, GG, HH, and II transformations for rounds 1, 2, 3, and 4.
 * Rotation is separate from addition to prevent recomputation.
 */

#define FF(a, b, c, d, x, s, ac) \
	(a) += F ((b), (c), (d)) + (x) + (ac); \
	ROTATE_LEFT ((a), (s)); \
	(a) += (b);

#define GG(a, b, c, d, x, s, ac) \
	(a) += G ((b), (c), (d)) + (x) + (ac); \
	ROTATE_LEFT ((a), (s)); \
	(a) += (b);

#define HH(a, b, c, d, x, s, ac) \
	(a) += H ((b), (c), (d)) + (x) + (ac); \
	ROTATE_LEFT ((a), (s)); \
	(a) += (b);

#define II(a, b, c, d, x, s, ac) \
	(a) += I ((b), (c), (d)) + (x) + (ac); \
	ROTATE_LEFT ((a), (s)); \
	(a) += (b);

#if MD5_X2
static void MD5_body(MD5_word x0[15], MD5_word x1[15],
	MD5_word out0[4], MD5_word out1[4]);
#else
static void MD5_body(MD5_word x[15], MD5_word out[4]);
#endif

#else

extern void MD5_body(MD5_word x[15], MD5_word out[4]);

#endif

static unsigned char PADDING[56] = {
	0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

#if ARCH_LITTLE_ENDIAN

#define MD5_swap(x, y, count)

#else

static void MD5_swap(MD5_word *x, MD5_word *y, int count)
{
	MD5_word tmp, mask;

	mask = OOFFOOFF;
	do {
		tmp = *x++;
		ROTATE_LEFT(tmp, 16);
		*y++ = ((tmp & mask) << 8) | ((tmp >> 8) & mask);
	} while (--count);
}

#endif

#define order				MD5_std_all._order
#define pool				MD5_std_all._pool
#define block				MD5_std_all._block
#define prefix				MD5_std_all.prefix
#define prelen				MD5_std_all.prelen

static void init_line(int line, int index, MD5_block *even, MD5_block *odd)
{
	order[line][index].even = even;
	order[line][index].odd = odd;
}

void MD5_std_init(void)
{
	int index;
	MD5_pool *current;

#if !MD5_IMM
	MD5_std_all.data = MD5_data_init;
#endif

	for (index = 0, current = pool; index < MD5_N; index++, current++) {
		init_line(0, index, &current->e.p, &current->o.psp);
		init_line(1, index, &current->e.spp, &current->o.pp);
		init_line(2, index, &current->e.spp, &current->o.psp);
		init_line(3, index, &current->e.pp, &current->o.ps);
		init_line(4, index, &current->e.spp, &current->o.pp);
		init_line(5, index, &current->e.spp, &current->o.psp);
		init_line(6, index, &current->e.pp, &current->o.psp);
		init_line(7, index, &current->e.sp, &current->o.pp);
		init_line(8, index, &current->e.spp, &current->o.psp);
		init_line(9, index, &current->e.pp, &current->o.psp);
		init_line(10, index, &current->e.spp, &current->o.p);
		init_line(11, index, &current->e.spp, &current->o.psp);
		init_line(12, index, &current->e.pp, &current->o.psp);
		init_line(13, index, &current->e.spp, &current->o.pp);
		init_line(14, index, &current->e.sp, &current->o.psp);
		init_line(15, index, &current->e.pp, &current->o.psp);
		init_line(16, index, &current->e.spp, &current->o.pp);
		init_line(17, index, &current->e.spp, &current->o.ps);
		init_line(18, index, &current->e.pp, &current->o.psp);
		init_line(19, index, &current->e.spp, &current->o.pp);
		init_line(20, index, &current->e.spp, &current->o.psp);
	}
}

void MD5_std_set_salt(char *salt)
{
	int length;

	for (length = 0; length < 8 && salt[length]; length++);

	memcpy(pool[0].s, salt, pool[0].l.s = length);
#if MD5_X2
	memcpy(pool[1].s, salt, pool[1].l.s = length);
#endif

	if (salt[8]) {
		prefix = "$apr1$";
		prelen = 6;
	} else {
		prefix = "$1$";
		prelen = 3;
	}
}

void MD5_std_set_key(char *key, int index)
{
	int length;
	MD5_pool *current;

	for (length = 0; key[length] && length < 15; length++);
	current = &pool[index];

	memcpy(current->o.p.b, key, current->l.p = length);
	memcpy(&current->o.p.b[length + 16], PADDING, 40 - length);
	current->o.p.w[14] = (length + 16) << 3;

	memcpy(current->o.pp.b, key, length);
	memcpy(&current->o.pp.b[length], key, length);
	current->l.pp = length << 1;
	memcpy(&current->o.pp.b[current->l.pp + 16], PADDING,
		40 - current->l.pp);
	current->o.pp.w[14] = (current->l.pp + 16) << 3;

	memcpy(&current->e.p.b[16], key, length);
	memcpy(&current->e.p.b[16 + length], PADDING, 40 - length);
	current->e.p.w[14] = (length + 16) << 3;
	MD5_swap(current->e.p.w, current->e.p.w, 14);

	memcpy(&current->e.pp.b[16], current->o.pp.b, current->l.pp);
	memcpy(&current->e.pp.b[16 + current->l.pp], PADDING,
		40 - current->l.pp);
	current->e.pp.w[14] = (current->l.pp + 16) << 3;
	MD5_swap(current->e.pp.w, current->e.pp.w, 14);

	order[1][index].length = current->l.pp;
	order[4][index].length = current->l.pp;
	order[7][index].length = current->l.pp;
	order[10][index].length = length;
	order[13][index].length = current->l.pp;
	order[16][index].length = current->l.pp;
	order[19][index].length = current->l.pp;
}

void MD5_std_crypt(void)
{
	int length, index, mask;
	MD5_pattern *line;
#if ARCH_LITTLE_ENDIAN
	MD5_word *last0;
#endif
#if MD5_X2
	MD5_pool *key;
#if ARCH_LITTLE_ENDIAN
	MD5_word *last1;
#endif
#endif

#if MD5_X2
	for (index = 0, key = pool; index < MD5_N; index++, key++) {
#else
#define index	0
#define key	pool
#endif
		memcpy(key->o.ps.b, key->o.p.b, key->l.p);
		memcpy(&key->o.ps.b[key->l.p], key->s, key->l.s);
		key->l.ps = key->l.p + key->l.s;
		memcpy(&key->o.ps.b[key->l.ps + 16], PADDING,
			40 - key->l.ps);
		key->o.ps.w[14] = (key->l.ps + 16) << 3;

		memcpy(key->o.psp.b, key->o.ps.b, key->l.ps);
		memcpy(&key->o.psp.b[key->l.ps], key->o.p.b, key->l.p);
		key->l.psp = key->l.ps + key->l.p;
		memcpy(&key->o.psp.b[key->l.psp + 16], PADDING,
			40 - key->l.psp);
		key->o.psp.w[14] = (key->l.psp + 16) << 3;

		memcpy(&key->e.sp.b[16], key->s, key->l.s);
		memcpy(&key->e.sp.b[16 + key->l.s], key->o.p.b,
			key->l.p);
		memcpy(&key->e.sp.b[16 + key->l.ps], PADDING,
			40 - key->l.ps);
		key->e.sp.w[14] = (key->l.ps + 16) << 3;
		MD5_swap(key->e.sp.w, key->e.sp.w, 14);

		memcpy(&key->e.spp.b[16], key->s, key->l.s);
		memcpy(&key->e.spp.b[16 + key->l.s], key->o.pp.b,
			key->l.pp);
		memcpy(&key->e.spp.b[16 + key->l.psp], PADDING,
			40 - key->l.psp);
		key->e.spp.w[14] = (key->l.psp + 16) << 3;
		MD5_swap(key->e.spp.w, key->e.spp.w, 14);

		order[0][index].length = key->l.psp;
		order[2][index].length = key->l.psp;
		order[3][index].length = key->l.ps;
		order[5][index].length = key->l.psp;
		order[6][index].length = key->l.psp;
		order[8][index].length = key->l.psp;
		order[9][index].length = key->l.psp;
		order[11][index].length = key->l.psp;
		order[12][index].length = key->l.psp;
		order[14][index].length = key->l.psp;
		order[15][index].length = key->l.psp;
		order[17][index].length = key->l.ps;
		order[18][index].length = key->l.psp;
		order[20][index].length = key->l.psp;

		memcpy(&block[index], key->o.psp.b, key->l.psp);
		memcpy(&block[index].b[key->l.psp], PADDING, 56 - key->l.psp);
		block[index].w[14] = key->l.psp << 3;
		MD5_swap(block[index].w, block[index].w, 14);
#if MD5_X2
	}

	MD5_body(block[0].w, block[1].w, MD5_out[0], MD5_out[1]);
	MD5_swap(MD5_out[0], MD5_out[0], 8);
#else
	MD5_body(block[0].w, MD5_out[0]);
	MD5_swap(MD5_out[0], MD5_out[0], 4);
#endif

#if MD5_X2
	for (index = 0, key = pool; index < MD5_N; index++, key++) {
#endif
		memcpy(&block[index], key->o.p.b, key->l.p);
		memcpy(&block[index].b[key->l.p], prefix, prelen);
		memcpy(&block[index].b[key->l.p + prelen], key->s, key->l.s);
		memcpy(&block[index].b[key->l.ps + prelen],
			MD5_out[index], key->l.p);
		length = key->l.psp + prelen;
		if ((mask = key->l.p))
		do {
			block[index].b[length++] =
				(mask & 1) ? 0 : key->o.p.b[0];
		} while (mask >>= 1);
		memcpy(&block[index].b[length], PADDING, 56 - length);
		block[index].w[14] = length << 3;
		MD5_swap(block[index].w, block[index].w, 14);
#if MD5_X2
	}
#else
#undef index
#undef key
#endif

#if MD5_X2
	MD5_body(block[0].w, block[1].w,
		order[0][0].even->w, order[0][1].even->w);
#else
	MD5_body(block[0].w, order[0][0].even->w);
#endif

	index = 500; line = order[0];
	do {
#if ARCH_LITTLE_ENDIAN
#if ARCH_ALLOWS_UNALIGNED
#if MD5_X2
		MD5_body(line[0].even->w, line[1].even->w,
			(MD5_word *)&line[0].odd->b[line[0].length],
			(MD5_word *)&line[1].odd->b[line[1].length]);
#else
		MD5_body(line[0].even->w,
			(MD5_word *)&line[0].odd->b[line[0].length]);
#endif
#else
#if MD5_X2
		MD5_body(line[0].even->w, line[1].even->w,
			MD5_out[0], MD5_out[1]);
		memcpy(&line[0].odd->b[line[0].length], MD5_out[0], 16);
		memcpy(&line[1].odd->b[line[1].length], MD5_out[1], 16);
#else
		if (((ARCH_WORD)&line[0].odd->b[line[0].length]) & 3) {
			MD5_body(line[0].even->w, MD5_out[0]);
			memcpy(&line[0].odd->b[line[0].length],
				MD5_out[0], 16);
		} else {
			MD5_body(line[0].even->w,
				(MD5_word *)&line[0].odd->b[line[0].length]);
		}
#endif
#endif
		last0 = line[0].odd->w;
#if MD5_X2
		last1 = line[1].odd->w;
		if ((line += 2) > &order[20][MD5_N - 1]) line = order[0];
		MD5_body(last0, last1, line[0].even->w, line[1].even->w);
#else
		if (++line > &order[20][0]) line = order[0];
		MD5_body(last0, line[0].even->w);
#endif
#else
#if MD5_X2
		MD5_body(line[0].even->w, line[1].even->w,
			MD5_out[0], MD5_out[1]);
		MD5_swap(MD5_out[0], MD5_out[0], 8);
#else
		MD5_body(line[0].even->w, MD5_out[0]);
		MD5_swap(MD5_out[0], MD5_out[0], 4);
#endif
		memcpy(&line[0].odd->b[line[0].length], MD5_out[0], 16);
#if MD5_X2
		memcpy(&line[1].odd->b[line[1].length], MD5_out[1], 16);
#endif
		MD5_swap(line[0].odd->w, block[0].w, 14);
		block[0].w[14] = line[0].odd->w[14];
#if MD5_X2
		MD5_swap(line[1].odd->w, block[1].w, 14);
		block[1].w[14] = line[1].odd->w[14];
		if ((line += 2) > &order[20][MD5_N - 1]) line = order[0];
		MD5_body(block[0].w, block[1].w,
			line[0].even->w, line[1].even->w);
#else
		if (++line > &order[20][0]) line = order[0];
		MD5_body(block[0].w, line[0].even->w);
#endif
#endif
	} while (--index);

	memcpy(MD5_out[0], line[0].even, 16);
#if MD5_X2
	memcpy(MD5_out[1], line[1].even, 16);
#endif
}

#if !MD5_ASM

#if !MD5_X2

static void MD5_body(MD5_word x[15], MD5_word out[4])
{
	MD5_word a, b = Cb, c = Cc, d;

/* Round 1 */
	a = AC1 + x[0];
	ROTATE_LEFT (a, S11); a += b;			/* 1 */
	d = (c ^ (a & MASK1)) + x[1] + AC2pCd;
	ROTATE_LEFT (d, S12); d += a;			/* 2 */
	c = F(d, a, b) + x[2] + AC3pCc;
	ROTATE_LEFT(c, S13); c += d;			/* 3 */
	b = F(c, d, a) + x[3] + AC4pCb;
	ROTATE_LEFT(b, S14); b += c;			/* 4 */
	FF (a, b, c, d, x[ 4], S11, AC5);		/* 5 */
	FF (d, a, b, c, x[ 5], S12, AC6);		/* 6 */
	FF (c, d, a, b, x[ 6], S13, AC7);		/* 7 */
	FF (b, c, d, a, x[ 7], S14, AC8);		/* 8 */
	FF (a, b, c, d, x[ 8], S11, AC9);		/* 9 */
	FF (d, a, b, c, x[ 9], S12, AC10);		/* 10 */
	FF (c, d, a, b, x[10], S13, AC11);		/* 11 */
	FF (b, c, d, a, x[11], S14, AC12);		/* 12 */
	FF (a, b, c, d, x[12], S11, AC13);		/* 13 */
	FF (d, a, b, c, x[13], S12, AC14);		/* 14 */
	FF (c, d, a, b, x[14], S13, AC15);		/* 15 */
	b += F (c, d, a) + AC16;
	ROTATE_LEFT (b, S14); b += c;			/* 16 */

/* Round 2 */
	GG (a, b, c, d, x[ 1], S21, AC17);		/* 17 */
	GG (d, a, b, c, x[ 6], S22, AC18);		/* 18 */
	GG (c, d, a, b, x[11], S23, AC19);		/* 19 */
	GG (b, c, d, a, x[ 0], S24, AC20);		/* 20 */
	GG (a, b, c, d, x[ 5], S21, AC21);		/* 21 */
	GG (d, a, b, c, x[10], S22, AC22);		/* 22 */
	c += G (d, a, b) + AC23;
	ROTATE_LEFT (c, S23); c += d;			/* 23 */
	GG (b, c, d, a, x[ 4], S24, AC24);		/* 24 */
	GG (a, b, c, d, x[ 9], S21, AC25);		/* 25 */
	GG (d, a, b, c, x[14], S22, AC26);		/* 26 */
	GG (c, d, a, b, x[ 3], S23, AC27);		/* 27 */
	GG (b, c, d, a, x[ 8], S24, AC28);		/* 28 */
	GG (a, b, c, d, x[13], S21, AC29);		/* 29 */
	GG (d, a, b, c, x[ 2], S22, AC30);		/* 30 */
	GG (c, d, a, b, x[ 7], S23, AC31);		/* 31 */
	GG (b, c, d, a, x[12], S24, AC32);		/* 32 */

/* Round 3 */
	HH (a, b, c, d, x[ 5], S31, AC33);		/* 33 */
	HH (d, a, b, c, x[ 8], S32, AC34);		/* 34 */
	HH (c, d, a, b, x[11], S33, AC35);		/* 35 */
	HH (b, c, d, a, x[14], S34, AC36);		/* 36 */
	HH (a, b, c, d, x[ 1], S31, AC37);		/* 37 */
	HH (d, a, b, c, x[ 4], S32, AC38);		/* 38 */
	HH (c, d, a, b, x[ 7], S33, AC39);		/* 39 */
	HH (b, c, d, a, x[10], S34, AC40);		/* 40 */
	HH (a, b, c, d, x[13], S31, AC41);		/* 41 */
	HH (d, a, b, c, x[ 0], S32, AC42);		/* 42 */
	HH (c, d, a, b, x[ 3], S33, AC43);		/* 43 */
	HH (b, c, d, a, x[ 6], S34, AC44);		/* 44 */
	HH (a, b, c, d, x[ 9], S31, AC45);		/* 45 */
	HH (d, a, b, c, x[12], S32, AC46);		/* 46 */
	c += H (d, a, b) + AC47;
	ROTATE_LEFT (c, S33); c += d;			/* 47 */
	HH (b, c, d, a, x[ 2], S34, AC48);		/* 48 */

/* Round 4 */
	II (a, b, c, d, x[ 0], S41, AC49);		/* 49 */
	II (d, a, b, c, x[ 7], S42, AC50);		/* 50 */
	II (c, d, a, b, x[14], S43, AC51);		/* 51 */
	II (b, c, d, a, x[ 5], S44, AC52);		/* 52 */
	II (a, b, c, d, x[12], S41, AC53);		/* 53 */
	II (d, a, b, c, x[ 3], S42, AC54);		/* 54 */
	II (c, d, a, b, x[10], S43, AC55);		/* 55 */
	II (b, c, d, a, x[ 1], S44, AC56);		/* 56 */
	II (a, b, c, d, x[ 8], S41, AC57);		/* 57 */
	d += I (a, b, c) + AC58;
	ROTATE_LEFT (d, S42); d += a;			/* 58 */
	II (c, d, a, b, x[ 6], S43, AC59);		/* 59 */
	II (b, c, d, a, x[13], S44, AC60);		/* 60 */
	II (a, b, c, d, x[ 4], S41, AC61);		/* 61 */
	II (d, a, b, c, x[11], S42, AC62);		/* 62 */
	II (c, d, a, b, x[ 2], S43, AC63);		/* 63 */
	II (b, c, d, a, x[ 9], S44, AC64);		/* 64 */

	out[0] = Ca + a;
	out[1] = Cb + b;
	out[2] = Cc + c;
	out[3] = Cd + d;
}

#else

static void MD5_body(MD5_word x0[15], MD5_word x1[15],
	MD5_word out0[4], MD5_word out1[4])
{
	MD5_word a0, b0 = Cb, c0 = Cc, d0;
	MD5_word a1, b1, c1, d1;
	MD5_word u, v;

/* Round 1 */
	a0 = (u = AC1) + x0[0];
	ROTATE_LEFT (a0, S11); a0 += b0;		/* 1 */
	a1 = u + x1[0];
	ROTATE_LEFT (a1, S11); a1 += b0;		/* 1 */
	d0 = (c0 ^ (a0 & (u = MASK1))) + x0[1] + (v = AC2pCd);
	ROTATE_LEFT (d0, S12); d0 += a0;		/* 2 */
	d1 = (c0 ^ (a1 & u)) + x1[1] + v;
	ROTATE_LEFT (d1, S12); d1 += a1;		/* 2 */
	c0 = F(d0, a0, b0) + x0[2] + (u = AC3pCc);
	ROTATE_LEFT(c0, S13); c0 += d0;			/* 3 */
	c1 = F(d1, a1, b0) + x1[2] + u;
	ROTATE_LEFT(c1, S13); c1 += d1;			/* 3 */
	b0 = F(c0, d0, a0) + x0[3] + (u = AC4pCb);
	ROTATE_LEFT(b0, S14); b0 += c0;			/* 4 */
	b1 = F(c1, d1, a1) + x1[3] + u;
	ROTATE_LEFT(b1, S14); b1 += c1;			/* 4 */
	FF (a0, b0, c0, d0, x0[ 4], S11, (u = AC5));	/* 5 */
	FF (a1, b1, c1, d1, x1[ 4], S11, u);		/* 5 */
	FF (d0, a0, b0, c0, x0[ 5], S12, (u = AC6));	/* 6 */
	FF (d1, a1, b1, c1, x1[ 5], S12, u);		/* 6 */
	FF (c0, d0, a0, b0, x0[ 6], S13, (u = AC7));	/* 7 */
	FF (c1, d1, a1, b1, x1[ 6], S13, u);		/* 7 */
	FF (b0, c0, d0, a0, x0[ 7], S14, (u = AC8));	/* 8 */
	FF (b1, c1, d1, a1, x1[ 7], S14, u);		/* 8 */
	FF (a0, b0, c0, d0, x0[ 8], S11, (u = AC9));	/* 9 */
	FF (a1, b1, c1, d1, x1[ 8], S11, u);		/* 9 */
	FF (d0, a0, b0, c0, x0[ 9], S12, (u = AC10));	/* 10 */
	FF (d1, a1, b1, c1, x1[ 9], S12, u);		/* 10 */
	FF (c0, d0, a0, b0, x0[10], S13, (u = AC11));	/* 11 */
	FF (c1, d1, a1, b1, x1[10], S13, u);		/* 11 */
	FF (b0, c0, d0, a0, x0[11], S14, (u = AC12));	/* 12 */
	FF (b1, c1, d1, a1, x1[11], S14, u);		/* 12 */
	FF (a0, b0, c0, d0, x0[12], S11, (u = AC13));	/* 13 */
	FF (a1, b1, c1, d1, x1[12], S11, u);		/* 13 */
	FF (d0, a0, b0, c0, x0[13], S12, (u = AC14));	/* 14 */
	FF (d1, a1, b1, c1, x1[13], S12, u);		/* 14 */
	FF (c0, d0, a0, b0, x0[14], S13, (u = AC15));	/* 15 */
	FF (c1, d1, a1, b1, x1[14], S13, u);		/* 15 */
	b0 += F (c0, d0, a0) + (u = AC16);
	ROTATE_LEFT (b0, S14); b0 += c0;		/* 16 */
	b1 += F (c1, d1, a1) + u;
	ROTATE_LEFT (b1, S14); b1 += c1;		/* 16 */

/* Round 2 */
	GG (a0, b0, c0, d0, x0[ 1], S21, (u = AC17));	/* 17 */
	GG (a1, b1, c1, d1, x1[ 1], S21, u);		/* 17 */
	GG (d0, a0, b0, c0, x0[ 6], S22, (u = AC18));	/* 18 */
	GG (d1, a1, b1, c1, x1[ 6], S22, u);		/* 18 */
	GG (c0, d0, a0, b0, x0[11], S23, (u = AC19));	/* 19 */
	GG (c1, d1, a1, b1, x1[11], S23, u);		/* 19 */
	GG (b0, c0, d0, a0, x0[ 0], S24, (u = AC20));	/* 20 */
	GG (b1, c1, d1, a1, x1[ 0], S24, u);		/* 20 */
	GG (a0, b0, c0, d0, x0[ 5], S21, (u = AC21));	/* 21 */
	GG (a1, b1, c1, d1, x1[ 5], S21, u);		/* 21 */
	GG (d0, a0, b0, c0, x0[10], S22, (u = AC22));	/* 22 */
	GG (d1, a1, b1, c1, x1[10], S22, u);		/* 22 */
	c0 += G (d0, a0, b0) + (u = AC23);
	ROTATE_LEFT (c0, S23); c0 += d0;		/* 23 */
	c1 += G (d1, a1, b1) + u;
	ROTATE_LEFT (c1, S23); c1 += d1;		/* 23 */
	GG (b0, c0, d0, a0, x0[ 4], S24, (u = AC24));	/* 24 */
	GG (b1, c1, d1, a1, x1[ 4], S24, u);		/* 24 */
	GG (a0, b0, c0, d0, x0[ 9], S21, (u = AC25));	/* 25 */
	GG (a1, b1, c1, d1, x1[ 9], S21, u);		/* 25 */
	GG (d0, a0, b0, c0, x0[14], S22, (u = AC26));	/* 26 */
	GG (d1, a1, b1, c1, x1[14], S22, u);		/* 26 */
	GG (c0, d0, a0, b0, x0[ 3], S23, (u = AC27));	/* 27 */
	GG (c1, d1, a1, b1, x1[ 3], S23, u);		/* 27 */
	GG (b0, c0, d0, a0, x0[ 8], S24, (u = AC28));	/* 28 */
	GG (b1, c1, d1, a1, x1[ 8], S24, u);		/* 28 */
	GG (a0, b0, c0, d0, x0[13], S21, (u = AC29));	/* 29 */
	GG (a1, b1, c1, d1, x1[13], S21, u);		/* 29 */
	GG (d0, a0, b0, c0, x0[ 2], S22, (u = AC30));	/* 30 */
	GG (d1, a1, b1, c1, x1[ 2], S22, u);		/* 30 */
	GG (c0, d0, a0, b0, x0[ 7], S23, (u = AC31));	/* 31 */
	GG (c1, d1, a1, b1, x1[ 7], S23, u);		/* 31 */
	GG (b0, c0, d0, a0, x0[12], S24, (u = AC32));	/* 32 */
	GG (b1, c1, d1, a1, x1[12], S24, u);		/* 32 */

/* Round 3 */
	HH (a0, b0, c0, d0, x0[ 5], S31, (u = AC33));	/* 33 */
	HH (a1, b1, c1, d1, x1[ 5], S31, u);		/* 33 */
	HH (d0, a0, b0, c0, x0[ 8], S32, (u = AC34));	/* 34 */
	HH (d1, a1, b1, c1, x1[ 8], S32, u);		/* 34 */
	HH (c0, d0, a0, b0, x0[11], S33, (u = AC35));	/* 35 */
	HH (c1, d1, a1, b1, x1[11], S33, u);		/* 35 */
	HH (b0, c0, d0, a0, x0[14], S34, (u = AC36));	/* 36 */
	HH (b1, c1, d1, a1, x1[14], S34, u);		/* 36 */
	HH (a0, b0, c0, d0, x0[ 1], S31, (u = AC37));	/* 37 */
	HH (a1, b1, c1, d1, x1[ 1], S31, u);		/* 37 */
	HH (d0, a0, b0, c0, x0[ 4], S32, (u = AC38));	/* 38 */
	HH (d1, a1, b1, c1, x1[ 4], S32, u);		/* 38 */
	HH (c0, d0, a0, b0, x0[ 7], S33, (u = AC39));	/* 39 */
	HH (c1, d1, a1, b1, x1[ 7], S33, u);		/* 39 */
	HH (b0, c0, d0, a0, x0[10], S34, (u = AC40));	/* 40 */
	HH (b1, c1, d1, a1, x1[10], S34, u);		/* 40 */
	HH (a0, b0, c0, d0, x0[13], S31, (u = AC41));	/* 41 */
	HH (a1, b1, c1, d1, x1[13], S31, u);		/* 41 */
	HH (d0, a0, b0, c0, x0[ 0], S32, (u = AC42));	/* 42 */
	HH (d1, a1, b1, c1, x1[ 0], S32, u);		/* 42 */
	HH (c0, d0, a0, b0, x0[ 3], S33, (u = AC43));	/* 43 */
	HH (c1, d1, a1, b1, x1[ 3], S33, u);		/* 43 */
	HH (b0, c0, d0, a0, x0[ 6], S34, (u = AC44));	/* 44 */
	HH (b1, c1, d1, a1, x1[ 6], S34, u);		/* 44 */
	HH (a0, b0, c0, d0, x0[ 9], S31, (u = AC45));	/* 45 */
	HH (a1, b1, c1, d1, x1[ 9], S31, u);		/* 45 */
	HH (d0, a0, b0, c0, x0[12], S32, (u = AC46));	/* 46 */
	HH (d1, a1, b1, c1, x1[12], S32, u);		/* 46 */
	c0 += H (d0, a0, b0) + (u = AC47);
	ROTATE_LEFT (c0, S33); c0 += d0;		/* 47 */
	c1 += H (d1, a1, b1) + u;
	ROTATE_LEFT (c1, S33); c1 += d1;		/* 47 */
	HH (b0, c0, d0, a0, x0[ 2], S34, (u = AC48));	/* 48 */
	HH (b1, c1, d1, a1, x1[ 2], S34, u);		/* 48 */

/* Round 4 */
	II (a0, b0, c0, d0, x0[ 0], S41, (u = AC49));	/* 49 */
	II (a1, b1, c1, d1, x1[ 0], S41, u);		/* 49 */
	II (d0, a0, b0, c0, x0[ 7], S42, (u = AC50));	/* 50 */
	II (d1, a1, b1, c1, x1[ 7], S42, u);		/* 50 */
	II (c0, d0, a0, b0, x0[14], S43, (u = AC51));	/* 51 */
	II (c1, d1, a1, b1, x1[14], S43, u);		/* 51 */
	II (b0, c0, d0, a0, x0[ 5], S44, (u = AC52));	/* 52 */
	II (b1, c1, d1, a1, x1[ 5], S44, u);		/* 52 */
	II (a0, b0, c0, d0, x0[12], S41, (u = AC53));	/* 53 */
	II (a1, b1, c1, d1, x1[12], S41, u);		/* 53 */
	II (d0, a0, b0, c0, x0[ 3], S42, (u = AC54));	/* 54 */
	II (d1, a1, b1, c1, x1[ 3], S42, u);		/* 54 */
	II (c0, d0, a0, b0, x0[10], S43, (u = AC55));	/* 55 */
	II (c1, d1, a1, b1, x1[10], S43, u);		/* 55 */
	II (b0, c0, d0, a0, x0[ 1], S44, (u = AC56));	/* 56 */
	II (b1, c1, d1, a1, x1[ 1], S44, u);		/* 56 */
	II (a0, b0, c0, d0, x0[ 8], S41, (u = AC57));	/* 57 */
	II (a1, b1, c1, d1, x1[ 8], S41, u);		/* 57 */
	d0 += I (a0, b0, c0) + (u = AC58);
	ROTATE_LEFT (d0, S42); d0 += a0;		/* 58 */
	d1 += I (a1, b1, c1) + u;
	ROTATE_LEFT (d1, S42); d1 += a1;		/* 58 */
	II (c0, d0, a0, b0, x0[ 6], S43, (u = AC59));	/* 59 */
	II (c1, d1, a1, b1, x1[ 6], S43, u);		/* 59 */
	II (b0, c0, d0, a0, x0[13], S44, (u = AC60));	/* 60 */
	II (b1, c1, d1, a1, x1[13], S44, u);		/* 60 */
	II (a0, b0, c0, d0, x0[ 4], S41, (u = AC61));	/* 61 */
	II (a1, b1, c1, d1, x1[ 4], S41, u);		/* 61 */
	II (d0, a0, b0, c0, x0[11], S42, (u = AC62));	/* 62 */
	II (d1, a1, b1, c1, x1[11], S42, u);		/* 62 */
	II (c0, d0, a0, b0, x0[ 2], S43, (u = AC63));	/* 63 */
	II (c1, d1, a1, b1, x1[ 2], S43, u);		/* 63 */
	II (b0, c0, d0, a0, x0[ 9], S44, (u = AC64));	/* 64 */
	II (b1, c1, d1, a1, x1[ 9], S44, u);		/* 64 */

	out1[3] = Cd + d1;

	out0[0] = Ca + a0;
	out0[1] = Cb + b0;
	out0[2] = Cc + c0;
	out0[3] = Cd + d0;

	out1[0] = Ca + a1;
	out1[1] = Cb + b1;
	out1[2] = Cc + c1;
}

#endif

#endif

char *MD5_std_get_salt(char *ciphertext)
{
	static char out[9];
	char *p, *q;
	int i;

	p = ciphertext + 3;
	if ((out[8] = !strncmp(ciphertext, "$apr1$", 6)))
		p = ciphertext + 6;

	q = out;
	for (i = 0; *p != '$' && i < 8; i++)
		*q++ = *p++;
	while (i++ < 8)
		*q++ = 0;

	return out;
}

#define TO_BINARY(b1, b2, b3) \
	value = \
		(MD5_word)atoi64[ARCH_INDEX(pos[0])] | \
		((MD5_word)atoi64[ARCH_INDEX(pos[1])] << 6) | \
		((MD5_word)atoi64[ARCH_INDEX(pos[2])] << 12) | \
		((MD5_word)atoi64[ARCH_INDEX(pos[3])] << 18); \
	pos += 4; \
	out.b[b1] = value >> 16; \
	out.b[b2] = value >> 8; \
	out.b[b3] = value;

MD5_word *MD5_std_get_binary(char *ciphertext)
{
	static union {
		MD5_binary w;
		char b[16];
	} out;
	char *pos;
	MD5_word value;

	pos = ciphertext + 3;
	if (!strncmp(ciphertext, "$apr1$", 6))
		pos = ciphertext + 6;

	while (*pos++ != '$');

	TO_BINARY(0, 6, 12);
	TO_BINARY(1, 7, 13);
	TO_BINARY(2, 8, 14);
	TO_BINARY(3, 9, 15);
	TO_BINARY(4, 10, 5);
	out.b[11] =
		(MD5_word)atoi64[ARCH_INDEX(pos[0])] |
		((MD5_word)atoi64[ARCH_INDEX(pos[1])] << 6);

	MD5_swap(out.w, out.w, 4);

	return out.w;
}
