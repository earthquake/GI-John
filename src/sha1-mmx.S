
// extern int mdfourmmx(unsigned char *out, unsigned char *in, int n) __attribute__((regparm(3)));

#include "arch.h"
#ifdef UNDERSCORES
#define shammx	_shammx
#define shammx_nosizeupdate _shammx_nosizeupdate
#define shammx_noinit_uniformsizeupdate _shammx_noinit_uniformsizeupdate
#endif

.globl shammx;
.globl shammx_nosizeupdate;
.globl shammx_noinit_uniformsizeupdate;

.data
.align(2*MMX_COEF)
const_init_a:
.long 0x67452301
.long 0x67452301
#if (MMX_COEF>=4)
.long 0x67452301
.long 0x67452301
#endif
const_init_b:
.long 0xefcdab89
.long 0xefcdab89
#if (MMX_COEF>=4)
.long 0xefcdab89
.long 0xefcdab89
#endif
const_init_c:
.long 0x98badcfe
.long 0x98badcfe
#if (MMX_COEF>=4)
.long 0x98badcfe
.long 0x98badcfe
#endif
const_init_d:
.long 0x10325476
.long 0x10325476
#if (MMX_COEF>=4)
.long 0x10325476
.long 0x10325476
#endif
const_init_e:
.long 0xc3d2e1f0
.long 0xc3d2e1f0
#if (MMX_COEF>=4)
.long 0xc3d2e1f0
.long 0xc3d2e1f0
#endif

.align(2*MMX_COEF)
const_stage0:
.long 0x5a827999
.long 0x5a827999
#if (MMX_COEF>=4)
.long 0x5a827999
.long 0x5a827999
#endif
const_stage1:
.long 0x6ed9eba1
.long 0x6ed9eba1
#if (MMX_COEF>=4)
.long 0x6ed9eba1
.long 0x6ed9eba1
#endif
const_stage2:
.long 0x8f1bbcdc
.long 0x8f1bbcdc
#if (MMX_COEF>=4)
.long 0x8f1bbcdc
.long 0x8f1bbcdc
#endif
const_stage3:
.long 0xca62c1d6
.long 0xca62c1d6
#if (MMX_COEF>=4)
.long 0xca62c1d6
.long 0xca62c1d6
#endif

.align(2*MMX_COEF)
mask0f0f:
.long 0x00ff00ff
.long 0x00ff00ff
#if (MMX_COEF>=4)
.long 0x00ff00ff
.long 0x00ff00ff
#endif
maskf0f0:
.long 0xff00ff00
.long 0xff00ff00
#if (MMX_COEF>=4)
.long 0xff00ff00
.long 0xff00ff00
#endif

#if (MMX_COEF == 2)
#define MMXMOVE movq
#define REGMM0 %mm0
#define REGMM1 %mm1
#define REGMM2 %mm2
#define REGMM3 %mm3
#define REGMM4 %mm4
#define REGMM5 %mm5
#define REGMM6 %mm6
#define REGMM7 %mm7
storea: ; .long 0 ; .long 0
storeb: ; .long 0 ; .long 0
storec: ; .long 0 ; .long 0
stored: ; .long 0 ; .long 0
storee: ; .long 0 ; .long 0
#else
#define MMXMOVE movapd
#define REGMM0 %xmm0
#define REGMM1 %xmm1
#define REGMM2 %xmm2
#define REGMM3 %xmm3
#define REGMM4 %xmm4
#define REGMM5 %xmm5
#define REGMM6 %xmm6
#define REGMM7 %xmm7
storea: ; .long 0 ; .long 0 ; .long 0 ; .long 0
storeb: ; .long 0 ; .long 0 ; .long 0 ; .long 0
storec: ; .long 0 ; .long 0 ; .long 0 ; .long 0
stored: ; .long 0 ; .long 0 ; .long 0 ; .long 0
storee: ; .long 0 ; .long 0 ; .long 0 ; .long 0
#endif

#define ctxa REGMM0
#define ctxb REGMM1
#define ctxc REGMM2
#define ctxd REGMM3
#define ctxe REGMM4
#define tmp1 REGMM5
#define tmp2 REGMM6
#define tmp3 REGMM7

//ft(x,y,z) = (x AND y) OR ((NOT x) AND z) ( 0 <= t <= 19) 
#define F0(x,y,z) \
	MMXMOVE x, tmp2; \
	MMXMOVE x, tmp1; \
	pand y, tmp2; \
	pandn z, tmp1; \
	por tmp2, tmp1; 

//ft(x,y,z) = x XOR y XOR z (20 <= t <= 39)
#define F1(x,y,z) \
	MMXMOVE z, tmp1; \
	pxor y, tmp1; \
	pxor x, tmp1

//ft(x,y,z) = (x AND y) OR (x AND z) OR (y AND z) (40 <= t <= 59)
//ft(x,y,z) = (x AND y) | ((x OR y) AND z) (40 <= t <= 59)
#define F2(x,y,z) \
	MMXMOVE x, tmp1; \
	MMXMOVE x, tmp2; \
	pand y, tmp1; \
	por y, tmp2; \
	pand z, tmp2; \
	por tmp2, tmp1;
	
//ft(x,y,z) = x XOR y XOR z (60 <= t <= 79).  = la seconde


#define expand(t) \
	MMXMOVE ((t-3)*4*MMX_COEF)(%edx), tmp1; \
	pxor ((t-8)*4*MMX_COEF)(%edx), tmp1; \
	pxor ((t-14)*4*MMX_COEF)(%edx), tmp1; \
	pxor ((t-16)*4*MMX_COEF)(%edx), tmp1; \
	MMXMOVE tmp1, tmp2; \
	pslld $1, tmp1; \
	psrld $31, tmp2; \
	por tmp2, tmp1; \
	MMXMOVE tmp1, (t*4*MMX_COEF)(%edx)

#define subRound(a, b, c, d, e, f, k, data) \
	f(b,c,d); \
	MMXMOVE a, tmp2; \
	MMXMOVE a, tmp3; \
	paddd tmp1, e; \
	pslld $5, tmp2; \
	psrld $27, tmp3; \
	por tmp3, tmp2; \
	paddd tmp2, e; \
	MMXMOVE b, tmp2; \
	pslld $30, b; \
	paddd k, e; \
	paddd (data*4*MMX_COEF)(%edx), e; \
	psrld $2, tmp2; \
	por tmp2, b;

#define subRoundu(a, b, c, d, e, f, k, data) \
	expand(data); \
	paddd tmp1, e; \
	f(b,c,d); \
	MMXMOVE a, tmp2; \
	MMXMOVE a, tmp3; \
	paddd tmp1, e; \
	pslld $5, tmp2; \
	psrld $27, tmp3; \
	por tmp3, tmp2; \
	paddd tmp2, e; \
	MMXMOVE b, tmp2; \
	pslld $30, b; \
	paddd k, e; \
	psrld $2, tmp2; \
	por tmp2, b;

.text
/*
 * Try to do some asm md4 w/ mmx
 * %eax ptr -> out
 * %edx ptr -> in (80*MMX_WIDTH mots)
 * %ecx n
 */

init_ctx:
	MMXMOVE const_init_a, ctxa
	MMXMOVE const_init_b, ctxb
	MMXMOVE const_init_c, ctxc
	MMXMOVE const_init_d, ctxd
	MMXMOVE const_init_e, ctxe
	ret

sizeupdate:
	 //MD4 Init
#if (MMX_COEF == 2)	
	shl $3, %ecx
	mov %ecx, %ebx
	and $0xffff, %ecx
	shrl $16,  %ebx
	// %ecx contient la taille du premier mdp
	// %edx celle du second
	mov %ecx, (15*4*MMX_COEF)(%edx)
	mov %ebx, (15*4*MMX_COEF+4)(%edx)
#else
	mov %ecx, %ebx
        shr $8, %ecx
        and $0xff, %ebx
        shl $3, %ebx
        mov %ebx, (15*16)(%edx)
        
        mov %ecx, %ebx
        shr $8, %ecx
        and $0xff, %ebx
        shl $3, %ebx
        mov %ebx, (15*16+4)(%edx)

        mov %ecx, %ebx
        shr $8, %ecx
        and $0xff, %ebx
        shl $3, %ebx
        mov %ebx, (15*16+8)(%edx)

        and $0xff, %ecx
        shl $3, %ecx
        mov %ecx, (15*16+12)(%edx)
#endif
	ret


uniformsizeupdate:
	shl $3, %ecx
	mov %ecx, (14*4*MMX_COEF)(%edx)
	mov %ecx, (14*4*MMX_COEF+4)(%edx)
#if (MMX_COEF == 4)
	mov %ecx, (14*4*MMX_COEF+8)(%edx)
	mov %ecx, (14*4*MMX_COEF+12)(%edx)
#endif
	ret


shammx_noinit_sizeupdate:
	pusha
	call sizeupdate
	jmp shammx_noinit

shammx_noinit_uniformsizeupdate:
	pusha
	call uniformsizeupdate
	jmp shammx_noinit

shammx:
	pusha
	call sizeupdate
	call init_ctx
	jmp shammx_noinit

shammx_nosizeupdate:
	pusha
	call init_ctx
	jmp shammx_noinit

shammx_noinit:
	MMXMOVE ctxa, storea
	MMXMOVE ctxb, storeb
	MMXMOVE ctxc, storec
	MMXMOVE ctxd, stored
	MMXMOVE ctxe, storee

round0:
	prefetchnta (%edx)
	subRound( ctxa, ctxb, ctxc, ctxd, ctxe, F0, const_stage0,  0 );
	subRound( ctxe, ctxa, ctxb, ctxc, ctxd, F0, const_stage0,  1 );
	subRound( ctxd, ctxe, ctxa, ctxb, ctxc, F0, const_stage0,  2 );
	subRound( ctxc, ctxd, ctxe, ctxa, ctxb, F0, const_stage0,  3 );
	subRound( ctxb, ctxc, ctxd, ctxe, ctxa, F0, const_stage0,  4 );
	subRound( ctxa, ctxb, ctxc, ctxd, ctxe, F0, const_stage0,  5 );
	subRound( ctxe, ctxa, ctxb, ctxc, ctxd, F0, const_stage0,  6 );
	subRound( ctxd, ctxe, ctxa, ctxb, ctxc, F0, const_stage0,  7 );
	subRound( ctxc, ctxd, ctxe, ctxa, ctxb, F0, const_stage0,  8 );
	subRound( ctxb, ctxc, ctxd, ctxe, ctxa, F0, const_stage0,  9 );
	subRound( ctxa, ctxb, ctxc, ctxd, ctxe, F0, const_stage0, 10 );
	subRound( ctxe, ctxa, ctxb, ctxc, ctxd, F0, const_stage0, 11 );
	subRound( ctxd, ctxe, ctxa, ctxb, ctxc, F0, const_stage0, 12 );
	subRound( ctxc, ctxd, ctxe, ctxa, ctxb, F0, const_stage0, 13 );
	subRound( ctxb, ctxc, ctxd, ctxe, ctxa, F0, const_stage0, 14 );
	subRound( ctxa, ctxb, ctxc, ctxd, ctxe, F0, const_stage0, 15 );
	subRoundu( ctxe, ctxa, ctxb, ctxc, ctxd, F0, const_stage0, 16 );
	subRoundu( ctxd, ctxe, ctxa, ctxb, ctxc, F0, const_stage0, 17 );
	subRoundu( ctxc, ctxd, ctxe, ctxa, ctxb, F0, const_stage0, 18 );
	subRoundu( ctxb, ctxc, ctxd, ctxe, ctxa, F0, const_stage0, 19 );

round1:
	subRoundu( ctxa, ctxb, ctxc, ctxd, ctxe, F1, const_stage1, 20 );
	subRoundu( ctxe, ctxa, ctxb, ctxc, ctxd, F1, const_stage1, 21 );
	subRoundu( ctxd, ctxe, ctxa, ctxb, ctxc, F1, const_stage1, 22 );
	subRoundu( ctxc, ctxd, ctxe, ctxa, ctxb, F1, const_stage1, 23 );
	subRoundu( ctxb, ctxc, ctxd, ctxe, ctxa, F1, const_stage1, 24 );
	subRoundu( ctxa, ctxb, ctxc, ctxd, ctxe, F1, const_stage1, 25 );
	subRoundu( ctxe, ctxa, ctxb, ctxc, ctxd, F1, const_stage1, 26 );
	subRoundu( ctxd, ctxe, ctxa, ctxb, ctxc, F1, const_stage1, 27 );
	subRoundu( ctxc, ctxd, ctxe, ctxa, ctxb, F1, const_stage1, 28 );
	subRoundu( ctxb, ctxc, ctxd, ctxe, ctxa, F1, const_stage1, 29 );
	subRoundu( ctxa, ctxb, ctxc, ctxd, ctxe, F1, const_stage1, 30 );
	subRoundu( ctxe, ctxa, ctxb, ctxc, ctxd, F1, const_stage1, 31 );
	subRoundu( ctxd, ctxe, ctxa, ctxb, ctxc, F1, const_stage1, 32 );
	subRoundu( ctxc, ctxd, ctxe, ctxa, ctxb, F1, const_stage1, 33 );
	subRoundu( ctxb, ctxc, ctxd, ctxe, ctxa, F1, const_stage1, 34 );
	subRoundu( ctxa, ctxb, ctxc, ctxd, ctxe, F1, const_stage1, 35 );
	subRoundu( ctxe, ctxa, ctxb, ctxc, ctxd, F1, const_stage1, 36 );
	subRoundu( ctxd, ctxe, ctxa, ctxb, ctxc, F1, const_stage1, 37 );
	subRoundu( ctxc, ctxd, ctxe, ctxa, ctxb, F1, const_stage1, 38 );
	subRoundu( ctxb, ctxc, ctxd, ctxe, ctxa, F1, const_stage1, 39 );

round2:
	subRoundu( ctxa, ctxb, ctxc, ctxd, ctxe, F2, const_stage2, 40 );
	subRoundu( ctxe, ctxa, ctxb, ctxc, ctxd, F2, const_stage2, 41 );
	subRoundu( ctxd, ctxe, ctxa, ctxb, ctxc, F2, const_stage2, 42 );
	subRoundu( ctxc, ctxd, ctxe, ctxa, ctxb, F2, const_stage2, 43 );
	subRoundu( ctxb, ctxc, ctxd, ctxe, ctxa, F2, const_stage2, 44 );
	subRoundu( ctxa, ctxb, ctxc, ctxd, ctxe, F2, const_stage2, 45 );
	subRoundu( ctxe, ctxa, ctxb, ctxc, ctxd, F2, const_stage2, 46 );
	subRoundu( ctxd, ctxe, ctxa, ctxb, ctxc, F2, const_stage2, 47 );
	subRoundu( ctxc, ctxd, ctxe, ctxa, ctxb, F2, const_stage2, 48 );
	subRoundu( ctxb, ctxc, ctxd, ctxe, ctxa, F2, const_stage2, 49 );
	subRoundu( ctxa, ctxb, ctxc, ctxd, ctxe, F2, const_stage2, 50 );
	subRoundu( ctxe, ctxa, ctxb, ctxc, ctxd, F2, const_stage2, 51 );
	subRoundu( ctxd, ctxe, ctxa, ctxb, ctxc, F2, const_stage2, 52 );
	subRoundu( ctxc, ctxd, ctxe, ctxa, ctxb, F2, const_stage2, 53 );
	subRoundu( ctxb, ctxc, ctxd, ctxe, ctxa, F2, const_stage2, 54 );
	subRoundu( ctxa, ctxb, ctxc, ctxd, ctxe, F2, const_stage2, 55 );
	subRoundu( ctxe, ctxa, ctxb, ctxc, ctxd, F2, const_stage2, 56 );
	subRoundu( ctxd, ctxe, ctxa, ctxb, ctxc, F2, const_stage2, 57 );
	subRoundu( ctxc, ctxd, ctxe, ctxa, ctxb, F2, const_stage2, 58 );
	subRoundu( ctxb, ctxc, ctxd, ctxe, ctxa, F2, const_stage2, 59 );

round3:
	subRoundu( ctxa, ctxb, ctxc, ctxd, ctxe, F1, const_stage3, 60 );
	subRoundu( ctxe, ctxa, ctxb, ctxc, ctxd, F1, const_stage3, 61 );
	subRoundu( ctxd, ctxe, ctxa, ctxb, ctxc, F1, const_stage3, 62 );
	subRoundu( ctxc, ctxd, ctxe, ctxa, ctxb, F1, const_stage3, 63 );
	subRoundu( ctxb, ctxc, ctxd, ctxe, ctxa, F1, const_stage3, 64 );
	subRoundu( ctxa, ctxb, ctxc, ctxd, ctxe, F1, const_stage3, 65 );
	subRoundu( ctxe, ctxa, ctxb, ctxc, ctxd, F1, const_stage3, 66 );
	subRoundu( ctxd, ctxe, ctxa, ctxb, ctxc, F1, const_stage3, 67 );
	subRoundu( ctxc, ctxd, ctxe, ctxa, ctxb, F1, const_stage3, 68 );
	subRoundu( ctxb, ctxc, ctxd, ctxe, ctxa, F1, const_stage3, 69 );
	subRoundu( ctxa, ctxb, ctxc, ctxd, ctxe, F1, const_stage3, 70 );
	subRoundu( ctxe, ctxa, ctxb, ctxc, ctxd, F1, const_stage3, 71 );
	subRoundu( ctxd, ctxe, ctxa, ctxb, ctxc, F1, const_stage3, 72 );
	subRoundu( ctxc, ctxd, ctxe, ctxa, ctxb, F1, const_stage3, 73 );
	subRoundu( ctxb, ctxc, ctxd, ctxe, ctxa, F1, const_stage3, 74 );
	subRoundu( ctxa, ctxb, ctxc, ctxd, ctxe, F1, const_stage3, 75 );
	subRoundu( ctxe, ctxa, ctxb, ctxc, ctxd, F1, const_stage3, 76 );
	subRoundu( ctxd, ctxe, ctxa, ctxb, ctxc, F1, const_stage3, 77 );
	subRoundu( ctxc, ctxd, ctxe, ctxa, ctxb, F1, const_stage3, 78 );
	subRoundu( ctxb, ctxc, ctxd, ctxe, ctxa, F1, const_stage3, 79 );

	paddd storea, ctxa
	paddd storeb, ctxb
	paddd storec, ctxc
	paddd stored, ctxd
	paddd storee, ctxe
	MMXMOVE ctxa, storea
	MMXMOVE ctxb, storeb
	MMXMOVE ctxc, storec
	MMXMOVE ctxd, stored
	MMXMOVE ctxe, storee
	jmp endianity

endianity:

//reverse indianity w/ rotate & and
//mmx has no rotate instructions ..
#define ENDIAN(a) \
	MMXMOVE a, tmp1; \
	MMXMOVE maskf0f0, tmp3; \
	pand tmp3, a; \
	MMXMOVE mask0f0f, tmp3; \
	pand tmp3, tmp1; \
	psrld $8, a; \
	pslld $8, tmp1; \
	por tmp1, a; \
	MMXMOVE a, tmp1; \
	psrld $16, a; \
	pslld $16, tmp1; \
	por tmp1, a

// why is this so slow ?
#define ENDIAN2(a) \
	pshuflw $177,a,a; \
	pshufhw $177,a,a; \
	movq a,tmp1; \
	pand maskf0f0, a; \
	pand mask0f0f, tmp1; \
	psrld $8, a; \
	pslld $8, tmp1; \
	por tmp1, a

//changes indianity ...
	MMXMOVE maskf0f0, tmp3
	MMXMOVE ctxa, tmp1
	MMXMOVE ctxb, tmp2
	pand tmp3, ctxa
	pand tmp3, ctxb
	MMXMOVE mask0f0f, tmp3
	pand tmp3, tmp1
	pand tmp3, tmp2
	psrld $8, ctxa
	psrld $8, ctxb
	pslld $8, tmp1
	pslld $8, tmp2
	por tmp1, ctxa
	por tmp2, ctxb
	MMXMOVE ctxa, tmp1
	MMXMOVE ctxb, tmp2
	psrld $16, ctxa
	psrld $16, ctxb
	pslld $16, tmp1
	pslld $16, tmp2
	por tmp1, ctxa
	por tmp2, ctxb 
	MMXMOVE ctxa, 0(%eax)
	MMXMOVE ctxb, 4*MMX_COEF(%eax)


//now 2 more register to play with ..
#define tmp4 ctxa
#define tmp5 ctxb

	MMXMOVE maskf0f0, tmp5
	MMXMOVE ctxc, tmp1
	MMXMOVE ctxd, tmp2
	MMXMOVE ctxe, tmp3
	pand tmp5, ctxc
	pand tmp5, ctxd
	pand tmp5, ctxe
	MMXMOVE mask0f0f, tmp5
	pand tmp5, tmp1
	pand tmp5, tmp2
	pand tmp5, tmp3
	psrld $8, ctxc
	psrld $8, ctxd
	psrld $8, ctxe
	pslld $8, tmp1
	pslld $8, tmp2
	pslld $8, tmp3
	por tmp1, ctxc
	por tmp2, ctxd
	por tmp3, ctxe
	MMXMOVE ctxc, tmp1
	MMXMOVE ctxd, tmp2
	MMXMOVE ctxe, tmp3
	psrld $16, ctxc
	psrld $16, ctxd
	psrld $16, ctxe
	pslld $16, tmp1
	pslld $16, tmp2
	pslld $16, tmp3
	por tmp1, ctxc
	por tmp2, ctxd
	por tmp3, ctxe

	MMXMOVE ctxc, 8*MMX_COEF(%eax)
	MMXMOVE ctxd, 12*MMX_COEF(%eax)
	MMXMOVE ctxe, 16*MMX_COEF(%eax)

	//mov %ecx, %eax
	//movd ctxe, %eax
	popa
	emms
	
	ret

/*
 alternate endianity conversion
 shouldn't be so slow ...
	pshuflw $177, ctxa, ctxa
	pshuflw $177, ctxb, ctxb
	pshuflw $177, ctxc, ctxc
	pshuflw $177, ctxd, ctxd
	pshuflw $177, ctxe, ctxe
	movq maskf0f0, tmp3
	pshufhw $177, ctxa, ctxa
	pshufhw $177, ctxb, ctxb
	pshufhw $177, ctxc, ctxc
	pshufhw $177, ctxd, ctxd
	pshufhw $177, ctxe, ctxe
	movq ctxa, tmp1
	movq ctxb, tmp2
	pand tmp3, ctxa
	pand tmp3, ctxb
	movq mask0f0f, tmp3
	pand tmp3, tmp1
	pand tmp3, tmp2
	psrld $8, ctxa
	psrld $8, ctxb
	pslld $8, tmp1
	pslld $8, tmp2
	por tmp1, ctxa
	por tmp2, ctxb
	MMXMOVE ctxa, 0(%eax)
	MMXMOVE ctxb, 4*MMX_COEF(%eax)

//now 2 more register to play with ..
#define tmp4 ctxa
#define tmp5 ctxb
	movq ctxc, tmp1
	movq ctxd, tmp2
	movq ctxe, tmp4
	pand tmp3, tmp1
	pand tmp3, tmp2
	pand tmp3, tmp4
	movq maskf0f0, tmp3
	pand tmp3, ctxc
	pand tmp3, ctxd
	pand tmp3, ctxe
	psrld $8, ctxc
	psrld $8, ctxd
	psrld $8, ctxe
	pslld $8, tmp1
	pslld $8, tmp2
	pslld $8, tmp4
	por tmp1, ctxc
	por tmp2, ctxd
	por tmp4, ctxe
*/

#if defined(__ELF__) && defined(__linux__)
.section .note.GNU-stack,"",@progbits
#endif
