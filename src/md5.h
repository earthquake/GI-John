/*
 * This is an OpenSSL-compatible implementation of the RSA Data Security,
 * Inc. MD5 Message-Digest Algorithm (RFC 1321).
 *
 * Written by Solar Designer <solar at openwall.com> in 2001, and placed
 * in the public domain.  There's absolutely no warranty.
 *
 * See md5.c for more information.
 *
 * This file has been modified in the JtR jumbo patch.
 * If you reuse the code for another purpose, please download the original from:
 * http://openwall.info/wiki/people/solar/software/public-domain-source-code/md5
 */

#ifdef HAVE_OPENSSL
#include <openssl/md5.h>
#elif !defined(_MD5_H)
#define _MD5_H

/* Any 32-bit or wider unsigned integer data type will do */
typedef unsigned int MD5_u32plus;

typedef struct {
	MD5_u32plus lo, hi;
	MD5_u32plus a, b, c, d;
	unsigned char buffer[64];
	MD5_u32plus block[16];
} MD5_CTX;

extern void MD5_Init(MD5_CTX *ctx);
extern void MD5_Update(MD5_CTX *ctx, void *data, unsigned long size);
extern void MD5_PreFinal(MD5_CTX *ctx);
extern void MD5_Final(unsigned char *result, MD5_CTX *ctx);

#ifdef MMX_COEF
extern int mdfivemmx(unsigned char *out, unsigned char *in, int n) __attribute__((regparm(3)));
extern int mdfivemmx_nosizeupdate(unsigned char *out, unsigned char *in, int n) __attribute__((regparm(3)));
extern int mdfivemmx_noinit_sizeupdate(unsigned char *out, unsigned char *in, int n) __attribute__((regparm(3)));
extern int mdfivemmx_noinit_uniformsizeupdate(unsigned char *out, unsigned char *in, int n) __attribute__((regparm(3)));
#endif

#endif
