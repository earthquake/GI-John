#ifndef JOHN_SHA_H
#define JOHN_SHA_H

#include <openssl/sha.h>

#ifdef MMX_COEF
extern int shammx(unsigned char *out, unsigned char *in, int n) __attribute__((regparm(3)));
extern int shammx_nosizeupdate(unsigned char *out, unsigned char *in, int n) __attribute__((regparm(3)));
extern int shammx_noinit_uniformsizeupdate(unsigned char *out, unsigned char *in, int n) __attribute__((regparm(3)));
#endif

#endif
