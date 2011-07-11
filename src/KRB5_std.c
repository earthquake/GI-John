/*
 * KRB5_std.c
 *
 *  Kerberos 5 module for John the Ripper by Solar Designer, based on the 
 *  KRB4 module by Dug Song.
 *
 * Author: Nasko Oskov <nasko at netsekure.org>
 *
 * Licensing:
 *   
 *  The module contains code derived or copied from the Heimdal project.
 *  
 *  Copyright (c) 1997-2000 Kungliga Tekniska H�gskolan 
 *  (Royal Institute of Technology, Stockholm, Sweden).
 *  All rights reserved.
 *
 *  Which is distribution of Kerberos based on M.I.T. implementation.
 *
 *  Copyright (C) 1990 by the Massachusetts Institute of Technology
 *
 */


#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "KRB5_std.h"

#if defined (_MSC_VER)
#define inline _inline
#endif


static DES_cblock ivec;
static const char derive_const[5] = "\x00\x00\x00\x03\xaa";

/**
 * Heimdal rr13 function                // {{{
 */
static inline void rr13(unsigned char *buf, int len) {   

    unsigned char *tmp;
    int bytes = (len + 7) / 8;
    int i;
    
    int bb;
    int b1, s1, b2, s2;
    
    const int bits = 13 % len;
    const int lbit = len % 8;

    if(len == 0)
        return;

    tmp = (unsigned char *) malloc(bytes);
    memcpy(tmp, buf, bytes);
    if(lbit) {
        // pad final byte with inital bits
        tmp[bytes - 1] &= 0xff << (8 - lbit);
        for(i = lbit; i < 8; i += len)
            tmp[bytes - 1] |= buf[0] >> i;
    }   
    for(i = 0; i < bytes; i++) {
        // calculate first bit position of this byte
        bb = 8 * i - bits;
        while(bb < 0)
            bb += len;
        // byte offset and shift count
        b1 = bb / 8;
        s1 = bb % 8;

        if(bb + 8 > bytes * 8)
            // watch for wraparound
            s2 = (len + 8 - s1) % 8;
        else
            s2 = 8 - s1;
        b2 = (b1 + 1) % bytes;
        buf[i] = (tmp[b1] << s1) | (tmp[b2] >> s2);
    }
    free(tmp);
}
// }}}

/**
 * Heimdal add1 function                            // {{{
 */
static inline void add1(unsigned char *a, unsigned char *b, size_t len) {
    int i, x;
    int carry = 0;
    for(i = len - 1; i >= 0; i--){
        x = a[i] + b[i] + carry;
        carry = x > 0xff;
        a[i] = x & 0xff;
    }
    for(i = len - 1; carry && i >= 0; i--){
        x = a[i] + carry;
        carry = x > 0xff;
        a[i] = x & 0xff;
    }
}
// }}}
 
/**
 * Heimdal _krb5_n_fold function        // {{{
 */
static inline void _krb5_n_fold(const void *str, int len, void *key, int size) {

    int maxlen = 2 * max(size, len), l = 0; 
    unsigned char *tmp = (unsigned char *) malloc(maxlen);
    unsigned char *buf = (unsigned char *) malloc(len);

    memcpy(buf, str, len);
    memset(key, 0, size);
    do {
        memcpy(tmp + l, buf, len);
        l += len;
        rr13(buf, len * 8);
        while(l >= size) {
            add1(key, tmp, size);
            l -= size;
            if(l == 0)
                break;
            memmove(tmp, tmp + size, l);
        }
    } while(l != 0);
    sfree(buf, len);
    sfree(tmp, maxlen);
}
// }}}

/**
 * Heimdal DES3_postproc function               // {{{
 */
static inline void DES3_postproc(unsigned char *k, int len, krb5_key *krb5key) {
    unsigned char x[24];
    int i, j;
    unsigned char foo;
    unsigned char b;
    
    memset(x, 0, sizeof(x));
    for (i = 0; i < 3; ++i) {
        for (j = 0; j < 7; ++j) {
            b = k[7 * i + j];
            x[8 * i + j] = b;
        }
        foo = 0;
        for (j = 6; j >= 0; --j) {
            foo |= k[7 * i + j] & 1;
            foo <<= 1;
        }
        x[8 * i + 7] = foo;
    }
    k = (unsigned char *) krb5key->key;
    memcpy(k, x, 24);
    DES_set_odd_parity((DES_cblock*)k);
    DES_set_odd_parity((DES_cblock*)(k + 8));
    DES_set_odd_parity((DES_cblock*)(k + 16));

#if 0    
    memset(x, 0, sizeof(x));
#endif
}
// }}}

/**
 * Heimdal based derive_key function                      // {{{
 */
static inline void derive_key(const void *constant, int len, krb5_key *krb5key) {

    unsigned char *k;
    unsigned int nblocks = 0, i;
    DES_cblock *bk;
    DES_key_schedule *s;
    
    // set the des schedule
    bk = (DES_cblock*) krb5key->key;
    s = (DES_key_schedule *) krb5key->schedule;
    DES_set_key(&bk[0], &s[0]);
    DES_set_key(&bk[1], &s[1]);
    DES_set_key(&bk[2], &s[2]);

    if(DES3_BLOCK_SIZE * 8 < DES3_KEY_BITS || len != DES3_BLOCK_SIZE) {
        nblocks = (DES3_KEY_BITS + DES3_BLOCK_SIZE * 8 - 1) / (DES3_BLOCK_SIZE * 8);
        k = (unsigned char *) malloc(nblocks * DES3_BLOCK_SIZE);
        if(k == NULL) {
            printf("malloc: out of memory\n");
            exit(1);
        }
        _krb5_n_fold(constant, len, k, DES3_BLOCK_SIZE);
        for(i = 0; i < nblocks; i++) {
            if(i > 0)
                memcpy(k + i * DES3_BLOCK_SIZE, k + (i - 1) * DES3_BLOCK_SIZE, DES3_BLOCK_SIZE);
             
            memset(ivec, 0x00, sizeof(ivec));
            DES_ede3_cbc_encrypt((void *) &k[i * DES3_BLOCK_SIZE], (void *) &k[i * DES3_BLOCK_SIZE], 
                    DES3_BLOCK_SIZE, &s[0], &s[1], &s[2], (DES_cblock *) ivec, 1);
        }
    } else {
        printf("Error, should never get here\n");
        exit(1);
    }

    // keytype dependent post-processing
    DES3_postproc(k, nblocks * DES3_BLOCK_SIZE, krb5key);
    
    sfree(k, nblocks * DES3_BLOCK_SIZE);
}
// }}}
   
/**
 * Heimdal based string_to_key_derived function          // {{{
 */
static inline void string_to_key_derived(const void *passwd, int len, krb5_key *krb5key) {   

    unsigned char *tmp;

    tmp = (unsigned char *) malloc(DES3_KEY_BITS_BYTES);
    if(tmp == NULL) {
        printf("malloc: out of memory\n");
        // FIXME make it real return value if sometime this is needed
        exit(1);
    }
    _krb5_n_fold(passwd, len, tmp, DES3_KEY_BITS_BYTES);
    
    DES3_postproc(tmp, DES3_KEY_BITS_BYTES, krb5key);
    derive_key("kerberos", strlen("kerberos"), krb5key);

    sfree(tmp, DES3_KEY_BITS_BYTES);
}
// }}}

/**
 * des3_decrypt                                                 // {{{
 */
void des3_decrypt(krb5_key *key, char *cipher, char *plain, int len) {
    
    DES_cblock *k;
    DES_key_schedule *s;
    
    memset(&ivec, 0x00, sizeof(ivec));

    k = (DES_cblock *) key->key;
    s = (DES_key_schedule *) key->schedule;

    DES_set_key(&k[0], &s[0]);
    DES_set_key(&k[1], &s[1]);
    DES_set_key(&k[2], &s[2]);
    
    DES_ede3_cbc_encrypt((const unsigned char*) cipher, (unsigned char*) plain, len, &s[0], &s[1], &s[2], &ivec, 0);

}
// }}}
 
/**
 * str2key                                                  // {{{
 */
void str2key(char *user, char *realm, char *passwd, krb5_key *krb5key) {
    int offset = 0;
    char *text;

    text = (char*) malloc(strlen(user) + strlen(realm) + strlen(passwd));
    if (text == NULL) {
        return;
    }

    memset(krb5key->key, 0x00, DES3_KEY_SIZE);
    memset(krb5key->schedule, 0x00, DES3_KEY_SCHED_SIZE);

    // make the string from the passwd, realm, username
    offset = 0;
    memcpy(text + offset, passwd, strlen(passwd));
    offset += strlen(passwd);
    memcpy(text + offset, realm, strlen(realm));
    offset += strlen(realm);
    memcpy(text + offset, user, strlen(user));
    offset += strlen(user);
    
    string_to_key_derived(text, offset, krb5key);
    
    // derive key from key
    derive_key(derive_const, sizeof(derive_const), krb5key);

    free(text);
}
// }}}

