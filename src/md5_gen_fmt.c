/*
 * This software was written by Jim Fougeron jfoug AT cox dot net 
 * in 2009. No copyright is claimed, and the software is hereby 
 * placed in the public domain. In case this attempt to disclaim 
 * copyright and place the software in the public domain is deemed 
 * null and void, then the software is Copyright © 2009 Jim Fougeron
 * and it is hereby released to the general public under the following
 * terms: 
 *
 * This software may be modified, redistributed, and used for any
 * purpose, in source and binary forms, with or without modification.
 *
 * Generic MD5 hashes cracker
 *
 * It uses the openSSL md5 for x86, and MMX/SSE2 md5 from md5-mmx.S
 * 
 * Only valid up to 54 bytes max string length (salts, rehashes, 
 * passwords, etc) if using SSE2.  96 byte keys (appended salts, 
 * keys, re-hashes, etc), if running under x86 mode.  NOTE some
 * hashes will NOT run properly under SSE2.  A hash such as 
 * md5(md5($p).md5($s)) would fail under SSE2, since it always 
 * would need at least 64 bytes to complete but even md5($p) would 
 * fail in SSE2 if the password is over 54 bytes.  NOTE no run-time
 * checks are made so if you provide data too large, it will not find
 * the hash, and will 'overwrite' some of the hashes being worked on,
 * and cause them to have invalid results. This is a bug that 'might'
 * be worked on, but I do not want do slow the cracking down performing
 * checks.
 *
 * This code has gone through a few iterations, and now is quite a bit
 * more mature.  It has been designed with an array for keys (which
 * is optionally used), a slot for the current salt, 2 arrays for 
 * input buffers (there is optional loading that loads keys directly
 * into input buffer #1 as an optimization for certain formats), and
 * a pair of arrays for crypt outputs.  The 'first' output buffer array
 * is used to return the final results.  There is also 2 arrays of lengths
 * of input buffers.  There are then 'primative' functions. These can 
 * append keys, append salts, blank out keys, move from input 1 to input 
 * 2, crypt input 1 -> output 1, (or from 1->2 or 2->2 or 2->1, etc).
 * There are functions that do base 16 conversions of the outputs back
 * into inputs (O1->I1 in base 16, 1->2 2->2 2->1, etc).  There are 
 * functions that over write the start of an input buffer from outputs
 * without 'adjusting' the lengths.  There are a few special functions
 * to do phpass work.    
 *
 * Then there are helper functions which allow another format to 'use'
 * the generic MD5 code.  So, we can make a VERY thin raw-md5 (or phpass
 * md5), where it simply has a format structure (which does not need to be
 * 'heavily' filled out, and that format only needs to implement a few
 * functions on its own.  It would need to implement init, valid, salt
 * and binary.  Then there needs to be a 'conversion' function that 
 * converts from the 'native' format, into the native GENERIC format.
 * Then, within the init function, that format would hook into the 
 * generic md5, by calling the md5_gen_RESET_LINK() function, passing
 * in its Format structure to have functions pointed into the md5 generic
 * stuff.  The conversion function is likely very trivial. For phpass, we
 * convert from 
 * $H$9aaaaaSXBjgypwqm.JsMssPLiS8YQ00
 * to 
 * md5_gen(17)jgypwqm.JsMssPLiS8YQ00$9aaaaaSXB
 *
 *  Here is that convert function:
 * static char *Convert(char *Buf, char *ciphertext) {
 *    sprintf(Buf, "md5_gen(17)%s%10.10s", &ciphertext[3+8+1], &ciphertext[2]);
 *    return Buf;
 * }
 *
 *
 * Generic MD5 can now be user expanded.  The first 1000 md5_gen(#) are
 * reserved as 'built-in' functions for john. Above 1000 is free to use
 * for anyone wanting to do so.  NO programming changes are needed to
 * add a format. All that is needed is modifcations to john.conf.  There is
 * FULL documentation about how to do this in doc/MD5_GENERIC.  There is
 * no parser 'generation' logic.  A person would have to understand the
 * primitive functions and how they work.  But the format can be added
 * without a rebuild of john.  There are 7 (or 8) examples already done
 * in john.conf at this time, which should make it pretty easy for someone
 * wanting to do a new or obscure format.
 *
 */

#include <string.h>

#include "arch.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "md5.h"
#include "md5_gen.h"
#include "options.h"
#include "config.h"

/* Data which is 'set' at init-step2 setup time */

// this 'will' be replaced, and will 'replace' FORMAT_NAME
static int                     md5_gen_FIXED_SALT_SIZE = 0;
static int                     md5_gen_SALT_OFFSET;
static int                     md5_gen_HASH_OFFSET;
static MD5_GEN_primitive_funcp md5_gen_FUNCTIONS[5000];
// 0 for 'raw-md5', 1 for vBulletin, etc. See md5_gen_preloads.c for 'official' types   
// -1 for not yet set.  Once it is set, it 'stays' set, and only works for THAT type.
static int                     md5_gen_WHICH_TYPE=-1;	
static char                    md5_gen_WHICH_TYPE_SIG[40];

#define FORMAT_LABEL		"md5-gen"
#define FORMAT_NAME         "Generic MD5"
#ifdef MMX_COEF
#if (MMX_COEF == 2)
#define ALGORITHM_NAME		"md5-gen MMX 32x2"
#else
#define ALGORITHM_NAME		"md5-gen SSE2 16x4"
#endif
#else
#define ALGORITHM_NAME		"md5-gen 64x1"
#endif

#ifdef MMX_TYPE
#define BENCHMARK_COMMENT	MMX_TYPE
#else
#define BENCHMARK_COMMENT		""
#endif
#define BENCHMARK_LENGTH		-1

#ifdef MMX_COEF
#define PLAINTEXT_LENGTH		53
#else
// Would LOVE to go to 128 bytes (would allow md5(md5($p).md5($p).md5($p).md5($p)) but
// due to other parts of john, we can only go to 128-3 as max sized plaintext.
#define PLAINTEXT_LENGTH		125
#endif

#define CIPHERTEXT_LENGTH		32

#define BINARY_SIZE				16
#define SALT_SIZE				64

#ifdef MMX_COEF
#if MMX_COEF==2
#define BLOCK_LOOPS 32
#else
#define BLOCK_LOOPS 16
#endif
#define MIN_KEYS_PER_CRYPT	MMX_COEF*BLOCK_LOOPS
#define MAX_KEYS_PER_CRYPT	MMX_COEF*BLOCK_LOOPS
#define GETPOS(i, index)		( (index)*4 + ((i) & (0xffffffff-3) )*MMX_COEF + ((i)&3) )
#else
#define MIN_KEYS_PER_CRYPT	1
#define MAX_KEYS_PER_CRYPT	64
#endif

// slots to do 24 'tests'. Note, we copy the
// same 3 tests over and over again.  Simply to validate that 
// tests use 'multiple' blocks.
static struct fmt_tests md5_gen_tests[] = {
	{NULL},{NULL},{NULL},{NULL},{NULL},{NULL},{NULL},{NULL},
	{NULL},{NULL},{NULL},{NULL},{NULL},{NULL},{NULL},{NULL},
	{NULL},{NULL},{NULL},{NULL},{NULL},{NULL},{NULL},{NULL},{NULL}
};

#ifdef MMX_COEF
// SSE2 works only with 54 byte keys. Thus, md5(md5($p).md5($s)) can NOT be used
// with the SSE2, since that final md5 will be over a 64 byte block of data.
#define input_buf  genMD5_input_buf
#define input_buf2 genMD5_input_buf2
#define crypt_key  genMD5_crypt_key
#define crypt_key2 genMD5_crypt_key2
unsigned char input_buf[BLOCK_LOOPS][64*MMX_COEF] __attribute__ ((aligned(16)));
unsigned char input_buf2[BLOCK_LOOPS][64*MMX_COEF] __attribute__ ((aligned(16)));
unsigned char crypt_key[BLOCK_LOOPS][BINARY_SIZE*MMX_COEF] __attribute__ ((aligned(16)));
unsigned char crypt_key2[BLOCK_LOOPS][BINARY_SIZE*MMX_COEF] __attribute__ ((aligned(16)));
static unsigned int total_len[BLOCK_LOOPS];
static unsigned int total_len2[BLOCK_LOOPS];
#else
// Our code uses the OpenSSL md5() functions.
static MD5_CTX ctx;
// Allows us to work with up to 96 byte keys in the non-sse2 code
static unsigned char input_buf[MAX_KEYS_PER_CRYPT][PLAINTEXT_LENGTH+1];
static unsigned char input_buf2[MAX_KEYS_PER_CRYPT][PLAINTEXT_LENGTH+1];
static unsigned char crypt_key[MAX_KEYS_PER_CRYPT][BINARY_SIZE];
static unsigned char crypt_key2[MAX_KEYS_PER_CRYPT][BINARY_SIZE];
static unsigned int total_len[MAX_KEYS_PER_CRYPT];
static unsigned int total_len2[MAX_KEYS_PER_CRYPT];
#endif

// if the format is non-base16 (i.e. base-64), then this flag is set, and 
// a the hash loading function uses it.
static int md5_gen_base64_inout;
// if set, then we load keys directly into input1 and NOT into the saved_key buffers
static int store_keys_in_input;
static int store_keys_normal_but_precompute_md5_to_output2;
static int store_keys_normal_but_precompute_md5_to_output2_base16_to_input1;
static int store_keys_normal_but_precompute_md5_to_output2_base16_to_input1_offset32;

static int md5_gen_salt_as_hex;

static int store_keys_normal_but_precompute_md5_to_output2_dirty;
// Used in 'get_key' if we are running in store_keys_in_input mode
static char out[PLAINTEXT_LENGTH+1];
// We store the salt here
static char cursalt[SALT_SIZE+1];
// length of salt (so we don't have to call strlen() all the time.
static int saltlen;
// array of the keys.  Also lengths of the keys. NOTE if store_keys_in_input, then the
// key array will NOT be used (but the length array still is).
static char saved_key[MAX_KEYS_PER_CRYPT][PLAINTEXT_LENGTH+1];
static int saved_key_len[MAX_KEYS_PER_CRYPT];

// This is the GLOBAL count of keys. ALL of the primitives which deal with a count
// will read from this variable.
static int m_count;

/*
 * This function will 'forget' which md5-gen subtype we are working with. It will allow
 * a different type to be used.  Very useful for things like -test (benchmarking).
 */
void md5_gen_RESET()
{
	if (fmt_MD5gen.private.initialized == 0) {
		fmt_MD5gen.methods.init();
		fmt_MD5gen.private.initialized = 1;
	}

	md5_gen_WHICH_TYPE = -1;
	memset(md5_gen_FUNCTIONS, 0, sizeof(md5_gen_FUNCTIONS));
	memset(md5_gen_WHICH_TYPE_SIG, 0, sizeof(md5_gen_WHICH_TYPE_SIG));
	m_count = 0;
	md5_gen_base64_inout = 0;
	store_keys_in_input = 0;
	md5_gen_salt_as_hex = 0;
	store_keys_normal_but_precompute_md5_to_output2 = 0;
	store_keys_normal_but_precompute_md5_to_output2_base16_to_input1 = 0;
	store_keys_normal_but_precompute_md5_to_output2_base16_to_input1_offset32 = 0;
	store_keys_normal_but_precompute_md5_to_output2_dirty = 0;
	saltlen = 0;
}

/*
 * This will LINK our functions into some other fmt_main struction. That way
 * that struction can use our code.  The other *_fmt.c file will need to 
 * 'override' the valid, the binary and the salt functions, and make changes
 * to the hash, BEFORE calling into the md5_gen valid/binary/salt functions.
 * Other than those functions (and calling into this linkage function at init time)
 * that is about all that needs to be in that 'other' *_fmt.c file, as long as the
 * format is part of the md5-generic 'class' of functions.
 */
void md5_gen_RESET_LINK(struct fmt_main *pFmt, char *ciphertext, char *orig_sig)
{
	int i;
	static char subformat[17], *cp;
	md5_gen_RESET();
	strncpy(subformat, ciphertext, 16);
	subformat[16] = 0;
	cp = strchr(subformat, ')');
	if (cp)
		cp[1] = 0;
	options.subformat = subformat;
	fmt_MD5gen.methods.valid(ciphertext);

	printf ("Using %s mode, by linking to %s functions", orig_sig, subformat);
	// If benchmarking, simply add a space.  If not, then add a newline.
	if (options.flags & FLG_TEST_CHK)
		printf (" ");
	else
		printf ("\n");

	pFmt->params.max_keys_per_crypt = fmt_MD5gen.params.max_keys_per_crypt;
	pFmt->params.min_keys_per_crypt = fmt_MD5gen.params.min_keys_per_crypt;
	pFmt->methods.cmp_all    = fmt_MD5gen.methods.cmp_all;
	pFmt->methods.cmp_one    = fmt_MD5gen.methods.cmp_one;
	pFmt->methods.cmp_exact  = fmt_MD5gen.methods.cmp_exact;
	pFmt->methods.set_salt   = fmt_MD5gen.methods.set_salt;
	pFmt->methods.salt_hash  = fmt_MD5gen.methods.salt_hash;
	pFmt->methods.split      = fmt_MD5gen.methods.split;
	pFmt->methods.set_key    = fmt_MD5gen.methods.set_key;
	pFmt->methods.get_key    = fmt_MD5gen.methods.get_key;
	pFmt->methods.clear_keys = fmt_MD5gen.methods.clear_keys;
	pFmt->methods.crypt_all  = fmt_MD5gen.methods.crypt_all;
	for (i = 0; i < 5; ++i)
	{
		pFmt->methods.binary_hash[i] = fmt_MD5gen.methods.binary_hash[i];
		pFmt->methods.get_hash[i]    = fmt_MD5gen.methods.get_hash[i];
	}
}

void md5_gen_DISPLAY_ALL_FORMATS()
{
	int i;
	for (i = 0; i < 1000; ++i)
	{
		char *sz = md5_gen_PRELOAD_SIGNATURE(i);
		if (!sz)
			break;
		printf ("Format = md5_gen(%d)%s  type = %s\n", i, i<10?" ":"", sz);
	}

	// The config has not been loaded, so we have to load it now, if we want to 'check' 
	// and show any user set md5-generic functions.
#if JOHN_SYSTEMWIDE
	cfg_init(CFG_PRIVATE_FULL_NAME, 1);
	cfg_init(CFG_PRIVATE_ALT_NAME, 1);
#endif
	cfg_init(CFG_FULL_NAME, 1);
	cfg_init(CFG_ALT_NAME, 0);

	for (i = 1000; i < 10000; ++i)
	{
		char *sz = md5_gen_LOAD_PARSER_SIGNATURE(i);
		if (sz)
			printf ("UserFormat = md5_gen(%d)%s  type = %s\n", i, i<10?" ":"", sz);
	}
}

/*********************************************************************************
 *********************************************************************************
 * Start of the 'normal' *_fmt code for md5-gen
 *********************************************************************************
 *********************************************************************************/

/*********************************************************************************
 * Detects a 'valid' md5-gen, and 'locks us' into that format. Once locked in,
 * ONLY that format will be deemed valid. Any other generic md5 line, or other
 * type data line will be called invalid.  A call to RESET (above) will clear
 * out this 'locked into' mentality, and let valid again search for a new type.
 *********************************************************************************/
static int valid(char *ciphertext)
{
	int i;
	char *cp;
	if (md5_gen_WHICH_TYPE == -1)
	{
		int type, cnt;
		extern struct options_main options;
		type = -1;
		if (options.subformat)
		{
			cnt = sscanf(options.subformat, "md5_gen(%d)", &type);
			if (cnt != 1)
				type = 0;
		}
		if (ciphertext == NULL)
		{
			if (type == -1)
				type = 0;
			// This is caused by doing a -test
			// we check to see if the user have provided a -subformat=  and if
			// so, use it. If NOT, we simply user format 0.
			md5_gen_WHICH_TYPE = type;
			if (type < 1000)
				md5_gen_RESERVED_PRELOAD_SETUP(type);
			else
				md5_gen_LOAD_PARSER_FUNCTIONS(type);
			md5_gen_HASH_OFFSET = sprintf(md5_gen_WHICH_TYPE_SIG, "md5_gen(%d)", type);
			if (md5_gen_base64_inout)
				md5_gen_SALT_OFFSET = md5_gen_HASH_OFFSET + 22 + 1;
			else
				md5_gen_SALT_OFFSET = md5_gen_HASH_OFFSET + 32 + 1;
			return 0;
		}

		if (type == -1) {
			cnt = sscanf(ciphertext, "md5_gen(%d)", &type);
			if (cnt != 1)
				return 0;
		}
		md5_gen_WHICH_TYPE = type;
		if (type < 1000)
			md5_gen_RESERVED_PRELOAD_SETUP(type);
		else
			md5_gen_LOAD_PARSER_FUNCTIONS(type);
		md5_gen_HASH_OFFSET = sprintf(md5_gen_WHICH_TYPE_SIG, "md5_gen(%d)", type);
		if (md5_gen_base64_inout)
			md5_gen_SALT_OFFSET = md5_gen_HASH_OFFSET + 22 + 1;
		else
			md5_gen_SALT_OFFSET = md5_gen_HASH_OFFSET + 32 + 1;
	}
	else
	{
		if (strncmp(ciphertext, md5_gen_WHICH_TYPE_SIG, strlen(md5_gen_WHICH_TYPE_SIG)))
			return 0;
	}
	cp = &ciphertext[strlen(md5_gen_WHICH_TYPE_SIG)];

	if (md5_gen_base64_inout)
	{
		// jgypwqm.JsMssPLiS8YQ00$BaaaaaSX
		int i;
		for (i = 0; i < 22; ++i)
				if (atoi64[ARCH_INDEX(cp[i])] == 0x7F)
						return 0;
		if (md5_gen_FIXED_SALT_SIZE && cp[22] != '$')
			return 0;
		if (md5_gen_FIXED_SALT_SIZE > 0 && strlen(&cp[23]) != md5_gen_FIXED_SALT_SIZE)
			return 0;
		return 1;
	}

	if (md5_gen_base64_inout)
	{
		if (strlen(cp) < 22)
			return 0;
	}
	else
	{
		if (strlen(cp) < 32)
			return 0;
	}
	for (i = 0; i < CIPHERTEXT_LENGTH; i++){
		if (!(  (('0' <= cp[i])&&(cp[i] <= '9')) ||
					(('a' <= cp[i])&&(cp[i] <= 'f'))  ))
			return 0;
	}
	if (md5_gen_FIXED_SALT_SIZE && ciphertext[md5_gen_SALT_OFFSET-1] != '$')
		return 0;
	if (md5_gen_FIXED_SALT_SIZE > 0 && strlen(&ciphertext[md5_gen_SALT_OFFSET]) != md5_gen_FIXED_SALT_SIZE)
		return 0;
	return 1;
}

/*********************************************************************************
 * init() here does nothing. NOTE many formats LINKING into us will have a valid
 * that DOES do something, but ours does nothing.
 *********************************************************************************/
static void md5_gen_init(void) { }

/*********************************************************************************
 * Stores the new salt provided into our 'working' salt
 *********************************************************************************/
static void md5_gen_set_salt(void *salt)
{
	memset(cursalt, 0, sizeof(cursalt));
	strncpy(cursalt, salt, SALT_SIZE);
	cursalt[SALT_SIZE] = 0;
	saltlen = strlen(cursalt);
}

/*********************************************************************************
 * init() here does nothing. NOTE many formats LINKING into us will have a valid that 
 * NOTE specific for phpass.  We internally look at a salt as 8 bytes, but external
 * it is 9. NOTE in the crypt, we DO use that last byte. It tells crypt how many
 * times to loop.  However, within ALL of the primitive functions, they only work
 * with the first 8 bytes of the salt (the true salt value), and ignore that 9th
 * byte.   
 *********************************************************************************/
static void phpass_gen_set_salt(void *salt)
{
	//memset(cursalt, 0, sizeof(cursalt));
	strncpy(cursalt, salt, saltlen+1);
	cursalt[saltlen+1] = 0;
}

/*********************************************************************************
 * Sets this key. It will either be dropped DIRECTLY into the input buffer 
 * number 1, or put into an array of keys.  Which one happens depends upon
 * HOW the generic functions were laid out for this type. Not all types can
 * load into the input.  If not they MUST use the key array. Using the input
 * buffer is faster, when it can be safely done.
 *********************************************************************************/
static void md5_gen_set_key(char *key, int index)
{
	if (store_keys_in_input)
	{
		unsigned int len = strlen(key);
#ifdef MMX_COEF
		unsigned int i, cnt;
		unsigned int idx = ( ((unsigned)index)>>(MMX_COEF>>1));
		ARCH_WORD_32 *pi = (ARCH_WORD_32 *)key;
		ARCH_WORD_32 *po = &((ARCH_WORD_32 *)(&(input_buf[idx])))[index&(MMX_COEF-1)];
		if(index==0)
			MD5GenBaseFunc__clean_input();
		if (len > 54)
			len = 54;
		cnt = len>>2;
		for (i = 0; i < cnt; ++i)
		{
			*po = *pi++;
			po += MMX_COEF;
		}
		for(i=cnt<<2;i<len;i++)
			input_buf[idx][GETPOS(i, index&(MMX_COEF-1))] = key[i];
		input_buf[idx][GETPOS(i, index&(MMX_COEF-1))] = 0x80;
		total_len[idx] += ( len << ( ( (32/MMX_COEF) * (index&(MMX_COEF-1)) ) ));
		saved_key_len[index] = len;
#else
		if(index==0)
			MD5GenBaseFunc__clean_input();
		strnzcpy(((char*)(input_buf[index])), key, sizeof(saved_key[index]));
		saved_key_len[index] = total_len[index] = len;
#endif
	}
	else
	{
#ifdef MMX_COEF
		strnzcpy(((char*)(saved_key[index])), key, 54);
#else
		strnzcpy(((char*)(saved_key[index])), key, sizeof(saved_key[index]));
#endif
		saved_key_len[index] = strlen(saved_key[index]);
		if (store_keys_normal_but_precompute_md5_to_output2)
			store_keys_normal_but_precompute_md5_to_output2_dirty = 1;
	}
}


/*********************************************************************************
 * Returns the key.  NOTE how it gets it depends upon if we are storing
 * into the array of keys (there we simply return it), or if we are
 * loading into input buffer #1. If in input buffer, we have to re-create
 * the key, prior to returning it.
 *********************************************************************************/
static char *md5_gen_get_key(int index)
{
	if (store_keys_in_input)
	{
#ifdef MMX_COEF
	unsigned int i,s;
	unsigned int idx = ( ((unsigned)index)>>(MMX_COEF>>1));
	
	s = saved_key_len[index];
	for(i=0;i<s;i++)
		out[i] = input_buf[idx][ GETPOS(i, index&(MMX_COEF-1)) ];
	out[i] = 0;
	return (char*)out;
#else
	int i;
	for(i=0;i<saved_key_len[index];++i)
		out[i] = input_buf[index][i];
	out[i] = 0;
	return (char*)out;
#endif
	}
	else
	{
		saved_key[index][saved_key_len[index]] = '\0';
		return saved_key[index];
	}
}

/*********************************************************************************
 * Looks for ANY key that was cracked.
 *********************************************************************************/
static int md5_gen_cmp_all(void *binary, int count)
{
#ifdef MMX_COEF
	unsigned int i, j;
	unsigned int cnt = ( ((unsigned)count+MMX_COEF-1)>>(MMX_COEF>>1));
	for (j = 0; j < cnt; ++j)
	{
		unsigned int SomethingGood = 1;
		i = 0;
		while(i < (BINARY_SIZE/4) )
		{
			if (
				( ((unsigned long *)binary)[i] != ((unsigned long *)&(crypt_key[j]))[i*MMX_COEF])
				&& ( ((unsigned long *)binary)[i] != ((unsigned long *)&(crypt_key[j]))[i*MMX_COEF+1])
#if (MMX_COEF > 3)
				&& ( ((unsigned long *)binary)[i] != ((unsigned long *)&(crypt_key[j]))[i*MMX_COEF+2])
				&& ( ((unsigned long *)binary)[i] != ((unsigned long *)&(crypt_key[j]))[i*MMX_COEF+3])
#endif
				)
			{
				SomethingGood = 0;
				break;
			}
			++i;
		}
		if (SomethingGood)
			return 1;
	}
	return 0;
#else
	unsigned int i;

	for (i = 0; i < count; i++) {
		if (!(*((unsigned int*)binary) - *((unsigned int*)&crypt_key[i])))
		{
			if (!(((unsigned int*)binary)[1] - ((unsigned int*)&crypt_key[i])[1] ) &&
				!(((unsigned int*)binary)[2] - ((unsigned int*)&crypt_key[i])[2] ) &&
				!(((unsigned int*)binary)[3] - ((unsigned int*)&crypt_key[i])[3] ) )
			return 1;
		}
	}

	return 0;
#endif
}

/*********************************************************************************
 * In this code, we always do exact compare, so if this function is called, it
 * simply returns true.
 *********************************************************************************/
static int md5_gen_cmp_exact(char *source, int index)
{
#ifdef MMX_COEF
	return 1;
#else
	return 1;
#endif
}

/*********************************************************************************
 * There was 'something' that was possibly hit. Now john will ask us to check
 * each one of the data items, for an 'exact' match.
 *********************************************************************************/
static int md5_gen_cmp_one(void *binary, int index) 
{
#ifdef MMX_COEF
	unsigned int idx = ( ((unsigned)index)>>(MMX_COEF>>1));
	return((((ARCH_WORD_32 *)binary)[0] == ((ARCH_WORD_32 *)&(crypt_key[idx]))[0*MMX_COEF+(index&(MMX_COEF-1))]) &&
			(((ARCH_WORD_32 *)binary)[1] == ((ARCH_WORD_32 *)&(crypt_key[idx]))[1*MMX_COEF+(index&(MMX_COEF-1))]) &&
			(((ARCH_WORD_32 *)binary)[2] == ((ARCH_WORD_32 *)&(crypt_key[idx]))[2*MMX_COEF+(index&(MMX_COEF-1))]) &&
			(((ARCH_WORD_32 *)binary)[3] == ((ARCH_WORD_32 *)&(crypt_key[idx]))[3*MMX_COEF+(index&(MMX_COEF-1))])
		);
#else
	if (!(*((unsigned int*)binary) - *((unsigned int*)&crypt_key[index])) &&
		!(((unsigned int*)binary)[1] - ((unsigned int*)&crypt_key[index])[1] ) &&
		!(((unsigned int*)binary)[2] - ((unsigned int*)&crypt_key[index])[2] ) &&
		!(((unsigned int*)binary)[3] - ((unsigned int*)&crypt_key[index])[3] ) )
		return 1;
	return 0;
#endif
}

/*********************************************************************************
 *********************************************************************************
 *  This is the real 'engine'.  It simply calls functions one
 *  at a time from the array of functions.
 *********************************************************************************
 *********************************************************************************/
static void md5_gen_crypt_all(int count)
{
  // get plaintext input in saved_key put it into ciphertext crypt_key
	int i;
	m_count = count;

	if (store_keys_normal_but_precompute_md5_to_output2 && store_keys_normal_but_precompute_md5_to_output2_dirty)
	{
		store_keys_normal_but_precompute_md5_to_output2_dirty = 0;
		MD5GenBaseFunc__clean_input2();
		MD5GenBaseFunc__append_keys2();
		MD5GenBaseFunc__crypt2();

		if (store_keys_normal_but_precompute_md5_to_output2_base16_to_input1)
		{
			MD5GenBaseFunc__clean_input();
			MD5GenBaseFunc__append_from_last_output2_to_input1_as_base16();
		}
		if (store_keys_normal_but_precompute_md5_to_output2_base16_to_input1_offset32)
		{
			MD5GenBaseFunc__clean_input();
			MD5GenBaseFunc__set_input_len_32();
			MD5GenBaseFunc__append_from_last_output2_to_input1_as_base16();
		}
	}

	for (i = 0; i<ARRAY_COUNT(md5_gen_FUNCTIONS) && md5_gen_FUNCTIONS[i]; ++i)
		(*md5_gen_FUNCTIONS[i])();
}

/*********************************************************************************
 * 'normal' hashing functions
 *********************************************************************************/
static int md5_gen_binary_hash_0(void * binary) { return ((ARCH_WORD_32 *)binary)[0] & 0xf; }
static int md5_gen_binary_hash_1(void * binary) { return ((ARCH_WORD_32 *)binary)[0] & 0xff; }
static int md5_gen_binary_hash_2(void * binary) { return ((ARCH_WORD_32 *)binary)[0] & 0xfff; }
static int md5_gen_binary_hash_3(void * binary) { return ((ARCH_WORD_32 *)binary)[0] & 0xffff; }
static int md5_gen_binary_hash_4(void * binary) { return ((ARCH_WORD_32 *)binary)[0] & 0xfffff; }


int md5_gen_get_hash_0(int index)
{
#ifdef MMX_COEF
	unsigned int idx = ( ((unsigned)index)>>(MMX_COEF>>1));
	return ((ARCH_WORD_32 *)&(crypt_key[idx]))[index&(MMX_COEF-1)] & 0xf;
#else
	return ((ARCH_WORD_32 *)&(crypt_key[index]))[0] & 0xf;
#endif
}

int md5_gen_get_hash_1(int index)
{
#ifdef MMX_COEF
	unsigned int idx = ( ((unsigned)index)>>(MMX_COEF>>1));
	return ((ARCH_WORD_32 *)&(crypt_key[idx]))[index&(MMX_COEF-1)] & 0xff;
#else
	return ((ARCH_WORD_32 *)&(crypt_key[index]))[0] & 0xff;
#endif
}

int md5_gen_get_hash_2(int index)
{
#ifdef MMX_COEF
	unsigned int idx = ( ((unsigned)index)>>(MMX_COEF>>1));
	return ((ARCH_WORD_32 *)&(crypt_key[idx]))[index&(MMX_COEF-1)] & 0xfff;
#else
	return ((ARCH_WORD_32 *)&(crypt_key[index]))[0] & 0xfff;
#endif
}

int md5_gen_get_hash_3(int index)
{
#ifdef MMX_COEF
	unsigned int idx = ( ((unsigned)index)>>(MMX_COEF>>1));
	return ((ARCH_WORD_32 *)&(crypt_key[idx]))[index&(MMX_COEF-1)] & 0xffff;
#else
	return ((ARCH_WORD_32 *)&(crypt_key[index]))[0] & 0xffff;
#endif
}
int md5_gen_get_hash_4(int index)
{
#ifdef MMX_COEF
	unsigned int idx = ( ((unsigned)index)>>(MMX_COEF>>1));
	return ((ARCH_WORD_32 *)&(crypt_key[idx]))[index&(MMX_COEF-1)] & 0xfffff;
#else
	return ((ARCH_WORD_32 *)&(crypt_key[index]))[0] & 0xfffff;
#endif
}

/*********************************************************************************
 * 'normal' get salt function. We simply return a pointer past the '$' char
 *********************************************************************************/
static void *get_salt(char *ciphertext)
{
	static char Salt[SALT_SIZE+1];
	memset(Salt, 0, SALT_SIZE+1);
	strncpy(Salt, &ciphertext[md5_gen_SALT_OFFSET], SALT_SIZE);
	Salt[SALT_SIZE] = 0;
	if (md5_gen_salt_as_hex)
	{
		// Do not 'worry' about SSE/MMX,  Only do 'generic' md5.  This is ONLY done
		// at the start of the run.  We will NEVER see this run, once john starts.
		MD5_CTX ctx;
		unsigned char Buf[16];
		char *cpo;
		unsigned char *cpi;
		int i;
		MD5_Init(&ctx);
		MD5_Update(&ctx, Salt, strlen(Salt));
		MD5_Final(Buf, &ctx);
		cpo = Salt;
		memset(Salt, 0, SALT_SIZE+1);
		cpi = Buf;
		for (i = 0; i < 16; ++i)
		{
			*cpo++ = itoa16[(*cpi)>>4];
			*cpo++ = itoa16[(*cpi)&0xF];
			++cpi;
		}
		*cpo = 0;
	}
	return Salt;
}
/*********************************************************************************
 * 'special' get salt function for phpass. We return the 8 bytes salt, followed by
 * the 1 byte loop count.  'normally' in phpass format, that order is reversed.
 * we do it this way, since our 'primitive' functions would not know to treat the
 * salt any differently for phpass.  Thus the primitives are told about the first
 * 8 bytes (and not the full 9).  But the phpass crypt function uses that 9th byte.
 *********************************************************************************/
static void * phpassmd5_salt(char *ciphertext)
{
	static unsigned char salt[10];
	// store off the 'real' 8 bytes of salt
	memcpy(salt, &ciphertext[34+1], 8);
	// append the 1 byte of loop count information.
	salt[8] = ciphertext[34];
	salt[9]=0;
	return salt;
}

/*********************************************************************************
 * This returns a 'decent' hash for salted hashes (where they are unk arbritray
 * text.  Many of the salts are from ' ' to 0x7E.  This function works well for 
 * them. NOTE we have to KNOW that a format is not salted, and ALWAYS return 0
 * for them.  If not, even though they are listed as not salted, JOHN will have
 * problems, and will treat them 'like' salted (i.e. slows john down A LOT).
 *********************************************************************************/
static int salt_hash(void *salt)
{
	int x,y;
	if (!salt || *((char*)salt) == 0)
		return 0;
	x = ((ARCH_WORD_32)(ARCH_INDEX(((unsigned char *)salt)[0])-' '));
	y = (((ARCH_WORD_32)(ARCH_INDEX(((unsigned char *)salt)[1])-' ')<<4));
	return (x+y) & 0x3FF;
}

/*********************************************************************************
 * Salt for phpass. Note, the above would have probably also worked, but this was
 * what was originally IN phpass.
 *********************************************************************************/
static int phpass_salt_hash(void *salt)
{
	return *((ARCH_WORD *)salt) & 0x3FF;
}

/*********************************************************************************
 * Gets the binary value from a base-16 hash.
 *********************************************************************************/
static void *md5_gen_binary(char *ciphertext)
{
	static char realcipher[BINARY_SIZE];
	int i;

	for(i=0;i<BINARY_SIZE;i++)
	{
		realcipher[i] = 
			atoi16[ARCH_INDEX(ciphertext[i*2+md5_gen_HASH_OFFSET])]*16 + 
			atoi16[ARCH_INDEX(ciphertext[i*2+md5_gen_HASH_OFFSET+1])];
	}
	return (void *)realcipher;
}
/*********************************************************************************
 * Gets the binary value from a base-64 hash (such as phpass)
 *********************************************************************************/
static void * md5_gen_binary_b64(char *ciphertext) 
{
		int i;
		unsigned sixbits;
		static unsigned char b[16];
		int bidx=0;
		char *pos;

		// ugly code, but only called one time (at program load, 
		// once for each candidate pass hash).

		pos = ciphertext;
		while (*pos++ != ')') 
			;
		for (i = 0; i < 5; ++i)
		{
				sixbits = atoi64[ARCH_INDEX(*pos++)];
				b[bidx] = sixbits;
				sixbits = atoi64[ARCH_INDEX(*pos++)];
				b[bidx++] |= (sixbits<<6);
				sixbits >>= 2;
				b[bidx] = sixbits;
				sixbits = atoi64[ARCH_INDEX(*pos++)];
				b[bidx++] |= (sixbits<<4);
				sixbits >>= 4;
				b[bidx] = sixbits;
				sixbits = atoi64[ARCH_INDEX(*pos++)];
				b[bidx++] |= (sixbits<<2);
		}
		sixbits = atoi64[ARCH_INDEX(*pos++)];
		b[bidx] = sixbits;
		sixbits = atoi64[ARCH_INDEX(*pos++)];
		b[bidx] |= (sixbits<<6);
		return b;
}

/*********************************************************************************
 * Here is the main mdg_generic fmt_main. NOTE in it's default settings, it is
 * ready to handle base-16 hashes.  The phpass stuff will be linked in later, IF
 * needed.
 *********************************************************************************/
struct fmt_main fmt_MD5gen = 
{
	{
		FORMAT_LABEL,
		FORMAT_NAME,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		PLAINTEXT_LENGTH,
		BINARY_SIZE,
		SALT_SIZE,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT,
		md5_gen_tests
	}, {
		md5_gen_init,
		valid,
		fmt_default_split,
		md5_gen_binary,
		get_salt,
		{
			md5_gen_binary_hash_0,
			md5_gen_binary_hash_1,
			md5_gen_binary_hash_2,
			md5_gen_binary_hash_3,
			md5_gen_binary_hash_4
		},
		salt_hash,
		md5_gen_set_salt,
		md5_gen_set_key,
		md5_gen_get_key,
		fmt_default_clear_keys,
		md5_gen_crypt_all,
		{
			md5_gen_get_hash_0,
			md5_gen_get_hash_1,
			md5_gen_get_hash_2,
			md5_gen_get_hash_3,
			md5_gen_get_hash_4
		},
		md5_gen_cmp_all,
		md5_gen_cmp_one,
		md5_gen_cmp_exact
	}
};

/**************************************************************
 **************************************************************
 **************************************************************
 **************************************************************
 *  These are the md5 'primitive' functions that are used by
 *  the build-in expressions, and by the expression generator
 *  They load passwords, salts, user ids, do crypts, convert
 *  crypts into base-16, etc.  They are pretty encompassing, 
 *  and have been found to be able to do most anything with
 *  a standard 'base-16' md5 hash, salted or unsalted that 
 *  fits a 'simple' php style expression.
 **************************************************************
 **************************************************************
 **************************************************************
 *************************************************************/

//#include "md5_gen_fmt_dbd_stuff.hxx"

/**************************************************************
 * MD5_GEN primitive helper function
 * This is a 'fake' function. It can ONLY be used as the 1st
 * function, and only if the expression fits certain 'forms'
 * and if certain other coding design is done.  But IF it can
 * be used, it replaces the intial clean_input() and load_keys()
 * calls, and eliminates a lot of buffer copy overhead.
 *************************************************************/
void MD5GenBaseFunc__InitialLoadKeysToInput()
{
	// we only want a function pointer here.  We NEVER call this 
	// function, just use it to 'signal' the code to load keys
	// directly and to 'get' keys directly from input #1 so as
	// to save buffer copies to and from 'saved_keys'
}
void MD5GenBaseFunc__InitialLoadKeys_md5crypt_ToOutput2()
{
	// not a 'real' function.  Used to 'preload' a md5 crypt
	// for parms like md5(md5($p).%s) so that we load ALL of the
	// inner md5($p) only once, then re-used them over and over again
}
void MD5GenBaseFunc__InitialLoadKeys_md5crypt_ToOutput2_Base16_to_Input1()
{
}
void MD5GenBaseFunc__InitialLoadKeys_md5crypt_ToOutput2_Base16_to_Input1_offset32()
{
}

void MD5GenBaseFunc__PHPassSetup()
{
	// Not a real function, but tells us to use a different salt function
}

/**************************************************************
 * MD5_GEN primitive helper function
 * Clears the input variable, and input 'lengths'
 *************************************************************/
void MD5GenBaseFunc__clean_input()
{
#if defined (MMX_COEF)
	memset(input_buf, 0, sizeof(input_buf));
	memset(total_len, 0, sizeof(total_len));
#else
	unsigned i;
	for (i = 0; i < MAX_KEYS_PER_CRYPT; ++i)
	{
		//input_buf[i][0] = 0;
		total_len[i] = 0;
	}
#endif
}

void MD5GenBaseFunc__clean_input_kwik()
{
#if defined (MMX_COEF)
//	memset(input_buf, 0, sizeof(input_buf));
	memset(total_len, 0, sizeof(total_len));
#else
	unsigned i;
	for (i = 0; i < MAX_KEYS_PER_CRYPT; ++i)
	{
		//input_buf[i][0] = 0;
		total_len[i] = 0;
	}
#endif
}

/**************************************************************
 * MD5_GEN primitive helper function
 * Clears the 2nd input variable, and 2nd input 'lengths'
 *************************************************************/
void MD5GenBaseFunc__clean_input2()
{
#if defined (MMX_COEF)
	memset(input_buf2, 0, sizeof(input_buf2));
	memset(total_len2, 0, sizeof(total_len2));
#else
	unsigned i;
	for (i = 0; i < MAX_KEYS_PER_CRYPT; ++i)
	{
		//input_buf2[i][0] = 0;
		total_len2[i] = 0;
	}
#endif
}
void MD5GenBaseFunc__clean_input2_kwik()
{
#if defined (MMX_COEF)
	//memset(input_buf2, 0, sizeof(input_buf2));
	memset(total_len2, 0, sizeof(total_len2));
#else
	unsigned i;
	for (i = 0; i < MAX_KEYS_PER_CRYPT; ++i)
	{
		//input_buf2[i][0] = 0;
		total_len2[i] = 0;
	}
#endif
}

/**************************************************************
 * MD5_GEN primitive helper function
 * Appends all keys to the end of the input variables, and 
 * updates lengths
 *************************************************************/
void MD5GenBaseFunc__append_keys()
{
#if defined (MMX_COEF)
	unsigned i, j, index, kp;
	ARCH_WORD_32 *po, *pi;
	for (index = 0; index < m_count; ++index)
	{
		unsigned idx, stop, len = saved_key_len[index];
		idx = ( ((unsigned)index)>>(MMX_COEF>>1));
		j = (total_len[idx] >> ((32/MMX_COEF)*(index&(MMX_COEF-1)))) & 0xFF;
		stop = len+j;
		kp = 0;
		if (!j)
		{
			unsigned cnt = len>>2;
			pi = (ARCH_WORD_32 *)&(saved_key[index]);
			po = &((ARCH_WORD_32 *)(&(input_buf[idx])))[index&(MMX_COEF-1)];
			for (i = 0; i < cnt; ++i)
			{
				*po = *pi++;
				po += MMX_COEF;
				j += 4;
				kp += 4;
			}
		}
		for(;j<stop;j++)
			input_buf[idx][GETPOS(j, index&(MMX_COEF-1))] = saved_key[index][kp++];
		input_buf[idx][GETPOS(j, index&(MMX_COEF-1))] = 0x80;
		total_len[idx] += ( len << ((32/MMX_COEF)*(index&(MMX_COEF-1))) );
	}
#else
	unsigned j;
	for (j = 0; j < m_count; ++j)
	{
		memcpy(&input_buf[j][total_len[j]], saved_key[j], saved_key_len[j]);
		total_len[j] += saved_key_len[j];
	}
#endif
}

/**************************************************************
 * MD5_GEN primitive helper function
 * Appends all keys to the end of the 2nd input variables, and 
 * updates lengths
 *************************************************************/
void MD5GenBaseFunc__append_keys2()
{
#if defined (MMX_COEF)
	unsigned i, j, index, kp;
	ARCH_WORD_32 *po, *pi;
	for (index = 0; index < m_count; ++index)
	{
		unsigned idx, stop, len = saved_key_len[index];
		idx = ( ((unsigned)index)>>(MMX_COEF>>1));
		j = (total_len2[idx] >> ((32/MMX_COEF)*(index&(MMX_COEF-1)))) & 0xFF;
		stop = len+j;
		kp = 0;
		if (!j)
		{
			unsigned cnt = len>>2;
			pi = (ARCH_WORD_32 *)&(saved_key[index]);
			po = &((ARCH_WORD_32 *)(&(input_buf2[idx])))[index&(MMX_COEF-1)];
			for (i = 0; i < cnt; ++i)
			{
				*po = *pi++;
				po += MMX_COEF;
				j += 4;
				kp += 4;
			}
		}
		for(;j<stop;j++)
			input_buf2[idx][GETPOS(j, index&(MMX_COEF-1))] = saved_key[index][kp++];
		input_buf2[idx][GETPOS(j, index&(MMX_COEF-1))] = 0x80;
		total_len2[idx] += ( len << ((32/MMX_COEF)*(index&(MMX_COEF-1))) );
	}
#else
	unsigned j;
	for (j = 0; j < m_count; ++j)
	{
		memcpy(&input_buf2[j][total_len2[j]], saved_key[j], saved_key_len[j]);
		total_len2[j] += saved_key_len[j];
	}
#endif
}

/**************************************************************
 * MD5_GEN primitive helper function
 * Appends the salt to the end of the input variables, and 
 * updates lengths
 *************************************************************/
void MD5GenBaseFunc__append_salt()
{
#if defined (MMX_COEF)
	unsigned i, j, k, cnt;
	cnt = ( ((unsigned)m_count+MMX_COEF-1)>>(MMX_COEF>>1));
	for (i = 0; i < cnt; ++i)
	{
		for (j = 0; j < MMX_COEF; ++j)
		{
			unsigned start_len = (total_len[i] >> ((32/MMX_COEF)*j)) & 0xFF;
			for (k = 0; k < saltlen; ++k)
				input_buf[i][GETPOS((k+start_len), j)] = cursalt[k];
			input_buf[i][GETPOS((saltlen+start_len), j)] = 0x80;
			total_len[i] += ( saltlen << ( ( (32/MMX_COEF) * j ) ));
		}
	}
#else
	unsigned j;
	for (j = 0; j < m_count; ++j)
	{
		memcpy(&input_buf[j][total_len[j]], cursalt, saltlen);
		total_len[j] += saltlen;
	}
#endif
}

extern void MD5GenBaseFunc__set_input_len_32()
{
#if defined (MMX_COEF)
	unsigned i, j, cnt;
	cnt = ( ((unsigned)m_count+MMX_COEF-1)>>(MMX_COEF>>1));
	for (i = 0; i < cnt; ++i)
	{
		total_len[i] = 0;
		for (j = 0; j < MMX_COEF; ++j)
			total_len[i] += ( 32 << ( ( (32/MMX_COEF) * j ) ));
	}
#else
	unsigned j;
	for (j = 0; j < m_count; ++j)
	{
		total_len[j] = 32;
	}
#endif
}

extern void MD5GenBaseFunc__set_input2_len_32()
{
#if defined (MMX_COEF)
	unsigned i, j, cnt;
	cnt = ( ((unsigned)m_count+MMX_COEF-1)>>(MMX_COEF>>1));
	for (i = 0; i < cnt; ++i)
	{
		total_len2[i] = 0;
		for (j = 0; j < MMX_COEF; ++j)
			total_len2[i] += ( 32 << ( ( (32/MMX_COEF) * j ) ));
	}
#else
	unsigned j;
	for (j = 0; j < m_count; ++j)
	{
		total_len2[j] = 32;
	}
#endif
}

void MD5GenBaseFunc__set_input_len_64()
{
#if defined (MMX_COEF)
	unsigned i, j, cnt;
	cnt = ( ((unsigned)m_count+MMX_COEF-1)>>(MMX_COEF>>1));
	for (i = 0; i < cnt; ++i)
	{
		total_len[i] = 0;
		for (j = 0; j < MMX_COEF; ++j)
			total_len[i] += ( 64 << ( ( (32/MMX_COEF) * j ) ));
	}
#else
	unsigned j;
	for (j = 0; j < m_count; ++j)
	{
		total_len[j] = 64;
	}
#endif
}
void MD5GenBaseFunc__set_input2_len_64()
{
#if defined (MMX_COEF)
	unsigned i, j, cnt;
	cnt = ( ((unsigned)m_count+MMX_COEF-1)>>(MMX_COEF>>1));
	for (i = 0; i < cnt; ++i)
	{
		total_len2[i] = 0;
		for (j = 0; j < MMX_COEF; ++j)
			total_len2[i] += ( 64 << ( ( (32/MMX_COEF) * j ) ));
	}
#else
	unsigned j;
	for (j = 0; j < m_count; ++j)
	{
		total_len2[j] = 64;
	}
#endif
}

/**************************************************************
 * MD5_GEN primitive helper function
 * Appends the salt to the end of the 2nd input variables, and 
 * updates lengths
 *************************************************************/
void MD5GenBaseFunc__append_salt2()
{
#if defined (MMX_COEF)
	unsigned i, j, k, cnt;
	cnt = ( ((unsigned)m_count+MMX_COEF-1)>>(MMX_COEF>>1));
	for (i = 0; i < cnt; ++i)
	{
		for (j = 0; j < MMX_COEF; ++j)
		{
			unsigned start_len = (total_len2[i] >> ((32/MMX_COEF)*j)) & 0xFF;
			for (k = 0; k < saltlen; ++k)
				input_buf2[i][GETPOS((k+start_len), j)] = cursalt[k];
			input_buf2[i][GETPOS((saltlen+start_len), j)] = 0x80;
			total_len2[i] += ( saltlen << ( ( (32/MMX_COEF) * j ) ));
		}
	}
#else
	unsigned j;
	for (j = 0; j < m_count; ++j)
	{
		memcpy(&input_buf2[j][total_len2[j]], cursalt, saltlen);
		total_len2[j] += saltlen;
	}
#endif
}

void MD5GenBaseFunc__append_input_from_input2()
{
#if defined (MMX_COEF)
	unsigned i, j, k, cnt;
	cnt = ( ((unsigned)m_count+MMX_COEF-1)>>(MMX_COEF>>1));
	for (i = 0; i < cnt; ++i)
	{
		for (j = 0; j < MMX_COEF; ++j)
		{
			unsigned start_len = (total_len[i] >> ((32/MMX_COEF)*j)) & 0xFF;
			unsigned len1 = (total_len2[i] >> ((32/MMX_COEF)*j)) & 0xFF;
			for (k = 0; k < len1; ++k)
				input_buf[i][GETPOS((k+start_len), j)] = input_buf2[i][GETPOS(k,j)];
			input_buf[i][GETPOS((len1+start_len), j)] = 0x80;
			total_len[i] += ( len1 << ( ( (32/MMX_COEF) * j ) ));
		}
	}
#else
	unsigned j;
	for (j = 0; j < m_count; ++j)
	{
		memcpy(&input_buf[j][total_len[j]], input_buf2[j], total_len2[j]);
		total_len[j] += total_len2[j];
	}
#endif
}

void MD5GenBaseFunc__append_input2_from_input()
{
#if defined (MMX_COEF)
	unsigned i, j, k, cnt;
	cnt = ( ((unsigned)m_count+MMX_COEF-1)>>(MMX_COEF>>1));
	for (i = 0; i < cnt; ++i)
	{
		for (j = 0; j < MMX_COEF; ++j)
		{
			unsigned start_len = (total_len2[i] >> ((32/MMX_COEF)*j)) & 0xFF;
			unsigned len1 = (total_len[i] >> ((32/MMX_COEF)*j)) & 0xFF;
			for (k = 0; k < len1; ++k)
				input_buf2[i][GETPOS((k+start_len), j)] = input_buf[i][GETPOS(k,j)];
			input_buf2[i][GETPOS((len1+start_len), j)] = 0x80;
			total_len2[i] += ( len1 << ( ( (32/MMX_COEF) * j ) ));
		}
	}
#else
	unsigned j;
	for (j = 0; j < m_count; ++j)
	{
		memcpy(&input_buf2[j][total_len2[j]], input_buf[j], total_len[j]);
		total_len2[j] += total_len[j];
	}
#endif
}

/**************************************************************
 * MD5_GEN primitive helper function
 * Encrypts the data in the first input field. The data is
 * still in the binary encrypted format, in the crypt_key.
 * we do not yet convert to base-16.  This is so we can output
 * as base-16, or later, if we add base-64, we can output to
 * that format instead.  Some functions do NOT change from
 * the binary format (such as phpass). Thus if we are doing
 * something like phpass, we would NOT want the conversion
 * to happen at all
 *************************************************************/
void MD5GenBaseFunc__crypt()
{
#if defined (MMX_COEF)
	unsigned i, cnt;
	cnt = ( ((unsigned)m_count+MMX_COEF-1)>>(MMX_COEF>>1));
	for (i = 0; i < cnt; ++i)
		mdfivemmx((unsigned char*)&(crypt_key[i]), (unsigned char*)&(input_buf[i]), total_len[i]);
#else
	unsigned i;
	for (i = 0; i < m_count; ++i)
	{
		MD5_Init( &ctx );
		MD5_Update( &ctx, input_buf[i], total_len[i] );
		MD5_Final( (unsigned char*)&(crypt_key[i]), &ctx);
	}
#endif
}

/**************************************************************
 * MD5_GEN primitive helper function
 * Special crypt to handle the 'looping' needed for phpass
 *************************************************************/
void MD5GenBaseFunc__PHPassCrypt()
{
	unsigned Lcount;
	Lcount = atoi64[ARCH_INDEX(cursalt[8])];
	if (Lcount < 7 || Lcount > 31)
		exit(fprintf(stderr, "Error, invalid loop byte in a php salt\n"));
	Lcount = (1<<Lcount);

	MD5GenBaseFunc__clean_input();

	// First 'round' is md5 of ($s.$p)  
	MD5GenBaseFunc__append_salt();
	MD5GenBaseFunc__append_keys();

	// The later rounds (variable number, based upon the salt's first byte)
	//   are ALL done as 16 byte md5 result of prior hash, with the password appeneded

	// crypt, and put the 'raw' 16 byte raw crypt data , into the
	// input buffer.  We will then append the keys to that, and never
	// have to append the keys again (we just make sure we do NOT adjust
	// the amount of bytes to md5 from this point no
	MD5GenBaseFunc__crypt_to_input_raw();
	// Now append the pass
	MD5GenBaseFunc__append_keys();

	// NOTE last we do 1 less than the required number of crypts in our loop
	while(--Lcount)
		MD5GenBaseFunc__crypt_to_input_raw_Overwrite_NoLen();

	// final crypt is to the normal 'output' buffer, since john uses that to find 'hits'.
	MD5GenBaseFunc__crypt();
}

/**************************************************************
 * MD5_GEN primitive helper function
 * Encrypts the data in the 2nd input field into crypt_keys2.
 *************************************************************/
void MD5GenBaseFunc__crypt2()
{
#if defined (MMX_COEF)
	unsigned i, cnt = ( ((unsigned)m_count+MMX_COEF-1)>>(MMX_COEF>>1));
	for (i = 0; i < cnt; ++i)
		mdfivemmx((unsigned char*)&(crypt_key2[i]), (unsigned char*)&(input_buf2[i]), total_len2[i]);
#else
	unsigned i;
	for (i = 0; i < m_count; ++i)
	{
		MD5_Init( &ctx );
		MD5_Update( &ctx, input_buf2[i], total_len2[i] );
		MD5_Final( (unsigned char*)&(crypt_key2[i]), &ctx);
	}
#endif
}

/**************************************************************
 * MD5_GEN primitive helper function
 * Encrypts the data in the 1st input field into crypt_keys2.
 *************************************************************/
void MD5GenBaseFunc__crypt_in1_to_out2()
{
#if defined (MMX_COEF)
	unsigned i, cnt = ( ((unsigned)m_count+MMX_COEF-1)>>(MMX_COEF>>1));
	for (i = 0; i < cnt; ++i)
		mdfivemmx((unsigned char*)&(crypt_key2[i]), (unsigned char*)&(input_buf[i]), total_len[i]);
#else
	unsigned i;
	for (i = 0; i < m_count; ++i)
	{
		MD5_Init( &ctx );
		MD5_Update( &ctx, input_buf[i], total_len[i] );
		MD5_Final( (unsigned char*)&(crypt_key2[i]), &ctx);
	}
#endif
}

/**************************************************************
 * MD5_GEN primitive helper function
 * Encrypts the data in the 2nd input field into crypt_keys.
 *************************************************************/
void MD5GenBaseFunc__crypt_in2_to_out1()
{
#if defined (MMX_COEF)
	unsigned i, cnt = ( ((unsigned)m_count+MMX_COEF-1)>>(MMX_COEF>>1));
	for (i = 0; i < cnt; ++i)
		mdfivemmx((unsigned char*)&(crypt_key[i]), (unsigned char*)&(input_buf2[i]), total_len2[i]);
#else
	unsigned i;
	for (i = 0; i < m_count; ++i)
	{
		MD5_Init( &ctx );
		MD5_Update( &ctx, input_buf2[i], total_len2[i] );
		MD5_Final( (unsigned char*)&(crypt_key[i]), &ctx);
	}
#endif
}

void MD5GenBaseFunc__crypt_to_input_raw()
{
#if defined (MMX_COEF)
	unsigned i, cnt;
	cnt = ( ((unsigned)m_count+MMX_COEF-1)>>(MMX_COEF>>1));
	for (i = 0; i < cnt; ++i)
	{
		unsigned char *cpib = input_buf[i];
		unsigned char *cpck = crypt_key[i];
		mdfivemmx(cpck, cpib, total_len[i]);
		memset(cpib+sizeof(crypt_key[0]), 0, sizeof(input_buf[0])-sizeof(crypt_key[0]));
		memcpy(cpib, cpck, sizeof(crypt_key[0]));
		cpib[GETPOS(0x10, 0)] = 0x80;
		cpib[GETPOS(0x10, 1)] = 0x80;
		cpib[GETPOS(0x10, 2)] = 0x80;
		cpib[GETPOS(0x10, 3)] = 0x80;
#if (MMX_COEF==4)
		total_len[i] = 0x10101010;
#else
		total_len[i] = 0x100010;
#endif
	}
#else
	unsigned i;
	for (i = 0; i < m_count; ++i)
	{
		MD5_Init( &ctx );
		MD5_Update( &ctx, input_buf[i], total_len[i] );
		// NOTE we do NOT have null terminated string here.  THUS
		// we need to change all of the strcat(buf) to do strcpy(&buf[len])
		MD5_Final( (unsigned char*)&(input_buf[i]), &ctx);
		total_len[i] = 0x10;
	}
#endif
}
void MD5GenBaseFunc__crypt_to_input_raw_Overwrite_NoLen()
{
#if defined (MMX_COEF)
	unsigned i, cnt;
	cnt = ( ((unsigned)m_count+MMX_COEF-1)>>(MMX_COEF>>1));
	for (i = 0; i < cnt; ++i)
		mdfivemmx((unsigned char*)&(input_buf[i]), (unsigned char*)&(input_buf[i]), total_len[i]);
#else
	unsigned i;
	for (i = 0; i < m_count; ++i)
	{
		MD5_Init( &ctx );
		MD5_Update( &ctx, input_buf[i], total_len[i] );
		// NOTE we do NOT have null terminated string here.  THUS
		// we need to change all of the strcat(buf) to do strcpy(&buf[len])
		MD5_Final( (unsigned char*)&(input_buf[i]), &ctx);
	}
#endif
}

void MD5GenBaseFunc__overwrite_salt_to_input1_no_size_fix()
{
#if defined (MMX_COEF)
	unsigned i, j, k, cnt;
	cnt = ( ((unsigned)m_count+MMX_COEF-1)>>(MMX_COEF>>1));
	for (i = 0; i < cnt; ++i)
	{
		for (j = 0; j < MMX_COEF; ++j)
		{
			for (k = 0; k < saltlen; ++k)
				input_buf[i][GETPOS(k, j)] = cursalt[k];
		}
	}
#else
	unsigned j;
	for (j = 0; j < m_count; ++j)
	{
		memcpy(input_buf[j], cursalt, saltlen);
	}
#endif
}
void MD5GenBaseFunc__overwrite_salt_to_input2_no_size_fix()
{
#if defined (MMX_COEF)
	unsigned i, j, k, cnt;
	cnt = ( ((unsigned)m_count+MMX_COEF-1)>>(MMX_COEF>>1));
	for (i = 0; i < cnt; ++i)
	{
		for (j = 0; j < MMX_COEF; ++j)
		{
			for (k = 0; k < saltlen; ++k)
				input_buf2[i][GETPOS(k, j)] = cursalt[k];
		}
	}
#else
	unsigned j;
	for (j = 0; j < m_count; ++j)
	{
		memcpy(input_buf2[j], cursalt, saltlen);
	}
#endif
}


/**************************************************************
 * MD5_GEN primitive helper function
 * This will take the data stored in the crypt_keys (the encrypted
 * 'first' key variable), and use a base-16 text formatting, and
 * append this to the first input buffer (adjusting the lengths)
 *************************************************************/
void MD5GenBaseFunc__append_from_last_output_as_base16()
{
#if defined (MMX_COEF)
	unsigned index, idx, k, cnt;
	cnt = ( ((unsigned)m_count+MMX_COEF-1)>>(MMX_COEF>>1));
	for (index = 0; index < m_count; ++index)
	{
		idx = ( ((unsigned)index)>>(MMX_COEF>>1));
		// This is the 'actual' work.
		unsigned ip = (total_len[idx] >> ((32/MMX_COEF)*(index&(MMX_COEF-1)))) & 0xFF;
		for (k = 0; k < 16; ++k)
		{
			unsigned char v = crypt_key[idx][GETPOS(k, index&(MMX_COEF-1))];
			input_buf[idx][GETPOS(ip+(k<<1), index&(MMX_COEF-1))] = itoa16[v>>4];
			input_buf[idx][GETPOS(ip+(k<<1)+1, index&(MMX_COEF-1))] = itoa16[v&0xF];
		}
		input_buf[idx][GETPOS(ip+32, index&(MMX_COEF-1))] = 0x80;
		total_len[idx] += ( 32 << ( ( (32/MMX_COEF) * (index&(MMX_COEF-1)) ) ));
	}
#else
	unsigned i, j;

	for (i = 0; i < m_count; ++i)
	{
		unsigned char *cp = &input_buf[i][total_len[i]];
		for (j = 0; j < 16; ++j)
		{
			*cp++ = itoa16[crypt_key[i][j]>>4];
			*cp++ = itoa16[crypt_key[i][j]&0xF];
		}
		*cp = 0;
		total_len[i] += 32;
	}
#endif
}

/**************************************************************
 * MD5_GEN primitive helper function
 * This will take the data stored in the crypt_keys2 (the encrypted
 * 'second' key variable), and base-16 appends to the 2nd input
 *************************************************************/
void MD5GenBaseFunc__append_from_last_output2_as_base16()
{
#if defined (MMX_COEF)
	unsigned index, idx, k, cnt;
	cnt = ( ((unsigned)m_count+MMX_COEF-1)>>(MMX_COEF>>1));
	for (index = 0; index < m_count; ++index)
	{
		idx = ( ((unsigned)index)>>(MMX_COEF>>1));
		// This is the 'actual' work.
		unsigned ip = (total_len2[idx] >> ((32/MMX_COEF)*(index&(MMX_COEF-1)))) & 0xFF;
		for (k = 0; k < 16; ++k)
		{
			unsigned char v = crypt_key2[idx][GETPOS(k, index&(MMX_COEF-1))];
			input_buf2[idx][GETPOS(ip+(k<<1), index&(MMX_COEF-1))] = itoa16[v>>4];
			input_buf2[idx][GETPOS(ip+(k<<1)+1, index&(MMX_COEF-1))] = itoa16[v&0xF];
		}
		input_buf2[idx][GETPOS(ip+32, index&(MMX_COEF-1))] = 0x80;
		total_len2[idx] += ( 32 << ( ( (32/MMX_COEF) * (index&(MMX_COEF-1)) ) ));
	}
#else
	unsigned i, j;

	for (i = 0; i < m_count; ++i)
	{
		unsigned char *cp = &input_buf2[i][total_len2[i]];
		for (j = 0; j < 16; ++j)
		{
			*cp++ = itoa16[crypt_key2[i][j]>>4];
			*cp++ = itoa16[crypt_key2[i][j]&0xF];
		}
		*cp = 0;
		total_len2[i] += 32;
	}
#endif
}

/**************************************************************
 * MD5_GEN primitive helper function
 * This will take the data stored in the crypt_keys1 (the encrypted
 * 'first' key variable), and base-16 appends to the 2nd input
 *************************************************************/
void MD5GenBaseFunc__append_from_last_output_to_input2_as_base16()
{
#if defined (MMX_COEF)
/*
	unsigned index, idx, k, cnt, ip, til, idxmod=0;
	unsigned char *CK, *IB2;
	cnt = ( ((unsigned)m_count+MMX_COEF-1)>>(MMX_COEF>>1));
	for (index = 0; index < m_count; ++index)
	{
		idx = ( ((unsigned)index)>>(MMX_COEF>>1));
		CK = crypt_key[idx];
		IB2 = input_buf2[idx];
		// This is the 'actual' work.
		ip = (total_len2[idx] >> ((32/MMX_COEF)*idxmod)) & 0xFF;
		til=ip+32;
		for (k = ip; k < til; k+=2)
		{
			unsigned char v = CK[GETPOS(k, idxmod)];
			IB2[GETPOS(k, idxmod)] = itoa16_shr_04[ARCH_INDEX(v)];
			IB2[GETPOS(k+1, idxmod)] = itoa16_and_0f[ARCH_INDEX(v)];
		}
		IB2[GETPOS(k, idxmod)] = 0x80;
		total_len2[idx] += ( 32 << ( ( (32/MMX_COEF) * idxmod ) ));
		++idxmod;
		idxmod &= (MMX_COEF-1);
	}
*/
	unsigned index, idx, k, cnt;
	cnt = ( ((unsigned)m_count+MMX_COEF-1)>>(MMX_COEF>>1));
	for (index = 0; index < m_count; ++index)
	{
		idx = ( ((unsigned)index)>>(MMX_COEF>>1));
		// This is the 'actual' work.
		unsigned ip = (total_len2[idx] >> ((32/MMX_COEF)*(index&(MMX_COEF-1)))) & 0xFF;
		for (k = 0; k < 16; ++k)
		{
			unsigned char v = crypt_key[idx][GETPOS(k, index&(MMX_COEF-1))];
			input_buf2[idx][GETPOS(ip+(k<<1), index&(MMX_COEF-1))] = itoa16[v>>4];
			input_buf2[idx][GETPOS(ip+(k<<1)+1, index&(MMX_COEF-1))] = itoa16[v&0xF];
		}
		input_buf2[idx][GETPOS(ip+32, index&(MMX_COEF-1))] = 0x80;
		total_len2[idx] += ( 32 << ( ( (32/MMX_COEF) * (index&(MMX_COEF-1)) ) ));
	}
#else
	unsigned i, j;

	for (i = 0; i < m_count; ++i)
	{
		unsigned char *cp = &input_buf2[i][total_len2[i]];
		for (j = 0; j < 16; ++j)
		{
			*cp++ = itoa16[crypt_key[i][j]>>4];
			*cp++ = itoa16[crypt_key[i][j]&0xF];
		}
		*cp = 0;
		total_len2[i] += 32;
	}
#endif
}

/**************************************************************
 * MD5_GEN primitive helper function
 * This will take the data stored in the crypt_keys2 (the encrypted
 * 'second' key variable), and base-16 appends to the 1st input
 *************************************************************/
void MD5GenBaseFunc__append_from_last_output2_to_input1_as_base16()
{
#if defined (MMX_COEF)
	unsigned index, idx, k, cnt;
	cnt = ( ((unsigned)m_count+MMX_COEF-1)>>(MMX_COEF>>1));
	for (index = 0; index < m_count; ++index)
	{
		idx = ( ((unsigned)index)>>(MMX_COEF>>1));
		// This is the 'actual' work.
		unsigned ip = (total_len[idx] >> ((32/MMX_COEF)*(index&(MMX_COEF-1)))) & 0xFF;
		for (k = 0; k < 16; ++k)
		{
			unsigned char v = crypt_key2[idx][GETPOS(k, index&(MMX_COEF-1))];
			input_buf[idx][GETPOS(ip+(k<<1), index&(MMX_COEF-1))] = itoa16[v>>4];
			input_buf[idx][GETPOS(ip+(k<<1)+1, index&(MMX_COEF-1))] = itoa16[v&0xF];
		}
		input_buf[idx][GETPOS(ip+32, index&(MMX_COEF-1))] = 0x80;
		total_len[idx] += ( 32 << ( ( (32/MMX_COEF) * (index&(MMX_COEF-1)) ) ));
	}
#else
	unsigned i, j;

	for (i = 0; i < m_count; ++i)
	{
		unsigned char *cp = &input_buf[i][total_len[i]];
		for (j = 0; j < 16; ++j)
		{
			*cp++ = itoa16[crypt_key2[i][j]>>4];
			*cp++ = itoa16[crypt_key2[i][j]&0xF];
		}
		*cp = 0;
		total_len[i] += 32;
	}
#endif
}


/**************************************************************
 **************************************************************
 * MD5_GEN primitive helper function
 * These are not done yet. Usage of them will exit john with
 * an error message. Some of these are for optimzations (like
 * speeding up phpass, some use 2nd salt and user id, which we
 * have not yet implemented
 **************************************************************
 *************************************************************/

/**************************************************************
 * MD5_GEN primitive helper function
 * overwrites start of input2 from the output1 data using base-16
 * an optimization, if the same thing is done over and over
 * again, such as md5(md5(md5(md5($p))))  There, we would only
 * call the copy and set length once, then simply call copy.
 *************************************************************/
void MD5GenBaseFunc__overwrite_from_last_output_to_input2_as_base16_no_size_fix()
{
	exit(fprintf(stderr, "Error, MD5GenBaseFunc__overwrite_from_last_output_to_input2_as_base16_no_size_fix() primitive has not been implemented\n"));
}
/**************************************************************
 * MD5_GEN primitive helper function
 * overwrites start of input2 from the output2 data using base-16
 *************************************************************/
void MD5GenBaseFunc__overwrite_from_last_output2_as_base16_no_size_fix()
{
	exit(fprintf(stderr, "Error, MD5GenBaseFunc__overwrite_from_last_output2_as_base16_no_size_fix() primitive has not been implemented\n"));
}
/**************************************************************
 * MD5_GEN primitive helper function
 * overwrites start of input1 from the output1 data using base-16
 *************************************************************/
void MD5GenBaseFunc__overwrite_from_last_output_as_base16_no_size_fix()
{
	exit(fprintf(stderr, "Error, MD5GenBaseFunc__overwrite_from_last_output_as_base16_no_size_fix() primitive has not been implemented\n"));
}
/**************************************************************
 * MD5_GEN primitive helper function
 * overwrites start of input1 from the output2 data using base-16
 *************************************************************/
void MD5GenBaseFunc__overwrite_from_last_output2_to_input1_as_base16_no_size_fix()
{
	exit(fprintf(stderr, "Error, MD5GenBaseFunc__overwrite_from_last_output2_to_input1_as_base16_no_size_fix() primitive has not been implemented\n"));
}
/**************************************************************
 * MD5_GEN primitive helper function
 * Append salt #2 into input 1
 *************************************************************/
void MD5GenBaseFunc__append_2nd_salt()
{
	exit(fprintf(stderr, "Error, MD5GenBaseFunc__append_2nd_salt() primitive has not been implemented\n"));
}
/**************************************************************
 * MD5_GEN primitive helper function
 * Append salt #2 into input 2
 *************************************************************/
void MD5GenBaseFunc__append_2nd_salt2()
{
	exit(fprintf(stderr, "Error, MD5GenBaseFunc__append_2nd_salt2() primitive has not been implemented\n"));
}
/**************************************************************
 * MD5_GEN primitive helper function
 * Append UserID into input 1
 *************************************************************/
void MD5GenBaseFunc__append_userid()
{
	exit(fprintf(stderr, "Error, MD5GenBaseFunc__append_userid() primitive has not been implemented\n"));
}
/**************************************************************
 * MD5_GEN primitive helper function
 * Append UserID into input 2
 *************************************************************/
void MD5GenBaseFunc__append_userid2()
{
	exit(fprintf(stderr, "Error, MD5GenBaseFunc__append_userid2() primitive has not been implemented\n"));
}

/**************************************************************
 **************************************************************
 **************************************************************
 **************************************************************
 * MD5_GEN primitive helper function
 * This is the END of the primitives.
 **************************************************************
 **************************************************************
 **************************************************************
 *************************************************************/


void md5_gen_SETUP(MD5_GEN_Setup *Setup)
{
	int i, cnt;
	// Handle These Flags types.
	//#define MGF_NOTSSE2Safe     0x01  (handled)
	//#define MGF_ColonNOTValid   0x02  (handled)
	//#define MGF_SALTED          0x04  (handled)
	//#define MGF_SALTED2         0x08
	//#define MGF_USERID          0x10
	//#define MGF_INPBASE64		  0x20  (handled, like for phpbb)

#if defined (MMX_COEF)
	if (Setup->flags & MGF_NOTSSE2Safe)
		exit(fprintf(stderr, "This format %s does NOT work an SSE/MMX build of John\n", Setup->szFORMAT_NAME));
#endif

	if (Setup->flags & MGF_ColonNOTValid)
	{
		extern struct options_main options;
		if (options.field_sep_char == ':')
		{
			exit(fprintf(stderr, "This format does NOT work using ':' as separator, since it is in a salt value, or the hash itself.  Use --field-separator-char=c and set c to a 'valid' unused character that 'matches' the input file"));
		}
	}

	md5_gen_base64_inout = 0;
	fmt_MD5gen.methods.binary = md5_gen_binary;
	if (Setup->flags & MGF_INPBASE64)
	{
		md5_gen_base64_inout = 1;
		fmt_MD5gen.methods.binary = md5_gen_binary_b64;
	}

	md5_gen_salt_as_hex = 0;
	if (Setup->flags & MFG_SALT_AS_HEX)
		md5_gen_salt_as_hex = 1;

	fmt_MD5gen.params.format_name = Setup->szFORMAT_NAME;
	if ( (Setup->flags & MGF_SALTED) == 0)
	{
		fmt_MD5gen.params.salt_size = 0;
		md5_gen_FIXED_SALT_SIZE = 0;
		fmt_MD5gen.params.benchmark_length = -1;
	}
	else
	{
		fmt_MD5gen.params.benchmark_length = 0;
		if (Setup->SaltLen > 0)
		{
			fmt_MD5gen.params.salt_size = Setup->SaltLen;
			md5_gen_FIXED_SALT_SIZE = Setup->SaltLen;
		}
		else
		{
			fmt_MD5gen.params.salt_size = SALT_SIZE;
			md5_gen_FIXED_SALT_SIZE = -1;		// says we have a salt, but NOT a fixed sized one that we 'know' about.
		}
	}

	store_keys_in_input = 0;
	if (Setup->pFuncs && Setup->pFuncs[0])
	{
		int j = 0;
		if (Setup->pFuncs[0] == MD5GenBaseFunc__InitialLoadKeysToInput)
		{
			store_keys_in_input = 1;
			// we do 'not' load this function into our array.  It is used
			// as an 'indicator' to store/fetch keys direct to/from input, 
			// but is not a real function.  So we start from array[1] to
			// store into our function pointer table.
			++j;
		}
		if (Setup->pFuncs[0] == MD5GenBaseFunc__InitialLoadKeys_md5crypt_ToOutput2)
		{
			store_keys_normal_but_precompute_md5_to_output2 = 1;
			++j;
		}
		if (Setup->pFuncs[0] == MD5GenBaseFunc__InitialLoadKeys_md5crypt_ToOutput2_Base16_to_Input1)
		{
			store_keys_normal_but_precompute_md5_to_output2 = 1;
			store_keys_normal_but_precompute_md5_to_output2_base16_to_input1 = 1;
			++j;
		}
		if (Setup->pFuncs[0] == MD5GenBaseFunc__InitialLoadKeys_md5crypt_ToOutput2_Base16_to_Input1_offset32)
		{
			store_keys_normal_but_precompute_md5_to_output2 = 1;
			store_keys_normal_but_precompute_md5_to_output2_base16_to_input1_offset32 = 1;
			++j;
		}
		if (Setup->pFuncs[0] == MD5GenBaseFunc__PHPassSetup)
		{
			fmt_MD5gen.methods.salt = phpassmd5_salt;
			fmt_MD5gen.methods.set_salt = phpass_gen_set_salt;
			fmt_MD5gen.methods.salt_hash = phpass_salt_hash;
			saltlen = 8;
			++j;
		}
		else
		{
			fmt_MD5gen.methods.salt = get_salt;
			fmt_MD5gen.methods.set_salt = md5_gen_set_salt;
			fmt_MD5gen.methods.salt_hash = salt_hash;

		}
		for (i=0; i < ARRAY_COUNT(md5_gen_FUNCTIONS) -1 && Setup->pFuncs[i]; ++i)
		{
			if (MD5GenBaseFunc__InitialLoadKeysToInput == Setup->pFuncs[j])
				exit(fprintf(stderr, "Pseudo fuction InitialLoadKeysToInput can NOT be called, other than as the very first function in generic MD5 scripts\n"));
			if (MD5GenBaseFunc__InitialLoadKeys_md5crypt_ToOutput2 == Setup->pFuncs[j])
				exit(fprintf(stderr, "Pseudo fuction MD5GenBaseFunc__InitialLoadKeysAs_md5base16_ToInput can NOT be called, other than as the very first function in generic MD5 scripts\n"));

			// Ok, if we ARE using store keys, these things will cause it to NOT work
			if (store_keys_in_input)
			{
				if (Setup->pFuncs[j] == MD5GenBaseFunc__append_keys)
					exit(fprintf(stderr, "InitialLoadKeysToInput used, but append_keys called and that is invalid\n"));
				if (Setup->pFuncs[j] == MD5GenBaseFunc__append_keys2)
					exit(fprintf(stderr, "InitialLoadKeysToInput used, but append_keys2 called and that is invalid\n"));
				if (Setup->pFuncs[j] == MD5GenBaseFunc__clean_input)
					exit(fprintf(stderr, "InitialLoadKeysToInput used, but clean_input called and that is invalid\n"));
				if (Setup->pFuncs[j] == MD5GenBaseFunc__append_salt)
					exit(fprintf(stderr, "InitialLoadKeysToInput used, but append_salt called and that is invalid\n"));
				if (Setup->pFuncs[j] == MD5GenBaseFunc__append_from_last_output2_to_input1_as_base16)
					exit(fprintf(stderr, "InitialLoadKeysToInput used, but append_from_last_output2_to_input1_as_base16 called and that is invalid\n"));
				if (Setup->pFuncs[j] == MD5GenBaseFunc__overwrite_from_last_output2_to_input1_as_base16_no_size_fix)
					exit(fprintf(stderr, "InitialLoadKeysToInput used, but overwrite_from_last_output2_to_input1_as_base16_no_size_fix called and that is invalid\n"));
				if (Setup->pFuncs[j] == MD5GenBaseFunc__append_from_last_output_as_base16)
					exit(fprintf(stderr, "InitialLoadKeysToInput used, but append_from_last_output_as_base16s called and that is invalid\n"));
				if (Setup->pFuncs[j] == MD5GenBaseFunc__overwrite_from_last_output_as_base16_no_size_fix)
					exit(fprintf(stderr, "InitialLoadKeysToInput used, but overwrite_from_last_output_as_base16_no_size_fix called and that is invalid\n"));
				if (Setup->pFuncs[j] == MD5GenBaseFunc__append_2nd_salt)
					exit(fprintf(stderr, "InitialLoadKeysToInput used, but append_2nd_salt called and that is invalid\n"));
				if (Setup->pFuncs[j] == MD5GenBaseFunc__append_userid)
					exit(fprintf(stderr, "InitialLoadKeysToInput used, but append_userid called and that is invalid\n"));
			}
			md5_gen_FUNCTIONS[i] = Setup->pFuncs[j++];
		}
		md5_gen_FUNCTIONS[j] = NULL;
	}
	if (!Setup->pPreloads || Setup->pPreloads[0].Hash == NULL)
	{
		exit(fprintf(stderr, "Error, no validation hash(s) for this format\n"));
	}
	cnt = 0;

	while (cnt < ARRAY_COUNT(md5_gen_tests)-1)
	{
		for (i = 0; cnt < ARRAY_COUNT(md5_gen_tests) -1 && Setup->pFuncs[i]; ++i, ++cnt)
		{
			md5_gen_tests[cnt].ciphertext = Setup->pPreloads[i].Hash;
			md5_gen_tests[cnt].plaintext = Setup->pPreloads[i].Passwd;
		}
	}
	md5_gen_tests[cnt].ciphertext = NULL;
	md5_gen_tests[cnt].plaintext = NULL;
}
