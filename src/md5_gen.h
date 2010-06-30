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
 * Interface functions and data structures required to make this
 * work, since it is split over multiple .c source files.
 *
 */

#if !defined (__MD5_GEN___H)
#define __MD5_GEN___H

typedef void(*MD5_GEN_primitive_funcp)();

typedef struct MD5_GEN_Preloads_t
{
	char *Hash;
	char *Passwd;
} MD5_GEN_Preloads;

#define MGF_NOTSSE2Safe     0x01
#define MGF_ColonNOTValid   0x02
#define MGF_SALTED          0x04
#define MGF_SALTED2         0x08
#define MGF_USERID          0x10
#define MGF_INPBASE64		0x20
#define MFG_SALT_AS_HEX		0x40

typedef struct MD5_GEN_Setup_t
{
	char *szFORMAT_NAME;  // md5(md5($p).$s) etc

	// Ok, this will be the functions to 'use'.  
	// This should be a 'null' terminated list.  5000 is MAX.
	MD5_GEN_primitive_funcp *pFuncs;
	MD5_GEN_Preloads *pPreloads;
	unsigned flags;
	int SaltLen;
} MD5_GEN_Setup;

void md5_gen_SETUP(MD5_GEN_Setup *);
int md5_gen_IS_VALID(int i);
void md5_gen_RESET();
void md5_gen_RESET_LINK(struct fmt_main *pFmt, char *ciphertext, char *orig_sig);
void md5_gen_DISPLAY_ALL_FORMATS();

void md5_gen_RESERVED_PRELOAD_SETUP(int cnt);
char *md5_gen_PRELOAD_SIGNATURE(int cnt);

// Here aer the 'parser' functions (i.e. user built stuff in john.conf)
int  md5_gen_LOAD_PARSER_FUNCTIONS(int which);
char *md5_gen_LOAD_PARSER_SIGNATURE(int which);

//
// These functions MUST be of type:   void function()
// these are the 'base' predicate functions used in
// building a generic MD5 attack algorithm.
//

extern void MD5GenBaseFunc__clean_input();
extern void MD5GenBaseFunc__clean_input_kwik();
extern void MD5GenBaseFunc__append_keys();
extern void MD5GenBaseFunc__crypt();
extern void MD5GenBaseFunc__append_from_last_output_as_base16();
extern void MD5GenBaseFunc__overwrite_from_last_output_as_base16_no_size_fix();
extern void MD5GenBaseFunc__append_salt();
extern void MD5GenBaseFunc__set_input_len_32();
extern void MD5GenBaseFunc__set_input_len_64();

extern void MD5GenBaseFunc__clean_input2();
extern void MD5GenBaseFunc__clean_input2_kwik();
extern void MD5GenBaseFunc__append_keys2();
extern void MD5GenBaseFunc__crypt2();
extern void MD5GenBaseFunc__append_from_last_output2_as_base16();
extern void MD5GenBaseFunc__overwrite_from_last_output2_as_base16_no_size_fix();
extern void MD5GenBaseFunc__append_from_last_output_to_input2_as_base16();
extern void MD5GenBaseFunc__overwrite_from_last_output_to_input2_as_base16_no_size_fix();
extern void MD5GenBaseFunc__append_from_last_output2_to_input1_as_base16();
extern void MD5GenBaseFunc__overwrite_from_last_output2_to_input1_as_base16_no_size_fix();
extern void MD5GenBaseFunc__append_salt2();
extern void MD5GenBaseFunc__set_input2_len_32();
extern void MD5GenBaseFunc__set_input2_len_64();

extern void MD5GenBaseFunc__overwrite_salt_to_input1_no_size_fix();
extern void MD5GenBaseFunc__overwrite_salt_to_input2_no_size_fix();

extern void MD5GenBaseFunc__append_input_from_input2();
extern void MD5GenBaseFunc__append_input2_from_input();

extern void MD5GenBaseFunc__append_2nd_salt();
extern void MD5GenBaseFunc__append_2nd_salt2();
extern void MD5GenBaseFunc__append_userid();
extern void MD5GenBaseFunc__append_userid2();

extern void MD5GenBaseFunc__crypt_in1_to_out2();
extern void MD5GenBaseFunc__crypt_in2_to_out1();

// These 2 dump the raw crypt back into input (only at the head of it).
// they are for phpass, wordpress, etc.
extern void MD5GenBaseFunc__crypt_to_input_raw_Overwrite_NoLen();
extern void MD5GenBaseFunc__crypt_to_input_raw();

// special for phpass
extern void MD5GenBaseFunc__PHPassSetup();
extern void MD5GenBaseFunc__PHPassCrypt();

// This is an optimimization function (actually NOT a function, but 
// changes the behavior of the format.setkey() and format.getkey() to
// load and retrieve directly to the input.   NOTE the function
// MUST observe certain characteristics before this optimization 
// can be used.  The function MUST be something that the first thing
// used is the $p, and it is packed to the bottom of an input.
// Also, the 2nd input must be used for ALL work after the initial 
// crypt of the input, due to the getkey() having to retrieve from
// the input data.  However, IF the expression 'fits' and can be
// written to work safely with this pseudo function, then we cut out
// a buffer copy, and can save a lot of time.  Getting this working
// changed md5($p) from being about 85% the speed of raw-md5 to being
// about 102% the speed of raw-md5 (yes, FASTER).   It also improves
// a lot of the simple ( md5(md5($p).$s), etc), about 10% or more.
// When used, this function can ONLY be the first called function.
// If used 'after' the first, the loader will abort with an error.
extern void MD5GenBaseFunc__InitialLoadKeysToInput();
extern void MD5GenBaseFunc__InitialLoadKeys_md5crypt_ToOutput2();
extern void MD5GenBaseFunc__InitialLoadKeys_md5crypt_ToOutput2_Base16_to_Input1();
extern void MD5GenBaseFunc__InitialLoadKeys_md5crypt_ToOutput2_Base16_to_Input1_offset32();

#define ARRAY_COUNT(a) (sizeof(a)/sizeof(a[0]))

// We need access to this global to get functions and data which we 'link' to
extern struct fmt_main fmt_MD5gen;

// End of generic md5 'types' and helpers

#endif // __MD5_GEN___H
