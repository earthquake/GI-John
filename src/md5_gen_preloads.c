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
 * Preloaded types md5gen(0) to md5gen(100) are 'reserved' types.
 * They are loaded from this file. If someone tryes to build a 'custom'
 * type in their john.ini file using one of those, john will abort 
 * the run.
 * 
 */

#include <string.h>

#include "arch.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "md5.h"
#include "md5_gen.h"

//
// HERE is the 'official' list of md5_gen(#) builtin's to John.
//
//md5_gen(0) --> md5($p)
//md5_gen(1) --> md5($p.$s)  (joomla)
//md5_gen(2) --> md5(md5($p))
//md5_gen(3) --> md5(md5(md5($p)))
//md5_gen(4) --> md5($s.$p)  (osCommerce MD5 2 byte salt)
//md5_gen(5) --> md5($s.$p.$s)
//md5_gen(6) --> md5(md5($p).$s)
//md5_gen(7) --> md5(md5($p).$s) vBulletin  (fixed 3 byte salt, colon not valid as field sep, since all chars from 0x20 to 0x7E are in the salt)
//md5_gen(8) --> md5(md5($s).$p)
//md5_gen(9) --> md5($s.md5($p))
//md5_gen(10) --> md5($s.md5($s.$p))
//md5_gen(11) --> md5($s.md5($p.$s)) 
//md5_gen(12) --> md5(md5($s).md5($p)) (IPB) // note will NOT work in SSE2 code
//md5_gen(13) --> md5(md5($p).md5($s))  // note will NOT work in SSE2 code
//md5_gen(14) --> md5($s.md5($p).$s) 
//md5_gen(15) --> md5($u.md5($p).$s)      // note $u is not handled yet (but we can 'reserve' the format)
//md5_gen(16) --> md5(md5(md5($p).$s).$s2) // note 2 salts is not handled yet.
//md5_gen(17) --> phpass ($P$ or $H$)      // phpass OR phpbb (or WordPress, etc).  Should handle all conforming formats

// gen_md5(0)  raw-md5
MD5_GEN_primitive_funcp _Funcs_0[] = 
{
	MD5GenBaseFunc__InitialLoadKeysToInput,
	MD5GenBaseFunc__crypt,
	NULL
};
MD5_GEN_Preloads _Preloads_0[] = 
{
	{"md5_gen(0)5a105e8b9d40e1329780d62ea2265d8a","test1"},
	{"md5_gen(0)378e2c4a07968da2eca692320136433d","thatsworking"},
	{"md5_gen(0)8ad8757baa8564dc136c1e07507f4a98","test3"},
	{NULL}
};

// gen_md5(1)  Joomla md5($p.$s)
MD5_GEN_primitive_funcp _Funcs_1[] =
{
	MD5GenBaseFunc__clean_input,
	MD5GenBaseFunc__append_keys,
	MD5GenBaseFunc__append_salt,
	MD5GenBaseFunc__crypt,
	NULL
};
MD5_GEN_Preloads _Preloads_1[] = 
{
	{"md5_gen(1)ed52af63d8ecf0c682442dfef5f36391$1aDNNojYGSc7pSzcdxKxhbqvLtEe4deG","test1"},
	{"md5_gen(1)4fa1e9d54d89bfbe48b4c0f0ca0a3756$laxcaXPjgcdKdKEbkX1SIjHKm0gfYt1c","thatsworking"},
	{"md5_gen(1)82568eeaa1fcf299662ccd59d8a12f54$BdWwFsbGtXPGc0H1TBxCrn0GasyAlJBJ","test3"},
	{NULL}
};


// gen_md5(2)  md5(md5($p))
MD5_GEN_primitive_funcp _Funcs_2[] = 
{
	MD5GenBaseFunc__InitialLoadKeysToInput,
	MD5GenBaseFunc__crypt,
	MD5GenBaseFunc__clean_input2,
	MD5GenBaseFunc__append_from_last_output_to_input2_as_base16,
	MD5GenBaseFunc__crypt_in2_to_out1,
	NULL
};
MD5_GEN_Preloads _Preloads_2[] = 
{
	{"md5_gen(2)418d89a45edadb8ce4da17e07f72536c","test1"},
	{"md5_gen(2)ccd3c4231a072b5e13856a2059d04fad","thatsworking"},
	{"md5_gen(2)9992295627e7e7162bdf77f14734acf8","test3"},
	{NULL}
};
// gen_md5(3)  md5(md5(md5($p)))
MD5_GEN_primitive_funcp _Funcs_3[] = 
{
	MD5GenBaseFunc__InitialLoadKeysToInput,
	MD5GenBaseFunc__crypt,
	MD5GenBaseFunc__clean_input2,
	MD5GenBaseFunc__append_from_last_output_to_input2_as_base16,
	MD5GenBaseFunc__crypt2, 
	// NOTE if we had an output_2_intput that overwrote instead of append, we would 
	// NOT need to clean here.
	MD5GenBaseFunc__clean_input2,
	MD5GenBaseFunc__append_from_last_output2_as_base16,
	MD5GenBaseFunc__crypt_in2_to_out1,
	NULL
};
MD5_GEN_Preloads _Preloads_3[] = 
{
	{"md5_gen(3)964c02612b2a1013ed26d46ba9a73e74","test1"},
	{"md5_gen(3)5d7e6330f69548797c07d97c915690fe","thatsworking"},
	{"md5_gen(3)2e54db8c72b312007f3f228d9d4dd34d","test3"},
	{NULL}
};

//md5_gen(4) --> md5($s.$p)
MD5_GEN_primitive_funcp _Funcs_4[] =
{
	MD5GenBaseFunc__clean_input,
	MD5GenBaseFunc__append_salt,
	MD5GenBaseFunc__append_keys,
	MD5GenBaseFunc__crypt,
	NULL
};
MD5_GEN_Preloads _Preloads_4[] = 
{
	{"md5_gen(4)c02e8eef3eaa1a813c2ff87c1780f9ed$123456","test1"},
	{"md5_gen(4)4a2a1b013da3cda7f7e0625cf3dc3f4c$1234","thatsworking"},
	{"md5_gen(4)3a032e36a9609df6411b8004070431d3$aaaaa","test3"},
	{NULL}
};

//md5_gen(5) --> md5($s.$p.$s)
MD5_GEN_primitive_funcp _Funcs_5[] =
{
	MD5GenBaseFunc__clean_input,
	MD5GenBaseFunc__append_salt,
	MD5GenBaseFunc__append_keys,
	MD5GenBaseFunc__append_salt,
	MD5GenBaseFunc__crypt,
	NULL
};
MD5_GEN_Preloads _Preloads_5[] = 
{
	{"md5_gen(5)c1003cd39cb5523dd0923a94ab15a3c7$123456","test1"},
	{"md5_gen(5)c1c8618abfc7bdbc4a3c49c2c2c48f82$1234","thatsworking"},
	{"md5_gen(5)e7222e806a8ce5efa6d48acb3aa56dc2$aaaaa","test3"},
	{NULL}
};

//md5_gen(6) --> md5(md5($p).$s)
MD5_GEN_primitive_funcp _Funcs_6[] =
{
	MD5GenBaseFunc__InitialLoadKeys_md5crypt_ToOutput2_Base16_to_Input1,
	MD5GenBaseFunc__set_input_len_32,
	MD5GenBaseFunc__append_salt,
	MD5GenBaseFunc__crypt,
	NULL
};
MD5_GEN_Preloads _Preloads_6[] = 
{
	{"md5_gen(6)3a9ae23758f05da1fe539e55a096b03b$S111XB","test1"},
	{"md5_gen(6)9694d706d1992abf04344c1e7da1c5d3$T &222","thatsworking"},
	{"md5_gen(6)b7a7f0c374d73fac422bb01f07f5a9d4$lxxxl","test3"},
	{NULL}
};

//md5_gen(7) --> md5(md5($p).$s) vBulletin  (forced 3 byte salt, valid chars from 0x20 to 0x7E)
MD5_GEN_primitive_funcp _Funcs_7[] =
{
	MD5GenBaseFunc__InitialLoadKeys_md5crypt_ToOutput2_Base16_to_Input1,
	MD5GenBaseFunc__set_input_len_32,
	MD5GenBaseFunc__append_salt,
	MD5GenBaseFunc__crypt,
	NULL
};
MD5_GEN_Preloads _Preloads_7[] = 
{
	{"md5_gen(7)daa61d77e218e42060c2fa198ac1feaf$SXB","test1"},
	{"md5_gen(7)de56b00bb15d6db79204bd44383469bc$T &","thatsworking"},
	{"md5_gen(7)fb685c6f469f6e549c85e4c1fb5a65a6$\\H:","test3"},
	{NULL}
};

//md5_gen(8) --> md5(md5($s).$p)
MD5_GEN_primitive_funcp _Funcs_8[] =
{
	MD5GenBaseFunc__clean_input,
	MD5GenBaseFunc__append_salt,
	MD5GenBaseFunc__crypt,
	MD5GenBaseFunc__clean_input,
	MD5GenBaseFunc__append_from_last_output_as_base16,
	MD5GenBaseFunc__append_keys,
	MD5GenBaseFunc__crypt,
	NULL
};
MD5_GEN_Preloads _Preloads_8[] = 
{
	{"md5_gen(8)534c2fb38e757d9448315abb9822db00$aaaSXB","test1"},
	{"md5_gen(8)02547864bed278658e8f54dd6dfd69b7$123456","thatsworking"},
	{"md5_gen(8)2f6f3881972653ebcf86e5ad3071a4ca$5555hh","test3"},
	{NULL}
};

//md5_gen(9) --> md5($s.md5($p))
MD5_GEN_primitive_funcp _Funcs_9[] =
{
//	MD5GenBaseFunc__InitialLoadKeysToInput,
//	MD5GenBaseFunc__crypt,
//	MD5GenBaseFunc__clean_input2,
//	MD5GenBaseFunc__append_salt2,
//	MD5GenBaseFunc__append_from_last_output_to_input2_as_base16,
//	MD5GenBaseFunc__crypt_in2_to_out1,
//	NULL
#if defined (MMX_COEF)
	MD5GenBaseFunc__InitialLoadKeys_md5crypt_ToOutput2,
	MD5GenBaseFunc__clean_input,
	MD5GenBaseFunc__append_salt,
	MD5GenBaseFunc__append_from_last_output2_to_input1_as_base16,
	MD5GenBaseFunc__crypt,
	NULL
#else
	MD5GenBaseFunc__InitialLoadKeys_md5crypt_ToOutput2_Base16_to_Input1,
	MD5GenBaseFunc__clean_input2,
	MD5GenBaseFunc__append_salt2,
	MD5GenBaseFunc__append_input2_from_input,
	MD5GenBaseFunc__crypt_in2_to_out1,
	NULL
#endif
};
MD5_GEN_Preloads _Preloads_9[] = 
{
	{"md5_gen(9)b38c18b5e5b676e211442bd41000b2ec$aaaSXB","test1"},
	{"md5_gen(9)4dde7cd4cbf0dc4c59b255ae77352914$123456","thatsworking"},
	{"md5_gen(9)899af20e3ebdd77aaecb0d9bc5fbbb66$5555hh","test3"},
	{NULL}
};

//md5_gen(10) --> md5($s.md5($s.$p))
MD5_GEN_primitive_funcp _Funcs_10[] =
{
	MD5GenBaseFunc__clean_input,
	MD5GenBaseFunc__append_salt,
	MD5GenBaseFunc__append_keys,
	MD5GenBaseFunc__crypt,
	MD5GenBaseFunc__clean_input,
	MD5GenBaseFunc__append_salt,
	MD5GenBaseFunc__append_from_last_output_as_base16,
	MD5GenBaseFunc__crypt,
	NULL
};
MD5_GEN_Preloads _Preloads_10[] = 
{
	{"md5_gen(10)781f83a676f45169dcfc7f36dfcdc3d5$aaaSXB","test1"},
	{"md5_gen(10)f385748e67a2dc1f6379b9124fabc0df$123456","thatsworking"},
	{"md5_gen(10)9e3702bb13386270cd4b0bd4dbdd489e$5555hh","test3"},
	{NULL}
};

//md5_gen(11) --> md5($s.md5($p.$s)) 
MD5_GEN_primitive_funcp _Funcs_11[] =
{
	MD5GenBaseFunc__clean_input,
	MD5GenBaseFunc__append_keys,
	MD5GenBaseFunc__append_salt,
	MD5GenBaseFunc__crypt,
	MD5GenBaseFunc__clean_input,
	MD5GenBaseFunc__append_salt,
	MD5GenBaseFunc__append_from_last_output_as_base16,
	MD5GenBaseFunc__crypt,
	NULL
};
MD5_GEN_Preloads _Preloads_11[] = 
{
	{"md5_gen(11)f809a64cbd0d23e099cd5b544c8501ac$aaaSXB","test1"},
	{"md5_gen(11)979e6671535cda6db95357d8a0afd9ac$123456","thatsworking"},
	{"md5_gen(11)78a61ea73806ebf27bef2ab6a9bf5412$5555hh","test3"},
	{NULL}
};

//md5_gen(12) --> md5(md5($s).md5($p))  // note will NOT work in SSE2 code
MD5_GEN_primitive_funcp _Funcs_12[] =
{
	// NOTE, only works for non-SSE2  (64 byte last md5 too big for SSE2)
	MD5GenBaseFunc__InitialLoadKeys_md5crypt_ToOutput2_Base16_to_Input1_offset32,
	MD5GenBaseFunc__overwrite_salt_to_input1_no_size_fix,
	MD5GenBaseFunc__set_input_len_64,
	MD5GenBaseFunc__crypt,
	NULL
};
MD5_GEN_Preloads _Preloads_12[] = 
{
	{"md5_gen(12)fbbd9532460f2d03fa8af9e75c41eefc$aaaSXB","test1"},
	{"md5_gen(12)b80eef24d1d01b61b3beff38559f9d26$123456","thatsworking"},
	{"md5_gen(12)1e5489bdca008aeed6e390ee87ce9b92$5555hh","test3"},
	{NULL}
};

//md5_gen(13) --> md5(md5($p).md5($s))  // note will NOT work in SSE2 code
MD5_GEN_primitive_funcp _Funcs_13[] =
{
	// NOTE, only works for non-SSE2  (64 byte last md5 too big for SSE2)
	MD5GenBaseFunc__InitialLoadKeys_md5crypt_ToOutput2_Base16_to_Input1,
	MD5GenBaseFunc__set_input_len_32,
	MD5GenBaseFunc__append_salt,
	MD5GenBaseFunc__crypt,
	NULL
};
MD5_GEN_Preloads _Preloads_13[] = 
{
	{"md5_gen(13)c6b69bec81d9ff5d0560d8f469a8efd5$aaaSXB","test1"},
	{"md5_gen(13)7abf788b3abbfc8719d900af96a3763a$123456","thatsworking"},
	{"md5_gen(13)1c55e15102ed17eabe5bf11271c7fcae$5555hh","test3"},
	{NULL}
};

//md5_gen(14) --> md5($s.md5($p).$s) 
MD5_GEN_primitive_funcp _Funcs_14[] =
{
//	MD5GenBaseFunc__InitialLoadKeysToInput,
//	MD5GenBaseFunc__crypt,
//	MD5GenBaseFunc__clean_input2,
//	MD5GenBaseFunc__append_salt2,
//	MD5GenBaseFunc__append_from_last_output_to_input2_as_base16,
//	MD5GenBaseFunc__append_salt2,
//	MD5GenBaseFunc__crypt_in2_to_out1,
//	NULL

#if defined (MMX_COEF)
	MD5GenBaseFunc__InitialLoadKeys_md5crypt_ToOutput2,
	MD5GenBaseFunc__clean_input,
	MD5GenBaseFunc__append_salt,
	MD5GenBaseFunc__append_from_last_output2_to_input1_as_base16,
	MD5GenBaseFunc__append_salt,
	MD5GenBaseFunc__crypt,
	NULL
#else

	MD5GenBaseFunc__InitialLoadKeys_md5crypt_ToOutput2_Base16_to_Input1,
	MD5GenBaseFunc__clean_input2,
	MD5GenBaseFunc__append_salt2,
	MD5GenBaseFunc__append_input2_from_input,
	MD5GenBaseFunc__append_salt2,
	MD5GenBaseFunc__crypt_in2_to_out1,
	NULL
#endif
};
MD5_GEN_Preloads _Preloads_14[] = 
{
	{"md5_gen(14)778e40e10d82a08f5377992330008cbe$aaaSXB","test1"},
	{"md5_gen(14)d6321956964b2d27768df71d139eabd2$123456","thatsworking"},
	{"md5_gen(14)1b3c72e16427a2f4f0819243877f7967$5555hh","test3"},
	{NULL}
};

//md5_gen(15) --> md5($u.md5($p).$s)      // note $u is not handled yet (but we can 'reserve' the format)
MD5_GEN_primitive_funcp _Funcs_15[] =
{
	MD5GenBaseFunc__clean_input,
	MD5GenBaseFunc__append_keys,
	MD5GenBaseFunc__crypt,
	MD5GenBaseFunc__clean_input,
	MD5GenBaseFunc__append_userid,
	MD5GenBaseFunc__append_from_last_output_as_base16,
	MD5GenBaseFunc__append_salt,
	MD5GenBaseFunc__crypt,
	NULL
};
MD5_GEN_Preloads _Preloads_15[] = 
{
	{"md5_gen(15)778e40e10d82a08f5377992330008cbe$aaaSXB","test1"},
	{"md5_gen(15)d6321956964b2d27768df71d139eabd2$123456","thatsworking"},
	{"md5_gen(15)1b3c72e16427a2f4f0819243877f7967$5555hh","test3"},
	{NULL}
};

//md5_gen(16) --> md5(md5(md5($p).$s).$s2) // note 2 salts is not handled yet.
MD5_GEN_primitive_funcp _Funcs_16[] =
{
	MD5GenBaseFunc__clean_input,
	MD5GenBaseFunc__append_keys,
	MD5GenBaseFunc__crypt,
	MD5GenBaseFunc__clean_input,
	MD5GenBaseFunc__append_from_last_output_as_base16,
	MD5GenBaseFunc__append_salt,
	MD5GenBaseFunc__crypt,
	MD5GenBaseFunc__clean_input,
	MD5GenBaseFunc__append_from_last_output_as_base16,
	MD5GenBaseFunc__append_2nd_salt,
	NULL
};
MD5_GEN_Preloads _Preloads_16[] = 
{
	{"md5_gen(16)778e40e10d82a08f5377992330008cbe$aaaSXB","test1"},
	{"md5_gen(16)d6321956964b2d27768df71d139eabd2$123456","thatsworking"},
	{"md5_gen(16)1b3c72e16427a2f4f0819243877f7967$5555hh","test3"},
	{NULL}
};

//md5_gen(17) --> $P$7 phpass (or $H$7
MD5_GEN_primitive_funcp _Funcs_17[] =
{
	MD5GenBaseFunc__PHPassSetup,
	MD5GenBaseFunc__PHPassCrypt,
	NULL
};
MD5_GEN_Preloads _Preloads_17[] = 
{
	// format:  md5_gen(17)hash$Xssssssss
	// Xssssssss is the 9 bytes immediately following the standard
	// signature of $P$  So $P$912345678jgypwqm.JsMssPLiS8YQ00 the
	// 912345678 will be inserted into $Xssssssss
	// ssssssss is the salt, and X is a byte used to count how many
	// times we do the inner md5 crypt packing.
	{"md5_gen(17)jgypwqm.JsMssPLiS8YQ00$9aaaaaSXB","test1"},
	{"md5_gen(17)5R3ueot5zwV.7MyzAItyg/$912345678","thatsworking"},
	{"md5_gen(17)Y5RwgMij0xFsUIrr33lM1/$9555555hh","test3"},

//	{"md5_gen(17)yhzfTrJXcouTpLleLSbnY/$7aaaaaSXB","test1"},
//	{"md5_gen(17)mwulIMWPGe6RPXG1/R8l50$712345678","thatsworking"},
//	{"md5_gen(17)nfKm8qpXa88RVUjLgjY/u1$7555555hh","test3"},

//	{"md5_gen(17)JSe8S8ufpLrsNE7utOpWc/$BaaaaaSXB","test1"},
//	{"md5_gen(17)aqkw6carDzQ67zCLOvVp60$B712345678","thatsworking"},
//	{"md5_gen(17)o2j.1E7X1NvVyEJ/QY9hX0$B555555hh","test3"},

	{NULL}
};

static MD5_GEN_Setup Setups[] = 
{
	{ " md5_gen(0): md5($p)  (raw-md5) ",           _Funcs_0, _Preloads_0 },
	{ " md5_gen(1): md5($p.$s)  (joomla) ",         _Funcs_1, _Preloads_1, MGF_SALTED },
	{ " md5_gen(2): md5(md5($p))  (e107) ",         _Funcs_2, _Preloads_2 },
	{ " md5_gen(3): md5(md5(md5($p))) ",            _Funcs_3, _Preloads_3 },
	{ " md5_gen(4): md5($s.$p)  (OSC) ",            _Funcs_4, _Preloads_4, MGF_SALTED },
	{ " md5_gen(5): md5($s.$p.$s) ",                _Funcs_5, _Preloads_5, MGF_SALTED },
	{ " md5_gen(6): md5(md5($p).$s) ",              _Funcs_6, _Preloads_6, MGF_SALTED },
	{ " md5_gen(7): md5(md5($p).$s)  (vBulletin) ", _Funcs_7, _Preloads_7, MGF_SALTED|MGF_ColonNOTValid, 3 },
	{ " md5_gen(8): md5(md5($s).$p) ",              _Funcs_8, _Preloads_8, MGF_SALTED },
	{ " md5_gen(9): md5($s.md5($p)) ",              _Funcs_9, _Preloads_9, MGF_SALTED },
	{ " md5_gen(10): md5($s.md5($s.$p)) ",          _Funcs_10,_Preloads_10,MGF_SALTED },
	{ " md5_gen(11): md5($s.md5($p.$s)) ",          _Funcs_11,_Preloads_11,MGF_SALTED },
	{ " md5_gen(12): md5(md5($s).md5($p))  (IPB) ", _Funcs_12,_Preloads_12,MGF_SALTED|MGF_NOTSSE2Safe|MFG_SALT_AS_HEX },
	{ " md5_gen(13): md5(md5($p).md5($s)) ",        _Funcs_13,_Preloads_13,MGF_SALTED|MGF_NOTSSE2Safe|MFG_SALT_AS_HEX },
	{ " md5_gen(14): md5($s.md5($p).$s) ",          _Funcs_14,_Preloads_14,MGF_SALTED },
	{ " md5_gen(15): md5($u.md5($p).$s) ",          _Funcs_15,_Preloads_15,MGF_SALTED|MGF_USERID },
	{ " md5_gen(16): md5(md5(md5($p).$s).$s2) ",    _Funcs_16,_Preloads_16,MGF_SALTED|MGF_SALTED2 },
	{ " md5_gen(17): phpass ($P$ or $H$) ",         _Funcs_17,_Preloads_17,MGF_SALTED|MGF_INPBASE64, 9 },
};

char *md5_gen_PRELOAD_SIGNATURE(int cnt)
{
	if (cnt < 0 || cnt > 1000)
		return NULL;
	if (cnt >= ARRAY_COUNT(Setups))
		return NULL;
	return Setups[cnt].szFORMAT_NAME;
}

void md5_gen_RESERVED_PRELOAD_SETUP(int cnt)
{
	if (cnt < 0 || cnt > 1000)
		exit(fprintf(stderr, "Error, RESERVED_PRELOAD of md5-gen called for out of range\n"));
	if (cnt >= ARRAY_COUNT(Setups))
		exit(fprintf(stderr, "Error, RESERVED_PRELOAD of md5-gen(%d) is not defined at this time\n", cnt));

	md5_gen_SETUP(&Setups[cnt]);
}

// -1 is NOT valid
// 0 is valid, but NOT usable by this build (i.e. no SSE2)
// 1 is valid.
int md5_gen_IS_VALID(int i)
{
	if (i < 0 || i > 100)
		return -1;
	if (i >= ARRAY_COUNT(Setups))
		return -1;

#if defined (MMX_COEF)
	if (Setups[i].flags & MGF_NOTSSE2Safe)
		return 0;	// not valid, but not at the end of the list.
#endif

	// At this time, we do NOT support $s2 or $u
	if (Setups[i].flags & MGF_SALTED2)
		return 0;
	if (Setups[i].flags & MGF_USERID)
		return 0;

	return 1;
}
