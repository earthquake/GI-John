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
 * This file implements code that allows 'dynamic' building of
 * generic MD5 functions.  john.conf is used to store the 'script'
 * and supporting data (like the expression, or 'flags' needed to
 * make the format work).
 *
 * To make this work, you simply add a "section" to the john.conf
 * file of this format:
 *
 *  [List.Generic:md5_gen(NUM)]
 *
 * Num has to be replaced with a number, greater than 1000, since
 * md5_gen(0) to md5_gen(1000) are reserved for 'built-in' and any
 * user defined md5_gen(#) functions need to start at 1001 or more.
 *
 * Then under the new section, add the script.  There are 2 required
 * data types, and 2 optional.  The required are a list of Func=
 * and a list of Test=    Then there is an optional Expression=
 * and an optional list of Flag= items.
 *
 * Here is an example, showing processing for md5(md5(md5(md5($p))))
 *
 * [List.Generic:md5_gen(1001)]
 * Expression=md5(md5(md5(md5($p))))
 * Func=MD5GenBaseFunc__InitialLoadKeysToInput
 * Func=MD5GenBaseFunc__crypt
 * Func=MD5GenBaseFunc__clean_input2
 * Func=MD5GenBaseFunc__append_from_last_output_to_input2_as_base16
 * Func=MD5GenBaseFunc__crypt2
 * Func=MD5GenBaseFunc__clean_input2_kwik
 * Func=MD5GenBaseFunc__append_from_last_output2_as_base16
 * Func=MD5GenBaseFunc__crypt2
 * Func=MD5GenBaseFunc__clean_input2_kwik
 * Func=MD5GenBaseFunc__append_from_last_output2_as_base16
 * Func=MD5GenBaseFunc__crypt_in2_to_out1
 * Test=md5_gen(1001)57200e13b490d4ae47d5e19be026b057:test1
 * Test=md5_gen(1001)c6cc44f9e7fb7efcde62ba2e627a49c6:thatsworking
 * Test=md5_gen(1001)0ae9549604e539a249c1fa9f5e5fb73b:test3
 * 
 */

#include <string.h>

#include "arch.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "config.h"
#include "md5.h"
#include "loader.h"
#include "options.h"

#define DEFINE_MD5_PREDICATE_POINTERS
#include "md5_gen.h"

typedef struct MD5Gen_Predicate_t
{
	char *name;
	void(*func)();
} MD5Gen_Predicate_t;

MD5Gen_Predicate_t MD5Gen_Predicate[] =  {
	{ "MD5GenBaseFunc__clean_input",  MD5GenBaseFunc__clean_input },
	{ "MD5GenBaseFunc__clean_input_kwik", MD5GenBaseFunc__clean_input_kwik },
	{ "MD5GenBaseFunc__append_keys", MD5GenBaseFunc__append_keys },
	{ "MD5GenBaseFunc__crypt", MD5GenBaseFunc__crypt },
	{ "MD5GenBaseFunc__append_from_last_output_as_base16", MD5GenBaseFunc__append_from_last_output_as_base16 },
	{ "MD5GenBaseFunc__overwrite_from_last_output_as_base16_no_size_fix", MD5GenBaseFunc__overwrite_from_last_output_as_base16_no_size_fix },
	{ "MD5GenBaseFunc__append_salt", MD5GenBaseFunc__append_salt },
	{ "MD5GenBaseFunc__set_input_len_32", MD5GenBaseFunc__set_input_len_32 },
	{ "MD5GenBaseFunc__clean_input2", MD5GenBaseFunc__clean_input2 },
	{ "MD5GenBaseFunc__clean_input2_kwik", MD5GenBaseFunc__clean_input2_kwik },
	{ "MD5GenBaseFunc__append_keys2", MD5GenBaseFunc__append_keys2 },
	{ "MD5GenBaseFunc__crypt2", MD5GenBaseFunc__crypt2 },
	{ "MD5GenBaseFunc__append_from_last_output2_as_base16", MD5GenBaseFunc__append_from_last_output2_as_base16 },
	{ "MD5GenBaseFunc__overwrite_from_last_output2_as_base16_no_size_fix", MD5GenBaseFunc__overwrite_from_last_output2_as_base16_no_size_fix },
	{ "MD5GenBaseFunc__append_from_last_output_to_input2_as_base16", MD5GenBaseFunc__append_from_last_output_to_input2_as_base16 },
	{ "MD5GenBaseFunc__overwrite_from_last_output_to_input2_as_base16_no_size_fix", MD5GenBaseFunc__overwrite_from_last_output_to_input2_as_base16_no_size_fix },
	{ "MD5GenBaseFunc__append_from_last_output2_to_input1_as_base16", MD5GenBaseFunc__append_from_last_output2_to_input1_as_base16 },
	{ "MD5GenBaseFunc__overwrite_from_last_output2_to_input1_as_base16_no_size_fix", MD5GenBaseFunc__overwrite_from_last_output2_to_input1_as_base16_no_size_fix },
	{ "MD5GenBaseFunc__append_salt2", MD5GenBaseFunc__append_salt2 },
	{ "MD5GenBaseFunc__set_input2_len_32", MD5GenBaseFunc__set_input2_len_32 },
	{ "MD5GenBaseFunc__append_input_from_input2", MD5GenBaseFunc__append_input_from_input2 },
	{ "MD5GenBaseFunc__append_input2_from_input", MD5GenBaseFunc__append_input2_from_input },
	{ "MD5GenBaseFunc__append_2nd_salt", MD5GenBaseFunc__append_2nd_salt },
	{ "MD5GenBaseFunc__append_2nd_salt2", MD5GenBaseFunc__append_2nd_salt2 },
	{ "MD5GenBaseFunc__append_userid", MD5GenBaseFunc__append_userid },
	{ "MD5GenBaseFunc__append_userid2", MD5GenBaseFunc__append_userid2 },
	{ "MD5GenBaseFunc__crypt_in1_to_out2", MD5GenBaseFunc__crypt_in1_to_out2 },
	{ "MD5GenBaseFunc__crypt_in2_to_out1", MD5GenBaseFunc__crypt_in2_to_out1 },
	{ "MD5GenBaseFunc__crypt_to_input_raw_Overwrite_NoLen", MD5GenBaseFunc__crypt_to_input_raw_Overwrite_NoLen },
	{ "MD5GenBaseFunc__crypt_to_input_raw", MD5GenBaseFunc__crypt_to_input_raw },
	{ "MD5GenBaseFunc__PHPassSetup", MD5GenBaseFunc__PHPassSetup },
	{ "MD5GenBaseFunc__PHPassCrypt", MD5GenBaseFunc__PHPassCrypt },
	{ "MD5GenBaseFunc__InitialLoadKeysToInput", MD5GenBaseFunc__InitialLoadKeysToInput },
	{ "MD5GenBaseFunc__InitialLoadKeys_md5crypt_ToOutput2", MD5GenBaseFunc__InitialLoadKeys_md5crypt_ToOutput2 },
	{ "MD5GenBaseFunc__InitialLoadKeys_md5crypt_ToOutput2_Base16_to_Input1", MD5GenBaseFunc__InitialLoadKeys_md5crypt_ToOutput2_Base16_to_Input1 },
	{ "MD5GenBaseFunc__set_input_len_64", MD5GenBaseFunc__set_input_len_64 },
	{ "MD5GenBaseFunc__set_input2_len_64", MD5GenBaseFunc__set_input2_len_64 },
	{ "MD5GenBaseFunc__InitialLoadKeys_md5crypt_ToOutput2_Base16_to_Input1_offset32", MD5GenBaseFunc__InitialLoadKeys_md5crypt_ToOutput2_Base16_to_Input1_offset32 },
	{ "MD5GenBaseFunc__overwrite_salt_to_input1_no_size_fix", MD5GenBaseFunc__overwrite_salt_to_input1_no_size_fix },
	{ "MD5GenBaseFunc__overwrite_salt_to_input2_no_size_fix", MD5GenBaseFunc__overwrite_salt_to_input2_no_size_fix },
	{ NULL, NULL }};

typedef struct MD5Gen_Str_Flag_t
{
	char *name;
	unsigned flag_bit;
} MD5Gen_Str_Flag_t;

MD5Gen_Str_Flag_t MD5Gen_Str_Flag[] =  {
	{ "MGF_NOTSSE2Safe",   MGF_NOTSSE2Safe },
	{ "MGF_ColonNOTValid", MGF_ColonNOTValid },
	{ "MGF_SALTED",        MGF_SALTED },
	{ "MGF_SALTED2",       MGF_SALTED2 },
	{ "MGF_USERID",        MGF_USERID },
	{ "MGF_INPBASE64",     MGF_INPBASE64 },
	{ "MFG_SALT_AS_HEX",   MFG_SALT_AS_HEX },
	{ NULL, 0 }};

static MD5_GEN_Setup Setup;
static int nMaxPreloadCnt;
static int nPreloadCnt;
static int nFuncCnt;
char SetupName[48];
extern struct options_main options;

int md5_gen_LOAD_PARSER_FUNCTIONS_LoadLINE(char *Line)
{
	if (!strncmp(Line, "Test=", 5))
	{
		if (nPreloadCnt < nMaxPreloadCnt)
		{
			char *Passwd, *Hash, *tmp, *cp;
			Passwd = malloc(strlen(Line));
			Hash = malloc(strlen(Line));
			tmp = malloc(strlen(Line)+1);
			strcpy(tmp, Line);
			cp = &tmp[5];
			cp = strchr(cp, options.loader.field_sep_char);
			if (!cp)
			{
				fprintf(stderr, "Error, invalid test line:  %s\n", Line);
				return 0;
			}
			*cp ++ = 0;
			strcpy(Hash, &tmp[5]);
			strcpy(Passwd, cp);
			strtok(Passwd, "\r\n");
			Setup.pPreloads[nPreloadCnt].Hash = Hash;
			Setup.pPreloads[nPreloadCnt].Passwd = Passwd;
			++nPreloadCnt;
			free(tmp);
			if (strncmp(Hash, SetupName, strlen(SetupName)))
			{
				fprintf(stderr, "Error, invalid test line (wrong generic type):  %s\n", Line);
				return 0;
			}
		}
		return 1;
	}
	if (!strncmp(Line, "Func=", 5))
	{
		int i;
		for (i = 0; MD5Gen_Predicate[i].name; ++i)
		{
			if (!strcasecmp(MD5Gen_Predicate[i].name, &Line[5]))
			{
				if (nFuncCnt == 4999)
				{
					fprintf(stderr, "Error, TOO complex generic md5.  Only 5000 predicates can be used\n");
					return 0;
				}
				Setup.pFuncs[nFuncCnt++] = MD5Gen_Predicate[i].func;
				return 1;
			}
		}
		fprintf(stderr, "Error, unknown function:  %s\n", Line);
		return 0;
	}
	if (!strncmp(Line, "Flag=", 5))
	{
		int i;
		for (i = 0; MD5Gen_Str_Flag[i].name; ++i)
		{
			if (!strcasecmp(MD5Gen_Str_Flag[i].name, &Line[5]))
			{
				Setup.flags |= MD5Gen_Str_Flag[i].flag_bit;
				return 1;
			}
		}
		fprintf(stderr, "Error, unknown flag:  %s\n", Line);
		return 0;
	}
	if (!strncmp(Line, "SaltLen=", 8))
	{
		if (sscanf(Line, "SaltLen=%d", &Setup.SaltLen) == 1)
			return 1;
		fprintf(stderr, "Error, Invalid SaltLen= line:  %s  \n", Line);
		return 0;
	}
	if (!strncmp(Line, "Expression=", 11))
	{
		char *orig = Setup.szFORMAT_NAME;
		Setup.szFORMAT_NAME = malloc(strlen(orig)+1+strlen(&Line[11])+1); // 2 extra bytes. 1 for space, 1 for null
		sprintf(Setup.szFORMAT_NAME, "%s %s", orig, &Line[11]);
		free(orig);
		return 1;
	}
	fprintf(stderr, "Error, unknown line:   %s\n", Line);
	return 0;
}

char *md5_gen_LOAD_PARSER_SIGNATURE(int which)
{
	static char Sig[256];
	char SubSection[128];
	struct cfg_list *gen_source;
	struct cfg_line *gen_line;
	if (which < 1000)
		return NULL;

	sprintf(SubSection, ":md5_gen(%d)", which);

	gen_source = cfg_get_list("list.generic", SubSection);
	if (!gen_source)
		return NULL;

	// Setup the 'default' format name
	sprintf(Sig, "md5_gen(%d) ", which);

	gen_line = gen_source->head;
	while (gen_line)
	{
		if (!strncmp(gen_line->data, "Expression=", 11))
		{
			char SigApp[241];
			strncpy(SigApp, &gen_line->data[11], 240);
			SigApp[240] = 0;
			strcat(Sig, SigApp);
			break;
		}
	}
	return Sig;
}

int md5_gen_LOAD_PARSER_FUNCTIONS(int which)
{
	// Ok, we load the section:
	// [List.Generic.md5_gen(#)]  where # == which

	char SubSection[128];
	struct cfg_list *gen_source;
	struct cfg_line *gen_line;

	sprintf(SubSection, ":md5_gen(%d)", which);

	gen_source = cfg_get_list("list.generic", SubSection);
	if (!gen_source)
	{
		fprintf(stderr, "Could not find section [List.Generic%s] in the john.ini/conf file\n", SubSection);
		error();
	}

	// Setup the 'default' format name
	Setup.szFORMAT_NAME = malloc(strlen(SubSection));
	sprintf(Setup.szFORMAT_NAME, "md5_gen(%d)", which);
	strcpy(SetupName, Setup.szFORMAT_NAME);

	// allocate (and set null) 5000 file pointers
	Setup.pFuncs = malloc(5000*sizeof(MD5_GEN_primitive_funcp));
	memset(Setup.pFuncs, 0, 5000*sizeof(MD5_GEN_primitive_funcp));

	// allocate (and set null) 20 Preloads
	nMaxPreloadCnt = 20;
	Setup.pPreloads = malloc((nMaxPreloadCnt+1)*sizeof(MD5_GEN_Preloads));
	memset(Setup.pPreloads, 0, (nMaxPreloadCnt+1)*sizeof(MD5_GEN_Preloads));

	Setup.flags = 0;
	Setup.SaltLen = 0;

	// Ok, now 'grind' through the data  I do know know how to use
	// the config stuff too much, so will grind for now, and later 
	// go back over this, and do it 'right', if there is a right way
	gen_line = gen_source->head;
	while (gen_line)
	{
		if (!md5_gen_LOAD_PARSER_FUNCTIONS_LoadLINE(gen_line->data))
		{
			fprintf(stderr, "Error parsing section [List.Generic%s] in the john.ini/conf file\n", SubSection);
			error();
		}
		gen_line = gen_line->next;
	}

	md5_gen_SETUP(&Setup);
	return 1;
}
