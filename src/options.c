/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-2010 by Solar Designer
 *
 * ...with changes in the jumbo patch, by various authors
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "arch.h"
#include "misc.h"
#include "params.h"
#include "memory.h"
#include "list.h"
#include "loader.h"
#include "logger.h"
#include "status.h"
#include "recovery.h"
#include "options.h"
#include "bench.h"
#include "md5_gen.h"
#include "gijohn.h"

struct options_main options;
static char *field_sep_char_string;

#if defined (__MINGW32__) || defined (_MSC_VER)
// Later versions of MSVC can handle %lld but some older
// ones can only handle %I64d.  Easiest to simply use
// %I64d then all versions of MSVC will handle it just fine
#define LLd "%I64d"
#else
#define LLd "%lld"
#endif

static struct opt_entry opt_list[] = {
	{"", FLG_PASSWD, 0, 0, 0, OPT_FMT_ADD_LIST, &options.passwd},
	{"single", FLG_SINGLE_SET, FLG_CRACKING_CHK, 0, 0,
		OPT_FMT_STR_ALLOC, &options.loader.activesinglerules},
	{"wordlist", FLG_WORDLIST_SET, FLG_CRACKING_CHK,
		0, OPT_REQ_PARAM, OPT_FMT_STR_ALLOC, &options.wordlist},
	{"stdin", FLG_STDIN_SET, FLG_CRACKING_CHK},
	{"rules", FLG_RULES, FLG_RULES, FLG_WORDLIST_CHK, FLG_STDIN_CHK,
		OPT_FMT_STR_ALLOC, &options.loader.activewordlistrules},
	{"incremental", FLG_INC_SET, FLG_CRACKING_CHK,
		0, 0, OPT_FMT_STR_ALLOC, &options.charset},
	{"markov", FLG_MKV_SET, FLG_CRACKING_CHK,
		0, 0, OPT_FMT_STR_ALLOC, &options.mkv_param},
	{"external", FLG_EXTERNAL_SET, FLG_EXTERNAL_CHK,
		0, OPT_REQ_PARAM, OPT_FMT_STR_ALLOC, &options.external},
	{"stdout", FLG_STDOUT, FLG_STDOUT,
		FLG_CRACKING_SUP, FLG_SINGLE_CHK | FLG_BATCH_CHK,
		"%u", &options.length},
	{"restore", FLG_RESTORE_SET, FLG_RESTORE_CHK,
		0, ~FLG_RESTORE_SET & ~OPT_REQ_PARAM,
		OPT_FMT_STR_ALLOC, &options.session},
	{"session", FLG_SESSION, FLG_SESSION,
		FLG_CRACKING_SUP, OPT_REQ_PARAM,
		OPT_FMT_STR_ALLOC, &options.session},
	{"status", FLG_STATUS_SET, FLG_STATUS_CHK,
		0, ~FLG_STATUS_SET & ~OPT_REQ_PARAM,
		OPT_FMT_STR_ALLOC, &options.session},
	{"make-charset", FLG_MAKECHR_SET, FLG_MAKECHR_CHK,
		0, FLG_CRACKING_CHK | FLG_SESSION | OPT_REQ_PARAM,
		OPT_FMT_STR_ALLOC, &options.charset},
	{"show", FLG_SHOW_SET, FLG_SHOW_CHK,
		0, FLG_CRACKING_SUP | FLG_MAKECHR_CHK,
		OPT_FMT_STR_ALLOC, &options.showuncracked_str},
	{"test", FLG_TEST_SET, FLG_TEST_CHK,
		0, ~FLG_TEST_SET & ~FLG_FORMAT & ~FLG_SAVEMEM &
		~OPT_REQ_PARAM & ~FLG_SUB_FORMAT, "%u", &benchmark_time},
	{"users", FLG_NONE, 0, FLG_PASSWD, OPT_REQ_PARAM,
		OPT_FMT_ADD_LIST_MULTI, &options.loader.users},
	{"groups", FLG_NONE, 0, FLG_PASSWD, OPT_REQ_PARAM,
		OPT_FMT_ADD_LIST_MULTI, &options.loader.groups},
	{"shells", FLG_NONE, 0, FLG_PASSWD, OPT_REQ_PARAM,
		OPT_FMT_ADD_LIST_MULTI, &options.loader.shells},
	{"salt-list", FLG_SALTS, FLG_SALTS, FLG_PASSWD, OPT_REQ_PARAM,
		OPT_FMT_ADD_LIST_MULTI, &options.loader.single_salts},
	{"salts", FLG_SALTS, FLG_SALTS, FLG_PASSWD, OPT_REQ_PARAM,
		OPT_FMT_STR_ALLOC, &options.salt_param},
	{"pot", FLG_NONE, FLG_NONE, 0, OPT_REQ_PARAM,
	    OPT_FMT_STR_ALLOC, &options.loader.activepot},
	{"format", FLG_FORMAT, FLG_FORMAT,
		0, FLG_STDOUT | OPT_REQ_PARAM,
		OPT_FMT_STR_ALLOC, &options.format},
	{"subformat", FLG_SUB_FORMAT, FLG_SUB_FORMAT,
		0, FLG_STDOUT | OPT_REQ_PARAM,
		OPT_FMT_STR_ALLOC, &options.subformat},
	{"save-memory", FLG_SAVEMEM, FLG_SAVEMEM, 0, OPT_REQ_PARAM,
		"%u", &mem_saving_level},
	{"mem-file-size", FLG_NONE, FLG_NONE, 0, OPT_REQ_PARAM,
		"%u", &options.loader.max_wordfile_memory},
	{"fix-state-delay", FLG_NONE, FLG_NONE, 0, OPT_REQ_PARAM,
		"%u", &options.loader.max_fix_state_delay},
	{"field-separator-char", FLG_NONE, FLG_NONE, 0, OPT_REQ_PARAM,
		OPT_FMT_STR_ALLOC, &field_sep_char_string},
	{"config", FLG_CONFIG_OPT, FLG_CONFIG_CLI, FLG_CONFIG_CLI,
		OPT_REQ_PARAM, OPT_FMT_STR_ALLOC, &options.config},
        {"gijohn", FLG_GIJOHN_CHK, FLG_GIJOHN_SET, 0, OPT_REQ_PARAM,
                OPT_FMT_STR_ALLOC, &gijohnserver},
        {"gijsmp", FLG_GIJOHN_SMP_CHK, FLG_GIJOHN_SMP_SET, 0, OPT_REQ_PARAM,
                "%u", &gijohnsmp},
        {"verbose", FLG_VERBOSE, FLG_VERBOSE},
	{NULL}
};

#define JOHN_COPYRIGHT \
	"Solar Designer and others"

#ifdef HAVE_CRYPT
#define MAYBE_CRYPT "/crypt"
#else
#define MAYBE_CRYPT ""
#endif

#define JOHN_USAGE \
"John the Ripper password cracker, version " JOHN_VERSION "\n" \
"Copyright (c) 1996-2010 by " JOHN_COPYRIGHT "\n" \
"Homepage: http://www.openwall.com/john/\n" \
"\n" \
"Usage: %s [OPTIONS] [PASSWORD-FILES]\n" \
"--config=FILE              use FILE instead of john.conf or john.ini\n" \
"--single[=SECTION]         \"single crack\" mode\n" \
"--wordlist=FILE --stdin    wordlist mode, read words from FILE or stdin\n" \
"--rules[=SECTION]          enable word mangling rules for wordlist mode\n" \
"--incremental[=MODE]       \"incremental\" mode [using section MODE]\n" \
"--markov[=LEVEL[:START:END[:MAXLEN]]] \"Markov\" mode (see documentation)\n" \
"--external=MODE            external mode or word filter\n" \
"--stdout[=LENGTH]          just output candidate passwords [cut at LENGTH]\n" \
"--restore[=NAME]           restore an interrupted session [called NAME]\n" \
"--session=NAME             give a new session the NAME\n" \
"--status[=NAME]            print status of a session [called NAME]\n" \
"--make-charset=FILE        make a charset, FILE will be overwritten\n" \
"--show[=LEFT]              show cracked passwords [if =LEFT, then uncracked]\n" \
"--test[=TIME]              run tests and benchmarks for TIME seconds each\n" \
"--users=[-]LOGIN|UID[,..]  [do not] load this (these) user(s) only\n" \
"--groups=[-]GID[,..]       load users [not] of this (these) group(s) only\n" \
"--shells=[-]SHELL[,..]     load users with[out] this (these) shell(s) only\n" \
"--salt-list=SALT[,SALT,..] load just the specified salt(s)\n" \
"--salts=[-]COUNT[:MAX]     load salts with[out] at least COUNT passwords only\n" \
"                           (or in range of COUNT to MAX)\n" \
"--pot=NAME                 pot file to use\n" \
"--format=NAME              force hash type NAME:\n" \
"                           DES/BSDI/MD5/BF/AFS/LM/NT/XSHA/PO/raw-MD5/MD5-gen/\n" \
"                           IPB2/raw-sha1/md5a/hmac-md5/phpass-md5/KRB5/bfegg/\n" \
"                           nsldap/ssha/openssha/oracle/oracle11/MYSQL/\n" \
"                           mysql-sha1/mscash/lotus5/DOMINOSEC/\n" \
"                           NETLM/NETNTLM/NETLMv2/NETNTLMv2/NETHALFLM/\n" \
"                           mssql/mssql05/epi/phps/mysql-fast/pix-md5/sapG/\n" \
"                           sapB/md5ns/HDAA/DMD5" MAYBE_CRYPT "\n" \
"--subformat=NAME           Some formats such as MD5-gen have subformats\n" \
"                           (like md5_gen(0), md5_gen(7), etc).\n" \
"                           This allows them to be specified.\n" \
"                           If the name is LIST, then john will show all\n" \
"                           subformats (help mode), and exit\n" \
"--save-memory=LEVEL        enable memory saving, at LEVEL 1..3\n" \
"--mem-file-size=SIZE       max size a wordlist file will preload into memory\n" \
"                           (default 5,000,000 bytes)\n" \
"--field-separator-char=c   Use 'c' instead of the ':' for processing fields\n" \
"                           (input file, pot file, etc)\n" \
"--fix-state-delay=N        only determine the wordlist offset every N times\n" \
"                           It is a performance gain to delay a while\n" \
"                           (say 100 loops for a fast algorithm).\n" \
"                           For slow algorithms it should not be used.\n" \
"--gijohn=SERVER:PORT       gijohn's server and port\n" \
"--gijsmp=NUM               gijohn makes NUM forks\n" \
"--verbose                  gijohn's verbose mode\n"

void opt_init(char *name, int argc, char **argv)
{
	if (argc < 2) {
		printf(JOHN_USAGE, name);
		exit(0);
	}

	memset(&options, 0, sizeof(options));

	options.loader.field_sep_char = options.field_sep_char = ':';
	options.loader.max_fix_state_delay = 0;
	options.loader.max_wordfile_memory = 5000000;

	list_init(&options.passwd);

	options.loader.flags = DB_LOGIN;
	list_init(&options.loader.users);
	list_init(&options.loader.groups);
	list_init(&options.loader.shells);
	list_init(&options.loader.single_salts);

	options.length = -1;

	opt_process(opt_list, &options.flags, argv);

	if ((options.flags &
	    (FLG_EXTERNAL_CHK | FLG_CRACKING_CHK | FLG_MAKECHR_CHK)) ==
	    FLG_EXTERNAL_CHK)
		options.flags |= FLG_CRACKING_SET;

	if (!(options.flags & FLG_ACTION))
		options.flags |= FLG_BATCH_SET;

	opt_check(opt_list, options.flags, argv);

	if (options.session) {
		rec_name = options.session;
		rec_name_completed = 0;
	}

	if (options.flags & FLG_RESTORE_CHK) {
		rec_restore_args(1);
		return;
	}

	if (options.subformat && !strcasecmp(options.subformat, "list"))
	{
		md5_gen_DISPLAY_ALL_FORMATS();
		// NOTE if we have other 'generics', like sha1, sha2, rc4, ....  then EACH of
		// them should have a DISPLAY_ALL_FORMATS() function and we can call them here.
		exit(0);
	}

	if (options.flags & FLG_STATUS_CHK) {
		rec_restore_args(0);
		options.flags |= FLG_STATUS_SET;
		status_init(NULL, 1);
		status_print();
		exit(0);
	}

	if (options.flags & FLG_SALTS)
	{
		int two_salts = 0;
		if (sscanf(options.salt_param, "%d:%d", &options.loader.min_pps, &options.loader.max_pps) == 2)
			two_salts = 1;
		if (!two_salts && sscanf(options.salt_param, "%d,%d", &options.loader.min_pps, &options.loader.max_pps) == 2)
			two_salts = 1;
		if (!two_salts){
			sscanf(options.salt_param, "%d", &options.loader.min_pps);
			if (options.loader.min_pps < 0) {
				options.loader.max_pps = -1 - options.loader.min_pps;
				options.loader.min_pps = 0;
			}
			else
				options.loader.max_pps = 0x7fffffff;
		} else if (options.loader.min_pps < 0) {
			fprintf(stderr, "Usage of negative -salt min is not 'valid' if using Min and Max salt range of values\n");
			error();
		}
		if (options.loader.min_pps > options.loader.max_pps) {
			fprintf(stderr, "Min number salts wanted is less than Max salts wanted\n");
			error();
		}
	}

	if (options.length < 0)
		options.length = PLAINTEXT_BUFFER_SIZE - 3;
	else
	if (options.length < 1 || options.length > PLAINTEXT_BUFFER_SIZE - 3) {
		fprintf(stderr, "Invalid plaintext length requested\n");
		error();
	}

	if (options.flags & FLG_STDOUT) options.flags &= ~FLG_PWD_REQ;

        if (options.flags & FLG_GIJOHN_CHK) options.flags &= ~FLG_PWD_REQ 
		& ~FLG_PASSWD;

	if ((options.flags & (FLG_PASSWD | FLG_PWD_REQ)) == FLG_PWD_REQ) {
		fprintf(stderr, "Password files required, "
			"but none specified\n");
		error();
	}

	if ((options.flags & (FLG_PASSWD | FLG_PWD_SUP)) == FLG_PASSWD) {
		fprintf(stderr, "Password files specified, "
			"but no option would use them\n");
		error();
	}

	if (options.flags & FLG_MKV_CHK) {
		options.mkv_start = 0; options.mkv_end = 0; options.mkv_maxlen =
	0;
		if (options.mkv_param)
			sscanf(options.mkv_param, "%d:%lld:%lld:%d", &options.mkv_level, &options.mkv_start, &options.mkv_end, &options.mkv_maxlen);
	}

	if ( (options.flags & FLG_SHOW_SET) && options.showuncracked_str) {
		if (!strcasecmp( options.showuncracked_str, "left"))  {
			options.loader.showuncracked = 1;
			// Note we 'do' want the pot file to load normally, but during that load, 
			// we print out hashes left. At the end of the load, john exits.  However
			// we do NOT want the 'special' -SHOW_CHK logic to happen (which happens
			// instead of normal loading if we are in 'normal' show mode)
			options.flags &= ~FLG_SHOW_CHK;
		}
		else {
			fprintf(stderr, "Invalid option in --show switch.\nOnly --show or --show=left are valid\n");
			error();
		}
	}

	if (options.loader.activepot == NULL)
		options.loader.activepot = str_alloc_copy(POT_NAME);

	if (options.loader.activewordlistrules == NULL)
		options.loader.activewordlistrules = str_alloc_copy(SUBSECTION_WORDLIST);

	if (options.loader.activesinglerules == NULL)
		options.loader.activesinglerules = str_alloc_copy(SUBSECTION_SINGLE);

	if (field_sep_char_string != NULL)
	{
		if (strlen(field_sep_char_string) == 1)
			options.field_sep_char = *field_sep_char_string;
		else if (field_sep_char_string[0] == '\\' && (field_sep_char_string[1]=='x'||field_sep_char_string[1]=='X'))
		{
			unsigned xTmp=0;
			sscanf(&field_sep_char_string[2], "%x", &xTmp);
			if (!xTmp || xTmp > 255)
			{
				fprintf (stderr, "trying to use an invalid field separator char:  %s\n", field_sep_char_string);
				error();
			}
			options.field_sep_char = (char)xTmp;
		}

		options.loader.field_sep_char = options.field_sep_char;
		if (options.loader.field_sep_char != ':')
			fprintf (stderr, "using field sep char '%c' (0x%02x)\n", options.field_sep_char, options.field_sep_char);
	}

	rec_argc = argc; rec_argv = argv;
	rec_check = 0;
}
