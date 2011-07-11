/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-2004,2006,2009-2011 by Solar Designer
 *
 * ...with changes in the jumbo patch, by various authors
 */

#include <stdio.h>
#ifndef _MSC_VER
#include <unistd.h>
#endif
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>

#include "arch.h"
#include "misc.h"
#include "params.h"
#include "path.h"
#include "memory.h"
#include "list.h"
#include "tty.h"
#include "signals.h"
#include "common.h"
#include "idle.h"
#include "formats.h"
#include "loader.h"
#include "logger.h"
#include "status.h"
#include "options.h"
#include "config.h"
#include "bench.h"
#include "charset.h"
#include "single.h"
#include "wordlist.h"
#include "inc.h"
#include "mkv.h"
#include "external.h"
#include "batch.h"
#include "gijohn.h"
#include "recovery.h"

#if CPU_DETECT
extern int CPU_detect(void);
#endif

extern struct fmt_main fmt_DES, fmt_BSDI, fmt_MD5, fmt_BF;
extern struct fmt_main fmt_AFS, fmt_LM;
#ifdef HAVE_CRYPT
extern struct fmt_main fmt_crypt;
#endif
extern struct fmt_main fmt_dummy;

extern struct fmt_main fmt_NT, fmt_XSHA;
extern struct fmt_main fmt_PO;
extern struct fmt_main fmt_rawMD5go;
extern struct fmt_main fmt_MD5gen;
extern struct fmt_main fmt_hmacMD5;
extern struct fmt_main fmt_IPB2;
extern struct fmt_main fmt_phpassmd5;
extern struct fmt_main fmt_DMD5;
extern struct fmt_main fmt_BFEgg;
extern struct fmt_main fmt_KRB4;
extern struct fmt_main fmt_KRB5;
extern struct fmt_main fmt_oracle;
extern struct fmt_main fmt_oracle11;
extern struct fmt_main fmt_MYSQL;
extern struct fmt_main fmt_mysqlSHA1;
extern struct fmt_main fmt_NSLDAP;
extern struct fmt_main fmt_NSLDAPS;
extern struct fmt_main fmt_OPENLDAPS;
extern struct fmt_main fmt_mscash;
extern struct fmt_main fmt_mscash2;
extern struct fmt_main fmt_rawSHA1;
extern struct fmt_main fmt_XSHA;
extern struct fmt_main fmt_sha1_gen;
extern struct fmt_main fmt_rawMD4;
extern struct fmt_main fmt_md4_gen;
extern struct fmt_main fmt_lotus5;
extern struct fmt_main fmt_DOMINOSEC;
extern struct fmt_main fmt_NETLM;
extern struct fmt_main fmt_NETNTLM;
extern struct fmt_main fmt_NETLMv2;
extern struct fmt_main fmt_NETNTLMv2;
extern struct fmt_main fmt_NETHALFLM;
extern struct fmt_main fmt_MSCHAPv2;
extern struct fmt_main fmt_mssql;
extern struct fmt_main fmt_mssql05;
extern struct fmt_main fmt_EPI;
extern struct fmt_main fmt_PHPS;
extern struct fmt_main fmt_MYSQL_fast;
extern struct fmt_main fmt_pixMD5;
extern struct fmt_main fmt_sapG;
extern struct fmt_main fmt_sapB;
extern struct fmt_main fmt_NS;
extern struct fmt_main fmt_HDAA;

#ifdef HAVE_SKEY
extern struct fmt_main fmt_SKEY;
#endif

extern int unshadow(int argc, char **argv);
extern int unafs(int argc, char **argv);
extern int undrop(int argc, char **argv);
extern int unique(int argc, char **argv);

extern struct db_main *crk_db;

struct db_main database;
static struct fmt_main dummy_format;

extern int aborted_gijohn;
extern unsigned int gijohnsmp;

static int exit_status = 0;

static void john_register_one(struct fmt_main *format)
{
	if (options.format)
	if (strcmp(options.format, format->params.label)) return;

	fmt_register(format);
}

static void john_register_all(void)
{
	if (options.format) strlwr(options.format);

	john_register_one(&fmt_DES);
	john_register_one(&fmt_BSDI);
	john_register_one(&fmt_MD5);
	john_register_one(&fmt_BF);
	john_register_one(&fmt_AFS);
	john_register_one(&fmt_LM);

	john_register_one(&fmt_NT);
	john_register_one(&fmt_XSHA);
	john_register_one(&fmt_mscash);
	john_register_one(&fmt_mscash2);
	john_register_one(&fmt_hmacMD5);
	john_register_one(&fmt_PO);
	john_register_one(&fmt_rawMD5go);
	john_register_one(&fmt_MD5gen);
	john_register_one(&fmt_phpassmd5);
	john_register_one(&fmt_DMD5);
	john_register_one(&fmt_IPB2);
	john_register_one(&fmt_rawSHA1);
	john_register_one(&fmt_sha1_gen);
	john_register_one(&fmt_rawMD4);
	john_register_one(&fmt_md4_gen);
	john_register_one(&fmt_KRB4);
	john_register_one(&fmt_KRB5);
	john_register_one(&fmt_NSLDAP);
	john_register_one(&fmt_NSLDAPS);
	john_register_one(&fmt_OPENLDAPS);
	john_register_one(&fmt_BFEgg);
	john_register_one(&fmt_oracle);
	john_register_one(&fmt_oracle11);
	john_register_one(&fmt_MYSQL);
	john_register_one(&fmt_mysqlSHA1);
	john_register_one(&fmt_lotus5);
	john_register_one(&fmt_DOMINOSEC);
	john_register_one(&fmt_NETLM);
	john_register_one(&fmt_NETNTLM);
	john_register_one(&fmt_NETLMv2);
	john_register_one(&fmt_NETNTLMv2);
	john_register_one(&fmt_NETHALFLM);
	john_register_one(&fmt_MSCHAPv2);
	john_register_one(&fmt_mssql);
	john_register_one(&fmt_mssql05);
	john_register_one(&fmt_EPI);
	john_register_one(&fmt_PHPS);
	john_register_one(&fmt_MYSQL_fast);
	john_register_one(&fmt_pixMD5);
	john_register_one(&fmt_sapG);
	john_register_one(&fmt_sapB);
	john_register_one(&fmt_NS);
	john_register_one(&fmt_HDAA);

#ifdef HAVE_SKEY
	john_register_one(&fmt_SKEY);
#endif

#ifdef HAVE_CRYPT
	john_register_one(&fmt_crypt);
#endif

	john_register_one(&fmt_dummy);

	if (!fmt_list) {
		fprintf(stderr, "Unknown ciphertext format name requested\n");
		error();
	}
}

static void john_log_format(void)
{
	int min_chunk, chunk;

	log_event("- Hash type: %.100s (lengths up to %d%s)",
		database.format->params.format_name,
		database.format->params.plaintext_length,
		(database.format == &fmt_DES || database.format == &fmt_LM) ?
		", longer passwords split" : "");

	log_event("- Algorithm: %.100s",
		database.format->params.algorithm_name);

	chunk = min_chunk = database.format->params.max_keys_per_crypt;
	if (options.flags & (FLG_SINGLE_CHK | FLG_BATCH_CHK) &&
	    chunk < SINGLE_HASH_MIN)
			chunk = SINGLE_HASH_MIN;
	if (chunk > 1)
		log_event("- Candidate passwords %s be buffered and "
			"tried in chunks of %d",
			min_chunk > 1 ? "will" : "may",
			chunk);
}

char *john_loaded_counts(void)
{
	static char s_loaded_counts[80];

	if (database.password_count == 1)
		return "1 password hash";

	sprintf(s_loaded_counts,
		database.salt_count > 1 ?
		"%d password hashes with %d different salts" :
		"%d password hashes with no different salts",
		database.password_count,
		database.salt_count);

	return s_loaded_counts;
}

static void john_load(void)
{
	struct list_entry *current;

#if !defined (_MSC_VER)
	umask(077);
#endif

	if ((options.flags & FLG_EXTERNAL_CHK) && FLG_GIJOHN_CHK)
		ext_init(options.external);

	if ((options.flags & FLG_GIJOHN_CHK) && FLG_EXTERNAL_CHK)
	{
		ext_init("gijohn");
	}

	if (options.flags & FLG_MAKECHR_CHK) {
		options.loader.flags |= DB_CRACKED;
		ldr_init_database(&database, &options.loader);

		if (options.flags & FLG_PASSWD) {
			ldr_show_pot_file(&database, options.loader.activepot);

			database.options->flags |= DB_PLAINTEXTS;
			if ((current = options.passwd->head))
			do {
				ldr_show_pw_file(&database, current->data);
			} while ((current = current->next));
		} else {
			database.options->flags |= DB_PLAINTEXTS;
			ldr_show_pot_file(&database, options.loader.activepot);
		}

		return;
	}

	if (options.flags & FLG_STDOUT) {
		ldr_init_database(&database, &options.loader);
		database.format = &dummy_format;
		memset(&dummy_format, 0, sizeof(dummy_format));
		dummy_format.params.plaintext_length = options.length;
		dummy_format.params.flags = FMT_CASE | FMT_8_BIT;
	}

	if (options.flags & FLG_PASSWD) {
		int total;

		if (options.flags & FLG_SHOW_CHK) {
			options.loader.flags |= DB_CRACKED;
			ldr_init_database(&database, &options.loader);

			ldr_show_pot_file(&database, options.loader.activepot);

			if ((current = options.passwd->head))
			do {
				ldr_show_pw_file(&database, current->data);
			} while ((current = current->next));

			printf("%s%d password hash%s cracked, %d left\n",
				database.guess_count ? "\n" : "",
				database.guess_count,
				database.guess_count != 1 ? "es" : "",
				database.password_count -
				database.guess_count);

			return;
		}

		if (options.flags & (FLG_SINGLE_CHK | FLG_BATCH_CHK) &&
		    status.pass <= 1)
			options.loader.flags |= DB_WORDS;
		else
		if (mem_saving_level) {
			options.loader.flags &= ~DB_LOGIN;
			options.loader.max_wordfile_memory = 0;
		}
		ldr_init_database(&database, &options.loader);

		if ((current = options.passwd->head))
		do {
			ldr_load_pw_file(&database, current->data);
		} while ((current = current->next));

		if ((options.flags & FLG_CRACKING_CHK) &&
		    database.password_count) {
			log_init(LOG_NAME, NULL, options.session);
			if (status_restored_time)
				log_event("Continuing an interrupted session");
			else
				log_event("Starting a new session");
			log_event("Loaded a total of %s", john_loaded_counts());
			printf("Loaded %s (%s [%s])\n",
				john_loaded_counts(),
				database.format->params.format_name,
				database.format->params.algorithm_name);
		}

		total = database.password_count;
		ldr_load_pot_file(&database, options.loader.activepot);
		ldr_fix_database(&database);

		if (!database.password_count) {
			log_discard();
			printf("No password hashes %s (see FAQ)\n",
			    total ? "left to crack" : "loaded");
		} else
		if (database.password_count < total) {
			log_event("Remaining %s", john_loaded_counts());
			printf("Remaining %s\n", john_loaded_counts());
		}

		if ((options.flags & FLG_PWD_REQ) && !database.salts) exit(0);
	}
}

static void john_init(char *name, int argc, char **argv)
{
	int make_check = (argc == 2 && !strcmp(argv[1], "--make_check"));
	if (make_check)
		argv[1] = "--test=0";

#if CPU_DETECT
	if (!CPU_detect()) {
#if CPU_REQ
#if CPU_FALLBACK
#if defined(__DJGPP__) || defined(__CYGWIN32__)
#error CPU_FALLBACK is incompatible with the current DOS and Win32 code
#endif
		if (!make_check) {
#define CPU_FALLBACK_PATHNAME JOHN_SYSTEMWIDE_EXEC "/" CPU_FALLBACK_BINARY
			execv(CPU_FALLBACK_PATHNAME, argv);
			perror("execv: " CPU_FALLBACK_PATHNAME);
		}
#endif
		fprintf(stderr, "Sorry, %s is required\n", CPU_NAME);
		if (make_check)
			exit(0);
		error();
#endif
	}
#endif

	if (!make_check) {
		path_init(argv);

    status_init(NULL, 1);
    opt_init(name, argc, argv);

    if (options.flags & FLG_CONFIG_CLI)
    {
      cfg_init(options.config, 1);
      cfg_init(CFG_ALT_NAME, 0);
    }
    else
    {
#if JOHN_SYSTEMWIDE
		cfg_init(CFG_PRIVATE_FULL_NAME, 1);
		cfg_init(CFG_PRIVATE_ALT_NAME, 1);
#endif
		cfg_init(CFG_FULL_NAME, 1);
		cfg_init(CFG_ALT_NAME, 0);
	}
	}

	john_register_all();
	common_init();

	sig_init();

	john_load();
}

static void john_run(void)
{
	if (options.flags & FLG_TEST_CHK)
		exit_status = benchmark_all() ? 1 : 0;
	else
	if (options.flags & FLG_MAKECHR_CHK)
		do_makechars(&database, options.charset);
	else
	if (options.flags & FLG_CRACKING_CHK) {
		int remaining = database.password_count;

		if (!(options.flags & FLG_STDOUT)) {
			status_init(NULL, 1);
			log_init(LOG_NAME, options.loader.activepot, options.session);
			john_log_format();
			if (idle_requested(database.format))
				log_event("- Configured to use otherwise idle "
					"processor cycles only");
		}
		tty_init(options.flags & FLG_STDIN_CHK);

		if (options.flags & FLG_SINGLE_CHK)
			do_single_crack(&database);
		else
		if ((options.flags & FLG_GIJOHN_CHK) && FLG_EXTERNAL_CHK)
		{
			do
			{
				do_external_crack(&database);
				if (!aborted_gijohn) ext_init("gijohn");
			}
			while (crk_db->password_count && !aborted_gijohn);
		}
		else
		if (options.flags & FLG_WORDLIST_CHK)
			do_wordlist_crack(&database, options.wordlist,
				(options.flags & FLG_RULES) != 0);
		else
		if (options.flags & FLG_INC_CHK)
			do_incremental_crack(&database, options.charset);
		else
		if (options.flags & FLG_MKV_CHK)
			do_markov_crack(&database, options.mkv_level, options.mkv_start, options.mkv_end, options.mkv_maxlen);
		else
		if (options.flags & FLG_EXTERNAL_CHK)
			do_external_crack(&database);
		else
		if (options.flags & FLG_BATCH_CHK)
			do_batch_crack(&database);

		status_print();
		tty_done();

		if (database.password_count < remaining) {
			char *might = "Warning: passwords printed above might";
			char *partial = " be partial";
			char *not_all = " not be all those cracked";
			switch (database.options->flags &
			    (DB_SPLIT | DB_NODUP)) {
			case DB_SPLIT:
				fprintf(stderr, "%s%s\n", might, partial);
				break;
			case DB_NODUP:
				fprintf(stderr, "%s%s\n", might, not_all);
				break;
			case (DB_SPLIT | DB_NODUP):
				fprintf(stderr, "%s%s and%s\n",
				    might, partial, not_all);
			}
			fputs("Use the \"--show\" option to display all of "
			    "the cracked passwords reliably\n", stderr);
		}
	}
}

static void john_done(void)
{
	path_done();

	if ((options.flags & FLG_CRACKING_CHK) &&
	    !(options.flags & FLG_STDOUT)) {
		if (event_abort)
			log_event("Session aborted");
		else
			log_event("Session completed");
	}
	log_done();
	check_abort(0);
}

int main(int argc, char **argv)
{
	char *name;

#ifdef __DJGPP__
	if (--argc <= 0) return 1;
	if ((name = strrchr(argv[0], '/')))
		strcpy(name + 1, argv[1]);
	name = argv[1];
	argv[1] = argv[0];
	argv++;
#else
	if (!argv[0])
		name = "john";
	else
	if ((name = strrchr(argv[0], '/')))
		name++;
#if defined(__CYGWIN32__) || defined (__MINGW32__) || defined (_MSC_VER)
	else
	if ((name = strrchr(argv[0], '\\')))
		name++;
#endif
	else
		name = argv[0];
#endif

#if defined(__CYGWIN32__) || defined (__MINGW32__) || defined (_MSC_VER)
	strlwr(name);
	if (strlen(name) > 4 && !strcmp(name + strlen(name) - 4, ".exe"))
		name[strlen(name) - 4] = 0;
#endif

	if (!strcmp(name, "unshadow"))
		return unshadow(argc, argv);

	if (!strcmp(name, "unafs"))
		return unafs(argc, argv);

	if (!strcmp(name, "unique"))
		return unique(argc, argv);

	if (!strcmp(name, "undrop"))
               return undrop(argc, argv);

	john_init(name, argc, argv);
	john_run();
	john_done();

	return exit_status;
}
