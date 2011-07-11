/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-98,2003,2006 by Solar Designer
 *
 * ...with changes in the jumbo patch, by various authors
 */

/*
 * John's command line options definition.
 */

#ifndef _JOHN_OPTIONS_H
#define _JOHN_OPTIONS_H

#include "list.h"
#include "loader.h"
#include "getopt.h"

/*
 * Option flags bitmasks.
 */
/* An action requested */
#define FLG_ACTION			0x00000001
/* Password files specified */
#define FLG_PASSWD			0x00000002
/* An option supports password files */
#define FLG_PWD_SUP			0x00000004
/* An option requires password files */
#define FLG_PWD_REQ			(0x00000008 | FLG_PWD_SUP)
/* Some option that doesn't have its own flag is specified */
#define FLG_NONE			0x00000000
/* A cracking mode enabled */
#define FLG_CRACKING_CHK		0x00000020
#define FLG_CRACKING_SUP		0x00000040
#define FLG_CRACKING_SET \
	(FLG_CRACKING_CHK | FLG_CRACKING_SUP | FLG_ACTION | FLG_PWD_REQ)
/* Wordlist mode enabled, options.wordlist is set to the file name or NULL
 * if reading from stdin. */
#define FLG_WORDLIST_CHK		0x00000080
#define FLG_WORDLIST_SET		(FLG_WORDLIST_CHK | FLG_CRACKING_SET)
/* Wordlist mode enabled, reading from stdin */
#define FLG_STDIN_CHK			0x00000100
#define FLG_STDIN_SET			(FLG_STDIN_CHK | FLG_WORDLIST_SET)
/* Wordlist rules enabled */
#define FLG_RULES			0x00000200
/* "Single crack" mode enabled */
#define FLG_SINGLE_CHK			0x00000400
#define FLG_SINGLE_SET			(FLG_SINGLE_CHK | FLG_CRACKING_SET)
/* Incremental mode enabled */
#define FLG_INC_CHK			0x00000800
#define FLG_INC_SET			(FLG_INC_CHK | FLG_CRACKING_SET)
/* External mode or word filter enabled */
#define FLG_EXTERNAL_CHK		0x00001000
#define FLG_EXTERNAL_SET \
	(FLG_EXTERNAL_CHK | FLG_ACTION | FLG_CRACKING_SUP | FLG_PWD_SUP)
/* Batch cracker */
#define FLG_BATCH_CHK			0x00004000
#define FLG_BATCH_SET			(FLG_BATCH_CHK | FLG_CRACKING_SET)
/* Stdout mode */
#define FLG_STDOUT			0x00008000
/* Restoring an interrupted session */
#define FLG_RESTORE_CHK			0x00010000
#define FLG_RESTORE_SET			(FLG_RESTORE_CHK | FLG_ACTION)
/* A session name is set */
#define FLG_SESSION			0x00020000
/* Print status of a session */
#define FLG_STATUS_CHK			0x00040000
#define FLG_STATUS_SET			(FLG_STATUS_CHK | FLG_ACTION)
/* Make a charset */
#define FLG_MAKECHR_CHK			0x00100000
#define FLG_MAKECHR_SET \
	(FLG_MAKECHR_CHK | FLG_ACTION | FLG_PWD_SUP)
/* Show cracked passwords */
#define FLG_SHOW_CHK			0x00200000
#define FLG_SHOW_SET \
	(FLG_SHOW_CHK | FLG_ACTION | FLG_PWD_REQ)
/* Perform a benchmark */
#define FLG_TEST_CHK			0x00400000
#define FLG_TEST_SET \
	(FLG_TEST_CHK | FLG_CRACKING_SUP | FLG_ACTION)
/* Passwords per salt requested */
#define FLG_SALTS			0x01000000
/* Ciphertext format forced */
#define FLG_FORMAT			0x02000000
/* Memory saving enabled */
#define FLG_SAVEMEM			0x04000000
/* Ciphertext 'sub'format forced (for md5-gen which has multiple formats)*/
#define FLG_SUB_FORMAT		0x20000000

/* gijohn's option */
#define FLG_GIJOHN_CHK                  0x08000000
#define FLG_GIJOHN_SET                  (FLG_GIJOHN_CHK | FLG_NONE)
/* gijohn's fork option */
#define FLG_GIJOHN_SMP_CHK              0x00000010
#define FLG_GIJOHN_SMP_SET              (FLG_GIJOHN_SMP_CHK | FLG_NONE)
/* verbose mode for gijohn */
#define FLG_VERBOSE                     0x00002000

/* Markov mode enabled */
#define FLG_MKV_CHK			0x40000000
#define FLG_MKV_SET			(FLG_MKV_CHK | FLG_CRACKING_SET)

/* Command-line config file */
#define FLG_CONFIG_CLI     0x10000000

/*
 * Structure with option flags and all the parameters.
 */
struct options_main {
/* Option flags */
	opt_flags flags;

/* Password files */
	struct list_main *passwd;

/* Password file loader options */
	struct db_options loader;

/* Session name */
	char *session;

/* Ciphertext format name */
	char *format;

/* Ciphertext subformat name */
	char *subformat;

/* Wordlist file name */
	char *wordlist;

/* Charset file name */
	char *charset;

/* External mode or word filter name */
	char *external;

/* Markov stuff */
	char *mkv_param;
	unsigned long long mkv_start;
	unsigned long long mkv_end;
	unsigned int mkv_level;
	unsigned int mkv_maxlen;

/* Maximum plaintext length for stdout mode */
	int length;

/* Configuration file name */
	char *config;

	char *showuncracked_str;
	char *salt_param;
	char field_sep_char;
};

extern struct options_main options;

/*
 * Initializes the options structure.
 */
extern void opt_init(char *name, int argc, char **argv);

#endif
