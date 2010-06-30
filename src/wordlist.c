/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-99,2003,2004,2006,2009 by Solar Designer
 *
 * Heavily modified by JimF and maybe by others.
 */

#include <stdio.h>
#include <sys/stat.h>
#if !defined (_MSC_VER)
#include <unistd.h>
#else
#pragma warning ( disable : 4996 )
#endif
#include <string.h>

#include "arch.h"
#include "misc.h"
#include "math.h"
#include "params.h"
#include "common.h"
#include "path.h"
#include "signals.h"
#include "loader.h"
#include "logger.h"
#include "status.h"
#include "recovery.h"
#include "rpp.h"
#include "rules.h"
#include "external.h"
#include "cracker.h"
#include "memory.h"

static FILE *word_file = NULL;
static int progress = 0, hund_progress = 0;

static int rec_rule;
static long rec_pos;

static int rule_number, rule_count, line_number;
static int length;
static struct rpp_context *rule_ctx;

// used for file in 'memory map' mode
static char *word_file_str, **words;
static unsigned int nWordFileLines = 0, nCurLine;
static struct db_main *_db;

static void save_state(FILE *file)
{
	fprintf(file, "%d\n%ld\n", rec_rule, rec_pos);
}

static int restore_rule_number(void)
{
	if (rule_ctx)
	for (rule_number = 0; rule_number < rec_rule; rule_number++)
	if (!rpp_next(rule_ctx)) return 1;

	return 0;
}

static void restore_line_number(void)
{
	char line[LINE_BUFFER_SIZE];

	for (line_number = 0; line_number < rec_pos; line_number++)
	if (!fgets(line, sizeof(line), word_file)) {
		if (ferror(word_file))
			pexit("fgets");
		else {
			fprintf(stderr, "fgets: Unexpected EOF\n");
			error();
		}
	}
}

static int restore_state(FILE *file)
{
	if (fscanf(file, "%d\n%ld\n", &rec_rule, &rec_pos) != 2) return 1;

	if (restore_rule_number()) return 1;

	if (word_file == stdin)
		restore_line_number();
	else {
		if (nWordFileLines) {
			for (nCurLine = 0; nCurLine < nWordFileLines; ++nCurLine) {
				if (words[nCurLine] - words[0] >= rec_pos)
					break;
			}
		}
		else
			if (fseek(word_file, rec_pos, SEEK_SET)) pexit("fseek");
	}

	return 0;
}

static int fix_state_delay;

static void fix_state(void)
{
	if (nWordFileLines) {
		rec_rule = rule_number;
		rec_pos = words[nCurLine] - words[0];
		return;
	}

	if (++fix_state_delay < _db->options->max_fix_state_delay)
		return;
	fix_state_delay=0;

	rec_rule = rule_number;

	if (word_file == stdin)
		rec_pos = line_number;
	else
	if ((rec_pos = ftell(word_file)) < 0) {
#ifdef __DJGPP__
		if (rec_pos != -1)
			rec_pos = 0;
		else
#endif
			pexit("ftell");
	}
}

static int get_progress(int *hundth_perc)
{
	struct stat file_stat;
	long pos;
	int hundredXpercent, percent;
	double x100, tmp;

	if (!word_file) {
		*hundth_perc = hund_progress;
		return progress;
	}

	if (word_file == stdin) {
		*hundth_perc = 0;
		return -1;
	}

	if (fstat(fileno(word_file), &file_stat)) pexit("fstat");
	if (nWordFileLines) {
		pos = rec_pos;
	}
	else {
		if ((pos = ftell(word_file)) < 0) {
#ifdef __DJGPP__
			if (pos != -1)
				pos = 0;
			else
#endif
				pexit("ftell");
		}
	}

	x100 = ((double)pos) * 10000.;
	// a double 'tmp' var is required, as I have seen the compiler
	// optimize away the next statement if assigned to an int
	tmp = (((double)rule_number)*10000. + x100/(file_stat.st_size+1)) / rule_count;
	// safe int assignment.  tmp will be from 0 to 10000.00
	hundredXpercent = (int)tmp;
	percent = hundredXpercent / 100;
	*hundth_perc = hundredXpercent - (percent*100);
	return percent;
}

static char *dummy_rules_apply(char *word, char *rule, int split, char *last)
{
	word[length] = 0;
	if (strcmp(word, last))
		return strcpy(last, word);
	return NULL;
}

void do_wordlist_crack(struct db_main *db, char *name, int rules)
{
	union {
		char buffer[2][LINE_BUFFER_SIZE + CACHE_BANK_SHIFT];
		ARCH_WORD dummy;
	} aligned;
	char *line = aligned.buffer[0], *last = aligned.buffer[1];
	struct rpp_context ctx;
	char *prerule, *rule, *word;
	char *(*apply)(char *word, char *rule, int split, char *last);
	long file_len;
	int i;

	log_event("Proceeding with wordlist mode");

	_db = db;

	if (name) {
		char *cp, csearch;

		if (!(word_file = fopen(path_expand(name), "rb")))
			pexit("fopen: %s", path_expand(name));
		log_event("- Wordlist file: %.100s", path_expand(name));

		/* this will both get us the file length, and tell us
		   of 'invalid' files (i.e. too big in Win32 or other
		   32 bit OS's.  A file between 2gb and 4gb returns
		   a negative number.  NOTE john craps out on files
		   this big.  The file needs cut before running through
		   through john */
		fseek(word_file, 0, SEEK_END);
		file_len = ftell(word_file);
		fseek(word_file, 0, SEEK_SET);
		if (file_len < 0)
		{
			fprintf(stderr, "Error, dictionary file is too large for john to read (probably a 32 bit OS issue)\n");
			error();
		}
		/* If the file is < max_wordfile_memory, then we work from a memory map of the file */
		if (file_len < db->options->max_wordfile_memory)
		{
			/* probably should only be debug message, but I left it in */
			log_event("loading wordfile %s into memory (%lu bytes, max_size=%u)\n", name, file_len, db->options->max_wordfile_memory);
/* XXX: would need to alloc more for dummy_rules_apply()'s "blind truncation" */
			word_file_str = mem_alloc(file_len+1);
			if (fread(word_file_str, 1, file_len, word_file) != file_len) {
				if (ferror(word_file))
					pexit("fread");
				fprintf(stderr, "fread: Unexpected EOF\n");
				error();
			}
			word_file_str[file_len] = 0;
			csearch = '\n';
			cp = strchr(word_file_str, csearch);
			if (!cp)
			{
				csearch = '\r';
				cp = strchr(word_file_str, csearch);
			}
			for (nWordFileLines = 1; cp; ++nWordFileLines)
				cp = strchr(&cp[1], csearch);
			words = mem_alloc(nWordFileLines * sizeof(char*));
			log_event("wordfile had %u lines and required %lu bytes for index.\n", nWordFileLines, (unsigned long)(nWordFileLines * sizeof(char*)));

			i = 0;
			cp = word_file_str;
			do
			{
				char *ep = cp, ec;
				while (*ep && *ep != '\n' && *ep != '\r') ep++;
				ec = *ep;
				*ep = 0;
				if (ep - cp >= LINE_BUFFER_SIZE)
					cp[LINE_BUFFER_SIZE-1] = 0;
				if (strncmp(cp, "#!comment", 9))
					words[i++] = cp;
				if (!ec || i == nWordFileLines)
					break;
				cp = ep + 1;
				if (ec == '\r' && *cp == '\n') cp++;
			} while (*cp);
			nWordFileLines = i;
			nCurLine=0;
		}
	} else {
		word_file = stdin;
		log_event("- Reading candidate passwords from stdin");
	}

	length = db->format->params.plaintext_length;

	if (rules) {
		if (rpp_init(rule_ctx = &ctx, db->options->activewordlistrules)) {
			log_event("! No wordlist mode rules found");
			fprintf(stderr, "No wordlist mode rules found in %s\n",
				cfg_name);
			error();
		}

		rules_init(length);
		rule_count = rules_count(&ctx, -1);

		log_event("- %d preprocessed word mangling rules", rule_count);

		apply = rules_apply;
	} else {
		rule_ctx = NULL;
		rule_count = 1;

		log_event("- No word mangling rules");

		apply = dummy_rules_apply;
	}

	line_number = rule_number = 0;

	status_init(get_progress, 0);

	rec_restore_mode(restore_state);
	rec_init(db, save_state);

	crk_init(db, fix_state, NULL);

	if (rules) prerule = rpp_next(&ctx); else prerule = "";
	rule = "";

/* A string that can't be produced by fgetl(). */
	last[0] = '\n';
	last[1] = 0;

	if (prerule)
	do {
		if (rules) {
			if ((rule = rules_reject(prerule, -1, last, db))) {
				if (strcmp(prerule, rule))
					log_event("- Rule #%d: '%.100s'"
						" accepted as '%.100s'",
						rule_number + 1, prerule, rule);
				else
					log_event("- Rule #%d: '%.100s'"
						" accepted",
						rule_number + 1, prerule);
			} else
				log_event("- Rule #%d: '%.100s' rejected",
					rule_number + 1, prerule);
		}

		if (rule)
		while (1) {
			if (nWordFileLines) {
				if (nCurLine == nWordFileLines)
					break;
#if 0 && ARCH_ALLOWS_UNALIGNED
/* XXX: somehow this breaks things - why? */
				line = words[nCurLine++];
#else
				strcpy(line, words[nCurLine++]);
#endif
			}
			else {
				if (!fgetl(line, LINE_BUFFER_SIZE, word_file))
					break;
			}
			line_number++;

			if (line[0] != '#') {
not_comment:
				if ((word = apply(line, rule, -1, last))) {
					last = word;

					if (ext_filter(word))
					if (crk_process_key(word)) {
						rules = 0;
						break;
					}
				}
				continue;
			}

			if (strncmp(line, "#!comment", 9))
				goto not_comment;
		}

		if (rules) {
			if (!(rule = rpp_next(&ctx))) break;
			rule_number++;

			line_number = 0;

			if (nWordFileLines)
				nCurLine = 0;
			else
				if (fseek(word_file, 0, SEEK_SET)) pexit("fseek");
		}
	} while (rules);

	crk_done();
	rec_done(event_abort || (status.pass && db->salts));

	if (ferror(word_file)) pexit("fgets");

	if (name) {
		if (event_abort)
			progress = get_progress(&hund_progress);
		else
			progress = 100;

		MEM_FREE(word_file_str);
		MEM_FREE(words);
		if (fclose(word_file)) pexit("fclose");
		word_file = NULL;
	}
}
