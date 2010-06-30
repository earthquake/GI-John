/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-2001,2003,2004,2006 by Solar Designer
 */

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>

#include "misc.h"
#include "params.h"
#include "signals.h"
#include "compiler.h"
#include "loader.h"
#include "logger.h"
#include "status.h"
#include "recovery.h"
#include "config.h"
#include "cracker.h"
#include "gijohn.h"

extern struct parsedxml xmlxml;
extern void init_external(char *charset_ex, int charsetl_ex, char *fword, char *lword);
extern void generate_external();
extern int getthenewpiece();
extern void sendtheresults();
extern void destroysession();

extern int first_time;
int gijohnmodule = 0;
extern int aborted_gijohn;

static char int_word[PLAINTEXT_BUFFER_SIZE];
static char rec_word[PLAINTEXT_BUFFER_SIZE];

char *ext_mode = NULL;

c_int ext_word[PLAINTEXT_BUFFER_SIZE];

static struct c_ident ext_globals = {
	NULL,
	"word",
	ext_word
};

static struct c_ident *f_generate;
struct c_ident *f_filter;

static struct cfg_list *ext_source;
static struct cfg_line *ext_line;
static int ext_pos;

static int ext_getchar(void)
{
	unsigned char c;

	if (!ext_line || !ext_line->data) return -1;

	if ((c = (unsigned char)ext_line->data[ext_pos++])) return c;

	ext_line = ext_line->next;
	ext_pos = 0;
	return '\n';
}

static void ext_rewind(void)
{
	ext_line = ext_source->head;
	ext_pos = 0;
}

void ext_init(char *mode)
{
        if (!strncmp(mode, "gijohn", 5)) gijohnmodule = 1;
        if (!gijohnmodule)
        {
                if (!(ext_source = cfg_get_list(SECTION_EXT, mode)))
                {
                        fprintf(stderr, "Unknown external mode: %s\n", mode);
                        error();
                }

                if (c_compile(ext_getchar, ext_rewind, &ext_globals))
                {
                        if (!ext_line) ext_line = ext_source->tail;

                        fprintf(stderr, "Compiler error in %s at line %d: %s\n", cfg_name, ext_line->number, c_errors[c_errno]);
                        error();
                }
        }

	ext_word[0] = 0;

        if (gijohnmodule)
        {
                sig_done();
                getthenewpiece();
                init_external(xmlxml.keymap.charset, strlen(xmlxml.keymap.charset), xmlxml.keymap.firstword, xmlxml.keymap.lastword);
                sig_init();
        }
        else
        {
                c_execute(c_lookup("init"));
        }
	f_generate = c_lookup("generate");
	f_filter = c_lookup("filter");

	ext_mode = mode;
}

int ext_filter_body(char *in, char *out)
{
	unsigned char *internal;
	c_int *external;

	internal = (unsigned char *)in;
	external = ext_word;
	while (*internal)
		*external++ = *internal++;
	*external = 0;

	c_execute(f_filter);

	if (in[0] && !ext_word[0]) return 0;

	internal = (unsigned char *)out;
	external = ext_word;
	while (*external)
		*internal++ = *external++;
	*internal = 0;

	return 1;
}

static void save_state(FILE *file)
{
	unsigned char *ptr;

	ptr = (unsigned char *)rec_word;
	do {
		fprintf(file, "%d\n", (int)*ptr);
	} while (*ptr++);
}

static int restore_state(FILE *file)
{
	int c;
	unsigned char *internal;
	c_int *external;
	int count;

	internal = (unsigned char *)int_word;
	external = ext_word;
	count = 0;
	do {
		if (fscanf(file, "%d\n", &c) != 1) return 1;
		if (++count >= PLAINTEXT_BUFFER_SIZE) return 1;
	} while ((*internal++ = *external++ = c));

	c_execute(c_lookup("restore"));

	return 0;
}

static void fix_state(void)
{
	strcpy(rec_word, int_word);
}

void do_external_crack(struct db_main *db)
{
	unsigned char *internal;
	c_int *external;

        if (!gijohnmodule)
        {
                log_event("Proceeding with external mode: %.100s", ext_mode);
                if (!f_generate) {
                        log_event("! No generate() function defined");
                        fprintf(stderr, "No generate() for external"
				" mode: %s\n", ext_mode);
                        error();
                }
        }

	internal = (unsigned char *)int_word;
	external = ext_word;
	while (*external)
		*internal++ = *external++;
	*internal = 0;

	status_init(NULL, 0);

	rec_restore_mode(restore_state);
	rec_init(db, save_state);

	crk_init(db, fix_state, NULL);

	do {
                if (gijohnmodule)
                {
                        if (!first_time)
                        {
                                generate_external();
                        }
                        else
                        {
                                first_time = 0;
                        }
                }
                else
                {
                        c_execute(f_generate);
                }
		if (!ext_word[0]) break;

		c_execute(f_filter);
		if (!ext_word[0]) continue;

		internal = (unsigned char *)int_word;
		external = ext_word;
		while (*external)
			*internal++ = *external++;
		*internal = 0;

		if (crk_process_key(int_word)) break;
	} while (1);

	crk_done();
	rec_done(event_abort);

        if (gijohnmodule)
        {
                if (!aborted_gijohn)
                {
                        sig_done();
                        sendtheresults();
                        sig_init();
                }
                else
                {
                        sig_done();
                        destroysession();
                }
        }
}

