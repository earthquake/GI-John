/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-99,2003,2004,2010 by Solar Designer
 *
 * ...with changes in the jumbo patch for mingw and MSC and
 * introducing field_sep, by JimF.
 */

#define _XOPEN_SOURCE /* for fileno(3) and fsync(2) */
#include <stdio.h>
#ifndef _MSC_VER
#include <unistd.h>
#include <sys/file.h>
#else
#include <io.h>
#pragma warning ( disable : 4996 )
#define S_IRUSR _S_IREAD
#define S_IWUSR _S_IWRITE
#endif
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <fcntl.h>
#include <errno.h>
#include <stdarg.h>
#include <string.h>

#include "arch.h"
#include "misc.h"
#include "params.h"
#include "path.h"
#include "memory.h"
#include "status.h"
#include "config.h"

static int cfg_beep;

/*
 * Note: the file buffer is allocated as (size + LINE_BUFFER_SIZE) bytes
 * and (ptr - buffer) may actually exceed size by up to LINE_BUFFER_SIZE.
 * As long as log_file_write() is called after every write to the buffer,
 * there's always room for at least LINE_BUFFER_SIZE bytes to be added.
 */
struct log_file {
	char *name;
	char *buffer, *ptr;
	int size;
	int fd;
};

#if defined (_MSC_VER)
// In release mode, the log() function gets in the way of our log struct object
#define log local_log_struct
#endif

static struct log_file log = {NULL, NULL, NULL, 0, -1};
static struct log_file pot = {NULL, NULL, NULL, 0, -1};

static int in_logger = 0;

static void log_file_init(struct log_file *f, char *name, int size)
{
	f->name = name;

	if (chmod(path_expand(name), S_IRUSR | S_IWUSR))
	if (errno != ENOENT)
		pexit("chmod: %s", path_expand(name));

	if ((f->fd = open(path_expand(name),
	    O_WRONLY | O_CREAT | O_APPEND, S_IRUSR | S_IWUSR)) < 0)
		pexit("open: %s", path_expand(name));

	f->ptr = f->buffer = mem_alloc(size + LINE_BUFFER_SIZE);
	f->size = size;
}

static void log_file_flush(struct log_file *f)
{
	int count;

	if (f->fd < 0) return;

	count = f->ptr - f->buffer;
	if (count <= 0) return;

#if defined(LOCK_EX) && OS_FLOCK
	if (flock(f->fd, LOCK_EX)) pexit("flock");
#endif
	if (write_loop(f->fd, f->buffer, count) < 0) pexit("write");
	f->ptr = f->buffer;
#if defined(LOCK_EX) && OS_FLOCK
	if (flock(f->fd, LOCK_UN)) pexit("flock");
#endif
}

static int log_file_write(struct log_file *f)
{
	if (f->ptr - f->buffer > f->size) {
		log_file_flush(f);
		return 1;
	}

	return 0;
}

static void log_file_fsync(struct log_file *f)
{
	if (f->fd < 0) return;

	log_file_flush(f);
#if !defined(__CYGWIN32__) && !defined(__MINGW32__) && !defined(_MSC_VER)
	if (fsync(f->fd)) pexit("fsync");
#endif
}

static void log_file_done(struct log_file *f)
{
	if (f->fd < 0) return;

	log_file_fsync(f);
	if (close(f->fd)) pexit("close");
	f->fd = -1;

	MEM_FREE(f->buffer);
}

static int log_time(void)
{
	unsigned int time;

	time = pot.fd >= 0 ? status_get_time() : status_restored_time;

	return (int)sprintf(log.ptr, "%u:%02u:%02u:%02u ",
		time / 86400, time % 86400 / 3600,
		time % 3600 / 60, time % 60);
}

void log_init(char *log_name, char *pot_name, char *session)
{
	in_logger = 1;

	if (log_name && log.fd < 0) {
		if (session)
			log_name = path_session(session, LOG_SUFFIX);

		log_file_init(&log, log_name, LOG_BUFFER_SIZE);
	}

	if (pot_name && pot.fd < 0) {
		log_file_init(&pot, pot_name, POT_BUFFER_SIZE);

		cfg_beep = cfg_get_bool(SECTION_OPTIONS, NULL, "Beep", 0);
	}

	in_logger = 0;
}

void log_guess(char *login, char *ciphertext, char *plaintext, char field_sep)
{
	int count1, count2;

	printf("%-16s (%s)\n", plaintext, login);

	in_logger = 1;

	if (pot.fd >= 0 && ciphertext &&
	    strlen(ciphertext) + strlen(plaintext) <= LINE_BUFFER_SIZE - 3) {
		count1 = (int)sprintf(pot.ptr,
			"%s%c%s\n", ciphertext, field_sep, plaintext);
		if (count1 > 0) pot.ptr += count1;
	}

	if (log.fd >= 0 &&
	    strlen(login) < LINE_BUFFER_SIZE - 64) {
		count1 = log_time();
		if (count1 > 0) {
			log.ptr += count1;
			count2 = (int)sprintf(log.ptr,
				"+ Cracked %s\n", login);
			if (count2 > 0)
				log.ptr += count2;
			else
				log.ptr -= count1;
		}
	}

/* Try to keep the two files in sync */
	if (log_file_write(&pot))
		log_file_flush(&log);
	else
	if (log_file_write(&log))
		log_file_flush(&pot);

	in_logger = 0;

	if (cfg_beep)
		write_loop(fileno(stderr), "\007", 1);
}

void log_event(char *format, ...)
{
	va_list args;
	int count1, count2;

	if (log.fd < 0) return;

/*
 * Handle possible recursion:
 * log_*() -> ... -> pexit() -> ... -> log_event()
 */
	if (in_logger) return;
	in_logger = 1;

	count1 = log_time();
	if (count1 > 0 &&
	    count1 + strlen(format) < LINE_BUFFER_SIZE - 500 - 1) {
		log.ptr += count1;

		va_start(args, format);
		count2 = (int)vsprintf(log.ptr, format, args);
		va_end(args);

		if (count2 > 0) {
			log.ptr += count2;
			*log.ptr++ = '\n';
		} else
			log.ptr -= count1;

		if (log_file_write(&log))
			log_file_flush(&pot);
	}

	in_logger = 0;
}

void log_discard(void)
{
	log.ptr = log.buffer;
}

void log_flush(void)
{
	in_logger = 1;

	log_file_fsync(&log);
	log_file_fsync(&pot);

	in_logger = 0;
}

void log_done(void)
{
/*
 * Handle possible recursion:
 * log_*() -> ... -> pexit() -> ... -> log_done()
 */
	if (in_logger) return;
	in_logger = 1;

	log_file_done(&log);
	log_file_done(&pot);

	in_logger = 0;
}
