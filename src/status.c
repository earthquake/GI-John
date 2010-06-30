/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-2001,2004,2006,2010 by Solar Designer
 *
 * ...with changes in the jumbo patch, by JimF.
 */

#ifdef __ultrix__
#define __POSIX
#define _POSIX_SOURCE
#endif

#ifdef _SCO_C_DIALECT
#include <limits.h>
#endif
#include <stdio.h>
#include <math.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <time.h>
#if !defined (__MINGW32__) && !defined (_MSC_VER)
#include <sys/times.h>
#endif

#include "times.h"

#if defined(__GNUC__) && defined(__i386__)
#include "arch.h" /* for CPU_REQ */
#endif

#include "misc.h"
#include "math.h"
#include "params.h"
#include "cracker.h"
#include "options.h"
#include "status.h"
#include "bench.h"

struct status_main status;
unsigned int status_restored_time = 0;
int (*status_get_progress)(int *) = NULL;

static clock_t get_time(void)
{
#if defined (__MINGW32__) || defined (_MSC_VER)
	return clock();
#else
	struct tms buf;

	return times(&buf);
#endif
}

void status_init(int (*get_progress)(int *), int start)
{
	if (start) {
		if (!status_restored_time)
			memset(&status, 0, sizeof(status));
		status.start_time = get_time();
	}

	status_get_progress = get_progress;

	clk_tck_init();
}

void status_ticks_overflow_safety(void)
{
	unsigned int time;
	clock_t ticks;

	ticks = get_time() - status.start_time;
	if (ticks > ((clock_t)1 << (sizeof(clock_t) * 8 - 2))) {
		time = ticks / clk_tck;
		status_restored_time += time;
		status.start_time += (clock_t)time * clk_tck;
	}
}

void status_update_crypts(unsigned int count)
{
	unsigned int saved_hi;

	saved_hi = status.crypts.hi;
	add32to64(&status.crypts, count);

	if (status.crypts.hi != saved_hi)
		status_ticks_overflow_safety();
}

unsigned int status_get_time(void)
{
	return status_restored_time +
		(get_time() - status.start_time) / clk_tck;
}

static char *status_get_cps(char *buffer)
{
	int use_ticks;
	clock_t ticks;
	unsigned long time;
	int64 tmp, cps;
	unsigned int cps_100;

	use_ticks = !status.crypts.hi && !status_restored_time;

	ticks = get_time() - status.start_time;
	if (use_ticks)
		time = ticks;
	else
		time = status_restored_time + ticks / clk_tck;
	if (!time) time = 1;

	cps = status.crypts;
	if (use_ticks) mul64by32(&cps, clk_tck);
	div64by32(&cps, time);

	if (cps.hi || cps.lo >= 1000000000)
		sprintf(buffer, "%uM", div64by32lo(&cps, 1000000));
	else
	if (cps.lo >= 1000000)
		sprintf(buffer, "%uK", div64by32lo(&cps, 1000));
	else
	if (cps.lo >= 100)
		sprintf(buffer, "%u", cps.lo);
	else {
		tmp = status.crypts;
		if (use_ticks) mul64by32(&tmp, clk_tck);
		mul64by32(&tmp, 100);
		cps_100 = div64by32lo(&tmp, time) % 100;
		sprintf(buffer, "%u.%02u", cps.lo, cps_100);
	}

	return buffer;
}

static char *status_get_ETA(char *percent, unsigned int secs_done)
{
	static char s_ETA[128];
	char *cp;
	double sec_left, percent_left;
	time_t t_ETA;
	struct tm *pTm;

#if CPU_REQ && defined(__GNUC__) && defined(__i386__)
/* ETA reporting would be wrong when cracking some hash types at least on a
 * Pentium 3 without this... */
	__asm__ __volatile__("emms");
#endif

	/* Compute the ETA for this run.  Assumes even run time for
	   work currently done and work left to do, and that the CPU
	   utilization of work done and work to do will stay same 
	   which may not always a valid assumtions */
	cp = percent;
	while (cp && *cp && isspace(*cp))
		++cp;
	if (!cp || *cp == 0 || !isdigit(*cp))
		return "";  /* dont show ETA if no valid percentage. */
	else
	{
		percent_left = atof(percent);
		if (percent_left == 0)
			percent_left = .005;
		percent_left /= 100;
		sec_left = secs_done;
		sec_left /= percent_left;
		sec_left -= secs_done;
		t_ETA = time(NULL);
		{
			/* Note, many localtime() will fault if given a time_t
			   later than Jan 19, 2038 (i.e. 0x7FFFFFFFF). We 
			   check for that here, and if so, this run will
			   not end anyway, so simply tell user it is a 
			   LONG wait */
			double chk;
			chk = sec_left;
			chk += t_ETA;
			if (chk > 0x7FFFF000) /* slightly less than 'max' 32 bit time_t, for safety */
			{
				strcpy(s_ETA, " (ETA: MANY years)");
				return s_ETA;
			}
		}
		t_ETA += sec_left;
		pTm = localtime(&t_ETA);
		/* the string to strftime, might be a GOOD addition
		   to john.conf in the 'global' section. for now, simply
		   use the %c  'local' specific canonical form, such as:
		   07/15/09 15:19:07
		   also good would be %#c which is long 'local' such as:
		   Wednesday, July 15, 2009, 15:41:29
		   Other 'good' ones are:
		   %d/%m/%y %H:%M   (day/mon/year hour:min)
		   %m/%d/%y %H:%M   (mon/day/year hour:min)
		  
		   NOTE the ETA will float around quite a bit. The seconds
		   and even minutes are pretty much worthless information
		   until a significant part of the data is done (say 20%) */
		strcpy(s_ETA, " (ETA: ");
		strftime(&s_ETA[7], sizeof(s_ETA)-10, "%c", pTm);
		strcat(s_ETA, ")");
	}
	return s_ETA;
}

static void status_print_stdout(char *percent)
{
	unsigned int time = status_get_time();
	char s_wps[64];
	char s_words[32];
	int64 current, next, rem;
	char *s_words_ptr;

	s_words_ptr = &s_words[sizeof(s_words) - 1];
	*s_words_ptr = 0;

	current = status.crypts;
	do {
		next = current;
		div64by32(&next, 10);
		rem = next;
		mul64by32(&rem, 10);
		neg64(&rem);
		add64to64(&rem, &current);
		*--s_words_ptr = rem.lo + '0';
		current = next;
	} while (current.lo || current.hi);

	fprintf(stderr,
		"words: %s  "
		"time: %u:%02u:%02u:%02u"
		"%s%s  "
		"w/s: %s",
		s_words_ptr,
		time / 86400, time % 86400 / 3600, time % 3600 / 60, time % 60,
		percent,
		status_get_ETA(percent, time),
		status_get_cps(s_wps));

	if ((options.flags & FLG_STATUS_CHK) ||
	    !(status.crypts.lo | status.crypts.hi))
		fputc('\n', stderr);
	else
		fprintf(stderr,
			"  current: %s\n",
			crk_get_key1());
}

static void status_print_cracking(char *percent)
{
	unsigned int time = status_get_time();
	char *key, saved_key[PLAINTEXT_BUFFER_SIZE];
	char s_cps[64];

	if (!(options.flags & FLG_STATUS_CHK)) {
		if ((key = crk_get_key2()))
			strnzcpy(saved_key, key, PLAINTEXT_BUFFER_SIZE);
		else
			saved_key[0] = 0;
	}

	fprintf(stderr,
		"guesses: %u  "
		"time: %u:%02u:%02u:%02u"
		"%s%s  "
		"c/s: %s",
		status.guess_count,
		time / 86400, time % 86400 / 3600, time % 3600 / 60, time % 60,
		percent,
		status_get_ETA(percent,time),
		status_get_cps(s_cps));

	if ((options.flags & FLG_STATUS_CHK) ||
	    !(status.crypts.lo | status.crypts.hi))
		fputc('\n', stderr);
	else
		fprintf(stderr,
			"  trying: %s%s%s\n",
			crk_get_key1(), saved_key[0] ? " - " : "", saved_key);
}

void status_print(void)
{
	int percent_value, hund_percent = 0;
	char s_percent[32];

	percent_value = -1;
	if (options.flags & FLG_STATUS_CHK)
		percent_value = status.progress;
	else
	if (status_get_progress)
		percent_value = status_get_progress(&hund_percent);

	s_percent[0] = 0;
	if (percent_value >= 0 && hund_percent >= 0)
		sprintf(s_percent, status.pass ? " %d.%02d%% (%d)" : " %d.%02d%%",
			percent_value, hund_percent, status.pass);
	else
	if (status.pass)
		sprintf(s_percent, " (%d)", status.pass);

	if (options.flags & FLG_STDOUT)
		status_print_stdout(s_percent);
	else
		status_print_cracking(s_percent);
}
