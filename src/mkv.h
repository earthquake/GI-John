#ifndef _JOHN_MKV_H
#define _JOHN_MKV_H

#include "loader.h"
#include "mkvlib.h"

/*
 * Runs the markov mode cracker.
 */
extern void do_markov_crack(struct db_main *db, unsigned int mkv_level, unsigned long long mkv_start, unsigned long long mkv_end, unsigned int mkv_maxlen);

#endif
