/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-98,2010,2011 by Solar Designer
 *
 * ...with changes in the jumbo patch, by various authors
 */

/*
 * Password database management.
 */

#ifndef _JOHN_LOADER_H
#define _JOHN_LOADER_H

#include "params.h"
#include "list.h"
#include "formats.h"

/*
 * Password list (with a fixed salt) entry.
 */
struct db_password {
/* Pointer to next password with the same salt */
	struct db_password *next;

/* Pointer to next password with the same salt and hash (used for a different
 * purpose while loading). */
	struct db_password *next_hash;

/* Some bytes of binary ciphertext for fast comparison */
	void *binary;

/* ASCII ciphertext for exact comparison and saving with cracked passwords */
	char *source;

/* Login field from the password file, with ":1" or ":2" appended if the
 * ciphertext was split into two parts. */
	char *login;

/* Words from GECOS field -- loaded for "single crack" mode only */
	struct list_main *words;
};

/*
 * Buffered keys hash table entry.
 */
struct db_keys_hash_entry {
/* Index of next key with the same hash */
	short next;

/* Byte offset of this key in the buffer */
	short offset;
};

/*
 * Buffered keys hash.
 */
struct db_keys_hash {
/* The hash table, maps to indices for the list below */
	short hash[SINGLE_HASH_SIZE];

/* List of keys with the same hash, allocated as min_keys_per_crypt entries */
	struct db_keys_hash_entry list[1];
};

/*
 * Buffered keys.
 */
struct db_keys {
/* Keys hash table, for fast dupe checking */
	struct db_keys_hash *hash;

/* &buffer[count * plaintext_length] */
	char *ptr;

/* Number of keys currently in the buffer */
	int count;

/* Whether we have words to base candidate passwords on or not.
 * Even if not, we need this keys buffer anyway to hold other salts' successful
 * guesses for testing against this salt's hashes. */
	int have_words;

/* Number of last processed rule */
	int rule;

/* Number of recursive calls for this salt */
	int lock;

/* The keys, allocated as (plaintext_length * min_keys_per_crypt) bytes */
	char buffer[1];
};

/*
 * Salt list entry.
 */
struct db_salt {
/* Pointer to next salt in the list */
	struct db_salt *next;

/* Salt in internal representation */
	void *salt;

/* Pointer to a hash function to get the index of password list to be
 * compared against the crypt_all() method output with given index. The
 * function always returns zero if there's no hash table for this salt. */
	int (*index)(int index);

/* List of passwords with this salt */
	struct db_password *list;

/* Password hash table for this salt, or a pointer to the list field */
	struct db_password **hash;

/* Hash table size code, negative for none */
	int hash_size;

/* Number of passwords with this salt */
	int count;

/* Buffered keys, allocated for "single crack" mode only */
	struct db_keys *keys;
};

/*
 * Structure to hold a cracked password.
 */
struct db_cracked {
/* Pointer to next password with the same hash */
	struct db_cracked *next;

/* Data from the pot file */
	char *ciphertext, *plaintext;
};

/*
 * Password database contents flags.
 */
/* Login fields loaded */
#define DB_LOGIN			0x00000001
/* Words from GECOS fields loaded */
#define DB_WORDS			0x00000002
/* Some hashed passwords were split into several entries */
#define DB_SPLIT			0x00000010
/* Duplicate hashes were seen and excluded */
#define DB_NODUP			0x00000020
/* Cracked passwords only (ciphertext, plaintext) */
#define DB_CRACKED			0x00000100
/* Cracked plaintexts list */
#define DB_PLAINTEXTS			0x00000200

/*
 * Password database options.
 */
struct db_options {
/* Contents flags bitmask */
	unsigned int flags;

/* Filters to use while loading */
	struct list_main *users, *groups, *shells;

/* Requested passwords per salt */
	int min_pps, max_pps;

/* Maximum size of a wordlist file to be 'preloaded' into memory  */
	unsigned max_wordfile_memory;

/* number of times fix_state_delay is called in wordfile.c before  any fseek() is done. */
	unsigned max_fix_state_delay;

/* the wordlist rules section (default if none entered is Wordlist) */
	char *activewordlistrules;

/* the 'single' rules section (default if none entered is Single) */
	char *activesinglerules;

/* the pot file used (default if none entered is $JOHN/john.pot or JOHN_PRIVATE_HOME/john.pot
   depending upon compile defines) */
	char *activepot;

/* if --show=left is used, this is set, and john dumps the non-cracked hashes and exits */
	int showuncracked;

/* by default will be ':', but -field-separator-char=c can over ride the default */
	char field_sep_char;
};

/*
 * Main password database.
 */
struct db_main {
/* Are hashed passwords loaded into this database? */
	int loaded;

/* Options */
	struct db_options *options;

/* Salt list */
	struct db_salt *salts;

/* Salt and password hash tables, used while loading */
	struct db_salt **salt_hash;
	struct db_password **password_hash;

/* binary_hash function used by the loader itself */
	int (*password_hash_func)(void *binary);

/* Cracked passwords */
	struct db_cracked **cracked_hash;

/* Cracked plaintexts list */
	struct list_main *plaintexts;

/* Number of salts, passwords and guesses */
	int salt_count, password_count, guess_count;

/* Ciphertext format */
	struct fmt_main *format;
};

/*
 * Initializes the database before loading.
 */
extern void ldr_init_database(struct db_main *db, struct db_options *options);

/*
 * Loads a password file into the database.
 */
extern void ldr_load_pw_file(struct db_main *db, char *name);

/*
 * Removes passwords cracked in previous sessions from the database.
 */
extern void ldr_load_pot_file(struct db_main *db, char *name);

/*
 * Fixes the database after loading.
 */
extern void ldr_fix_database(struct db_main *db);

/*
 * Updates the database after a password has been cracked.
 */
extern void ldr_remove_hash(struct db_main *db, struct db_salt *salt,
	struct db_password *pw, int gijohnpresent);

/*
 * Loads cracked passwords into the database.
 */
extern void ldr_show_pot_file(struct db_main *db, char *name);

/*
 * Shows cracked passwords.
 */
extern void ldr_show_pw_file(struct db_main *db, char *name);

/*
 * Modified functions for gijohn
 */
 
extern void ldr_load_xml_array(struct db_main *db, char *xmls, char *xmlformat);
extern void ldr_load_xml_delarray(struct db_main *db, char *xmls);
extern void ldr_fix_xmldatabase(struct db_main *db, int clearhashes);

#endif
