/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-98,2010 by Solar Designer
 */

#include "params.h"

int password_hash_sizes[PASSWORD_HASH_SIZES] = {
	PASSWORD_HASH_SIZE_0,
	PASSWORD_HASH_SIZE_1,
	PASSWORD_HASH_SIZE_2,
	PASSWORD_HASH_SIZE_3,
	PASSWORD_HASH_SIZE_4
};

int password_hash_thresholds[PASSWORD_HASH_SIZES] = {
	PASSWORD_HASH_THRESHOLD_0,
	PASSWORD_HASH_THRESHOLD_1,
	PASSWORD_HASH_THRESHOLD_2,
	PASSWORD_HASH_THRESHOLD_3,
	PASSWORD_HASH_THRESHOLD_4
};
