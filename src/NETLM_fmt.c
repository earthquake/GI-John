/*
 * NETLM_fmt.c -- LM Challenge/Response 
 *
 * Written by JoMo-Kun <jmk at foofus.net> in 2007
 * and placed in the public domain.
 *
 * This algorithm is designed for performing brute-force cracking of the LM 
 * challenge/response pairs exchanged during network-based authentication 
 * attempts [1]. The captured challenge/response pairs from these attempts 
 * should be stored using the L0phtCrack 2.0 LC format, specifically: 
 * username:unused:unused:lm response:ntlm response:challenge. For example:
 *
 * CORP\Administrator:::25B2B477CE101D83648BB087CE7A1C217F51C7FC64C0EBB1::
 * C8BD0C1630A9ECF7A95F494A8F0B2CB4A3F25B1225514304:1122334455667788
 *
 * It should be noted that a LM authentication response is not same as a LM 
 * password hash, which can be extracted using tools such as FgDump [2]. LM 
 * responses can be gathered via normal network capture or via tools which 
 * perform layer 2 attacks, such as Ettercap [3] and Cain [4]. The responses can
 * also be harvested using a modified Samba service [5] in conjunction with 
 * some trickery to convince the user to connect to it. I leave what that 
 * trickery may actually be as an exercise for the reader (HINT: Karma, NMB 
 * broadcasts, IE, Outlook, social engineering, ...).
 * 
 * [1] http://davenport.sourceforge.net/ntlm.html#theLmResponse
 * [2] http://www.foofus.net/fizzgig/fgdump/
 * [3] http://ettercap.sourceforge.net/
 * [4] http://www.oxid.it/cain.html
 * [5] http://www.foofus.net/jmk/smbchallenge.html
 *
 */

#include <stdio.h>
#include <string.h>

#include "misc.h"
#include "common.h"
#include "formats.h"

#include <openssl/des.h>

#ifndef uchar
#define uchar unsigned char
#endif

#define FORMAT_LABEL         "netlm"
#define FORMAT_NAME          "LM C/R DES"
#define ALGORITHM_NAME       "netlm"
#define BENCHMARK_COMMENT    ""
#define BENCHMARK_LENGTH     0
#define PLAINTEXT_LENGTH     14
#define BINARY_SIZE          24
#define SALT_SIZE            8
#define CIPHERTEXT_LENGTH    48
#define TOTAL_LENGTH         8 + 2 * SALT_SIZE + CIPHERTEXT_LENGTH
#define MIN_KEYS_PER_CRYPT   1
#define MAX_KEYS_PER_CRYPT   1

static struct fmt_tests tests[] = {
  {"$NETLM$1122334455667788$6E1EC36D3417CE9E09A4424309F116C4C991948DAEB4ADAD", "G3RG3P00!"},
  {"$NETLM$1122334455667788$16A7FDFE0CA109B937BFFB041F0E5B2D8B94A97D3FCA1A18", "HIYAGERGE"},
  {"$NETLM$1122334455667788$B3A1B87DBBD4DF3CFA296198DD390C2F4E2E93C5C07B1D8B", "MEDUSAFGDUMP12"},
  {"$NETLM$1122334455667788$0836F085B124F33895875FB1951905DD2F85252CC731BB25", "CORY21"},
  {NULL}
};

static char saved_plain[PLAINTEXT_LENGTH + 1];
static uchar challenge[SALT_SIZE + 1];
static uchar output[BINARY_SIZE + 1];

static int netlm_valid(char *ciphertext)
{
  char *pos;

  if (strncmp(ciphertext, "$NETLM$", 5)!=0) return 0;
  if (ciphertext[23] != '$') return 0;

  for (pos = &ciphertext[24]; atoi16[ARCH_INDEX(*pos)] != 0x7F; pos++);
    if (!*pos && pos - ciphertext - 24 == CIPHERTEXT_LENGTH)
      return 1;
    else
      return 0;
}

static char *netlm_split(char *ciphertext, int index)
{
  static char out[TOTAL_LENGTH + 1];

  memset(out, 0, TOTAL_LENGTH + 1);
  memcpy(&out, ciphertext, TOTAL_LENGTH); 
  strlwr(&out[6]); /* Exclude: $NETLM$ */
  
  return out;
}

static void *netlm_get_binary(char *ciphertext)
{
  static uchar binary[BINARY_SIZE];
  int i;

  ciphertext+=24;
  for (i=0; i<BINARY_SIZE; i++)
  {
    binary[i] = (atoi16[ARCH_INDEX(ciphertext[i*2])])<<4;
    binary[i] |= (atoi16[ARCH_INDEX(ciphertext[i*2+1])]);
  }

  return binary;
}

void setup_des_key(unsigned char key_56[], DES_key_schedule *ks)
{
  DES_cblock key;

  key[0] = key_56[0];
  key[1] = (key_56[0] << 7) | (key_56[1] >> 1);
  key[2] = (key_56[1] << 6) | (key_56[2] >> 2);
  key[3] = (key_56[2] << 5) | (key_56[3] >> 3);
  key[4] = (key_56[3] << 4) | (key_56[4] >> 4);
  key[5] = (key_56[4] << 3) | (key_56[5] >> 5);
  key[6] = (key_56[5] << 2) | (key_56[6] >> 6);
  key[7] = (key_56[6] << 1);

  DES_set_key(&key, ks);
}

static void netlm_crypt_all(int count)
{
  static unsigned char magic[] = {0x4b, 0x47, 0x53, 0x21, 0x40, 0x23, 0x24, 0x25};
  DES_key_schedule ks;
  unsigned char password[14 + 1];
  unsigned char lm[21];

  memset(password, 0, 14 + 1);
  memset(lm, 0, 21);
  memset(output, 0, 24);

  strncpy((char *) password, saved_plain, 14);
 
  /* Generate 16-byte LM hash */
  setup_des_key(password, &ks);
  DES_ecb_encrypt((DES_cblock*)magic, (DES_cblock*)lm, &ks, DES_ENCRYPT);
  setup_des_key(&password[7], &ks);
  DES_ecb_encrypt((DES_cblock*)magic, (DES_cblock*)&lm[8], &ks, DES_ENCRYPT);

  /* 
    NULL-pad 16-byte LM hash to 21-bytes
    Split resultant value into three 7-byte thirds
    DES-encrypt challenge using each third as a key
    Concatenate three 8-byte resulting values to form 24-byte LM response
  */ 
  setup_des_key(lm, &ks);
  DES_ecb_encrypt((DES_cblock*)challenge, (DES_cblock*)output, &ks, DES_ENCRYPT);
  setup_des_key(&lm[7], &ks);
  DES_ecb_encrypt((DES_cblock*)challenge, (DES_cblock*)&output[8], &ks, DES_ENCRYPT);
  setup_des_key(&lm[14], &ks);
  DES_ecb_encrypt((DES_cblock*)challenge, (DES_cblock*)&output[16], &ks, DES_ENCRYPT);
}

static int netlm_cmp_all(void *binary, int count)
{
  return !memcmp(output, binary, BINARY_SIZE);
}

static int netlm_cmp_one(void *binary, int index)
{
  return !memcmp(output, binary, BINARY_SIZE);
}

static int netlm_cmp_exact(char *source, int index)
{
  return !memcmp(output, netlm_get_binary(source), BINARY_SIZE);
}

static void *netlm_get_salt(char *ciphertext)
{
  static unsigned char binary_salt[SALT_SIZE];
  int i;

  ciphertext += 7;
  for (i = 0; i < SALT_SIZE; ++i)
    binary_salt[i] = (atoi16[ARCH_INDEX(ciphertext[i*2])] << 4) + atoi16[ARCH_INDEX(ciphertext[i*2+1])];

  return (void*)binary_salt;
}

static void netlm_set_salt(void *salt)
{
  memcpy(challenge, salt, SALT_SIZE);
}

static void netlm_set_key(char *key, int index)
{
  int i;
 
  memset(saved_plain, 0, PLAINTEXT_LENGTH + 1); 
  strncpy(saved_plain, key, PLAINTEXT_LENGTH);
  
  /* Upper-case password */
  for(i=0; i<PLAINTEXT_LENGTH; i++)
    if ((saved_plain[i] >= 'a') && (saved_plain[i] <= 'z')) saved_plain[i] ^= 0x20;
}

static char *netlm_get_key(int index)
{
  return saved_plain;
}

struct fmt_main fmt_NETLM = {
  {
    FORMAT_LABEL,
    FORMAT_NAME,
    ALGORITHM_NAME,
    BENCHMARK_COMMENT,
    BENCHMARK_LENGTH,
    PLAINTEXT_LENGTH,
    BINARY_SIZE,
    SALT_SIZE,
    MIN_KEYS_PER_CRYPT,
    MAX_KEYS_PER_CRYPT,
    FMT_8_BIT | FMT_BS | FMT_SPLIT_UNIFIES_CASE, 
    tests
  }, {
    fmt_default_init,
    netlm_valid,
    netlm_split,
    netlm_get_binary,
    netlm_get_salt,
    {
      fmt_default_binary_hash,
      fmt_default_binary_hash,
      fmt_default_binary_hash,
      fmt_default_binary_hash,
      fmt_default_binary_hash
    },
    fmt_default_salt_hash,
    netlm_set_salt,
    netlm_set_key,
    netlm_get_key,
    fmt_default_clear_keys,
    netlm_crypt_all,
    {
      fmt_default_get_hash,
      fmt_default_get_hash,
      fmt_default_get_hash,
      fmt_default_get_hash,
      fmt_default_get_hash
    },
    netlm_cmp_all,
    netlm_cmp_one,
    netlm_cmp_exact
  }
};
