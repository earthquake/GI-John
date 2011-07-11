/*
 * NETNTLM_fmt.c -- NTLM Challenge/Response 
 *
 * Written by JoMo-Kun <jmk at foofus.net> in 2007
 * and placed in the public domain.
 *
 * This algorithm is designed for performing brute-force cracking of the NTLM 
 * (version 1) challenge/response pairs exchanged during network-based 
 * authentication attempts [1]. The captured challenge/response pairs from these
 * attempts should be stored using the L0phtCrack 2.0 LC format, specifically: 
 * username:unused:unused:lm response:ntlm response:challenge. For example:
 *
 * CORP\Administrator:::25B2B477CE101D83648BB087CE7A1C217F51C7FC64C0EBB1:
 * C8BD0C1630A9ECF7A95F494A8F0B2CB4A3F25B1225514304:1122334455667788
 *
 * It should be noted that a NTLM authentication response is not same as a NTLM 
 * password hash, which can be extracted using tools such as FgDump [2]. NTLM 
 * responses can be gathered via normal network capture or via tools which 
 * perform layer 2 attacks, such as Ettercap [3] and Cain [4]. The responses can
 * also be harvested using a modified Samba service [5] in conjunction with 
 * some trickery to convince the user to connect to it. I leave what that 
 * trickery may actually be as an exercise for the reader (HINT: Karma, NMB 
 * broadcasts, IE, Outlook, social engineering, ...).
 * 
 * [1] http://davenport.sourceforge.net/ntlm.html#theNtLmResponse
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

#define FORMAT_LABEL         "netntlm"
#define FORMAT_NAME          "NTLMv1 C/R MD4 DES"
#define ALGORITHM_NAME       "netntlm"
#define BENCHMARK_COMMENT    ""
#define BENCHMARK_LENGTH     0
#define PLAINTEXT_LENGTH     54 /* ?127? */
#define BINARY_SIZE          24
#define SALT_SIZE            8
#define CIPHERTEXT_LENGTH    48
#define TOTAL_LENGTH         10 + 2 * SALT_SIZE + CIPHERTEXT_LENGTH
#define MIN_KEYS_PER_CRYPT   1
#define MAX_KEYS_PER_CRYPT   1

static struct fmt_tests tests[] = {
  {"$NETNTLM$1122334455667788$BFCCAF26128EC95F9999C9792F49434267A1D9B0EF89BFFB", "g3rg3g3rg3g3rg3"},
  {"$NETNTLM$1122334455667788$E463FAA5D868ECE20CAE622474A2F440A652D642156AF863", "M1xedC4se%^&*@)##(blahblah!@#"},
  {"$NETNTLM$1122334455667788$35B62750E1B9B3205C50D6BA351092C12A1B9B3CDC65D44A", "FooBarGerg"},
  {"$NETNTLM$1122334455667788$A4765EBFE83D345A7CB1660B8899251905164029F8086DDE", "visit www.foofus.net"},
  {"$NETNTLM$1122334455667788$B2B2220790F40C88BCFF347C652F67A7C4A70D3BEBD70233", "cory21"},
  {NULL}
};

static char saved_plain[PLAINTEXT_LENGTH + 1];
static uchar challenge[SALT_SIZE + 1];
static uchar output[BINARY_SIZE + 1];

extern void E_md4hash(uchar *passwd, uchar *p16);
extern void setup_des_key(unsigned char key_56[], DES_key_schedule *ks);

static int netntlm_valid(char *ciphertext)
{
  char *pos;

  if (strncmp(ciphertext, "$NETNTLM$", 9)!=0) return 0;
  if (ciphertext[25] != '$') return 0;

  for (pos = &ciphertext[26]; atoi16[ARCH_INDEX(*pos)] != 0x7F; pos++);
    if (!*pos && pos - ciphertext - 26 == CIPHERTEXT_LENGTH)
      return 1;
    else
      return 0;
}

static char *netntlm_split(char *ciphertext, int index)
{
  static char out[TOTAL_LENGTH + 1];

  memset(out, 0, TOTAL_LENGTH + 1);
  memcpy(&out, ciphertext, TOTAL_LENGTH);
  strlwr(&out[8]); /* Exclude: $NETNTLM$ */

  return out;
}

static void *netntlm_get_binary(char *ciphertext)
{
  static uchar binary[BINARY_SIZE];
  int i;

  ciphertext+=26;
  for (i=0; i<BINARY_SIZE; i++)
  {
    binary[i] = (atoi16[ARCH_INDEX(ciphertext[i*2])])<<4;
    binary[i] |= (atoi16[ARCH_INDEX(ciphertext[i*2+1])]);
  }

  return binary;
}

static void netntlm_crypt_all(int count)
{
  DES_key_schedule ks;
  unsigned char ntlm[21];

  memset(output, 0, 24);
  memset(ntlm, 0, 21);

  /* Generate 16-byte NTLM hash */
  E_md4hash((unsigned char *) saved_plain, ntlm);
  
  /* Hash is NULL padded to 21-bytes */
  ntlm[16] = ntlm[17] = ntlm[18] = ntlm[19] = ntlm[20] = 0;
  
  /* Split into three 7-byte segments for use as DES keys
     Use each key to DES encrypt challenge 
     Concatenate output to for 24-byte NTLM response */
  setup_des_key(ntlm, &ks);
  DES_ecb_encrypt((DES_cblock*)challenge, (DES_cblock*)output, &ks, DES_ENCRYPT);
  setup_des_key(&ntlm[7], &ks);
  DES_ecb_encrypt((DES_cblock*)challenge, (DES_cblock*)&output[8], &ks, DES_ENCRYPT);
  setup_des_key(&ntlm[14], &ks);
  DES_ecb_encrypt((DES_cblock*)challenge, (DES_cblock*)&output[16], &ks, DES_ENCRYPT);
}

static int netntlm_cmp_all(void *binary, int count)
{
  return !memcmp(output, binary, BINARY_SIZE);
}

static int netntlm_cmp_one(void *binary, int index)
{
  return !memcmp(output, binary, BINARY_SIZE);
}

static int netntlm_cmp_exact(char *source, int index)
{
  return !memcmp(output, netntlm_get_binary(source), BINARY_SIZE);
}

static void *netntlm_get_salt(char *ciphertext)
{
  static unsigned char binary_salt[SALT_SIZE];
  int i;

  ciphertext += 9;
  for (i = 0; i < SALT_SIZE; ++i)
    binary_salt[i] = (atoi16[ARCH_INDEX(ciphertext[i*2])] << 4) + atoi16[ARCH_INDEX(ciphertext[i*2+1])];

  return (void*)binary_salt;
}

static void netntlm_set_salt(void *salt)
{
  memcpy(challenge, salt, SALT_SIZE);
}

static void netntlm_set_key(char *key, int index)
{
  strncpy(saved_plain, key, PLAINTEXT_LENGTH);
  saved_plain[PLAINTEXT_LENGTH] = 0;
}

static char *netntlm_get_key(int index)
{
  return saved_plain;
}

struct fmt_main fmt_NETNTLM = {
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
    FMT_CASE | FMT_8_BIT | FMT_SPLIT_UNIFIES_CASE,
    tests
  }, {
    fmt_default_init,
    netntlm_valid,
    netntlm_split,
    netntlm_get_binary,
    netntlm_get_salt,
    {
      fmt_default_binary_hash,
      fmt_default_binary_hash,
      fmt_default_binary_hash,
      fmt_default_binary_hash,
      fmt_default_binary_hash
    },
    fmt_default_salt_hash,
    netntlm_set_salt,
    netntlm_set_key,
    netntlm_get_key,
    fmt_default_clear_keys,
    netntlm_crypt_all,
    {
      fmt_default_get_hash,
      fmt_default_get_hash,
      fmt_default_get_hash,
      fmt_default_get_hash,
      fmt_default_get_hash
    },
    netntlm_cmp_all,
    netntlm_cmp_one,
    netntlm_cmp_exact
  }
};
