/*
 * MSCHAPv2_fmt.c -- Microsoft PPP CHAP Extensions, Version 2 
 *
 * Written by JoMo-Kun <jmk at foofus.net> in 2010
 * and placed in the public domain.
 *
 * This algorithm is designed for performing brute-force cracking of the 
 * MSCHAPv2 challenge/response sets exchanged during network-based 
 * authentication attempts. The captured challenge/response set from these 
 * attempts should be stored using the following format: 
 *
 * USERNAME:::AUTHENTICATOR CHALLENGE:MSCHAPv2 RESPONSE:PEER CHALLENGE
 * USERNAME::DOMAIN:AUTHENTICATOR CHALLENGE:MSCHAPv2 RESPONSE:PEER CHALLENGE
 * DOMAIN\USERNAME:::AUTHENTICATOR CHALLENGE:MSCHAPv2 RESPONSE:PEER CHALLENGE
 *
 * For example:
 * User:::5B5D7C7D7B3F2F3E3C2C602132262628:82309ECD8D708B5EA08FAA3981CD83544233114A3D85D6DF:21402324255E262A28295F2B3A337C7E
 * domain\fred:::56d64cbe7bad61349a0b752335100eaf:d7d829d9545cef1d631b4e568ffb7586050fa3a4d02dbc0b:7f8a466cff2a6bf0c80218bbf56d76bc
 *
 * http://freeradius.org/rfc/rfc2759.txt 
 *
 */

#include <stdio.h>
#include <string.h>

#include "misc.h"
#include "common.h"
#include "formats.h"

#include "sha.h"
#include <openssl/des.h>

#ifndef uchar
#define uchar unsigned char
#endif

#define FORMAT_LABEL         "mschapv2"
#define FORMAT_NAME          "MSCHAPv2 C/R MD4 DES"
#define ALGORITHM_NAME       "mschapv2"
#define BENCHMARK_COMMENT    ""
#define BENCHMARK_LENGTH     0
#define PLAINTEXT_LENGTH     54 /* lmcons.h - PWLEN (256) ? 127 ? */
#define USERNAME_LENGTH      256 /* lmcons.h - UNLEN (256) / LM20_UNLEN (20) */
#define DOMAIN_LENGTH        15  /* lmcons.h - CNLEN / DNLEN */
#define BINARY_SIZE          24
#define CHALLENGE_LENGTH     64
#define SALT_SIZE            8
#define CIPHERTEXT_LENGTH    48
#define TOTAL_LENGTH         13 + USERNAME_LENGTH + CHALLENGE_LENGTH + CIPHERTEXT_LENGTH
#define MIN_KEYS_PER_CRYPT   1
#define MAX_KEYS_PER_CRYPT   1

static struct fmt_tests tests[] = {
  {"$MSCHAPv2$5B5D7C7D7B3F2F3E3C2C602132262628$82309ECD8D708B5EA08FAA3981CD83544233114A3D85D6DF$21402324255E262A28295F2B3A337C7E$User", "clientPass"},
  {"$MSCHAPv2$d07054459a1fdbc266a006f0220e6fac$33c8331a9b03b7e003f09dd253d740a2bead544143cc8bde$3545cb1d89b507a5de104435e81b14a4$testuser1", "Cricket8"},
  {"$MSCHAPv2$56d64cbe7bad61349a0b752335100eaf$d7d829d9545cef1d631b4e568ffb7586050fa3a4d02dbc0b$7f8a466cff2a6bf0c80218bbf56d76bc$fred", "OMG!BBQ!11!one"}, /* domain\fred */
  {"$MSCHAPv2$b3c42db475b881d3c52ff3923d7b3bf8$f07c7a4eb391f5debe32d814679a5a69661b86b33227c4f8$6321f8649b971bd11ce8d5cb22a4a738$bOb", "asdblahblahblahblahblahblahblahblah"}, /* WorkGroup\bOb */
  {"$MSCHAPv2$d94e7c7972b2376b28c268583e162de7$eba25a3b04d2c7085d01f842e2befc91745c40db0f792356$0677ca7318fd7f65ae1b4f58c9f4f400$lameuser", ""}, /* no password */
  {NULL}
};

uchar saved_plain[PLAINTEXT_LENGTH + 1];
uchar challenge[SALT_SIZE + 1];
uchar output[BINARY_SIZE + 1];

extern void E_md4hash(uchar *passwd, uchar *p16);
extern void setup_des_key(unsigned char key_56[], DES_key_schedule *ks);

static int mschapv2_valid(char *ciphertext)
{
  char *pos, *pos2;
  
  if (ciphertext == NULL) return 0;
  else if (strncmp(ciphertext, "$MSCHAPv2$", 10)!=0) return 0;
 
  /* Validate Authenticator/Server Challenge Length */
  pos = &ciphertext[10];
  for (pos2 = pos; strncmp(pos2, "$", 1) != 0; pos2++)
    if (atoi16[ARCH_INDEX(*pos2)] == 0x7F)
      return 0;

  if ( !(*pos2 && (pos2 - pos == CHALLENGE_LENGTH / 2)) )
    return 0;

  /* Validate MSCHAPv2 Response Length */
  pos2++; pos = pos2;
  for (; strncmp(pos2, "$", 1) != 0; pos2++)
    if (atoi16[ARCH_INDEX(*pos2)] == 0x7F)
      return 0;

  if ( !(*pos2 && (pos2 - pos == CIPHERTEXT_LENGTH)) )
    return 0;

  /* Validate Peer/Client Challenge Length */
  pos2++; pos = pos2;
  for (; strncmp(pos2, "$", 1) != 0; pos2++)
    if (atoi16[ARCH_INDEX(*pos2)] == 0x7F)
      return 0;

  if ( !(*pos2 && (pos2 - pos == CHALLENGE_LENGTH / 2)) )
    return 0;
  
  /* Validate Username Length */
  pos2++; pos = pos2;
  for (; atoi16[ARCH_INDEX(*pos2)] != 0x7F; pos2++);
  if ( !(*pos2 && (pos2 - pos <= USERNAME_LENGTH)) )
    return 0;

  return 1;
}

static char *mschapv2_split(char *ciphertext, int index)
{
  static char out[TOTAL_LENGTH + 1];
  int i;

  memset(out, 0, TOTAL_LENGTH + 1);
  memcpy(&out, ciphertext, strlen(ciphertext));

  /* convert hashes to lower-case - exclude $MSCHAPv2 and USERNAME */
  for (i = 10; i < 10 + 16*2 + 1 + 24*2 + 1 + 16*2; i++)
    if (out[i] >= 'A' && out[i] <= 'Z')
      out[i] |= 0x20;
 
  return out;
}

static void *mschapv2_get_binary(char *ciphertext)
{
  static uchar binary[BINARY_SIZE];
  int i;
 
  ciphertext += 10 + 16*2 + 1; /* Skip - $MSCHAPv2$, Authenticator Challenge */
  
  for (i=0; i<BINARY_SIZE; i++)
  {
    binary[i] = (atoi16[ARCH_INDEX(ciphertext[i*2])])<<4;
    binary[i] |= (atoi16[ARCH_INDEX(ciphertext[i*2+1])]);
  }
  
  return binary;
}

/* Calculate the MSCHAPv2 response for the given challenge, using the
   specified authentication identity (username), password and client 
   nonce.
*/
static void mschapv2_crypt_all(int count)
{
  unsigned char ntlm[21];
  DES_key_schedule ks;

  memset(ntlm, 0, 21);
  memset(output, 0, 24);

  /* Generate 16-byte NTLM hash */
  E_md4hash(saved_plain, ntlm);
  
  /* 
    NULL-pad 16-byte NTLM hash to 21-bytes
    Split resultant value into three 7-byte thirds
    DES-encrypt challenge using each third as a key
    Concatenate three 8-byte resulting values to form 24-byte MSCHAPv2 response
  */
  setup_des_key(ntlm, &ks);
  DES_ecb_encrypt((DES_cblock*)challenge, (DES_cblock*)output, &ks, DES_ENCRYPT);
  setup_des_key(&ntlm[7], &ks);
  DES_ecb_encrypt((DES_cblock*)challenge, (DES_cblock*)&output[8], &ks, DES_ENCRYPT);
  setup_des_key(&ntlm[14], &ks);
  DES_ecb_encrypt((DES_cblock*)challenge, (DES_cblock*)&output[16], &ks, DES_ENCRYPT);
}

static int mschapv2_cmp_all(void *binary, int count)
{
  return !memcmp(output, binary, BINARY_SIZE);
}

static int mschapv2_cmp_one(void *binary, int index)
{
  return !memcmp(output, binary, BINARY_SIZE);
}

static int mschapv2_cmp_exact(char *source, int index)
{
  return !memcmp(output, mschapv2_get_binary(source), BINARY_SIZE);
}

/* We're essentially using three salts, but we're going to generate a single value here for later use.
   |Peer/Client Challenge (8 Bytes)|Authenticator/Server Challenge (8 Bytes)|Username (<=256)|
*/
static void *mschapv2_get_salt(char *ciphertext)
{
  static unsigned char binary_salt[SALT_SIZE];
  static SHA_CTX ctx;
  unsigned char tmp[16];
  int i;
  char *pos = NULL;
  unsigned char digest[20];

  memset(binary_salt, 0, SALT_SIZE);
  memset(digest, 0, 20);
  SHA1_Init(&ctx);

  /* Peer Challenge */
  pos = ciphertext + 10 + 16*2 + 1 + 24*2 + 1; /* Skip $MSCHAPv2$, Authenticator Challenge and Response Hash */

  memset(tmp, 0, 16);
  for (i = 0; i < 16; i++)
    tmp[i] = (atoi16[ARCH_INDEX(pos[i*2])] << 4) + atoi16[ARCH_INDEX(pos[i*2+1])];

  SHA1_Update(&ctx, tmp, 16);
  
  /* Authenticator Challenge */
  pos = ciphertext + 10; /* Skip $MSCHAPv2$ */

  memset(tmp, 0, 16);
  for (i = 0; i < 16; i++)
    tmp[i] = (atoi16[ARCH_INDEX(pos[i*2])] << 4) + atoi16[ARCH_INDEX(pos[i*2+1])];

  SHA1_Update(&ctx, tmp, 16);
 
  /* Username - Only the user name (as presented by the peer and
     excluding any prepended domain name) is used as input to SHAUpdate()
  */
  pos = ciphertext + 10 + 16*2 + 1 + 24*2 + 1 + 16*2 + 1; /* Skip $MSCHAPv2$, Authenticator, Response and Peer */
  SHA1_Update(&ctx, pos, strlen(pos));
  
  SHA1_Final(digest, &ctx);
  memcpy(binary_salt, digest, 8);

  return (void*)binary_salt;
}

static void mschapv2_set_salt(void *salt)
{
  memcpy(challenge, salt, SALT_SIZE);
}

static void mschapv2_set_key(char *key, int index)
{
  strncpy((char *)saved_plain, key, PLAINTEXT_LENGTH);
  saved_plain[PLAINTEXT_LENGTH] = 0;
}

static char *mschapv2_get_key(int index)
{
  return (char *)saved_plain;
}

struct fmt_main fmt_MSCHAPv2 = {
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
    mschapv2_valid,
    mschapv2_split,
    mschapv2_get_binary,
    mschapv2_get_salt,
    {
      fmt_default_binary_hash,
      fmt_default_binary_hash,
      fmt_default_binary_hash,
      fmt_default_binary_hash,
      fmt_default_binary_hash
    },
    fmt_default_salt_hash,
    mschapv2_set_salt,
    mschapv2_set_key,
    mschapv2_get_key,
    fmt_default_clear_keys,
    mschapv2_crypt_all,
    {
      fmt_default_get_hash,
      fmt_default_get_hash,
      fmt_default_get_hash,
      fmt_default_get_hash,
      fmt_default_get_hash
    },
    mschapv2_cmp_all,
    mschapv2_cmp_one,
    mschapv2_cmp_exact
  }
};
