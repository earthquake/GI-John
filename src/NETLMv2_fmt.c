/*
 * NETLMv2_fmt.c -- LMv2 Challenge/Response 
 *
 * Written by JoMo-Kun <jmk at foofus.net> in 2008
 * and placed in the public domain.
 *
 * This algorithm is designed for performing brute-force cracking of the LMv2 
 * challenge/response sets exchanged during network-based authentication 
 * attempts [1]. The captured challenge/response set from these attempts 
 * should be stored using the following format: 
 *
 * USERNAME::DOMAIN:SERVER CHALLENGE:LMv2 RESPONSE:CLIENT CHALLENGE
 *
 * For example:
 * Administrator::WORKGROUP:1122334455667788:6759A5A7EFB25452911DE7DE8296A0D8:F503236B200A5B3A
 *
 * It should be noted that a LMv2 authentication response is not same as a LM 
 * password hash, which can be extracted using tools such as FgDump [2]. In
 * fact, a NTLM hash and not a LM hash is used within the LMv2 algorithm. LMv2
 * challenge/response authentication typically takes place when the GPO 
 * "Network Security: LAN Manager authentication level" is configured to a setting
 * that enforces the use of NTLMv2, such as "Send NTLMv2 response only\refuse 
 * LM & NTLM." 
 *
 * LMv2 responses can be gathered via normal network capture or via tools which 
 * perform layer 2 attacks, such as Ettercap [3] and Cain [4]. The responses can
 * also be harvested using a modified Samba service [5] in conjunction with 
 * some trickery to convince the user to connect to it. I leave what that 
 * trickery may actually be as an exercise for the reader (HINT: Karma, NMB 
 * broadcasts, IE, Outlook, social engineering, ...).
 * 
 * [1] http://davenport.sourceforge.net/ntlm.html#theLmv2Response
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

#include "md5.h"
#include "hmacmd5.h"

#ifndef uchar
#define uchar unsigned char
#endif

#define FORMAT_LABEL         "netlmv2"
#define FORMAT_NAME          "LMv2 C/R MD4 HMAC-MD5"
#define ALGORITHM_NAME       "netlmv2"
#define BENCHMARK_COMMENT    ""
#define BENCHMARK_LENGTH     0
#define PLAINTEXT_LENGTH     54 /* lmcons.h - PWLEN (256) ? 127 ? */
#define USERNAME_LENGTH      20 /* lmcons.h - UNLEN (256) / LM20_UNLEN (20) */
#define DOMAIN_LENGTH        15 /* lmcons.h - CNLEN / DNLEN */
#define BINARY_SIZE          16
#define CHALLENGE_LENGTH     32
#define SALT_SIZE            16 + USERNAME_LENGTH + DOMAIN_LENGTH
#define CIPHERTEXT_LENGTH    32
#define TOTAL_LENGTH         12 + USERNAME_LENGTH + DOMAIN_LENGTH + CHALLENGE_LENGTH + CIPHERTEXT_LENGTH
#define MIN_KEYS_PER_CRYPT   1
#define MAX_KEYS_PER_CRYPT   1

static struct fmt_tests tests[] = {
  {"$NETLMv2$ADMINISTRATORFOODOM$1122334455667788$6F64C5C1E35F68DD80388C0F00F34406$F0F3FF27037AA69F", "1337adminPASS"},
  {"$NETLMv2$USER1$1122334455667788$B1D163EA5881504F3963DC50FCDC26C1$EB4D9E8138149E20", "foobar"},
  {"$NETLMv2$ATEST$1122334455667788$83B59F1536D3321DBF1FAEC14ADB1675$A1E7281FE8C10E53", "SomeFancyP4$$w0rdHere"},
  {NULL}
};

static uchar saved_plain[PLAINTEXT_LENGTH + 1];
static uchar challenge[SALT_SIZE + 1];
static uchar output[BINARY_SIZE + 1];

extern void E_md4hash(uchar *passwd, uchar *p16);
extern void hmac_md5_init_limK_to_64(const unsigned char*, int, HMACMD5Context*);
extern void hmac_md5_update(const unsigned char*, int, HMACMD5Context*);
extern void hmac_md5_final(unsigned char*, HMACMD5Context*);

#if !defined(uint16) && !defined(HAVE_UINT16_FROM_RPC_RPC_H)
#if (SIZEOF_SHORT == 4)
#define uint16 __ERROR___CANNOT_DETERMINE_TYPE_FOR_INT16;
#else /* SIZEOF_SHORT != 4 */
#define uint16 unsigned short
#endif /* SIZEOF_SHORT != 4 */
#endif

#if !defined(int16) && !defined(HAVE_INT16_FROM_RPC_RPC_H)
#if (SIZEOF_SHORT == 4)
#define int16 __ERROR___CANNOT_DETERMINE_TYPE_FOR_INT16;
#else /* SIZEOF_SHORT != 4 */
#define int16 short
#endif /* SIZEOF_SHORT != 4 */
#endif

#include "byteorder.h"

/* Routines for Windows NT MD4 Hash functions. */
static int lmv2_wcslen(int16 *str)
{
  int len = 0;
  while(*str++ != 0)
    len++;
  return len;
}

/*
 * Convert a string into an NT UNICODE string.
 * Note that regardless of processor type 
 * this must be in intel (little-endian)
 * format.
 */
int lmv2_mbstowcs(int16 *dst, uchar *src, int len)
{
  int i;
  int16 val;

  for(i = 0; i < len; i++) {
    val = *src;
    SSVAL(dst,0,val);
    dst++;
    src++;
    if(val == 0)
      break;
  }
  return i;
}

static int netlmv2_valid(char *ciphertext)
{
  char *pos, *pos2;

  if (ciphertext == NULL) return 0;
  else if (strncmp(ciphertext, "$NETLMv2$", 9)!=0) return 0;
  
  pos = &ciphertext[9];
  
  /* Validate Username and Domain Length */
  for (pos2 = pos; strncmp(pos2, "$", 1) != 0; pos2++)
    if ( (*pos2 < 0x20) || (*pos2 > 0x7E) )
      return 0;
  
  if ( !(*pos2 && (pos2 - pos <= USERNAME_LENGTH + DOMAIN_LENGTH)) )
    return 0;

  /* Validate Server Challenge Length */
  pos2++; pos = pos2;
  for (; strncmp(pos2, "$", 1) != 0; pos2++)
    if (atoi16[ARCH_INDEX(*pos2)] == 0x7F)
      return 0;

  if ( !(*pos2 && (pos2 - pos == CHALLENGE_LENGTH / 2)) )
    return 0;

  /* Validate LMv2 Response Length */
  pos2++; pos = pos2;
  for (; strncmp(pos2, "$", 1) != 0; pos2++)
    if (atoi16[ARCH_INDEX(*pos2)] == 0x7F)
      return 0;

  if ( !(*pos2 && (pos2 - pos == CIPHERTEXT_LENGTH)) )
    return 0;

  /* Validate Client Challenge Length */
  pos2++; pos = pos2;
  for (; atoi16[ARCH_INDEX(*pos2)] != 0x7F; pos2++);
  if (pos2 - pos != CHALLENGE_LENGTH / 2)
    return 0;

  return 1;
}

static char *netlmv2_split(char *ciphertext, int index)
{
  static char out[TOTAL_LENGTH + 1];
  char *pos = NULL;
  int identity_length = 0;

  /* Calculate identity length */
  for (pos = ciphertext + 9; strncmp(pos, "$", 1) != 0; pos++);
  identity_length = pos - (ciphertext + 9);

  memset(out, 0, TOTAL_LENGTH + 1);
  memcpy(&out, ciphertext, strlen(ciphertext));
  strlwr(&out[10 + identity_length]); /* Exclude: $NETLMv2$USERDOMAIN$ */
  
  return out;
}

static void *netlmv2_get_binary(char *ciphertext)
{
  static uchar binary[BINARY_SIZE];
  char *pos = NULL;
  int i, identity_length;
  
  for (pos = ciphertext + 9; strncmp(pos, "$", 1) != 0; pos++);
  identity_length = pos - (ciphertext + 9);

  ciphertext += 9 + identity_length + 1 + CHALLENGE_LENGTH / 2 + 1;
  for (i=0; i<BINARY_SIZE; i++)
  {
    binary[i] = (atoi16[ARCH_INDEX(ciphertext[i*2])])<<4;
    binary[i] |= (atoi16[ARCH_INDEX(ciphertext[i*2+1])]);
  }

  return binary;
}

/* Calculate the LMv2 response for the given challenge, using the
   specified authentication identity (username and domain), password 
   and client nonce.
*/
static void netlmv2_crypt_all(int count)
{
  HMACMD5Context ctx;
  unsigned char ntlm[16];
  unsigned char ntlm_v2_hash[16];
  uchar *identity = NULL;
  int identity_length = 0;
  int16 identity_usc[129];
  int identity_usc_length;

  memset(ntlm, 0, 16);
  memset(ntlm_v2_hash, 0, 16);
  memset(output, 0, 16);
  memset(identity_usc, 0, 129);
  identity_usc_length = 0;

  /* Convert identity (username + domain) string to NT unicode */
  identity_length = strlen((char *)challenge) - CHALLENGE_LENGTH / 2;
  identity = challenge + CHALLENGE_LENGTH / 2;

  lmv2_mbstowcs(identity_usc, identity, identity_length);
  identity_usc_length = lmv2_wcslen(identity_usc) * sizeof(int16);

  /* Generate 16-byte NTLM hash */
  E_md4hash(saved_plain, ntlm);

  /* Generate 16-byte NTLMv2 Hash */
  /* HMAC-MD5(Username + Domain, NTLM Hash) */
  hmac_md5_init_limK_to_64(ntlm, 16, &ctx);
  hmac_md5_update((const unsigned char *)identity_usc, identity_usc_length, &ctx);
  hmac_md5_final(ntlm_v2_hash, &ctx);

  /* Generate 16-byte non-client nonce portion of LMv2 Response */
  /* HMAC-MD5(Challenge + Nonce, NTLMv2 Hash) + Nonce */
  hmac_md5_init_limK_to_64(ntlm_v2_hash, 16, &ctx);
  hmac_md5_update(challenge, 16, &ctx);
  hmac_md5_final(output, &ctx);
}

static int netlmv2_cmp_all(void *binary, int count)
{
  return !memcmp(output, binary, BINARY_SIZE);
}

static int netlmv2_cmp_one(void *binary, int index)
{
  return !memcmp(output, binary, BINARY_SIZE);
}

static int netlmv2_cmp_exact(char *source, int index)
{
  return !memcmp(output, netlmv2_get_binary(source), BINARY_SIZE);
}

/* We're essentially using three salts, but we're going to pack it into a single blob for now.
   |Client Challenge (8 Bytes)|Server Challenge (8 Bytes)|Username (<=20)|Domain (<=15)|
*/
static void *netlmv2_get_salt(char *ciphertext)
{
  static unsigned char binary_salt[SALT_SIZE];
  int i, identity_length;
  char *pos = NULL;

  memset(binary_salt, 0, SALT_SIZE);

  /* Calculate identity length */
  for (pos = ciphertext + 9; strncmp(pos, "$", 1) != 0; pos++);
  identity_length = pos - (ciphertext + 9);
  strncpy((char *)binary_salt + CHALLENGE_LENGTH / 2, ciphertext + 9, identity_length);

  /* Set server challenge */
  ciphertext += 10 + identity_length;

  for (i = 0; i < 8; i++)
    binary_salt[i] = (atoi16[ARCH_INDEX(ciphertext[i*2])] << 4) + atoi16[ARCH_INDEX(ciphertext[i*2+1])];
 
  /* Set client challenge */
  ciphertext += 2 + CHALLENGE_LENGTH / 2 + CIPHERTEXT_LENGTH; 

  for (i = 0; i < 8; ++i)
    binary_salt[i + 8] = (atoi16[ARCH_INDEX(ciphertext[i*2])] << 4) + atoi16[ARCH_INDEX(ciphertext[i*2+1])];

  /* Return a concatenation of the server and client challenges and the identity value */ 
  return (void*)binary_salt;
}

static void netlmv2_set_salt(void *salt)
{
  memcpy(challenge, salt, SALT_SIZE);
}

static void netlmv2_set_key(char *key, int index)
{
  strncpy((char *)saved_plain, key, PLAINTEXT_LENGTH);
  saved_plain[PLAINTEXT_LENGTH] = 0;
}

static char *netlmv2_get_key(int index)
{
  return (char *)saved_plain;
}

struct fmt_main fmt_NETLMv2 = {
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
    netlmv2_valid,
    netlmv2_split,
    netlmv2_get_binary,
    netlmv2_get_salt,
    {
      fmt_default_binary_hash,
      fmt_default_binary_hash,
      fmt_default_binary_hash,
      fmt_default_binary_hash,
      fmt_default_binary_hash
    },
    fmt_default_salt_hash,
    netlmv2_set_salt,
    netlmv2_set_key,
    netlmv2_get_key,
    fmt_default_clear_keys,
    netlmv2_crypt_all,
    {
      fmt_default_get_hash,
      fmt_default_get_hash,
      fmt_default_get_hash,
      fmt_default_get_hash,
      fmt_default_get_hash
    },
    netlmv2_cmp_all,
    netlmv2_cmp_one,
    netlmv2_cmp_exact
  }
};
