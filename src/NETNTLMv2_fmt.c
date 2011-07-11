/*
 * NETNTLMv2_fmt.c -- NTLMv2 Challenge/Response 
 *
 * Written by JoMo-Kun <jmk at foofus.net> in 2009
 * and placed in the public domain.
 *
 * This algorithm is designed for performing brute-force cracking of the NTLMv2 
 * challenge/response sets exchanged during network-based authentication 
 * attempts [1]. The captured challenge/response set from these attempts 
 * should be stored using the following format: 
 *
 * USERNAME::DOMAIN:SERVER CHALLENGE:NTLMv2 RESPONSE:CLIENT CHALLENGE
 *
 * For example:
 * ntlmv2test::WORKGROUP:1122334455667788:07659A550D5E9D02996DFD95C87EC1D5:0101000000000000006CF6385B74CA01B3610B02D99732DD000000000200120057004F0052004B00470052004F00550050000100200044004100540041002E00420049004E0043002D0053004500430055005200490000000000
 *
 * It should be noted that a NTLMv2 authentication response is not same as a NTLM 
 * password hash, which can be extracted using tools such as FgDump [2]. NTLMv2
 * challenge/response authentication typically takes place when the GPO 
 * "Network Security: LAN Manager authentication level" is configured to a setting
 * that enforces the use of NTLMv2, such as "Send NTLMv2 response only\refuse 
 * LM & NTLM." 
 *
 * NTLMv2 responses can be gathered via normal network capture or via tools which 
 * perform layer 2 attacks, such as Ettercap [3] and Cain [4]. The responses can
 * also be harvested using a modified Samba service [5] in conjunction with 
 * some trickery to convince the user to connect to it. I leave what that 
 * trickery may actually be as an exercise for the reader (HINT: Karma, NMB 
 * broadcasts, IE, Outlook, social engineering, ...).
 * 
 * [1] http://davenport.sourceforge.net/ntlm.html#theNtlmv2Response 
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

#define FORMAT_LABEL         "netntlmv2"
#define FORMAT_NAME          "NTLMv2 C/R MD4 HMAC-MD5"
#define ALGORITHM_NAME       "netntlmv2"
#define BENCHMARK_COMMENT    ""
#define BENCHMARK_LENGTH     0
#define PLAINTEXT_LENGTH     54 /* lmcons.h - PWLEN (256) ? 127 ? */
#define USERNAME_LENGTH      20 /* lmcons.h - UNLEN (256) / LM20_UNLEN (20) */
#define DOMAIN_LENGTH        15 /* lmcons.h - CNLEN / DNLEN */
#define BINARY_SIZE          16
#define SERVER_CHALL_LENGTH  16
#define CLIENT_CHALL_LENGTH_MAX  2048 /* FIX - Max Target Information Size Unknown */ 
#define SALT_SIZE_MAX        USERNAME_LENGTH + DOMAIN_LENGTH + 3 + SERVER_CHALL_LENGTH/2 + CLIENT_CHALL_LENGTH_MAX/2
#define CIPHERTEXT_LENGTH    32
#define TOTAL_LENGTH         12 + USERNAME_LENGTH + DOMAIN_LENGTH + SERVER_CHALL_LENGTH + CLIENT_CHALL_LENGTH_MAX + CIPHERTEXT_LENGTH
#define MIN_KEYS_PER_CRYPT   1
#define MAX_KEYS_PER_CRYPT   1
  
static struct fmt_tests tests[] = {
  {"$NETNTLMv2$NTLMV2TESTWORKGROUP$1122334455667788$07659A550D5E9D02996DFD95C87EC1D5$0101000000000000006CF6385B74CA01B3610B02D99732DD000000000200120057004F0052004B00470052004F00550050000100200044004100540041002E00420049004E0043002D0053004500430055005200490000000000", "password"},
  {"$NETNTLMv2$TESTUSERW2K3ADWIN7$1122334455667788$989B96DC6EAB529F72FCBA852C0D5719$01010000000000002EC51CEC91AACA0124576A744F198BDD000000000200120057004F0052004B00470052004F00550050000000000000000000", "testpass"},
  {"$NETNTLMv2$USERW2K3ADWIN7$1122334455667788$5BD1F32D8AFB4FB0DD0B77D7DE2FF7A9$0101000000000000309F56FE91AACA011B66A7051FA48148000000000200120057004F0052004B00470052004F00550050000000000000000000", "password"},
  {"$NETNTLMv2$USER1W2K3ADWIN7$1122334455667788$027EF88334DAA460144BDB678D4F988D$010100000000000092809B1192AACA01E01B519CB0248776000000000200120057004F0052004B00470052004F00550050000000000000000000", "SomeLongPassword1BlahBlah"},
  {"$NETNTLMv2$TEST_USERW2K3ADWIN7$1122334455667788$A06EC5ED9F6DAFDCA90E316AF415BA71$010100000000000036D3A13292AACA01D2CD95757A0836F9000000000200120057004F0052004B00470052004F00550050000000000000000000", "TestUser's Password"},
  {"$NETNTLMv2$USER1Domain$1122334455667788$5E4AB1BF243DCA304A00ADEF78DC38DF$0101000000000000BB50305495AACA01338BC7B090A62856000000000200120057004F0052004B00470052004F00550050000000000000000000", "password"},
  {NULL}
};

static uchar saved_plain[PLAINTEXT_LENGTH + 1];
static uchar challenge[SALT_SIZE_MAX + 1];
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
static int ntlmv2_wcslen(int16 *str)
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
int ntlmv2_mbstowcs(int16 *dst, uchar *src, int len)
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

static int netntlmv2_valid(char *ciphertext)
{
  char *pos, *pos2;

  if (ciphertext == NULL) return 0;
  else if (strncmp(ciphertext, "$NETNTLMv2$", 11)!=0) return 0;
  
  pos = &ciphertext[11];
  
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

  if ( !(*pos2 && (pos2 - pos == SERVER_CHALL_LENGTH)) )
    return 0;

  /* Validate NTLMv2 Response Length */
  pos2++; pos = pos2;
  for (; strncmp(pos2, "$", 1) != 0; pos2++)
    if (atoi16[ARCH_INDEX(*pos2)] == 0x7F)
      return 0;

  if ( !(*pos2 && (pos2 - pos == CIPHERTEXT_LENGTH)) )
    return 0;

  /* Validate Client Challenge Length */
  pos2++; pos = pos2;
  for (; atoi16[ARCH_INDEX(*pos2)] != 0x7F; pos2++);
  if (pos2 - pos > CLIENT_CHALL_LENGTH_MAX)
    return 0;

  return 1;
}

static char *netntlmv2_split(char *ciphertext, int index)
{
  static char out[TOTAL_LENGTH + 1];
  char *pos = NULL;
  int identity_length = 0;

  /* Calculate identity length */
  for (pos = ciphertext + 11; strncmp(pos, "$", 1) != 0; pos++);
  identity_length = pos - (ciphertext + 11);

  memset(out, 0, TOTAL_LENGTH + 1);
  memcpy(&out, ciphertext, strlen(ciphertext));
  strlwr(&out[12 + identity_length]); /* Exclude: $NETNTLMv2$USERDOMAIN$ */
  
  return out;
}

static void *netntlmv2_get_binary(char *ciphertext)
{
  static uchar binary[BINARY_SIZE];
  char *pos = NULL;
  int i, identity_length;
  
  for (pos = ciphertext + 11; strncmp(pos, "$", 1) != 0; pos++);
  identity_length = pos - (ciphertext + 11);

  ciphertext += 11 + identity_length + 1 + SERVER_CHALL_LENGTH + 1;
  for (i=0; i<BINARY_SIZE; i++)
  {
    binary[i] = (atoi16[ARCH_INDEX(ciphertext[i*2])])<<4;
    binary[i] |= (atoi16[ARCH_INDEX(ciphertext[i*2+1])]);
  }

  return binary;
}

/* Calculate the NTLMv2 response for the given challenge, using the
   specified authentication identity (username and domain), password 
   and client nonce.
  
   challenge: Identity \0 Challenge Size \0 Server Challenge + Client Challenge
*/
static void netntlmv2_crypt_all(int count)
{
  HMACMD5Context ctx;
  unsigned char ntlm[16];
  unsigned char ntlm_v2_hash[16];
  uchar *identity = NULL;
  int identity_length = 0;
  int16 identity_usc[129];
  int identity_usc_length = 0;
  int challenge_size = 0; 

  memset(ntlm, 0, 16);
  memset(ntlm_v2_hash, 0, 16);
  memset(output, 0, 16);
  memset(identity_usc, 0, 129);
  identity_usc_length = 0;

  /* --- HMAC #1 Caculations --- */

  /* Convert identity (username + domain) string to NT unicode */
  identity_length = strlen((char *)challenge);
  identity = challenge;

  ntlmv2_mbstowcs(identity_usc, identity, identity_length);
  identity_usc_length = ntlmv2_wcslen(identity_usc) * sizeof(int16);

  /* Generate 16-byte NTLM hash */
  E_md4hash(saved_plain, ntlm);

  /* Generate 16-byte NTLMv2 Hash */
  /* HMAC-MD5(Username + Domain, NTLM Hash) */
  hmac_md5_init_limK_to_64(ntlm, 16, &ctx);
  hmac_md5_update((const unsigned char *)identity_usc, identity_usc_length, &ctx);
  hmac_md5_final(ntlm_v2_hash, &ctx);

  /* --- Blob Construction --- */

  /*  
    The blob consists of the target (from Type 2 message), client nonce and timestamp. 
    This data was provided by the client during authentication and we can use it as is. 
  */

  /* --- HMAC #2 Caculations --- */

  /*
    The (server) challenge from the Type 2 message is concatenated with the blob. The 
    HMAC-MD5 message authentication code algorithm is applied to this value using the 
    16-byte NTLMv2 hash (calculated above) as the key. This results in a 16-byte output 
    value.
  */

  /* 
    Generate 16-byte non-client nonce portion of NTLMv2 Response 
    HMAC-MD5(Challenge + Nonce, NTLMv2 Hash)
  
    The length of the challenge was set in netntlmv2_get_salt(). We find the server
    challenge and blob following the identity and challenge size value.
    challenge -> Identity \0 Size (2 bytes) \0 Server Challenge + Client Challenge (Blob)
  */
  challenge_size = (*(challenge + identity_length + 1) << 8) | *(challenge + identity_length + 2);

  hmac_md5_init_limK_to_64(ntlm_v2_hash, 16, &ctx);
  hmac_md5_update(challenge + identity_length + 1 + 2 + 1, challenge_size, &ctx); 
  hmac_md5_final(output, &ctx);
}

static int netntlmv2_cmp_all(void *binary, int count)
{
  return !memcmp(output, binary, BINARY_SIZE);
}

static int netntlmv2_cmp_one(void *binary, int index)
{
  return !memcmp(output, binary, BINARY_SIZE);
}

static int netntlmv2_cmp_exact(char *source, int index)
{
  return !memcmp(output, netntlmv2_get_binary(source), BINARY_SIZE);
}

/* 
  We're essentially using three salts, but we're going to pack it into a single blob for now.

  Input:  $NETNTLMv2$USER_DOMAIN$_SERVER_CHALLENGE_$_NTLMv2_RESP_$_CLIENT_CHALLENGE_
    Username: <=20
    Domain: <=15
    Server Challenge: 8 bytes
    Client Challenge: ???
  Output: Identity \0 Challenge Size \0 Server Challenge + Client Challenge
*/
static void *netntlmv2_get_salt(char *ciphertext)
{
  static unsigned char binary_salt[SALT_SIZE_MAX];
  int i, identity_length, challenge_size;
  char *pos = NULL;

  memset(binary_salt, 0, SALT_SIZE_MAX);

  /* Calculate identity length; Set identity */
  for (pos = ciphertext + 11; strncmp(pos, "$", 1) != 0; pos++);
  identity_length = pos - (ciphertext + 11);
  strncpy((char *)binary_salt, ciphertext + 11, identity_length);

  /* Set server and client challenge size */

  /* Skip: $NETNTLMv2$USER_DOMAIN$ */
  ciphertext += 11 + identity_length + 1;

  /* SERVER_CHALLENGE$NTLMV2_RESPONSE$CLIENT_CHALLENGE --> SERVER_CHALLENGECLIENT_CHALLENGE */
  /* CIPHERTEXT == NTLMV2_RESPONSE (16 bytes / 32 characters) */
  challenge_size = (strlen(ciphertext) - CIPHERTEXT_LENGTH - 2) / 2;

  /* Set challenge size in response - 2 bytes - use NULL separators */
  memset(binary_salt + identity_length + 1, (challenge_size & 0xFF00) >> 8, 1); 
  memset(binary_salt + identity_length + 2, challenge_size & 0x00FF, 1); 
  
  /* Set server challenge - add NULL separator after challenge size */
  for (i = 0; i < SERVER_CHALL_LENGTH / 2; i++)
    binary_salt[identity_length + 1 + 2 + 1 + i] = (atoi16[ARCH_INDEX(ciphertext[i*2])] << 4) + atoi16[ARCH_INDEX(ciphertext[i*2+1])];
  
  /* Set client challenge */
  ciphertext += SERVER_CHALL_LENGTH + 1 + CIPHERTEXT_LENGTH + 1; 
  for (i = 0; i < strlen(ciphertext) / 2; ++i)
    binary_salt[identity_length + 1 + 2 + 1 + SERVER_CHALL_LENGTH / 2 + i] = (atoi16[ARCH_INDEX(ciphertext[i*2])] << 4) + atoi16[ARCH_INDEX(ciphertext[i*2+1])];

  /* Return a concatenation of the server and client challenges and the identity value */ 
  return (void*)binary_salt;
}

static void netntlmv2_set_salt(void *salt)
{
  memcpy(challenge, salt, SALT_SIZE_MAX);
}

static void netntlmv2_set_key(char *key, int index)
{
  strncpy((char *)saved_plain, key, PLAINTEXT_LENGTH);
  saved_plain[PLAINTEXT_LENGTH] = 0;
}

static char *netntlmv2_get_key(int index)
{
  return (char *)saved_plain;
}

struct fmt_main fmt_NETNTLMv2 = {
  {
    FORMAT_LABEL,
    FORMAT_NAME,
    ALGORITHM_NAME,
    BENCHMARK_COMMENT,
    BENCHMARK_LENGTH,
    PLAINTEXT_LENGTH,
    BINARY_SIZE,
    SALT_SIZE_MAX,
    MIN_KEYS_PER_CRYPT,
    MAX_KEYS_PER_CRYPT,
    FMT_CASE | FMT_8_BIT | FMT_SPLIT_UNIFIES_CASE,
    tests
  }, {
    fmt_default_init,
    netntlmv2_valid,
    netntlmv2_split,
    netntlmv2_get_binary,
    netntlmv2_get_salt,
    {
      fmt_default_binary_hash,
      fmt_default_binary_hash,
      fmt_default_binary_hash
    },
    fmt_default_salt_hash,
    netntlmv2_set_salt,
    netntlmv2_set_key,
    netntlmv2_get_key,
    fmt_default_clear_keys,
    netntlmv2_crypt_all,
    {
      fmt_default_get_hash,
      fmt_default_get_hash,
      fmt_default_get_hash
    },
    netntlmv2_cmp_all,
    netntlmv2_cmp_one,
    netntlmv2_cmp_exact
  }
};
