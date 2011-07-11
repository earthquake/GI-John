/*
 * NETHALFLM_fmt.c
 * Written by DSK (Based on NetLM/NetNTLM patch by JoMo-Kun)
 * Performs brute-force cracking of the HalfLM challenge/response pairs. 

 * Storage Format: 
 * domain\username:::lm response:nt response:challenge
 *
 * Code is in public domain.
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

#define FORMAT_LABEL         "nethalflm"
#define FORMAT_NAME          "HalfLM C/R DES"
#define ALGORITHM_NAME       "nethalflm"
#define BENCHMARK_COMMENT    ""
#define BENCHMARK_LENGTH     0
#define PLAINTEXT_LENGTH     7
#define BINARY_SIZE          8
#define SALT_SIZE            8
#define CIPHERTEXT_LENGTH    48
#define TOTAL_LENGTH         12 + 2 * SALT_SIZE + CIPHERTEXT_LENGTH
#define MIN_KEYS_PER_CRYPT   1
#define MAX_KEYS_PER_CRYPT   1

static struct fmt_tests tests[] = {
  {"$NETHALFLM$1122334455667788$6E1EC36D3417CE9E09A4424309F116C4C991948DAEB4ADAD", "G3RG3P00!"},
  {"$NETHALFLM$1122334455667788$6E1EC36D3417CE9E09A4424309F116C4C991948DAEB4ADAD", "G3RG3P0"},
  {"$NETHALFLM$1122334455667788$1354FD5ABF3B627B8B49587B8F2BBA0F9F6C5E420824E0A2", "ZEEEZ@1"},
  {NULL}
};

static char saved_plain[PLAINTEXT_LENGTH + 1];
static uchar challenge[SALT_SIZE + 1];
static uchar output[BINARY_SIZE + 1];

static int nethalflm_valid(char *ciphertext)
{
  char *pos;

  if (strncmp(ciphertext, "$NETHALFLM$", 11)!=0) return 0;
  if (ciphertext[27] != '$') return 0;

  for (pos = &ciphertext[28]; atoi16[ARCH_INDEX(*pos)] != 0x7F; pos++);
    if (!*pos && pos - ciphertext - 28 == CIPHERTEXT_LENGTH) {
	    return 1;
    }
    else
      return 0;
}

static char *nethalflm_split(char *ciphertext, int index)
{
  static char out[TOTAL_LENGTH + 1] = {0};

  memcpy(&out, ciphertext, TOTAL_LENGTH); 
  strlwr(&out[10]); /* Exclude: $NETHALFLM$ */
  return out;
}

static void *nethalflm_get_binary(char *ciphertext)
{
  static uchar binary[BINARY_SIZE];
  int i;

  ciphertext+=28;
  for (i=0; i<BINARY_SIZE; i++)
  {
    binary[i] = (atoi16[ARCH_INDEX(ciphertext[i*2])])<<4;
    binary[i] |= (atoi16[ARCH_INDEX(ciphertext[i*2+1])]);
  }
  return binary;
}

/* Avoid clash with NETLM_fmt.c */
static void setup_des_key(unsigned char key_56[], DES_key_schedule *ks)
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

static void nethalflm_crypt_all(int count)
{
  static unsigned char magic[] = {0x4b, 0x47, 0x53, 0x21, 0x40, 0x23, 0x24, 0x25};
  DES_key_schedule ks;
  unsigned char password[7 + 1];
  unsigned char lm[8];

  /* clear buffers */
  memset(lm, 0, 8);
  memset(output, 0, 8);  

  strncpy((char *) password, saved_plain, 7);
  /* Generate first 8-bytes of LM hash */
  setup_des_key(password, &ks);
  DES_ecb_encrypt((DES_cblock*)magic, (DES_cblock*)lm, &ks, DES_ENCRYPT);

  /* DES-encrypt challenge using LM hash */
  setup_des_key(lm, &ks);
  DES_ecb_encrypt((DES_cblock*)challenge, (DES_cblock*)output, &ks, DES_ENCRYPT);
  /*printf("\nLM Response: ");
  int i;
  for( i = 0; i< BINARY_SIZE ;i++)
	  printf("%.2x",output[i]); */
}

static int nethalflm_cmp_all(void *binary, int count)
{
  return !memcmp(output, binary, 8);
}

static int nethalflm_cmp_one(void *binary, int index)
{
  return !memcmp(output, binary, 8);
}

static int nethalflm_cmp_exact(char *source, int index)
{
  return !memcmp(output, nethalflm_get_binary(source), 8);
}

static void *nethalflm_get_salt(char *ciphertext)
{
  static unsigned char binary_salt[SALT_SIZE];
  int i;

  ciphertext += 11;
  for (i = 0; i < SALT_SIZE; ++i) {
	  binary_salt[i] = (atoi16[ARCH_INDEX(ciphertext[i*2])] << 4) + atoi16[ARCH_INDEX(ciphertext[i*2+1])];
	  /*printf("%.2x",binary_salt[i]);*/
  }
  return (void*)binary_salt;
}

static void nethalflm_set_salt(void *salt)
{
  memcpy(challenge, salt, SALT_SIZE);
}

static void nethalflm_set_key(char *key, int index)
{
  int i;
 
  strncpy(saved_plain, key, PLAINTEXT_LENGTH);
  
  /* Upper-case password */
  for(i=0; i<PLAINTEXT_LENGTH && saved_plain[i]!=0 ; i++)
    if ((saved_plain[i] >= 'a') && (saved_plain[i] <= 'z')) saved_plain[i] ^= 0x20;
}

static char *nethalflm_get_key(int index)
{
  return saved_plain;
}

struct fmt_main fmt_NETHALFLM = {
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
    FMT_8_BIT | FMT_SPLIT_UNIFIES_CASE, 
    tests
  }, {
    fmt_default_init,
    nethalflm_valid,
    nethalflm_split,
    nethalflm_get_binary,
    nethalflm_get_salt,
    {
      fmt_default_binary_hash,
      fmt_default_binary_hash,
      fmt_default_binary_hash,
      fmt_default_binary_hash,
      fmt_default_binary_hash
    },
    fmt_default_salt_hash,
    nethalflm_set_salt,
    nethalflm_set_key,
    nethalflm_get_key,
    fmt_default_clear_keys,
    nethalflm_crypt_all,
    {
      fmt_default_get_hash,
      fmt_default_get_hash,
      fmt_default_get_hash,
      fmt_default_get_hash,
      fmt_default_get_hash
    },
    nethalflm_cmp_all,
    nethalflm_cmp_one,
    nethalflm_cmp_exact
  }
};

