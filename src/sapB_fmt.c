/*
 * this is a SAP-BCODE plugin for john the ripper. 
 * tested on linux/x86 only, rest is up to you.. at least, someone did the reversing :-)
 *
 * please note: this code is in a "works for me"-state, feel free to modify/speed up/clean/whatever it...
 *
 * (c) x7d8 sap loverz, public domain, btw
 * cheers: see test-cases.
 */

/* char transition table for BCODE (from disp+work) */
#define TRANSTABLE_LENGTH 16*16
unsigned char transtable[TRANSTABLE_LENGTH]=
{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
 0x3F, 0x40, 0x41, 0x50, 0x43, 0x44, 0x45, 0x4B, 0x47, 0x48, 0x4D, 0x4E, 0x54, 0x51, 0x53, 0x46,
 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x56, 0x55, 0x5C, 0x49, 0x5D, 0x4A,
 0x42, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x58, 0x5B, 0x59, 0xFF, 0x52,
 0x4C, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29,
 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33, 0x34, 0x57, 0x5E, 0x5A, 0x4F, 0xFF,
 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

#define BCODE_ARRAY_LENGTH 3*16 
char bcodeArr[BCODE_ARRAY_LENGTH]=
{0x14,0x77,0xF3,0xD4,0xBB,0x71,0x23,0xD0,0x03,0xFF,0x47,0x93,0x55,0xAA,0x66,0x91,
0xF2,0x88,0x6B,0x99,0xBF,0xCB,0x32,0x1A,0x19,0xD9,0xA7,0x82,0x22,0x49,0xA2,0x51,
0xE2,0xB7,0x33,0x71,0x8B,0x9F,0x5D,0x01,0x44,0x70,0xAE,0x11,0xEF,0x28,0xF0,0x0D};


#include <string.h>
#include <ctype.h>

#include "arch.h"
#include "misc.h"
#include "common.h"
#include "formats.h"

#include "md5.h"

#define FORMAT_LABEL			"sapb"
#define FORMAT_NAME			"SAP BCODE"
#define ALGORITHM_NAME			"sapb"

#define BENCHMARK_COMMENT		""
#define BENCHMARK_LENGTH		0

#define SALT_SIZE			40	/* the max username length */
#define PLAINTEXT_LENGTH		8	/* passwordlength max 8 chars */
#define CIPHERTEXT_LENGTH		SALT_SIZE + 1 + 16	/* SALT + $ + 2x8 bytes for BCODE-representation */

#define BINARY_SIZE			8	/* half of md5 */

#define MIN_KEYS_PER_CRYPT		1
#define MAX_KEYS_PER_CRYPT		1

static struct fmt_tests sapbcode_tests[] = { 
 	{"F                                       $E3A65AAA9676060F", "X"},
	{"JOHNNY                                  $7F7207932E4DE471", "CYBERPUNK"},
	{"VAN                                     $487A2A40A7BA2258", "HAUSER"},
	{"ROOT                                    $8366A4E9E6B72CB0", "KID"},
	{"MAN                                     $9F48E7CE5B184D2E", "u"},
	{"----------------------------------------$08CEDAFED0C750A0", "-------"},
	{"SAP*                                    $7016BFF7C5472F1B", "MAsTeR"}, 
	{"DDIC                                    $C94E2F7DD0178374", "DDIC"},
	{"DOLLAR$$$---                            $C3413C498C48EB67", "dollar$$$---"},
	{NULL}
};

static char saved_key[PLAINTEXT_LENGTH + 1];
static char crypt_key[BINARY_SIZE];
static MD5_CTX ctx;
static char theSalt[SALT_SIZE];

static int sapbcode_valid(char *ciphertext)
{
	int i;

	if(strlen(ciphertext)!=CIPHERTEXT_LENGTH) 
		return 0; 

	if (ciphertext[SALT_SIZE]!='$')
		return 0;

	for (i = SALT_SIZE+1; i< CIPHERTEXT_LENGTH; i++)
		if (!(((ciphertext[i]>='A' && ciphertext[i]<='F')) ||
			((ciphertext[i]>='a' && ciphertext[i]<='f')) ||
			((ciphertext[i]>='0' && ciphertext[i]<='9')) ))
			return 0; 
	return 1;
}

static void sapbcode_set_salt(void *salt) 
{
	memcpy(theSalt, salt, SALT_SIZE); 
}


void strToUpper_B(char* str)
{
	int i=0;
	if (NULL==str) 
		return;
	for (i=0; i<strlen(str);i++)
		if ((str[i] >= 'a') && (str[i] <= 'z')) str[i] ^= 0x20;
}


static void sapbcode_set_key(char *key, int index) {
	strnzcpy(saved_key, key, PLAINTEXT_LENGTH+1);
}

static char *sapbcode_get_key(int index) {
	return saved_key;
}

static int sapbcode_cmp_all(void *binary, int index) { 
	return !memcmp(binary, crypt_key, BINARY_SIZE);
}

static int sapbcode_cmp_exact(char *source, int count){
  return 1; 
}

static int sapbcode_cmp_one(void * binary, int index)
{
	return sapbcode_cmp_all(binary, index);
}


/*
 * this function is needed to determine the actual size of the salt (==username)
 * theSalt has to point at the beginning of the actual salt. no more checks are done; relies on valid() 
 * this is needed because, afaik, john only supports salts w/ fixed length. sap uses the username, so we have to 
 * "strip" the padding (blanks at the end) for the calculation.... 
 * usernames w/ spaces at the end are not supported (SAP does not support them either)
 */
int calcActualSaltSize_B(char* theSalt)
{
    int i;
	if (NULL==theSalt)
		return 0;
	i=SALT_SIZE-1;
	while (theSalt[i--]==0x20);
	return i+2;
}


#define TEMP_ARRAY_SIZE 4*16
static void sapbcode_crypt_all(int count) {  
	static unsigned char temp_key[BINARY_SIZE*2]; 
	static unsigned char final_key[BINARY_SIZE*2];
	static char username[SALT_SIZE+1], password[PLAINTEXT_LENGTH+1];
	static char unConverted[SALT_SIZE+1], pwConverted[PLAINTEXT_LENGTH+1];
	unsigned int i;
	unsigned int sum20;
	int I1, I2;
	int revI1;
	int I3;
	int strlenUN, strlenPW;
	char destArray[TEMP_ARRAY_SIZE];
	int I4;
	
	//username: theSalt (we have to determine the right length...)
	//password: saved_key
	strnzcpy(username, theSalt, calcActualSaltSize_B(theSalt)+1);
	strnzcpy(password, saved_key, PLAINTEXT_LENGTH+1);

  	strToUpper_B(password); //only UPPERCASE passwords accepted for BCODE

	//transform... 
	for (i=0; i<strlen(username); i++) 
		unConverted[i]=transtable[ARCH_INDEX(username[i])];
	unConverted[i]='\0';	

	for (i=0; i<strlen(password); i++) 
		pwConverted[i]=transtable[ARCH_INDEX(password[i])];
	pwConverted[i]='\0';

	MD5_Init(&ctx);
	MD5_Update(&ctx, pwConverted, strlen(pwConverted));
	MD5_Update(&ctx, unConverted, strlen(unConverted));
	MD5_Final(temp_key,&ctx);

	//some magic in between....yes, #4 is ignored...
	sum20 = temp_key[5]%4 + temp_key[3]%4 + temp_key[2]%4 + temp_key[1]%4 + temp_key[0]%4 +0x20; 


	strlenUN=strlen(username);
	strlenPW=strlen(password);
	memset(destArray,0,TEMP_ARRAY_SIZE);
#define DEFAULT_OFFSET 15
	I1=0;
	I2=0; 
	revI1=0;
	I3=0;
	
	//now: walld0rf-magic [tm], (c), <g>
	do {
		if (I1<strlenPW) { 			
			if ((temp_key[DEFAULT_OFFSET+revI1] % 2) != 0)
				destArray[I2++]=bcodeArr[BCODE_ARRAY_LENGTH+revI1-1];
			destArray[I2++]=pwConverted[I1++];
			revI1--;
		}
		if (I3<strlenUN) 
			destArray[I2++]=unConverted[I3++];

		I4=I2-I1-I3;
		I2++; 
		destArray[I2-1]=bcodeArr[I4];
		I2++; 
	} while (I2<sum20); 
	//end of walld0rf-magic [tm], (c), <g>

	MD5_Init(&ctx);
	MD5_Update(&ctx, destArray, sum20);
	MD5_Final(final_key, &ctx);

	for (i=0; i<8; i++)
		crypt_key[i]=final_key[i+8]^final_key[i];
}

static void * sapbcode_binary(char *ciphertext) 
{
	static char realcipher[BINARY_SIZE];
	int i;
	
	char* newCiphertextPointer=&ciphertext[SALT_SIZE+1];

	for(i=0;i<BINARY_SIZE;i++)
	{ 
		realcipher[i] = atoi16[ARCH_INDEX(newCiphertextPointer[i*2])]*16 + atoi16[ARCH_INDEX(newCiphertextPointer[i*2+1])];
	}
	return (void *)realcipher;
}

static void *sapbcode_get_salt(char *ciphertext)
{
	static unsigned char uglyStaticStackSalt[SALT_SIZE];
	memcpy(uglyStaticStackSalt, ciphertext, SALT_SIZE); //salt is in the beginning of the ciphertext
	return uglyStaticStackSalt;
}

char *sapbcode_split(char *ciphertext, int index)
{
	static char out[CIPHERTEXT_LENGTH + 1];
  	memset(out, 0, CIPHERTEXT_LENGTH + 1);
	memcpy(out, ciphertext, CIPHERTEXT_LENGTH); 
	strToUpper_B(out); //username (==salt) && resulting hash can be uppercase...
	return out;
}

struct fmt_main fmt_sapB = {
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
		sapbcode_tests
	}, {
		fmt_default_init,
		sapbcode_valid,
		sapbcode_split,
		sapbcode_binary,
		sapbcode_get_salt,
		{
			fmt_default_binary_hash,
			fmt_default_binary_hash,
			fmt_default_binary_hash,
			fmt_default_binary_hash,
			fmt_default_binary_hash
		},
		fmt_default_salt_hash,
		sapbcode_set_salt,
		sapbcode_set_key,
		sapbcode_get_key,
		fmt_default_clear_keys,
		sapbcode_crypt_all,
		{
			fmt_default_get_hash,
			fmt_default_get_hash,
			fmt_default_get_hash,
			fmt_default_get_hash,
			fmt_default_get_hash
		},
		sapbcode_cmp_all,
		sapbcode_cmp_one,
		sapbcode_cmp_exact
	}
};
