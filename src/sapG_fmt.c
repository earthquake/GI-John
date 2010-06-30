/*
 * this is a SAP PASSCODE (CODEVN G) plugin for john the ripper. 
 * tested on linux/x86 only, rest is up to you.. at least, someone did the reversing :-)
 *
 * please note: this code is in a "works for me"-state, feel free to modify/speed up/clean/whatever it...
 *
 * (c) x7d8 sap loverz, public domain, btw
 * cheers: see test-cases.
 */

//this array is from disp+work (sap's worker process)
#define MAGIC_ARRAY_SIZE 160
unsigned char theMagicArray[MAGIC_ARRAY_SIZE]=
{0x91, 0xAC, 0x51, 0x14, 0x9F, 0x67, 0x54, 0x43, 0x24, 0xE7, 0x3B, 0xE0, 0x28, 0x74, 0x7B, 0xC2,
 0x86, 0x33, 0x13, 0xEB, 0x5A, 0x4F, 0xCB, 0x5C, 0x08, 0x0A, 0x73, 0x37, 0x0E, 0x5D, 0x1C, 0x2F,
 0x33, 0x8F, 0xE6, 0xE5, 0xF8, 0x9B, 0xAE, 0xDD, 0x16, 0xF2, 0x4B, 0x8D, 0x2C, 0xE1, 0xD4, 0xDC,
 0xB0, 0xCB, 0xDF, 0x9D, 0xD4, 0x70, 0x6D, 0x17, 0xF9, 0x4D, 0x42, 0x3F, 0x9B, 0x1B, 0x11, 0x94,
 0x9F, 0x5B, 0xC1, 0x9B, 0x06, 0x05, 0x9D, 0x03, 0x9D, 0x5E, 0x13, 0x8A, 0x1E, 0x9A, 0x6A, 0xE8,
 0xD9, 0x7C, 0x14, 0x17, 0x58, 0xC7, 0x2A, 0xF6, 0xA1, 0x99, 0x63, 0x0A, 0xD7, 0xFD, 0x70, 0xC3,
 0xF6, 0x5E, 0x74, 0x13, 0x03, 0xC9, 0x0B, 0x04, 0x26, 0x98, 0xF7, 0x26, 0x8A, 0x92, 0x93, 0x25,
 0xB0, 0xA2, 0x0D, 0x23, 0xED, 0x63, 0x79, 0x6D, 0x13, 0x32, 0xFA, 0x3C, 0x35, 0x02, 0x9A, 0xA3,
 0xB3, 0xDD, 0x8E, 0x0A, 0x24, 0xBF, 0x51, 0xC3, 0x7C, 0xCD, 0x55, 0x9F, 0x37, 0xAF, 0x94, 0x4C,
 0x29, 0x08, 0x52, 0x82, 0xB2, 0x3B, 0x4E, 0x37, 0x9F, 0x17, 0x07, 0x91, 0x11, 0x3B, 0xFD, 0xCD };


#include <string.h>
#include <ctype.h>

#include "arch.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "sha.h"

#define FORMAT_LABEL			"sapg" 
#define FORMAT_NAME			"SAP CODVN G (PASSCODE)"
#define ALGORITHM_NAME			"sapg"

#define BENCHMARK_COMMENT		""
#define BENCHMARK_LENGTH		0

#define PLAINTEXT_LENGTH		48	/* netweaver 2004s limit */

#define BINARY_SIZE			20	
#define SALT_SIZE			40	/* the max username length */
#define CIPHERTEXT_LENGTH		SALT_SIZE + 1 + 40	/* SALT + $ + 2x20 bytes for SHA1-representation */

#define MIN_KEYS_PER_CRYPT		1
#define MAX_KEYS_PER_CRYPT		1


static struct fmt_tests sapcodvng_tests[] = {
	{"F                                       $646A0AD270DF651065669A45D171EDD62DFE39A1", "X"},
	{"JOHNNY                                  $7D79B478E70CAAE63C41E0824EAB644B9070D10A", "CYBERPUNK"},
	{"VAN                                     $D15597367F24090F0A501962788E9F19B3604E73", "hauser"},
	{"ROOT                                    $1194E38F14B9F3F8DA1B181F14DEB70E7BDCC239", "KID"},
	{"MAN                                     $22886450D0AB90FDA7F91C4F3DD5619175B372EA", "u"},
	{"----------------------------------------$D594002761406B589A75CE86042A8B4A922AA74F", "-------"},
	{"SAP*                                    $60A0F7E06D95BC9FB45F605BDF1F7B660E5D5D4E", "MaStEr"},
	{"DDIC                                    $6066CD3147915331EC4C602847D27A75EB3E8F0A", "DDIC"},
	{"DoLlAR$$$---                            $E0180FD4542D8B6715E7D0D9EDE7E2D2E40C3D4D", "Dollar$$$---"},
	{NULL}
};

static char saved_key[PLAINTEXT_LENGTH + 1];
static ARCH_WORD_32 crypt_key[BINARY_SIZE / 4];
static SHA_CTX ctx;

static char theSalt[SALT_SIZE];

static int sapcodvng_valid(char *ciphertext)
{
	int i;
	if (NULL==ciphertext)
		return 0;

	if (ciphertext[SALT_SIZE]!='$') 
		return 0;

	if (strlen(ciphertext) != CIPHERTEXT_LENGTH)  	
		return 0; 

	for (i = SALT_SIZE+1; i < CIPHERTEXT_LENGTH; i++){
		if (!(  
			(('0' <= ciphertext[i])&&(ciphertext[i] <= '9')) 
				|| (('a' <= ciphertext[i])&&(ciphertext[i] <= 'f'))  
				|| (('A' <= ciphertext[i])&&(ciphertext[i] <= 'F'))
			))
			return 0; 
	}
	
	return 1;
}

static void sapcodvng_set_salt(void *salt) 
{
	memcpy(theSalt, salt, SALT_SIZE);
}

static void *sapcodvng_get_salt(char *ciphertext)
{
	static unsigned char sssalt[SALT_SIZE];
	memcpy(sssalt, ciphertext, SALT_SIZE); 
	return sssalt;
}

static void sapcodvng_init(void)
{ }

static void sapcodvng_set_key(char *key, int index)
{
	strnzcpy(saved_key, key, PLAINTEXT_LENGTH+1);
}

static char *sapcodvng_get_key(int index) {
	return saved_key;
}

static int sapcodvng_cmp_all(void *binary, int index) { 
	return !memcmp(binary, crypt_key, BINARY_SIZE);
}

static int sapcodvng_cmp_exact(char *source, int count){
  return (1);
}

static int sapcodvng_cmp_one(void * binary, int index)
{
	return sapcodvng_cmp_all(binary, index);
}


/*
 * this function is needed to determine the actual size of the salt (==username)
 * theSalt has to point at the beginning of the actual salt. no more checks are done; relies on valid() 
 * this is needed because, afaik, john only supports salts w/ fixed length. sap uses the username, so we have to 
 * "strip" the padding (blanks at the end) for the calculation.... 
 * usernames w/ spaces at the end are not supported (SAP does not support them either)
 */
int calcActualSaltSize_G(char* theSalt)
{ 
    int i;
	if (NULL==theSalt)
		return 0;
	i=SALT_SIZE-1;
	while (theSalt[i--]==0x20);
	return SALT_SIZE-(SALT_SIZE-i)+2;
}

/*
 * calculate the length of data that has to be hashed from the magic array. pass the first hash result in here.
 * this is part of the walld0rf-magic
 */
unsigned int extractLengthOfMagicArray(unsigned char *pbHashArray) 
{
	unsigned int modSum=0, i;

	for (i=0; i<=9; i++) 
		modSum+=pbHashArray[i]%6;

	return modSum+0x20; //0x20 is hardcoded...
}

/*
 * Calculate the offset into the magic array. pass the first hash result in here
 * part of the walld0rf-magic 
 */
unsigned int extractOffsetToMagicArray(unsigned char *pbHashArray)  
{
	unsigned int modSum=0, i;
	
	for (i=19; i>=10; i--) 
		modSum+=pbHashArray[i]%8;
	
	return modSum;
}

/*
 * used to alter the username which is always(!) uppercase...
 */
void strToUpper_G(char* str)
{
	int i=0;
	if (NULL==str) 
		return;
	for (i=0; i<strlen(str);i++)
		if ((str[i] >= 'a') && (str[i] <= 'z')) str[i] ^= 0x20;
}

/*
 * translation for passwords (chars >7bit ascii).
 * translates just some >7bit chars to some weird magic bytes (not unicode?!)
 * works for most west-european (e.g. french) passwords...
 */
static char* translatePassword(char* origPassword)
{
	static char password[PLAINTEXT_LENGTH*2];
	unsigned int j=0, i;

	for (i=0; i<strlen(origPassword); i++) {
		if (origPassword[i] & 0x80) {
			switch ((unsigned char)origPassword[i]) {
				case 0xFC:
					password[j]=0xC3; password[j+1]=0xBC; j+=2; break;
				case 0xF6:
					password[j]=0xC3; password[j+1]=0xB6; j+=2; break;
				case 0xE4:
					password[j]=0xC3; password[j+1]=0xA4; j+=2; break;
				case 0xDC:
					password[j]=0xC3; password[j+1]=0x9C; j+=2; break;
				case 0xD6:
					password[j]=0xC3; password[j+1]=0x96; j+=2; break;
				case 0xC4:
					password[j]=0xC3; password[j+1]=0x84; j+=2; break;
				case 0xDF:
					password[j]=0xC3; password[j+1]=0x9F; j+=2; break;
				case 0xBA:
					password[j]=0xC2; password[j+1]=0xB0; j+=2; break;
				case 0xB4:
					password[j]=0xC2; password[j+1]=0xB4; j+=2; break;
				case 0xE9:
					password[j]=0xC3; password[j+1]=0xA9; j+=2; break;
				case 0xEA:
					password[j]=0xC3; password[j+1]=0xAA; j+=2; break;
				case 0xE8:
					password[j]=0xC3; password[j+1]=0xA8; j+=2; break;
				case 0xC9:
					password[j]=0xC3; password[j+1]=0x89; j+=2; break;
				case 0xCA:
					password[j]=0xC3; password[j+1]=0x8A; j+=2; break;
				case 0xC8:
					password[j]=0xC3; password[j+1]=0x88; j+=2; break;
				case 0xA7:
					password[j]=0xC2; password[j+1]=0xA7; j+=2; break;
				default:
					password[j]=origPassword[i]; j++;
					break;
				} //switch 
			} else 
				password[j++]=origPassword[i];
	}
	password[j]='\0';
	return password;
}

static void sapcodvng_crypt_all(int count) {  
	static char temp_key[BINARY_SIZE+1];
	unsigned int offsetMagicArray;
	unsigned int lengthIntoMagicArray;
	unsigned char secondHashData[PLAINTEXT_LENGTH*2+MAGIC_ARRAY_SIZE]; //max size... 
	size_t secondHashDataLen;
	size_t pwLen, unLen;
	char tempVar[PLAINTEXT_LENGTH*2]; 	//PLAINTEXT_LENGTH is maxlen of password AND maxlen of username
	
	//0.	translate special characters in the password
	char* trPassword=translatePassword(saved_key);
	pwLen=strlen(trPassword);

	unLen=calcActualSaltSize_G(theSalt);

	//1.	we need to SHA1 the password and username
	strnzcpy(tempVar, trPassword, PLAINTEXT_LENGTH);  //first: the password
	strnzcpy(tempVar+strlen(tempVar), theSalt, unLen+1); //second: the salt(username)
	
	
	SHA1_Init(&ctx);
	SHA1_Update(&ctx, (unsigned char*)tempVar, strlen(tempVar));
	SHA1_Final((unsigned char*)&temp_key, &ctx);

	lengthIntoMagicArray=extractLengthOfMagicArray((unsigned char*)temp_key);
	offsetMagicArray=extractOffsetToMagicArray((unsigned char*)temp_key);	

	//2.     now, hash again --> sha1($password+$partOfMagicArray+$username) --> this is CODVNG passcode...
	memcpy(secondHashData, trPassword, pwLen); 
	memcpy(secondHashData+pwLen, &theMagicArray[offsetMagicArray], lengthIntoMagicArray);
	memcpy(secondHashData+pwLen+lengthIntoMagicArray, theSalt, unLen+1);
	secondHashDataLen=pwLen+lengthIntoMagicArray+unLen;	

	SHA1_Init(&ctx);
	SHA1_Update(&ctx, secondHashData, secondHashDataLen);
	SHA1_Final((unsigned char*)crypt_key, &ctx);

}

static void * sapcodvng_binary(char *ciphertext) 
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


static int binary_hash_0(void *binary)
{
	return ((ARCH_WORD_32 *)binary)[0] & 0xF;
}

static int binary_hash_1(void *binary)
{
	return ((ARCH_WORD_32 *)binary)[0] & 0xFF;
}

static int binary_hash_2(void *binary)
{
	return ((ARCH_WORD_32 *)binary)[0] & 0xFFF;
}

static int get_hash_0(int index)
{
	return crypt_key[0] & 0xF;
}

static int get_hash_1(int index)
{
	return crypt_key[0] & 0xFF;
}

static int get_hash_2(int index)
{
	return crypt_key[0] & 0xFFF;
}


char *sapcodvng_split(char *ciphertext, int index)
{
	static char out[CIPHERTEXT_LENGTH + 1];
  	memset(out, 0, CIPHERTEXT_LENGTH + 1);
	memcpy(out, ciphertext, CIPHERTEXT_LENGTH); 
	strToUpper_G(out); //username (==salt) && resulting hash can be uppercase...
	return out;
}


struct fmt_main fmt_sapG = {
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
		sapcodvng_tests
	}, {
		sapcodvng_init,
		sapcodvng_valid,
		sapcodvng_split,
		sapcodvng_binary,
		sapcodvng_get_salt,
		{
			binary_hash_0,
			binary_hash_1,
			binary_hash_2,
			NULL,
			NULL
		},
		fmt_default_salt_hash,
		sapcodvng_set_salt,
		sapcodvng_set_key,
		sapcodvng_get_key,
		fmt_default_clear_keys,
		sapcodvng_crypt_all,
		{
			get_hash_0,
			get_hash_1,
			get_hash_2,
			NULL,
			NULL
		},
		sapcodvng_cmp_all,
		sapcodvng_cmp_one,
		sapcodvng_cmp_exact
	}
};
