/* MSCASH patch for john (performance improvement)
 *
 * Written by Alain Espinosa <alainesp at gmail.com> in 2007
 * and placed in the public domain.
 */

#include <string.h>
#include "arch.h"
#include "misc.h"
#include "memory.h"
#include "common.h"
#include "formats.h"

#define FORMAT_LABEL			"mscash"
#define FORMAT_NAME			"M$ Cache Hash"

#define BENCHMARK_COMMENT		""
#define BENCHMARK_LENGTH		0

#define PLAINTEXT_LENGTH		27
#define MAX_CIPHERTEXT_LENGTH		(2 + 32 + 1 + 32)


static struct fmt_tests tests[] = {
	{"M$test1#64cd29e36a8431a2b111378564a10631", "test1" },
	{"M$test2#ab60bdb4493822b175486810ac2abe63", "test2" },
	{"M$test3#14dd041848e12fc48c0aa7a416a4a00c", "test3" },
	{"M$test4#b945d24866af4b01a6d89b9d932a153c", "test4" },
	{NULL}
};

#define ALGORITHM_NAME			"Generic 1x"

#define BINARY_SIZE			16
#define SALT_SIZE			(11*4)

#define MS_NUM_KEYS			64
#define MIN_KEYS_PER_CRYPT		MS_NUM_KEYS
#define MAX_KEYS_PER_CRYPT		MS_NUM_KEYS


static unsigned int ms_buffer1x[16*MS_NUM_KEYS];
static unsigned int output1x[4*MS_NUM_KEYS];

static unsigned int crypt[4*MS_NUM_KEYS];
static unsigned int last[4*MS_NUM_KEYS];

static unsigned int last_i[MS_NUM_KEYS];
static char saved_plain[32*MS_NUM_KEYS];

static unsigned int *salt_buffer;
static unsigned int new_key;

//Init values
#define INIT_A 0x67452301
#define INIT_B 0xefcdab89
#define INIT_C 0x98badcfe
#define INIT_D 0x10325476

#define SQRT_2 0x5a827999
#define SQRT_3 0x6ed9eba1

static void init(void)
{
	memset(ms_buffer1x,0,64*MS_NUM_KEYS);
	memset(last_i,0,4*MS_NUM_KEYS);
	new_key=1;
}

static char * ms_split(char *ciphertext, int index)
{
	static char out[MAX_CIPHERTEXT_LENGTH + 1];
	int i=0;

	for(; ciphertext[i] && i < MAX_CIPHERTEXT_LENGTH; i++)
		out[i]=ciphertext[i];
	
	out[i]=0;
	
	if (i >= 32)
		strlwr(&out[i-32]);

	return out;
}

static int valid(char *ciphertext)
{
	unsigned int i;
	unsigned int l;

	/*
	* 2 cases
	* 1 - it comes from the disk, and does not have M$ + salt
	* 2 - it comes from memory, and has got M$ + salt + # + blah
	*/

	if (!strncmp(ciphertext, "M$", 2))
	{
		l = strlen(ciphertext);
		if (l <= 32 || l > MAX_CIPHERTEXT_LENGTH)
			return 0;
		l -= 32;
		if(ciphertext[l-1]!='#')
			return 0;
	}
	else
	{
		if(strlen(ciphertext)!=32)
			return 0;
		l = 0;
	}
	for (i = l; i < l + 32; i++)
		if (atoi16[ARCH_INDEX(ciphertext[i])] == 0x7F)
			return 0;
	
	return 1;
}

static void set_salt(void *salt) {
	salt_buffer=salt;
}

static void * get_salt(char * ciphertext)
{
	//lenght=11 for save memory
	//last position = 0
	//4 first position are crypt[?]
	static unsigned int out[11];
	unsigned int md4_size=0;
	
	memset(out,0,44);
	
	ciphertext+=2;
	
	for(;;md4_size++)
		if(ciphertext[md4_size]!='#' && md4_size < 19)
		{
			md4_size++;
			
			out[md4_size>>1] = ciphertext[md4_size-1] | ((ciphertext[md4_size]!='#') ? (ciphertext[md4_size]<<16) : 0x800000);
			
			if(ciphertext[md4_size]=='#')
				break;
		}
		else
		{
			out[md4_size>>1] = 0x80;
			break;
		}

	out[10] = (8 + md4_size) << 4;

	return out;
}

static void *get_binary(char *ciphertext)
{
	static unsigned int out[4];
	unsigned int i=0;
	unsigned int temp;
	unsigned int * salt=get_salt(ciphertext);
	
	for(;ciphertext[0]!='#';ciphertext++);
	
	ciphertext++;
	
	for(; i<4 ;i++)
	{
		temp  = (atoi16[ARCH_INDEX(ciphertext[i*8+0])])<<4;
		temp |= (atoi16[ARCH_INDEX(ciphertext[i*8+1])]);
		
		temp |= (atoi16[ARCH_INDEX(ciphertext[i*8+2])])<<12;
		temp |= (atoi16[ARCH_INDEX(ciphertext[i*8+3])])<<8;
		
		temp |= (atoi16[ARCH_INDEX(ciphertext[i*8+4])])<<20;
		temp |= (atoi16[ARCH_INDEX(ciphertext[i*8+5])])<<16;
		
		temp |= (atoi16[ARCH_INDEX(ciphertext[i*8+6])])<<28;
		temp |= (atoi16[ARCH_INDEX(ciphertext[i*8+7])])<<24;
		
		out[i]=temp;
	}
	
	out[0] -= INIT_A;
	out[1] -= INIT_B;
	out[2] -= INIT_C;
	out[3] -= INIT_D;
	
	// Reversed	b += (c ^ d ^ a) + salt_buffer[11] +  SQRT_3; b = (b << 15) | (b >> 17);
	out[1]  = (out[1] >> 15) | (out[1] << 17);
	out[1] -= SQRT_3 + (out[2] ^ out[3] ^ out[0]);
	// Reversed	c += (d ^ a ^ b) + salt_buffer[3]  +  SQRT_3; c = (c << 11) | (c >> 21);
	out[2] = (out[2] << 21) | (out[2] >> 11);
	out[2]-= SQRT_3 + (out[3] ^ out[0] ^ out[1]) + salt[3];
	// Reversed	d += (a ^ b ^ c) + salt_buffer[7]  +  SQRT_3; d = (d << 9 ) | (d >> 23);
	out[3]  = (out[3] << 23) | (out[3] >> 9);
	out[3] -= SQRT_3 + (out[0] ^ out[1] ^ out[2]) + salt[7];
	//+ SQRT_3; d = (d << 9 ) | (d >> 23);
	out[3]=(out[3] << 23 ) | (out[3] >> 9);
	out[3]-=SQRT_3;

	return out;
}

static int binary_hash_0(void *binary)
{
	return ((unsigned int*)binary)[3] & 0x0F;
}

static int binary_hash_1(void *binary)
{
	return ((unsigned int*)binary)[3] & 0xFF;
}

static int binary_hash_2(void *binary)
{
	return ((unsigned int*)binary)[3] & 0x0FFF;
}

static int get_hash_0(int index)
{
	return output1x[4*index+3] & 0x0F;
}

static int get_hash_1(int index)
{
	return output1x[4*index+3] & 0xFF;
}

static int get_hash_2(int index)
{
	return output1x[4*index+3] & 0x0FFF;
}

void nt_hash(void)
{
	unsigned int a;
	unsigned int b;
	unsigned int c;
	unsigned int d;
	unsigned int i=0;
	
	for(;i<MS_NUM_KEYS;i++)
	{
		/* Round 1 */
		a = 		0xFFFFFFFF 		  + ms_buffer1x[16*i+0];a = (a << 3 ) | (a >> 29);
		d = INIT_D + (INIT_C ^ (a & 0x77777777))  + ms_buffer1x[16*i+1];d = (d << 7 ) | (d >> 25);
		c = INIT_C + (INIT_B ^ (d & (a ^ INIT_B)))+ ms_buffer1x[16*i+2];c = (c << 11) | (c >> 21);
		b =    INIT_B + (a ^ (c & (d ^ a))) 	  + ms_buffer1x[16*i+3];b = (b << 19) | (b >> 13);
		
		a += (d ^ (b & (c ^ d))) + ms_buffer1x[16*i+4]  ;a = (a << 3 ) | (a >> 29);
		d += (c ^ (a & (b ^ c))) + ms_buffer1x[16*i+5]  ;d = (d << 7 ) | (d >> 25);
		c += (b ^ (d & (a ^ b))) + ms_buffer1x[16*i+6]  ;c = (c << 11) | (c >> 21);
		b += (a ^ (c & (d ^ a))) + ms_buffer1x[16*i+7]  ;b = (b << 19) | (b >> 13);
		
		a += (d ^ (b & (c ^ d))) + ms_buffer1x[16*i+8]  ;a = (a << 3 ) | (a >> 29);
		d += (c ^ (a & (b ^ c))) + ms_buffer1x[16*i+9]  ;d = (d << 7 ) | (d >> 25);
		c += (b ^ (d & (a ^ b))) + ms_buffer1x[16*i+10] ;c = (c << 11) | (c >> 21);
		b += (a ^ (c & (d ^ a))) + ms_buffer1x[16*i+11] ;b = (b << 19) | (b >> 13);
		
		a += (d ^ (b & (c ^ d))) + ms_buffer1x[16*i+12] ;a = (a << 3 ) | (a >> 29);
		d += (c ^ (a & (b ^ c))) + ms_buffer1x[16*i+13] ;d = (d << 7 ) | (d >> 25);
		c += (b ^ (d & (a ^ b))) + ms_buffer1x[16*i+14] ;c = (c << 11) | (c >> 21);
		b += (a ^ (c & (d ^ a)))/*+ms_buffer1x[16*i+15]*/;b = (b << 19) | (b >> 13);
		
		/* Round 2 */
		a += ((b & (c | d)) | (c & d)) + ms_buffer1x[16*i+0]  + SQRT_2; a = (a << 3 ) | (a >> 29);
		d += ((a & (b | c)) | (b & c)) + ms_buffer1x[16*i+4]  + SQRT_2; d = (d << 5 ) | (d >> 27);
		c += ((d & (a | b)) | (a & b)) + ms_buffer1x[16*i+8]  + SQRT_2; c = (c << 9 ) | (c >> 23);
		b += ((c & (d | a)) | (d & a)) + ms_buffer1x[16*i+12] + SQRT_2; b = (b << 13) | (b >> 19);
		
		a += ((b & (c | d)) | (c & d)) + ms_buffer1x[16*i+1]  + SQRT_2; a = (a << 3 ) | (a >> 29);
		d += ((a & (b | c)) | (b & c)) + ms_buffer1x[16*i+5]  + SQRT_2; d = (d << 5 ) | (d >> 27);
		c += ((d & (a | b)) | (a & b)) + ms_buffer1x[16*i+9]  + SQRT_2; c = (c << 9 ) | (c >> 23);
		b += ((c & (d | a)) | (d & a)) + ms_buffer1x[16*i+13] + SQRT_2; b = (b << 13) | (b >> 19);
		
		a += ((b & (c | d)) | (c & d)) + ms_buffer1x[16*i+2]  + SQRT_2; a = (a << 3 ) | (a >> 29);
		d += ((a & (b | c)) | (b & c)) + ms_buffer1x[16*i+6]  + SQRT_2; d = (d << 5 ) | (d >> 27);
		c += ((d & (a | b)) | (a & b)) + ms_buffer1x[16*i+10] + SQRT_2; c = (c << 9 ) | (c >> 23);
		b += ((c & (d | a)) | (d & a)) + ms_buffer1x[16*i+14] + SQRT_2; b = (b << 13) | (b >> 19);
		
		a += ((b & (c | d)) | (c & d)) + ms_buffer1x[16*i+3]  + SQRT_2; a = (a << 3 ) | (a >> 29);
		d += ((a & (b | c)) | (b & c)) + ms_buffer1x[16*i+7]  + SQRT_2; d = (d << 5 ) | (d >> 27);
		c += ((d & (a | b)) | (a & b)) + ms_buffer1x[16*i+11] + SQRT_2; c = (c << 9 ) | (c >> 23);
		b += ((c & (d | a)) | (d & a))/*+ms_buffer1x[16*i+15]*/+SQRT_2; b = (b << 13) | (b >> 19);
		
		/* Round 3 */
		a += (b ^ c ^ d) + ms_buffer1x[16*i+0]  + SQRT_3; a = (a << 3 ) | (a >> 29);
		d += (a ^ b ^ c) + ms_buffer1x[16*i+8]  + SQRT_3; d = (d << 9 ) | (d >> 23);
		c += (d ^ a ^ b) + ms_buffer1x[16*i+4]  + SQRT_3; c = (c << 11) | (c >> 21);
		b += (c ^ d ^ a) + ms_buffer1x[16*i+12] + SQRT_3; b = (b << 15) | (b >> 17);
	
		a += (b ^ c ^ d) + ms_buffer1x[16*i+2]  + SQRT_3; a = (a << 3 ) | (a >> 29);
		d += (a ^ b ^ c) + ms_buffer1x[16*i+10] + SQRT_3; d = (d << 9 ) | (d >> 23);
		c += (d ^ a ^ b) + ms_buffer1x[16*i+6]  + SQRT_3; c = (c << 11) | (c >> 21);
		b += (c ^ d ^ a) + ms_buffer1x[16*i+14] + SQRT_3; b = (b << 15) | (b >> 17);
	
		a += (b ^ c ^ d) + ms_buffer1x[16*i+1]  + SQRT_3; a = (a << 3 ) | (a >> 29);
		d += (a ^ b ^ c) + ms_buffer1x[16*i+9]  + SQRT_3; d = (d << 9 ) | (d >> 23);
		c += (d ^ a ^ b) + ms_buffer1x[16*i+5]  + SQRT_3; c = (c << 11) | (c >> 21);
		b += (c ^ d ^ a) + ms_buffer1x[16*i+13] + SQRT_3; b = (b << 15) | (b >> 17);
		
		a += (b ^ c ^ d) + ms_buffer1x[16*i+3]  + SQRT_3; a = (a << 3 ) | (a >> 29);
		d += (a ^ b ^ c) + ms_buffer1x[16*i+11] + SQRT_3; d = (d << 9 ) | (d >> 23);
		c += (d ^ a ^ b) + ms_buffer1x[16*i+7]  + SQRT_3; c = (c << 11) | (c >> 21);
		b += (c ^ d ^ a) /*+ ms_buffer1x[16*i+15] */+ SQRT_3; b = (b << 15) | (b >> 17);
	
		crypt[4*i+0] = a + INIT_A;
		crypt[4*i+1] = b + INIT_B;
		crypt[4*i+2] = c + INIT_C;
		crypt[4*i+3] = d + INIT_D;
		
		//Another MD4_crypt for the salt
		/* Round 1 */
		a= 	        0xFFFFFFFF 	            +crypt[4*i+0]; a=(a<<3 )|(a>>29);
		d=INIT_D + ( INIT_C ^ ( a & 0x77777777))    +crypt[4*i+1]; d=(d<<7 )|(d>>25);
		c=INIT_C + ( INIT_B ^ ( d & ( a ^ INIT_B))) +crypt[4*i+2]; c=(c<<11)|(c>>21);
		b=INIT_B + (    a   ^ ( c & ( d ^    a  ))) +crypt[4*i+3]; b=(b<<19)|(b>>13);
		
		last[4*i+0]=a;
		last[4*i+1]=b;
		last[4*i+2]=c;
		last[4*i+3]=d;
	}
}

static void crypt_all(int count)
{
	unsigned int a;
	unsigned int b;
	unsigned int c;
	unsigned int d;
	unsigned int i=0;
	
	if(new_key)
	{
		new_key=0;
		nt_hash();
	}
	
	for(;i<MS_NUM_KEYS;i++)
	{
		a = last[4*i+0];
		b = last[4*i+1];
		c = last[4*i+2];
		d = last[4*i+3];
		
		a += (d ^ (b & (c ^ d)))  + salt_buffer[0]  ;a = (a << 3 ) | (a >> 29);
		d += (c ^ (a & (b ^ c)))  + salt_buffer[1]  ;d = (d << 7 ) | (d >> 25);
		c += (b ^ (d & (a ^ b)))  + salt_buffer[2]  ;c = (c << 11) | (c >> 21);
		b += (a ^ (c & (d ^ a)))  + salt_buffer[3]  ;b = (b << 19) | (b >> 13);
		
		a += (d ^ (b & (c ^ d)))  + salt_buffer[4]  ;a = (a << 3 ) | (a >> 29);
		d += (c ^ (a & (b ^ c)))  + salt_buffer[5]  ;d = (d << 7 ) | (d >> 25);
		c += (b ^ (d & (a ^ b)))  + salt_buffer[6]  ;c = (c << 11) | (c >> 21);
		b += (a ^ (c & (d ^ a)))  + salt_buffer[7]  ;b = (b << 19) | (b >> 13);
		
		a += (d ^ (b & (c ^ d)))  + salt_buffer[8]  ;a = (a << 3 ) | (a >> 29);
		d += (c ^ (a & (b ^ c)))  + salt_buffer[9]  ;d = (d << 7 ) | (d >> 25);
		c += (b ^ (d & (a ^ b)))  + salt_buffer[10] ;c = (c << 11) | (c >> 21);
		b += (a ^ (c & (d ^ a)))/*+salt_buffer[11]*/;b = (b << 19) | (b >> 13);
		
		/* Round 2 */
		a += ((b & (c | d)) | (c & d))  +  crypt[4*i+0]    + SQRT_2; a = (a << 3 ) | (a >> 29);
		d += ((a & (b | c)) | (b & c))  +  salt_buffer[0]  + SQRT_2; d = (d << 5 ) | (d >> 27);
		c += ((d & (a | b)) | (a & b))  +  salt_buffer[4]  + SQRT_2; c = (c << 9 ) | (c >> 23);
		b += ((c & (d | a)) | (d & a))  +  salt_buffer[8]  + SQRT_2; b = (b << 13) | (b >> 19);
		
		a += ((b & (c | d)) | (c & d))  +  crypt[4*i+1]    + SQRT_2; a = (a << 3 ) | (a >> 29);
		d += ((a & (b | c)) | (b & c))  +  salt_buffer[1]  + SQRT_2; d = (d << 5 ) | (d >> 27);
		c += ((d & (a | b)) | (a & b))  +  salt_buffer[5]  + SQRT_2; c = (c << 9 ) | (c >> 23);
		b += ((c & (d | a)) | (d & a))  +  salt_buffer[9]  + SQRT_2; b = (b << 13) | (b >> 19);
		
		a += ((b & (c | d)) | (c & d))  +  crypt[4*i+2]    + SQRT_2; a = (a << 3 ) | (a >> 29);
		d += ((a & (b | c)) | (b & c))  +  salt_buffer[2]  + SQRT_2; d = (d << 5 ) | (d >> 27);
		c += ((d & (a | b)) | (a & b))  +  salt_buffer[6]  + SQRT_2; c = (c << 9 ) | (c >> 23);
		b += ((c & (d | a)) | (d & a))  +  salt_buffer[10] + SQRT_2; b = (b << 13) | (b >> 19);
		
		a += ((b & (c | d)) | (c & d))  +  crypt[4*i+3]    + SQRT_2; a = (a << 3 ) | (a >> 29);
		d += ((a & (b | c)) | (b & c))  +  salt_buffer[3]  + SQRT_2; d = (d << 5 ) | (d >> 27);
		c += ((d & (a | b)) | (a & b))  +  salt_buffer[7]  + SQRT_2; c = (c << 9 ) | (c >> 23);
		b += ((c & (d | a)) | (d & a))/*+ salt_buffer[11]*/+ SQRT_2; b = (b << 13) | (b >> 19);
		
		/* Round 3 */
		a += (b ^ c ^ d) + crypt[4*i+0]    +  SQRT_3; a = (a << 3 ) | (a >> 29);
		d += (a ^ b ^ c) + salt_buffer[4]  +  SQRT_3; d = (d << 9 ) | (d >> 23);
		c += (d ^ a ^ b) + salt_buffer[0]  +  SQRT_3; c = (c << 11) | (c >> 21);
		b += (c ^ d ^ a) + salt_buffer[8]  +  SQRT_3; b = (b << 15) | (b >> 17);
	
		a += (b ^ c ^ d) + crypt[4*i+2]    +  SQRT_3; a = (a << 3 ) | (a >> 29);
		d += (a ^ b ^ c) + salt_buffer[6]  +  SQRT_3; d = (d << 9 ) | (d >> 23);
		c += (d ^ a ^ b) + salt_buffer[2]  +  SQRT_3; c = (c << 11) | (c >> 21);
		b += (c ^ d ^ a) + salt_buffer[10] +  SQRT_3; b = (b << 15) | (b >> 17);
	
		a += (b ^ c ^ d) + crypt[4*i+1]    +  SQRT_3; a = (a << 3 ) | (a >> 29);
		d += (a ^ b ^ c) + salt_buffer[5];
		
		output1x[4*i+0]=a;
		output1x[4*i+1]=b;
		output1x[4*i+2]=c;
		output1x[4*i+3]=d;
	}
}

static int cmp_all(void *binary, int count)
{
	unsigned int i=0;
	unsigned int d=((unsigned int *)binary)[3];
	
	for(;i<MS_NUM_KEYS;i++)
		if(d==output1x[i*4+3])
			return 1;
	
	return 0;
}

static int cmp_one(void * binary, int index)
{
	unsigned int *t=(unsigned int *)binary;
	unsigned int a=output1x[4*index+0];
	unsigned int b=output1x[4*index+1];
	unsigned int c=output1x[4*index+2];
	unsigned int d=output1x[4*index+3];
	
	if(d!=t[3])
		return 0;
	d+=SQRT_3;d = (d << 9 ) | (d >> 23);
	
	c += (d ^ a ^ b) + salt_buffer[1]  +  SQRT_3; c = (c << 11) | (c >> 21);
	if(c!=t[2])
		return 0;
	
	b += (c ^ d ^ a) + salt_buffer[9]  +  SQRT_3; b = (b << 15) | (b >> 17);
	if(b!=t[1])
		return 0;
	
	a += (b ^ c ^ d) + crypt[4*index+3]+  SQRT_3; a = (a << 3 ) | (a >> 29);
	return (a==t[0]);
}

static int cmp_exact(char *source, int index)
{
	// This check its for the unreal case of collisions.
	// It verify that the salts its the same.
	unsigned int *salt=get_salt(source);
	unsigned int i=0;
	for(;i<11;i++)
		if(salt[i]!=salt_buffer[i])
			return 0;
	return 1;
}

static void set_key(char *key, int index)
{
	unsigned int md4_size=0;
	unsigned int i=0;
	unsigned int temp;
	unsigned int saved_base=index<<5;
	unsigned int buff_base=index<<4;
	
	for(;key[md4_size] && md4_size<PLAINTEXT_LENGTH;i++,md4_size++)
	{
		saved_plain[saved_base+md4_size]=key[md4_size];
		temp=key[++md4_size];
		saved_plain[saved_base+md4_size]=temp;
		
		if(temp)
		{
			ms_buffer1x[buff_base+i] = key[md4_size-1] | (temp<<16);
		}
		else
		{
			ms_buffer1x[buff_base+i] = key[md4_size-1] | 0x800000;
			goto key_cleaning;
		}
	}
	
	ms_buffer1x[buff_base+i]=0x80;
	saved_plain[saved_base+md4_size]=0;
	
key_cleaning:
	i++;
	for(;i<=last_i[index];i++)
		ms_buffer1x[buff_base+i]=0;
	
	last_i[index]=md4_size>>1;
	
	ms_buffer1x[buff_base+14] = md4_size << 4;
	
	//new password_candidate
	new_key=1;
}

static char *get_key(int index)
{
	return saved_plain+(index<<5);
}

int salt_hash(void *salt)
{
	return ((unsigned char*)salt)[0];
}

struct fmt_main fmt_mscash = {
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
		init,
		valid,
		ms_split,
		get_binary,
		get_salt,
		{
			binary_hash_0,
			binary_hash_1,
			binary_hash_2,
			NULL,
			NULL
		},
		salt_hash,
		set_salt,
		set_key,
		get_key,
		fmt_default_clear_keys,
		crypt_all,
		{
			get_hash_0,
			get_hash_1,
			get_hash_2,
			NULL,
			NULL
		},
		cmp_all,
		cmp_one,
		cmp_exact
	}
};
