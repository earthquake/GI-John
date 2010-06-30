/* NTLM patch for john (performance improvement)
 *
 * Written by Alain Espinosa <alainesp@gmail.com> in 2007
 * and placed in the public domain.
 */

#include <string.h>
#include "arch.h"
#include "misc.h"
#include "memory.h"
#include "common.h"
#include "formats.h"

//Init values
#define INIT_A 0x67452301
#define INIT_B 0xefcdab89
#define INIT_C 0x98badcfe
#define INIT_D 0x10325476

#define SQRT_2 0x5a827999
#define SQRT_3 0x6ed9eba1


#define FORMAT_LABEL			"nt"
#define FORMAT_NAME			"NT MD4"

#define BENCHMARK_COMMENT		""
#define BENCHMARK_LENGTH		-1

#define PLAINTEXT_LENGTH		27
#define CIPHERTEXT_LENGTH		36

static struct fmt_tests tests[] = {
	{"$NT$b7e4b9022cd45f275334bbdb83bb5be5", "John the Ripper"},
	{"$NT$8846f7eaee8fb117ad06bdd830b7586c", "password"},
	{"$NT$0cb6948805f797bf2a82807973b89537", "test"},
	{"$NT$31d6cfe0d16ae931b73c59d7e0c089c0", ""},
	{NULL}
};

#define BINARY_SIZE			16
#define SALT_SIZE			0

#if defined (NT_X86_64)
	#define NT_NUM_KEYS	32
	
	unsigned int nt_buffer8x[16*NT_NUM_KEYS] __attribute__ ((aligned(16)));
	unsigned int output8x[4*NT_NUM_KEYS] __attribute__ ((aligned(16)));
	
	#define ALGORITHM_NAME		"128/128 X2 SSE2-16"
	#define NT_CRYPT_FUN		nt_crypt_all_x86_64
	extern void nt_crypt_all_x86_64(int count);
#elif defined (NT_SSE2)
	#define NT_NUM_KEYS	40
	#define NT_NUM_KEYS1	8
	#define NT_NUM_KEYS4	32
	
	unsigned int nt_buffer4x[64*NT_NUM_KEYS1] __attribute__ ((aligned(16)));
	unsigned int output4x[16*NT_NUM_KEYS1] __attribute__ ((aligned(16)));

	unsigned int nt_buffer1x[16*NT_NUM_KEYS1];
	unsigned int output1x[4*NT_NUM_KEYS1];
	
	#define ALGORITHM_NAME		"128/128 SSE2 + 32/32"
	#define NT_CRYPT_FUN		nt_crypt_all_sse2
	extern void nt_crypt_all_sse2(int count);
#else
	#define NT_NUM_KEYS		64
	unsigned int nt_buffer1x[16*NT_NUM_KEYS];
	unsigned int output1x[4*NT_NUM_KEYS];
	
	#define ALGORITHM_NAME		"32/32"
	#define NT_CRYPT_FUN		nt_crypt_all_generic
	static void nt_crypt_all_generic(int count)
	{
		unsigned int a;
		unsigned int b;
		unsigned int c;
		unsigned int d;
		unsigned int i=0;
		
		for(;i<NT_NUM_KEYS;i++)
		{
			/* Round 1 */
			a = 		0xFFFFFFFF 		 +nt_buffer1x[i*16+0];a=(a<<3 )|(a>>29);
			d = INIT_D+(INIT_C ^ (a & 0x77777777))   +nt_buffer1x[i*16+1];d=(d<<7 )|(d>>25);
			c = INIT_C+(INIT_B ^ (d & (a ^ INIT_B))) +nt_buffer1x[i*16+2];c=(c<<11)|(c>>21);
			b = INIT_B + (a ^ (c & (d ^ a))) 	 +nt_buffer1x[i*16+3];b=(b<<19)|(b>>13);
			
			a += (d ^ (b & (c ^ d)))  +  nt_buffer1x[i*16+4]  ;a = (a << 3 ) | (a >> 29);
			d += (c ^ (a & (b ^ c)))  +  nt_buffer1x[i*16+5]  ;d = (d << 7 ) | (d >> 25);
			c += (b ^ (d & (a ^ b)))  +  nt_buffer1x[i*16+6]  ;c = (c << 11) | (c >> 21);
			b += (a ^ (c & (d ^ a)))  +  nt_buffer1x[i*16+7]  ;b = (b << 19) | (b >> 13);
			
			a += (d ^ (b & (c ^ d)))  +  nt_buffer1x[i*16+8]  ;a = (a << 3 ) | (a >> 29);
			d += (c ^ (a & (b ^ c)))  +  nt_buffer1x[i*16+9]  ;d = (d << 7 ) | (d >> 25);
			c += (b ^ (d & (a ^ b)))  +  nt_buffer1x[i*16+10] ;c = (c << 11) | (c >> 21);
			b += (a ^ (c & (d ^ a)))  +  nt_buffer1x[i*16+11] ;b = (b << 19) | (b >> 13);
			
			a += (d ^ (b & (c ^ d)))  +  nt_buffer1x[i*16+12] ;a = (a << 3 ) | (a >> 29);
			d += (c ^ (a & (b ^ c)))  +  nt_buffer1x[i*16+13] ;d = (d << 7 ) | (d >> 25);
			c += (b ^ (d & (a ^ b)))  +  nt_buffer1x[i*16+14] ;c = (c << 11) | (c >> 21);
			b += (a ^ (c & (d ^ a)));b = (b << 19) | (b >> 13);
			
			/* Round 2 */
			a += ((b & (c | d)) | (c & d))+nt_buffer1x[i*16+0] +SQRT_2;a = (a<<3 ) | (a>>29);
			d += ((a & (b | c)) | (b & c))+nt_buffer1x[i*16+4] +SQRT_2;d = (d<<5 ) | (d>>27);
			c += ((d & (a | b)) | (a & b))+nt_buffer1x[i*16+8] +SQRT_2;c = (c<<9 ) | (c>>23);
			b += ((c & (d | a)) | (d & a))+nt_buffer1x[i*16+12]+SQRT_2;b = (b<<13) | (b>>19);
			
			a += ((b & (c | d)) | (c & d))+nt_buffer1x[i*16+1] +SQRT_2;a = (a<<3 ) | (a>>29);
			d += ((a & (b | c)) | (b & c))+nt_buffer1x[i*16+5] +SQRT_2;d = (d<<5 ) | (d>>27);
			c += ((d & (a | b)) | (a & b))+nt_buffer1x[i*16+9] +SQRT_2;c = (c<<9 ) | (c>>23);
			b += ((c & (d | a)) | (d & a))+nt_buffer1x[i*16+13]+SQRT_2;b = (b<<13) | (b>>19);
			
			a += ((b & (c | d)) | (c & d))+nt_buffer1x[i*16+2] +SQRT_2;a = (a<<3 ) | (a>>29);
			d += ((a & (b | c)) | (b & c))+nt_buffer1x[i*16+6] +SQRT_2;d = (d<<5 ) | (d>>27);
			c += ((d & (a | b)) | (a & b))+nt_buffer1x[i*16+10]+SQRT_2;c = (c<<9 ) | (c>>23);
			b += ((c & (d | a)) | (d & a))+nt_buffer1x[i*16+14]+SQRT_2;b = (b<<13) | (b>>19);
			
			a += ((b & (c | d)) | (c & d))+nt_buffer1x[i*16+3] +SQRT_2;a = (a<<3 ) | (a>>29);
			d += ((a & (b | c)) | (b & c))+nt_buffer1x[i*16+7] +SQRT_2;d = (d<<5 ) | (d>>27);
			c += ((d & (a | b)) | (a & b))+nt_buffer1x[i*16+11]+SQRT_2;c = (c<<9 ) | (c>>23);
			b += ((c & (d | a)) | (d & a))			   +SQRT_2;b = (b<<13) | (b>>19);
			
			/* Round 3 */
			a += (d ^ c ^ b) + nt_buffer1x[i*16+0]  +  SQRT_3; a = (a << 3 ) | (a >> 29);
			d += (c ^ b ^ a) + nt_buffer1x[i*16+8]  +  SQRT_3; d = (d << 9 ) | (d >> 23);
			c += (b ^ a ^ d) + nt_buffer1x[i*16+4]  +  SQRT_3; c = (c << 11) | (c >> 21);
			b += (a ^ d ^ c) + nt_buffer1x[i*16+12] +  SQRT_3; b = (b << 15) | (b >> 17);
		
			a += (d ^ c ^ b) + nt_buffer1x[i*16+2]  +  SQRT_3; a = (a << 3 ) | (a >> 29);
			d += (c ^ b ^ a) + nt_buffer1x[i*16+10] +  SQRT_3; d = (d << 9 ) | (d >> 23);
			c += (b ^ a ^ d) + nt_buffer1x[i*16+6]  +  SQRT_3; c = (c << 11) | (c >> 21);
			b += (a ^ d ^ c) + nt_buffer1x[i*16+14] +  SQRT_3; b = (b << 15) | (b >> 17);
		
			a += (d ^ c ^ b) + nt_buffer1x[i*16+1]  +  SQRT_3; a = (a << 3 ) | (a >> 29);
			d += (c ^ b ^ a) + nt_buffer1x[i*16+9]  +  SQRT_3; d = (d << 9 ) | (d >> 23);
			c += (b ^ a ^ d) + nt_buffer1x[i*16+5]  +  SQRT_3; c = (c << 11) | (c >> 21);
			b += (a ^ d ^ c) + nt_buffer1x[i*16+13];
		
			output1x[4*i+0]=a;
			output1x[4*i+1]=b;
			output1x[4*i+2]=c;
			output1x[4*i+3]=d;	
		}
	}	
#endif

static unsigned int last_i[NT_NUM_KEYS];
static char saved_plain[32*NT_NUM_KEYS];

#define MIN_KEYS_PER_CRYPT		NT_NUM_KEYS
#define MAX_KEYS_PER_CRYPT		NT_NUM_KEYS

static void fmt_NT_init(void)
{
	memset(last_i,0,4*NT_NUM_KEYS);
#if defined(NT_X86_64)
	memset(nt_buffer8x,0,16*4*NT_NUM_KEYS);
#elif defined(NT_SSE2)
	memset(nt_buffer4x,0,64*4*NT_NUM_KEYS1);
	memset(nt_buffer1x,0,16*4*NT_NUM_KEYS1);
#else
	memset(nt_buffer1x,0,16*4*NT_NUM_KEYS);
#endif
}

static char * nt_split(char *ciphertext, int index)
{
	static char out[37];

	if (!strncmp(ciphertext, "$NT$", 4))
		ciphertext += 4;

	out[0] = '$';
	out[1] = 'N';
	out[2] = 'T';
	out[3] = '$';

	memcpy(&out[4], ciphertext, 32);
	out[36] = 0;

	strlwr(&out[4]);

	return out;
}

static int valid(char *ciphertext)
{
        char *pos;

	if (strncmp(ciphertext, "$NT$", 4)!=0) return 0;

        for (pos = &ciphertext[4]; atoi16[ARCH_INDEX(*pos)] != 0x7F; pos++);

        if (!*pos && pos - ciphertext == CIPHERTEXT_LENGTH)
		return 1;
        else
        	return 0;

}

static void *get_binary(char *ciphertext)
{
	static unsigned int out[4];
	unsigned int i=0;
	unsigned int temp;

	ciphertext+=4;
	for (; i<4; i++)
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
	
	out[1]  = (out[1] >> 15) | (out[1] << 17);
	out[1] -= SQRT_3 + (out[2] ^ out[3] ^ out[0]);
	out[1]  = (out[1] >> 15) | (out[1] << 17);
	out[1] -= SQRT_3;
	
	return out;
}

static int binary_hash_0(void *binary)
{
	return ((unsigned int *)binary)[1] & 0x0F;
}

static int binary_hash_1(void *binary)
{
	return ((unsigned int *)binary)[1] & 0xFF;
}

static int binary_hash_2(void *binary)
{
	return ((unsigned int *)binary)[1] & 0x0FFF;
}

static int get_hash_0(int index)
{
#if defined(NT_X86_64)
	return output8x[32*(index>>3)+8+index%8] & 0x0F;
#elif defined(NT_SSE2)
	if(index<NT_NUM_KEYS4)
		return output4x[16*(index>>2)+4+index%4] & 0x0F;
	else
		return output1x[(index-NT_NUM_KEYS4)*4+1] & 0x0F;
#else
	return output1x[(index<<2)+1] & 0x0F;
#endif
}

static int get_hash_1(int index)
{
#if defined(NT_X86_64)
	return output8x[32*(index>>3)+8+index%8] & 0xFF;
#elif defined(NT_SSE2)
	if(index<NT_NUM_KEYS4)
		return output4x[16*(index>>2)+4+index%4] & 0xFF;
	else
		return output1x[(index-NT_NUM_KEYS4)*4+1] & 0xFF;
#else
	return output1x[(index<<2)+1] & 0xFF;
#endif
}

static int get_hash_2(int index)
{
#if defined(NT_X86_64)
	return output8x[32*(index>>3)+8+index%8] & 0x0FFF;
#elif defined(NT_SSE2)
	if(index<NT_NUM_KEYS4)
		return output4x[16*(index>>2)+4+index%4] & 0x0FFF;
	else
		return output1x[(index-NT_NUM_KEYS4)*4+1] & 0x0FFF;
#else
	return output1x[(index<<2)+1] & 0x0FFF;
#endif
}

static int cmp_all(void *binary, int count)
{
	unsigned int i=0;
	unsigned int b=((unsigned int *)binary)[1];

#if defined(NT_X86_64)
	for(;i<(NT_NUM_KEYS/2);i+=4)
		if(b==output8x[i] || b==output8x[i+1] || b==output8x[i+2] || b==output8x[i+3] || b==output8x[i+4] || b==output8x[i+5] || b==output8x[i+6] || b==output8x[i+7])
			return 1;
#elif defined(NT_SSE2)
	unsigned int pos=4;
	
	for(;i<NT_NUM_KEYS1;i++,pos+=16)
		if(b==output4x[pos] || b==output4x[pos+1] || b==output4x[pos+2] || b==output4x[pos+3])
			return 1;
	i=1;
	for(;i<NT_NUM_KEYS4;i+=4)
		if(b==output1x[i])
			return 1;
#else
	for(;i<NT_NUM_KEYS;i++)
		if(b==output1x[i*4+1])
			return 1;
#endif
	
	return 0;
}

static int cmp_one(void * binary, int index)
{
	unsigned int *t=(unsigned int *)binary;
	unsigned int a;
	unsigned int b;
	unsigned int c;
	unsigned int d;
	
	unsigned int * buffer;
	int pos1;
	int pos2;
	int pos3;
	
#if defined(NT_X86_64)
	int temp;
	buffer=nt_buffer8x;
	
	temp=32*(index>>3)+index%8;
	
	a=output8x[temp];
	b=output8x[temp+8];
	c=output8x[temp+16];
	d=output8x[temp+24];
	
	pos1=24+index%8+128*(index>>3);
	pos2=64+pos1;
	pos3=32+pos1;
#elif defined(NT_SSE2)
	int temp;
	
	if(index<NT_NUM_KEYS4)
	{
		buffer=nt_buffer4x;
		
		temp=16*(index>>2)+index%4;
		
		a=output4x[temp];
		b=output4x[temp+4];
		c=output4x[temp+8];
		d=output4x[temp+12];
		
		pos1=12+index%4+64*(index>>2);
		pos2=32+pos1;
		pos3=16+pos1;
	}
	else
	{
		buffer=nt_buffer1x;
		
		temp=4*(index-NT_NUM_KEYS4);
		
		a=output1x[temp];
		b=output1x[temp+1];
		c=output1x[temp+2];
		d=output1x[temp+3];
		
		pos1=3+4*temp;
		pos2=8+pos1;
		pos3=4+pos1;
	}
#else
	buffer=nt_buffer1x;
	
	a=output1x[(index<<2)];
	b=output1x[(index<<2)+1];
	c=output1x[(index<<2)+2];
	d=output1x[(index<<2)+3];
	
	pos1=(index<<4)+3;
	pos2=8+pos1;
	pos3=4+pos1;
#endif
	if(b!=t[1])
		return 0;
	b += SQRT_3;b = (b << 15) | (b >> 17);
	
	a += (b ^ c ^ d) + buffer[pos1] + SQRT_3; a = (a << 3 ) | (a >> 29);
	if(a!=t[0])
		return 0;
	
	d += (a ^ b ^ c) + buffer[pos2] + SQRT_3; d = (d << 9 ) | (d >> 23);
	if(d!=t[3])
		return 0;
	
	c += (d ^ a ^ b) + buffer[pos3] + SQRT_3; c = (c << 11) | (c >> 21);	
	return c==t[2];
}

static int cmp_exact(char *source, int index)
{
	return 1;
}

static void set_salt(void *salt)
{
}

static void set_key(char *key, int index)
{
	unsigned int i=0;
	unsigned int md4_size=0;
	unsigned int saved_base=index<<5;
	unsigned int temp;
	int buff_base;
#if defined(NT_X86_64)
	unsigned int last_length=last_i[index]<<2;

	buff_base=128*(index>>3)+index%8;
	
	for(;key[md4_size] && md4_size<PLAINTEXT_LENGTH;i+=8,md4_size++)
	{
		saved_plain[saved_base+md4_size]=key[md4_size];
		temp=key[++md4_size];
		saved_plain[saved_base+md4_size]=temp;
		
		if(temp)
		{
			nt_buffer8x[i+buff_base] = key[md4_size-1] | (temp<<16);
		}
		else
		{
			nt_buffer8x[i+buff_base] = key[md4_size-1] | 0x800000;
			goto key_cleaning;
		}
	}
	
	nt_buffer8x[i+buff_base]=0x80;
	saved_plain[saved_base+md4_size]=0;
	
key_cleaning:
	i+=8;
	for(;i<=last_length;i+=8)
		nt_buffer8x[i+buff_base]=0;
	
	last_i[index]=md4_size;
	
	nt_buffer8x[112+buff_base] = md4_size << 4;
#elif defined(NT_SSE2)
	unsigned int last_length=last_i[index]<<1;

	if(index<NT_NUM_KEYS4)
	{
		buff_base=64*(index>>2)+index%4;
		
		for(;key[md4_size] && md4_size<PLAINTEXT_LENGTH;i+=4,md4_size++)
		{
			saved_plain[saved_base+md4_size]=key[md4_size];
			temp=key[++md4_size];
			saved_plain[saved_base+md4_size]=temp;
			
			if(temp)
			{
				nt_buffer4x[i+buff_base] = key[md4_size-1] | (temp<<16);
			}
			else
			{
				nt_buffer4x[i+buff_base] = key[md4_size-1] | 0x800000;
				goto key_cleaning;
			}
		}
		
		nt_buffer4x[i+buff_base]=0x80;
		saved_plain[saved_base+md4_size]=0;
		
	key_cleaning:
		i+=4;
		for(;i<=last_length;i+=4)
			nt_buffer4x[i+buff_base]=0;
		
		last_i[index]=md4_size;
		
		nt_buffer4x[56+buff_base] = md4_size << 4;
	}
	else
	{
		buff_base=16*(index-NT_NUM_KEYS4);
		
		for(;key[md4_size] && md4_size<PLAINTEXT_LENGTH;i++,md4_size++)
		{
			saved_plain[saved_base+md4_size]=key[md4_size];
			temp=key[++md4_size];
			saved_plain[saved_base+md4_size]=temp;
			
			if(temp)
			{
				nt_buffer1x[i+buff_base] = key[md4_size-1] | (temp<<16);
			}
			else
			{
				nt_buffer1x[i+buff_base] = key[md4_size-1] | 0x800000;
				goto key_cleaning1;
			}
		}
		
		nt_buffer1x[i+buff_base]=0x80;
		saved_plain[saved_base+md4_size]=0;
		
	key_cleaning1:
		i++;
		last_length>>=1;
		
		for(;i<=last_length;i++)
			nt_buffer1x[i+buff_base]=0;
		
		last_i[index]=md4_size>>1;
		
		nt_buffer1x[14+buff_base] = md4_size << 4;
	}
#else
	buff_base=index<<4;
	
	for(;key[md4_size] && md4_size<PLAINTEXT_LENGTH;i++,md4_size++)
	{
		saved_plain[saved_base+md4_size]=key[md4_size];
		temp=key[++md4_size];
		saved_plain[saved_base+md4_size]=temp;
		
		if(temp)
		{
			nt_buffer1x[buff_base+i] = key[md4_size-1] | (temp<<16);
		}
		else
		{
			nt_buffer1x[buff_base+i] = key[md4_size-1] | 0x800000;
			goto key_cleaning;
		}
	}
	
	nt_buffer1x[buff_base+i]=0x80;
	saved_plain[saved_base+md4_size]=0;
	
key_cleaning:
	i++;
	for(;i<=last_i[index];i++)
		nt_buffer1x[buff_base+i]=0;
	
	last_i[index]=md4_size>>1;
	
	nt_buffer1x[buff_base+14] = md4_size << 4;
#endif
}

static char *get_key(int index)
{
	return saved_plain+(index<<5);
}

struct fmt_main fmt_NT = {
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
		fmt_NT_init,
		valid,
		nt_split,
		get_binary,
		fmt_default_salt,
		{
			binary_hash_0,
			binary_hash_1,
			binary_hash_2,
			NULL,
			NULL
		},
		fmt_default_salt_hash,
		set_salt,
		set_key,
		get_key,
		fmt_default_clear_keys,
		NT_CRYPT_FUN,
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
