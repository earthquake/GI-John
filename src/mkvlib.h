#ifndef _JOHN_MKVLIB_H
#define _JOHN_MKVLIB_H


struct s_pwd
{
	unsigned int level;
	unsigned int len;
	unsigned int index;
	unsigned char password[MAX_MKV_LEN+1];
};

extern unsigned int * proba1;
extern unsigned int * proba2;
extern unsigned long long * nbparts;
extern unsigned int * first;
extern unsigned char charsorted[256*256];

extern unsigned int gmax_level;
extern unsigned int gmax_len;
extern unsigned long long gidx;
extern unsigned long long gstart;
extern unsigned long long gend;

void print_pwd(unsigned long long index, struct s_pwd * pwd, unsigned int max_lvl, unsigned int max_len);
unsigned long long nb_parts(unsigned char lettre, unsigned int len, unsigned int level, unsigned int max_lvl, unsigned int max_len);
void init_probatables(char * filename);
#endif
