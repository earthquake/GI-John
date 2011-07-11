#include <stdio.h>
#include <stdlib.h>
#if !defined (_MSC_VER)
#include <unistd.h>
#else
#pragma warning ( disable : 4244 )
#endif
#include <string.h>

#if defined (__MINGW32__) || defined (_MSC_VER)
// Later versions of MSVC can handle %lld but some older
// ones can only handle %I64d.  Easiest to simply use
// %I64d then all versions of MSVC will handle it just fine
#define LLd "I64d"
#else
#define LLd "lld"
#endif

#define MAX_LVL_LEN 28
#define MAX_LEN 7

#define C2I(c) ((unsigned int)(unsigned char)(c))

unsigned int * proba1;
unsigned int * proba2;
unsigned int * first;

int main(int argc, char * * argv)
{
	FILE * fichier;
	char * ligne;
	unsigned int i;
	unsigned int j;
	unsigned int k;
	unsigned int l;
	unsigned long long index;
	unsigned char position[256];
	unsigned int charset;
	unsigned int nb_lignes;

	if(argc!=3)
	{
		printf("Usage: %s statfile pwdfile\n", argv[0]);
		return -1;
	}

	fichier = fopen(argv[1], "r");
	if(!fichier)
	{
		printf("could not open %s\n", argv[1]);
		return -1;
	}

	first = malloc( sizeof(int) * 256 );

	ligne = malloc(4096);

	proba2 = malloc(sizeof(unsigned int) * 256 * 256);
	proba1 = malloc(sizeof(unsigned int) * 256 );
	for(i=0;i<256*256;i++)
		proba2[i] = 1000;
	for(i=0;i<256;i++)
		proba1[i] = 1000;

	for(i=0;i<256;i++)
	{
		first[i] = 255;
		position[i] = 255;
	}
	
	nb_lignes = 0;
	charset = 0;
	while(fgets(ligne, 4096, fichier))
	{
		if (ligne[0] == 0)
			continue;
		ligne[strlen(ligne)-1] = 0; // chop
		if( sscanf(ligne, "%d=proba1[%d]", &i, &j) == 2 )
		{
			proba1[j] = i;
			if(position[j] == 255)
			{
				position[j] = charset;
				charset++;
			}
		}
		if( sscanf(ligne, "%d=proba2[%d*256+%d]", &i, &j, &k) == 3 )
		{
			if( (first[j]>k) && (i<1000))
				first[j] = k;
			proba2[j*256+k] = i;
			if(position[k] == 255)
			{
				position[k] = charset;
				charset++;
			}
		}
		nb_lignes++;
	}
	fclose(fichier);

	fichier = fopen(argv[2], "r");
	if(!fichier)
	{
		printf("could not open %s\n", argv[2]);
		return -1;
	}

	while(fgets(ligne, 4096, fichier))
	{
		if (ligne[0] == 0)
			continue;
		ligne[strlen(ligne)-1] = 0; // chop
		i=1; j=0; k=0;
		j = C2I(ligne[0]);
		k = proba1[j];
		printf("%s\t%d", ligne, k);
		l = 0;
		index = position[j];
		if(position[j]==255)
			index = 8.1E18;
		while(ligne[i])
		{
			if(index<8E18)
				index = (index*charset)+position[C2I(ligne[i])];
			if(position[C2I(ligne[i])]==255)
				index = 8.1E18;
			printf("+%d", proba2[j*256+C2I(ligne[i])]);
			k+=proba2[j*256+C2I(ligne[i])];
			if(l)
				l+=proba2[j*256+C2I(ligne[i])];
			if(i==2)
				l=proba1[C2I(ligne[i])];
			j = C2I(ligne[i]);
			i++;
		}
		if(index<8E18)
			printf("\t%d\t%d\t%"LLd"\t%d\n",k,i,index,l);
		else
			printf("\t%d\t%d\t-\t%d\n",k,i,l);
	}

	free(proba1);
	free(proba2);

	free(first);

	free(ligne);

	fprintf(stderr, "charsetsize = %d\n", charset);
	
	return 0;
}
