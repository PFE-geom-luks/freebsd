#include <errno.h>
#include "g_luks_metadata.h"

size_t
af_splitted_size(size_t blocksize, unsigned int blocknumber)
{
	size_t af_size;
	
	af_size = blocksize * blocknumber;
	af_size = (af_size + (LUKS_SECTOR_SIZE-1)) / LUKS_SECTOR_SIZE;

	return af_size;
}


static __inline void
xor(const char *block1, const char *block2, char *dst, size_t length)
{
	size_t j;
	for (j=0;j<length,j++){
		dst[j] = block1[j] ^ block2[j];
	}
}

int
af_split(const char *material, char *dst, size_t length, unsigned int stripes, const char *hashspec)
{
	unsigned int i;
	size_t blocksize = length * stripes;
	char *lastblock = calloc(length,1);

	bzero(dst,length);
	for (i=0;i<stripes-1;i++){
		arc4rand(dst+(i*length),length,0);
		xor(dst+(i*length),lastblock,lastblock,length);
		luks_hash(hashspec,lastblock,length,lastblock);	
	}
	xor(material,lastblock,dst+(stripes*length),length);
}


int
af_merge(const char *material, char *dst, size_t length, unsigned int stripes, const char *hashspec)
{	
	unsigned int i;
	size_t blocksize = length * stripes;
	char *lastblock = calloc(length,1);

	for (i=0;i<stripes-1;i++){
		xor(material+(i*length),lastblock,lastblock,length);
		luks_hash(hashspec,lastblock,length,lastblock);	
	}
	xor(material+(stripes*length),lastblock,dst,length);
}

