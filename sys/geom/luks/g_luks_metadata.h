/*-
 * Copyright (c) 2005-2011 Pawel Jakub Dawidek <pawel@dawidek.net>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHORS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD$
 */

#ifndef	_G_LUKS_METADATA_H_
#define	_G_LUKS_METADATA_H_

#include <sys/endian.h>
#include <sys/errno.h>
#include <sys/malloc.h>
#include <crypto/sha2/sha256.h>
#include <crypto/sha2/sha512.h>
#include <opencrypto/cryptodev.h>
#include <geom/luks/g_luks.h>

#ifdef _KERNEL
#include <sys/bio.h>
#include <sys/libkern.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <geom/geom.h>
#include <crypto/intake.h>
#include <crypto/sha1.h>
#else
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <sha.h>
#include <stdlib.h>
#include <malloc_np.h>
#endif
#include <sys/queue.h>
#include <sys/tree.h>
#ifndef _OpenSSL_
#include <sys/md5.h>
#endif


#define LUKS_MAGIC_L		6
#define LUKS_CIPHERNAME_L 	32
#define LUKS_CIPHERMODE_L 	32
#define LUKS_HASHSPEC_L 	32
#define UUID_STRING_L 		40
#define LUKS_NUMKEYS 		8
#define LUKS_DIGESTSIZE 	20
#define LUKS_SALTSIZE 		32
#define LUKS_VERSION_01 	1
#define LUKS_SECTOR_SIZE	512
#define LUKS_KEY_ENABLED	0x00AC71F3

#define G_LUKS_PASSLEN		1024


#ifdef _KERNEL
MALLOC_DECLARE(M_LUKS);
#endif

struct g_luks_metadata_raw {
	char 				md_magic[LUKS_MAGIC_L];			/* Magic value. */
	uint16_t			md_version;				/* Version number. */
	char				md_ciphername[LUKS_CIPHERNAME_L];	/* Cipher name. */
	char 				md_ciphermode[LUKS_CIPHERMODE_L];	/* Encryption algorithm. */
	char				md_hashspec[LUKS_HASHSPEC_L];		/* Hash specification. */
	uint32_t			md_payloadoffset;			/* Payload offset. */
	uint32_t			md_keybytes;				/* Provider's size. */
	char				md_mkdigest[LUKS_DIGESTSIZE];		/* Master key checksum from PKCS#5v2. */
	char				md_mkdigestsalt[LUKS_SALTSIZE];		/* Salt parameter for master key PKCS#5v2. */
	int32_t				md_iterations;				/* Number of iterations for PKCS#5v2. */
	char 				md_uuid[UUID_STRING_L];			/* UUID of the partition */
	struct {
		uint32_t 	active;			/* State of keyslot enabled/disabled */
		uint32_t 	iterations; 		/* Number of iterations for PKCS#5v2 */
		char 		salt[LUKS_SALTSIZE];	/* Salt parameter for PKCS#5v2 */
		uint32_t 	keymaterialoffset;	/* Start sector of key material */
		uint32_t 	stripes;		/* number of anti-forensic stripes */
	} md_keyslot[LUKS_NUMKEYS];			/* Key-slot */

	/* Align structure to 512 sector size */
	char 	_padding[432];
} __packed;

#ifndef _OpenSSL_

static __inline void
luks_metadata_raw_encode(struct g_luks_metadata_raw *md, u_char *data)
{
	u_char *p;

	p = data;
	bcopy(md->md_magic, p, sizeof(md->md_magic));
	p += sizeof(md->md_magic);
	le16enc(p, md->md_version);
	p += sizeof(md->md_version);
	switch (md->md_version) {
	case LUKS_VERSION_01:
		bcopy(md->md_ciphername,p,sizeof(md->md_ciphername)); 	p += sizeof(md->md_ciphername);
		bcopy(md->md_ciphermode,p,sizeof(md->md_ciphermode));	p += sizeof(md->md_ciphermode);
		bcopy(md->md_hashspec,p,sizeof(md->md_hashspec));	p += sizeof(md->md_hashspec);
		le32enc(p,md->md_payloadoffset);		p += sizeof(md->md_payloadoffset);
		le32enc(p,md->md_keybytes);			p += sizeof(md->md_keybytes);
		bcopy(md->md_mkdigest,p,sizeof(md->md_mkdigest));	p += sizeof(md->md_mkdigest);
		bcopy(md->md_mkdigestsalt,p,sizeof(md->md_mkdigestsalt)); p += sizeof(md->md_mkdigestsalt);
		le32enc(p,md->md_iterations);			p += sizeof(md->md_iterations);
		bcopy(md->md_uuid,p,sizeof(md->md_uuid)); 	p += sizeof(md->md_uuid);
		bcopy(md->md_keyslot,p,sizeof(md->md_keyslot));
		break;
	default:
#ifdef _KERNEL
		panic("%s: Unsupported version %u.", __func__,
		    (u_int)md->md_version);
#else
		assert(!"Unsupported metadata version.");
#endif
	}
}


static __inline int
luks_metadata_raw_decode(const u_char *data, struct g_luks_metadata_raw *md)
{
	int error;

	const u_char *p;
	unsigned int i;

	p = data;

	bcopy(p,md->md_magic,sizeof(md->md_magic)); p += sizeof(md->md_magic);
	if (memcmp(md->md_magic, G_LUKS_MAGIC,LUKS_MAGIC_L) != 0)
		return (EINVAL);
	md->md_version = be16dec(p); p += sizeof(md->md_version);
	switch (md->md_version) {
	case LUKS_VERSION_01:

		bcopy(p,md->md_ciphername,sizeof(md->md_ciphername)); 	p += sizeof(md->md_ciphername);
		md->md_ciphername[LUKS_CIPHERNAME_L-1]='\0';

		bcopy(p,md->md_ciphermode,sizeof(md->md_ciphermode));	p += sizeof(md->md_ciphermode);
		md->md_ciphermode[LUKS_CIPHERMODE_L-1]='\0';

		bcopy(p,md->md_hashspec,sizeof(md->md_hashspec));	p += sizeof(md->md_hashspec);
		md->md_hashspec[LUKS_HASHSPEC_L-1]='\0';



		md->md_payloadoffset = be32dec(p);		p += sizeof(md->md_payloadoffset);
		md->md_keybytes = be32dec(p);			p += sizeof(md->md_keybytes);
		bcopy(p,md->md_mkdigest,sizeof(md->md_mkdigest));	p += sizeof(md->md_mkdigest);
		bcopy(p,md->md_mkdigestsalt,sizeof(md->md_mkdigestsalt)); p += sizeof(md->md_mkdigestsalt);
		md->md_iterations = be32dec(p);			p += sizeof(md->md_iterations);

		bcopy(p,md->md_uuid,sizeof(md->md_uuid)); 	p += sizeof(md->md_uuid);
		md->md_uuid[UUID_STRING_L-1]='\0';

		bcopy(p,md->md_keyslot,sizeof(md->md_keyslot));
		for ( i = 0 ; i < LUKS_NUMKEYS; i++){
			md->md_keyslot[i].active = 	be32dec(&(md->md_keyslot[i].active)); 
			md->md_keyslot[i].iterations = 	be32dec(&(md->md_keyslot[i].iterations));
			md->md_keyslot[i].keymaterialoffset = be32dec(&(md->md_keyslot[i].keymaterialoffset));
			md->md_keyslot[i].stripes = be32dec(&(md->md_keyslot[i].stripes));
		}
		error=0;
		break;
	default:
		error = EOPNOTSUPP;
		break;
	}
	return (error);
}

#endif

static __inline void
hexprint(const char *d, int n, const char *sep)
{
	for(int i = 0; i < n; ++i)
		printf("%02hhx%s", (const char)d[i], sep);
}

static __inline void
luks_metadata_raw_dump(const struct g_luks_metadata_raw *md)
{
//	printf("LUKS header information for %s\n\n", mdata_device_path(cd));
	printf("Version:       \t%d\n", (u_int)md->md_version);
	printf("Cipher name:   \t%s\n", md->md_ciphername);
	printf("Cipher mode:   \t%s\n", md->md_ciphermode);
	printf("Hash spec:     \t%s\n", md->md_hashspec);
	printf("Payload offset:\t%d\n", md->md_payloadoffset);
	printf("MK bits:       \t%d\n", md->md_keybytes * 8);
	printf("MK digest:     \t");
	hexprint(md->md_mkdigest, LUKS_DIGESTSIZE, " ");
	printf("\n");
	printf("MK salt:       \t");
	hexprint(md->md_mkdigestsalt, LUKS_SALTSIZE/2, " ");
	printf("\n               \t");
	hexprint(md->md_mkdigestsalt+LUKS_SALTSIZE/2, LUKS_SALTSIZE/2, " ");
	printf("\n");
	printf("MK iterations: \t%d\n", md->md_iterations);
	printf("UUID:          \t%s\n\n", md->md_uuid);
	for(int i = 0; i < LUKS_NUMKEYS; ++i) {
		if(md->md_keyslot[i].active == LUKS_KEY_ENABLED) {
			printf("Key Slot %d: ENABLED\n",i);
			printf("\tIterations:         \t%d\n", md->md_keyslot[i].iterations);
			printf("\tSalt:               \t");
			hexprint(md->md_keyslot[i].salt, LUKS_SALTSIZE/2, " ");
			printf("\n\t                      \t");
			hexprint(md->md_keyslot[i].salt + LUKS_SALTSIZE/2, LUKS_SALTSIZE/2, " ");
			printf("\n");

			printf("\tKey material offset:\t%d\n", md->md_keyslot[i].keymaterialoffset);
			printf("\tAF stripes:            \t%d\n", md->md_keyslot[i].stripes);
		}
		else
			printf("Key Slot %d: DISABLED\n", i);
	}

//	printf("        magic: %s\n", md->md_magic);
}

static __inline u_int
g_luks_cipher2ealgo(const char *name, const char *mode)
{
	if (strcasecmp("aes", name) == 0) {
		if (strcasecmp("xts-plain64", mode) == 0)
			return (CRYPTO_AES_XTS);
		else if (strcasecmp("cbc-essiv:sha256", mode) == 0)
			return (CRYPTO_AES_CBC);
		else if (strcasecmp("cbc-plain", mode) == 0)
			// TODO: handle the case with PLAIN as cipher mode
			return (CRYPTO_ALGORITHM_MIN - 1);
	}
	else if (strcasecmp("cast5", name) == 0 && strcasecmp("cbc-plain", mode) == 0) {
		return (CRYPTO_CAST_CBC);
	}
	return (CRYPTO_ALGORITHM_MIN - 1);
}

static __inline void
luks_metadata_raw_to_md(const struct g_luks_metadata_raw *md_raw, struct g_luks_metadata *md)
{
	uint8_t keys = 0;

	bcopy(md_raw->md_magic,md->md_magic,sizeof(md->md_magic));
	md->md_version = G_LUKS_VERSION_04;
	md->md_ealgo = g_luks_cipher2ealgo(md_raw->md_ciphername, md_raw->md_ciphermode);
	md->md_keylen = 8 * md_raw->md_keybytes;
	md->md_sectorsize = LUKS_SECTOR_SIZE;
	md->md_iterations = md_raw->md_iterations;
	bcopy(md_raw->md_mkdigestsalt,md->md_salt,sizeof(md->md_salt));

	// We only have one key available for all the data
	md->md_flags = G_LUKS_FLAG_SINGLE_KEY;
	// TODO: G_LUKS_FLAG_FIRST_KEY ???

	for (int i = 0; i < LUKS_NUMKEYS; ++i)
		if (md_raw->md_keyslot[i].active == LUKS_KEY_ENABLED)
			++keys;
	md->md_keys = keys;

	//md->md_aalgo = NULL;
	//md->md_hash = NULL;

	// TODO: md->md_provsize
	// TODO: md->md_mkeys
}



static __inline void
luks_hash(const char *hashspec,const uint8_t *data, size_t length ,char *digest)
{
	if(strcasecmp("sha256",hashspec)==0){
		SHA256_CTX lctx;
		SHA256_Init(&lctx);
		SHA256_Update(&lctx,data,length);
		SHA256_Final(digest,&lctx);
	}else if (strcasecmp("sha512",hashspec)==0){
		SHA512_CTX lctx;
		SHA512_Init(&lctx);
		SHA512_Update(&lctx,data,length);
		SHA512_Final(digest,&lctx);
	}else if (strcasecmp("sha1",hashspec)==0){
		SHA1_CTX lctx;
#ifdef _KERNEL
		SHA1Init(&lctx);
		SHA1Update(&lctx,data,length);
		SHA1Final(digest,&lctx);
#else
		SHA1_Init(&lctx);
		SHA1_Update(&lctx,data,length);
		SHA1_Final(digest,&lctx);
#endif
	}
}


static __inline size_t
af_splitted_size(size_t blocksize, unsigned int blocknumber)
{
	size_t af_size;
	
	af_size = blocksize * blocknumber;
	af_size = (af_size + (LUKS_SECTOR_SIZE-1)) / LUKS_SECTOR_SIZE;

	return af_size;
}


static __inline void
xor_af(const char *block1, const char *block2, char *dst, size_t length)
{
	size_t j;
	for (j=0;j<length;j++){
		dst[j] = block1[j] ^ block2[j];
	}
}

static __inline void
af_split(const char *material, char *dst, size_t length, unsigned int stripes, const char *hashspec)
{
	unsigned int i;
#ifdef _KERNEL
	char *lastblock = malloc(length, M_LUKS, M_WAITOK | M_ZERO);
#else
	char *lastblock = calloc(length,1);
#endif
	bzero(dst,length);
	for (i=0;i<stripes-1;i++){
#ifdef _KERNEL
		arc4rand(dst+(i*length),length,0);
#else
		arc4random_buf(dst+(i*length),length);
#endif
		xor_af(dst+(i*length),lastblock,lastblock,length);
		luks_hash(hashspec,lastblock,length,lastblock);	
	}
	xor_af(material,lastblock,dst+(stripes*length),length);
#ifdef _KERNEL
	free(lastblock,M_LUKS);
#else
	free(lastblock);
#endif
}


static __inline void
af_merge(const char *material, char *dst, size_t length, unsigned int stripes, const char *hashspec)
{	
	unsigned int i;
#ifdef _KERNEL
	char *lastblock = malloc(length, M_LUKS, M_WAITOK | M_ZERO);
#else
	char *lastblock = calloc(length,1);
#endif

	for (i=0;i<stripes-1;i++){
		xor_af(material+(i*length),lastblock,lastblock,length);
		luks_hash(hashspec,lastblock,length,lastblock);	
	}
	xor_af(material+(stripes*length),lastblock,dst,length);
#ifdef _KERNEL
	free(lastblock,M_LUKS);
#else
	free(lastblock);
#endif
}



static __inline u_int
g_luks_hashstr2aalgo(const char *hashspec)
{
        if (strcasecmp("sha1", hashspec) == 0)
                return (CRYPTO_SHA1_HMAC);
        else if (strcasecmp("ripemd160", hashspec) == 0)
                return (CRYPTO_RIPEMD160_HMAC);
        else if (strcasecmp("sha256", hashspec) == 0)
                return (CRYPTO_SHA2_256_HMAC);
        else if (strcasecmp("sha512", hashspec) == 0)
                return (CRYPTO_SHA2_512_HMAC);
        return (CRYPTO_ALGORITHM_MIN - 1);
}

static __inline u_int
g_luks_hashlen_hmac(int aalgo)
{
	switch (aalgo) {
	case CRYPTO_SHA1_HMAC:
		return SHA1_MDLEN;
	case CRYPTO_RIPEMD160_HMAC:
		return RIPEMD160_MDLEN;
	case CRYPTO_SHA2_256_HMAC:
		return SHA256_MDLEN;
	case CRYPTO_SHA2_512_HMAC:
		return SHA512_MDLEN;
	}
	return (0);

}


int g_luks_mkey_decrypt_raw(const struct g_luks_metadata_raw *md_raw, const struct g_luks_metadata *md, unsigned char *keymaterial, const unsigned char *passphrase,
		unsigned char *mkey, unsigned int nkey );

void g_luks_crypto_hmac_init_sha1(struct hmac_sha1_ctx *ctx, const uint8_t *hkey,
    size_t hkeylen);
void g_luks_crypto_hmac_update_sha1(struct hmac_sha1_ctx *ctx, const uint8_t *data,
    size_t datasize);
void g_luks_crypto_hmac_final_sha1(struct hmac_sha1_ctx *ctx, uint8_t *md, size_t mdsize);
void g_luks_crypto_hmac_sha1(const uint8_t *hkey, size_t hkeysize,
    const uint8_t *data, size_t datasize, uint8_t *md, size_t mdsize);

void g_luks_crypto_hmac_init_sha256(struct hmac_sha256_ctx *ctx, const uint8_t *hkey,
    size_t hkeylen);
void g_luks_crypto_hmac_update_sha256(struct hmac_sha256_ctx *ctx, const uint8_t *data,
    size_t datasize);
void g_luks_crypto_hmac_final_sha256(struct hmac_sha256_ctx *ctx, uint8_t *md, size_t mdsize);
void g_luks_crypto_hmac_sha256(const uint8_t *hkey, size_t hkeysize,
    const uint8_t *data, size_t datasize, uint8_t *md, size_t mdsize);

#ifdef _KERNEL
int g_luks_read_metadata(struct g_class *mp, struct g_provider *pp,
    struct g_luks_metadata_raw *md);
#endif

#endif
