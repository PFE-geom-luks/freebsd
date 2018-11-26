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
#else
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
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
	md->md_version = le16dec(p); p += sizeof(md->md_version);
	switch (md->md_version) {
	case LUKS_VERSION_01:

		bcopy(p,md->md_ciphername,sizeof(md->md_ciphername)); 	p += sizeof(md->md_ciphername);
		md->md_ciphername[LUKS_CIPHERNAME_L-1]='\0';

		bcopy(p,md->md_ciphermode,sizeof(md->md_ciphermode));	p += sizeof(md->md_ciphermode);
		md->md_ciphermode[LUKS_CIPHERMODE_L-1]='\0';
		
		bcopy(p,md->md_hashspec,sizeof(md->md_hashspec));	p += sizeof(md->md_hashspec);
		md->md_hashspec[LUKS_HASHSPEC_L-1]='\0';



		md->md_payloadoffset = le32dec(p);		p += sizeof(md->md_payloadoffset);
		md->md_keybytes = le32dec(p);			p += sizeof(md->md_keybytes);
		bcopy(p,md->md_mkdigest,sizeof(md->md_mkdigest));	p += sizeof(md->md_mkdigest);
		bcopy(p,md->md_mkdigestsalt,sizeof(md->md_mkdigestsalt)); p += sizeof(md->md_mkdigestsalt);
		md->md_iterations = le32dec(p);			p += sizeof(md->md_iterations);
		
		bcopy(p,md->md_uuid,sizeof(md->md_uuid)); 	p += sizeof(md->md_uuid);
		md->md_uuid[UUID_STRING_L-1]='\0';

		bcopy(p,md->md_keyslot,sizeof(md->md_keyslot));
		for ( i = 0 ; i < LUKS_NUMKEYS; i++){
			md->md_keyslot[i].active = 	le32dec(p); p += sizeof(md->md_keyslot[i].active);
			md->md_keyslot[i].iterations = 	le32dec(p); p += sizeof(md->md_keyslot[i].iterations);
			md->md_keyslot[i].keymaterialoffset = le32dec(p); p += sizeof(md->md_keyslot[i].keymaterialoffset);
			md->md_keyslot[i].stripes = le32dec(p); p+= sizeof(md->md_keyslot[i].stripes);
		}
		error=0;
	default:
		error = EOPNOTSUPP;
		break;
	}
	return (error);
}

#endif

static __inline void
luks_metadata_raw_dump(const struct g_luks_metadata_raw *md)
{
	printf("     magic: %s\n", md->md_magic);
	printf("   version: %u\n", (u_int)md->md_version);
}

#endif
