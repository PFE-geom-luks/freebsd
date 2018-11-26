/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2004-2006 Pawel Jakub Dawidek <pjd@FreeBSD.org>
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

#ifndef	_G_LUKS_H_
#define	_G_LUKS_H_

#include <sys/endian.h>
#include <sys/errno.h>
#include <sys/malloc.h>
#include <crypto/sha2/sha256.h>
#include <crypto/sha2/sha512.h>
#include <opencrypto/cryptodev.h>
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

#define	G_LUKS_CLASS_NAME	"LUKS"
#define	G_LUKS_VERSION		1
#define	G_LUKS_SUFFIX		".luks"
/*
 * Special flag to instruct gluks to passthrough the underlying provider's
 * physical path
 */
#define G_LUKS_PHYSPATH_PASSTHROUGH "\255"

#define LUKS_MAGIC_L		6
#define LUKS_CIPHERNAME_L 	32
#define LUKS_CIPHERMODE_L 	32
#define LUKS_HASHSPEC_L 	32
#define UUID_STRING_L 		40
#define LUKS_NUMKEYS 		8
#define LUKS_DIGESTSIZE 	20
#define LUKS_SALTSIZE 		32


#ifdef _KERNEL
#define	G_LUKS_DEBUG(lvl, ...)	do {					\
	if (g_luks_debug >= (lvl)) {					\
		printf("GEOM_LUKS");					\
		if (g_luks_debug > 0)					\
			printf("[%u]", lvl);				\
		printf(": ");						\
		printf(__VA_ARGS__);					\
		printf("\n");						\
	}								\
} while (0)
#define	G_LUKS_LOGREQ(bp, ...)	G_LUKS_LOGREQLVL(2, bp, __VA_ARGS__)
#define G_LUKS_LOGREQLVL(lvl, bp, ...) do {				\
	if (g_luks_debug >= (lvl)) {					\
		printf("GEOM_LUKS[%d]: ", (lvl));			\
		printf(__VA_ARGS__);					\
		printf(" ");						\
		g_print_bio(bp);					\
		printf("\n");						\
	}								\
} while (0)

struct g_luks_softc {
	struct g_geom  *sc_geom;
	uint16_t 	sc_version;
	char 		sc_magic[LUKS_MAGIC_L];
};

#endif	/* _KERNEL */


struct g_luks_metadata {
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
} __packed;

static __inline int
luks_metadata_decode(const u_char *data, struct g_luks_metadata *md)
{
	const u_char *p;
	unsigned int i;

	p = data;

	bcopy(p,md->md_magic,sizeof(md->md_magic)); p += sizeof(md->md_magic);
	md->md_version = le16dec(p); p += sizeof(md->md_version);
	md->md_magic[LUKS_MAGIC_L - 1]='\0';
	bcopy(p,md->md_ciphername,sizeof(md->md_ciphername)); 	p += sizeof(md->md_ciphername);
	bcopy(p,md->md_ciphermode,sizeof(md->md_ciphermode));	p += sizeof(md->md_ciphermode);
	bcopy(p,md->md_hashspec,sizeof(md->md_hashspec));	p += sizeof(md->md_hashspec);
	md->md_payloadoffset = le32dec(p);		p += sizeof(md->md_payloadoffset);
	md->md_keybytes = le32dec(p);			p += sizeof(md->md_keybytes);
	bcopy(p,md->md_mkdigest,sizeof(md->md_mkdigest));	p += sizeof(md->md_mkdigest);
	bcopy(p,md->md_mkdigestsalt,sizeof(md->md_mkdigestsalt)); p += sizeof(md->md_mkdigestsalt);
	md->md_iterations = le32dec(p);			p += sizeof(md->md_iterations);
	bcopy(p,md->md_uuid,sizeof(md->md_uuid)); 	p += sizeof(md->md_uuid);
	bcopy(p,md->md_keyslot,sizeof(md->md_keyslot));
	for ( i = 0 ; i < LUKS_NUMKEYS; i++){
		md->md_keyslot[i].active = 	le32dec(md->md_keyslot[i].active);
		md->md_keyslot[i].iterations = 	le32dec(md->md_keyslot[i].iterations);
		md->md_keyslot[i].keymaterialoffset = le32dec(md->md_keyslot[i].keymaterialoffset);
		md->md_keyslot[i].stripes = le32dec(md->md_keyslot[i].stripes);
	}

	return (0);
}

static __inline void
luks_metadata_dump(const struct g_luks_metadata *md){
	printf(" magic: %s", md->md_magic);
}

static __inline void
luks_metadata_softc(struct g_luks_softc *sc, const struct g_luks_metadata *md)
{
	sc->sc_magic = md->md_magic;
	sc->sc_version = md->md_version;
}



#endif	/* _G_LUKS_H_ */
