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
#define	G_LUKS_MAGIC		{'L','U','K','S', 0xba, 0xbe};
#define	G_LUKS_SUFFIX		".luks"

/*
 * Version history:
 * 1 - As described by LUKS specification
 */
#define	G_LUKS_VERSION_01	1
#define	G_LUKS_VERSION		G_LUKS_VERSION_01

/* ON DISK FLAGS. */
/* Use random, onetime keys. */
#define	G_LUKS_FLAG_ONETIME		0x00000001
/* Ask for the passphrase from the kernel, before mounting root. */
#define	G_LUKS_FLAG_BOOT			0x00000002
/* Detach on last close, if we were open for writing. */
#define	G_LUKS_FLAG_WO_DETACH		0x00000004
/* Detach on last close. */
#define	G_LUKS_FLAG_RW_DETACH		0x00000008
/* Provider is read-only, we should deny all write attempts. */
#define	G_LUKS_FLAG_RO			0x00000020
/* Don't pass through BIO_DELETE requests. */
#define	G_LUKS_FLAG_NODELETE		0x00000040
/* This GLUKS supports GLUKSBoot */
#define	G_LUKS_FLAG_GLUKSBOOT		0x00000080
/* Hide passphrase length in GLUKSboot. */
#define	G_LUKS_FLAG_GLUKSDISPLAYPASS	0x00000100
/* RUNTIME FLAGS. */
/* Provider was open for writing. */
#define	G_LUKS_FLAG_WOPEN		0x00010000
/* Destroy device. */
#define	G_LUKS_FLAG_DESTROY		0x00020000
/* Device suspended. */
#define	G_LUKS_FLAG_SUSPEND		0x00100000
/* Provider uses first encryption key. */
#define	G_LUKS_FLAG_FIRST_KEY		0x00200000
#define	G_LUKS_NEW_BIO	255

#define	SHA512_MDLEN		64
#define	G_LUKS_AUTH_SECKEYLEN	SHA256_DIGEST_LENGTH

#define	G_LUKS_MAXMKEYS		2
#define	G_LUKS_MAXKEYLEN		64
#define	G_LUKS_USERKEYLEN	G_LUKS_MAXKEYLEN
#define	G_LUKS_DATAKEYLEN	G_LUKS_MAXKEYLEN
#define	G_LUKS_AUTHKEYLEN	G_LUKS_MAXKEYLEN
#define	G_LUKS_IVKEYLEN		G_LUKS_MAXKEYLEN
#define	G_LUKS_SALTLEN		64
#define	G_LUKS_DATAIVKEYLEN	(G_LUKS_DATAKEYLEN + G_LUKS_IVKEYLEN)
/* Data-Key, IV-Key, HMAC_SHA512(Derived-Key, Data-Key+IV-Key) */
#define	G_LUKS_MKEYLEN		(G_LUKS_DATAIVKEYLEN + SHA512_MDLEN)
#define	G_LUKS_OVERWRITES	5
/* Switch data encryption key every 2^20 blocks. */
#define	G_LUKS_KEY_SHIFT		20

#define	G_LUKS_CRYPTO_UNKNOWN	0
#define	G_LUKS_CRYPTO_HW		1
#define	G_LUKS_CRYPTO_SW		2

#ifdef _KERNEL
#if (MAX_KEY_BYTES < G_LUKS_DATAIVKEYLEN)
#error "MAX_KEY_BYTES is less than G_LUKS_DATAKEYLEN"
#endif

extern int g_luks_debug;
extern u_int g_luks_overwrites;
extern u_int g_luks_batch;

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
#define	G_LUKS_LOGREQ(lvl, bp, ...)	do {				\
	if (g_luks_debug >= (lvl)) {					\
		printf("GEOM_LUKS");					\
		if (g_luks_debug > 0)					\
			printf("[%u]", lvl);				\
		printf(": ");						\
		printf(__VA_ARGS__);					\
		printf(" ");						\
		g_print_bio(bp);					\
		printf("\n");						\
	}								\
} while (0)

struct g_luks_worker {
	struct g_luks_softc	*w_softc;
	struct proc		*w_proc;
	u_int			 w_number;
	uint64_t		 w_sid;
	boolean_t		 w_active;
	LIST_ENTRY(g_luks_worker) w_next;
};

#endif	/* _KERNEL */

struct g_luks_softc {
	struct g_geom	*sc_geom;
	u_int		 sc_version;
	u_int		 sc_crypto;
	uint8_t		 sc_mkey[G_LUKS_DATAIVKEYLEN];
	uint8_t		 sc_ekey[G_LUKS_DATAKEYLEN];
	TAILQ_HEAD(, g_luks_key) sc_ekeys_queue;
	RB_HEAD(g_luks_key_tree, g_luks_key) sc_ekeys_tree;
	struct mtx	 sc_ekeys_lock;
	uint64_t	 sc_ekeys_total;
	uint64_t	 sc_ekeys_allocated;
	u_int		 sc_ealgo;
	u_int		 sc_ekeylen;
	uint8_t		 sc_akey[G_LUKS_AUTHKEYLEN];
	u_int		 sc_aalgo;
	u_int		 sc_akeylen;
	u_int		 sc_alen;
	SHA256_CTX	 sc_akeyctx;
	uint8_t		 sc_ivkey[G_LUKS_IVKEYLEN];
	SHA256_CTX	 sc_ivctx;
	int		 sc_nkey;
	uint32_t	 sc_flags;
	int		 sc_inflight;
	off_t		 sc_mediasize;
	size_t		 sc_sectorsize;
	u_int		 sc_bytes_per_sector;
	u_int		 sc_data_per_sector;
#ifndef _KERNEL
	int		 sc_cpubind;
#else /* _KERNEL */
	boolean_t	 sc_cpubind;

	/* Only for software cryptography. */
	struct bio_queue_head sc_queue;
	struct mtx	 sc_queue_mtx;
	LIST_HEAD(, g_luks_worker) sc_workers;
#endif /* _KERNEL */
};
#define	sc_name		 sc_geom->name

#define	G_LUKS_KEY_MAGIC	0xe11341c

struct g_luks_key {
	/* Key value, must be first in the structure. */
	uint8_t		gek_key[G_LUKS_DATAKEYLEN];
	/* Magic. */
	int		gek_magic;
	/* Key number. */
	uint64_t	gek_keyno;
	/* Reference counter. */
	int		gek_count;
	/* Keeps keys sorted by most recent use. */
	TAILQ_ENTRY(g_luks_key) gek_next;
	/* Keeps keys sorted by number. */
	RB_ENTRY(g_luks_key) gek_link;
};

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

#ifndef _OpenSSL_

static __inline void
luks_metadata_encode(struct g_luks_metadata *md, u_char *data)
{
	u_char *p;

	p = data;
	bcopy(md->md_magic, p, sizeof(md->md_magic));
	p += sizeof(md->md_magic);
	le16enc(p, md->md_version);
	p += sizeof(md->md_version);
	switch (md->md_version) {
	case G_LUKS_VERSION_01:
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
luks_metadata_decode(const u_char *data, struct g_luks_metadata *md)
{
	int error;

	const u_char *p;
	unsigned int i;

	p = data;

	bcopy(p,md->md_magic,sizeof(md->md_magic)); p += sizeof(md->md_magic);
	md->md_magic[LUKS_MAGIC_L - 1]='\0';
	if (strcmp(md->md_magic, G_LUKS_MAGIC) != 0)
		return (EINVAL);
	md->md_version = le16dec(p); p += sizeof(md->md_version);
	switch (md->md_version) {
	case G_LUKS_VERSION_01:

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

		error=0;
	default:
		error = EOPNOTSUPP;
		break;
	}
	return (error);
}
#endif	/* !_OpenSSL */

static __inline u_int
g_luks_str2ealgo(const char *name, const char *mode)
{

	if (strcasecmp("aes", name) == 0){
		if (strcasecmp("xts-plain64", mode) == 0)
			return (CRYPTO_AES_XTS)
	}
	return (CRYPTO_ALGORITHM_MIN - 1);
}

static __inline const char *
g_luks_algo2str(u_int algo)
{

	switch (algo) {
	case CRYPTO_AES_XTS:
		return ("aes-xts-plain");
	}
	return ("unknown");
}

static __inline void
luks_metadata_dump(const struct g_luks_metadata *md)
{
	static const char hex[] = "0123456789abcdef";
	char str[sizeof(md->md_mkeys) * 2 + 1];
	u_int i;

	printf("     magic: %s\n", md->md_magic);
	printf("   version: %u\n", (u_int)md->md_version);
	printf("     ealgo: %s mode: %s\n", md->md_ealgo,md->md_emode);
}

static __inline u_int
g_luks_keylen(u_int algo, u_int keylen)
{

	switch (algo) {
	case CRYPTO_AES_XTS:
		switch (keylen) {
		case 0:
			return (128);
		case 128:
		case 256:
			return (keylen);
		default:
			return (0);
		}
	default:
		return (0);
	}
}

static __inline u_int
g_luks_hashlen(u_int algo)
{

	switch (algo) {
	case CRYPTO_MD5_HMAC:
		return (16);
	case CRYPTO_SHA1_HMAC:
		return (20);
	case CRYPTO_RIPEMD160_HMAC:
		return (20);
	case CRYPTO_SHA2_256_HMAC:
		return (32);
	case CRYPTO_SHA2_384_HMAC:
		return (48);
	case CRYPTO_SHA2_512_HMAC:
		return (64);
	}
	return (0);
}

static __inline void
luks_metadata_softc(struct g_luks_softc *sc, const struct g_luks_metadata *md,
    u_int sectorsize, off_t mediasize)
{

	sc->sc_version = md->md_version;
	sc->sc_inflight = 0;
	sc->sc_crypto = G_LUKS_CRYPTO_UNKNOWN;
	sc->sc_flags = 0x00000000;

	sc->sc_ealgo = g_luks_str2ealgo(md->md_ealgo,md->md_emode);

	sc->sc_sectorsize = 512;
	sc->sc_mediasize = mediasize;
}

#ifdef _KERNEL
int g_luks_read_metadata(struct g_class *mp, struct g_provider *pp,
    struct g_luks_metadata *md);
struct g_geom *g_luks_create(struct gctl_req *req, struct g_class *mp,
    struct g_provider *bpp, const struct g_luks_metadata *md,
    const u_char *mkey, int nkey);
int g_luks_destroy(struct g_luks_softc *sc, boolean_t force);

int g_luks_access(struct g_provider *pp, int dr, int dw, int de);
void g_luks_config(struct gctl_req *req, struct g_class *mp, const char *verb);

void g_luks_read_done(struct bio *bp);
void g_luks_write_done(struct bio *bp);
int g_luks_crypto_rerun(struct cryptop *crp);

void g_luks_crypto_read(struct g_luks_softc *sc, struct bio *bp, boolean_t fromworker);
void g_luks_crypto_run(struct g_luks_worker *wr, struct bio *bp);

void g_luks_auth_read(struct g_luks_softc *sc, struct bio *bp);
void g_luks_auth_run(struct g_luks_worker *wr, struct bio *bp);
#endif
void g_luks_crypto_ivgen(struct g_luks_softc *sc, off_t offset, u_char *iv,
    size_t size);

void g_luks_mkey_hmac(unsigned char *mkey, const unsigned char *key);
int g_luks_mkey_decrypt(const struct g_luks_metadata *md,
    const unsigned char *key, unsigned char *mkey, unsigned *nkeyp);
int g_luks_mkey_encrypt(unsigned algo, const unsigned char *key, unsigned keylen,
    unsigned char *mkey);
#ifdef _KERNEL
void g_luks_mkey_propagate(struct g_luks_softc *sc, const unsigned char *mkey);
#endif

int g_luks_crypto_encrypt(u_int algo, u_char *data, size_t datasize,
    const u_char *key, size_t keysize);
int g_luks_crypto_decrypt(u_int algo, u_char *data, size_t datasize,
    const u_char *key, size_t keysize);

struct hmac_ctx {
	SHA512_CTX	innerctx;
	SHA512_CTX	outerctx;
};

void g_luks_crypto_hmac_init(struct hmac_ctx *ctx, const uint8_t *hkey,
    size_t hkeylen);
void g_luks_crypto_hmac_update(struct hmac_ctx *ctx, const uint8_t *data,
    size_t datasize);
void g_luks_crypto_hmac_final(struct hmac_ctx *ctx, uint8_t *md, size_t mdsize);
void g_luks_crypto_hmac(const uint8_t *hkey, size_t hkeysize,
    const uint8_t *data, size_t datasize, uint8_t *md, size_t mdsize);

void g_luks_key_fill(struct g_luks_softc *sc, struct g_luks_key *key,
    uint64_t keyno);
#ifdef _KERNEL
void g_luks_key_init(struct g_luks_softc *sc);
void g_luks_key_destroy(struct g_luks_softc *sc);
uint8_t *g_luks_key_hold(struct g_luks_softc *sc, off_t offset, size_t blocksize);
void g_luks_key_drop(struct g_luks_softc *sc, uint8_t *rawkey);
#endif
#endif	/* !_G_LUKS_H_ */
