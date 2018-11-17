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
	char		md_magic[6];	/* Magic value. */
	uint16_t	md_version;	/* Version number. */
	uint16_t	md_ealgo;	/* Encryption algorithm. */
	uint16_t	md_keylen;	/* Key length. */
	uint16_t	md_aalgo;	/* Authentication algorithm. */
	uint64_t	md_provsize;	/* Provider's size. */
	uint32_t	md_sectorsize;	/* Sector size. */
	uint8_t		md_keys;	/* Available keys. */
	int32_t		md_iterations;	/* Number of iterations for PKCS#5v2. */
	uint8_t		md_salt[G_LUKS_SALTLEN]; /* Salt. */
			/* Encrypted master key (IV-key, Data-key, HMAC). */
	uint8_t		md_mkeys[G_LUKS_MAXMKEYS * G_LUKS_MKEYLEN];
	u_char		md_hash[16];	/* MD5 hash. */
} __packed;
#ifndef _OpenSSL_
static __inline void
luks_metadata_encode_v1v2v3v4v5v6v7(struct g_luks_metadata *md, u_char **datap)
{
	u_char *p;

	p = *datap;
	le16enc(p, md->md_ealgo);	p += sizeof(md->md_ealgo);
	le16enc(p, md->md_keylen);	p += sizeof(md->md_keylen);
	le16enc(p, md->md_aalgo);	p += sizeof(md->md_aalgo);
	le64enc(p, md->md_provsize);	p += sizeof(md->md_provsize);
	le32enc(p, md->md_sectorsize);	p += sizeof(md->md_sectorsize);
	*p = md->md_keys;		p += sizeof(md->md_keys);
	le32enc(p, md->md_iterations);	p += sizeof(md->md_iterations);
	bcopy(md->md_salt, p, sizeof(md->md_salt)); p += sizeof(md->md_salt);
	bcopy(md->md_mkeys, p, sizeof(md->md_mkeys)); p += sizeof(md->md_mkeys);
	*datap = p;
}
static __inline void
luks_metadata_encode(struct g_luks_metadata *md, u_char *data)
{
	uint32_t hash[4];
	MD5_CTX ctx;
	u_char *p;

	p = data;
	bcopy(md->md_magic, p, sizeof(md->md_magic));
	p += sizeof(md->md_magic);
	le16enc(p, md->md_version);
	p += sizeof(md->md_version);
	switch (md->md_version) {
	case G_LUKS_VERSION_01:
		luks_metadata_encode_v1v2v3v4v5v6v7(md, &p);
		break;
	default:
#ifdef _KERNEL
		panic("%s: Unsupported version %u.", __func__,
		    (u_int)md->md_version);
#else
		assert(!"Unsupported metadata version.");
#endif
	}
	MD5Init(&ctx);
	MD5Update(&ctx, data, p - data);
	MD5Final((void *)hash, &ctx);
	bcopy(hash, md->md_hash, sizeof(md->md_hash));
	bcopy(md->md_hash, p, sizeof(md->md_hash));
}

static __inline int
luks_metadata_decode_v1v2v3v4v5v6v7(const u_char *data, struct g_luks_metadata *md)
{
	uint32_t hash[4];
	MD5_CTX ctx;
	const u_char *p;

	p = data + sizeof(md->md_magic) + sizeof(md->md_version);
	md->md_ealgo = le16dec(p);	p += sizeof(md->md_ealgo);
	md->md_keylen = le16dec(p);	p += sizeof(md->md_keylen);
	md->md_aalgo = le16dec(p);	p += sizeof(md->md_aalgo);
	md->md_provsize = le64dec(p);	p += sizeof(md->md_provsize);
	md->md_sectorsize = le32dec(p);	p += sizeof(md->md_sectorsize);
	md->md_keys = *p;		p += sizeof(md->md_keys);
	md->md_iterations = le32dec(p);	p += sizeof(md->md_iterations);
	bcopy(p, md->md_salt, sizeof(md->md_salt)); p += sizeof(md->md_salt);
	bcopy(p, md->md_mkeys, sizeof(md->md_mkeys)); p += sizeof(md->md_mkeys);
	MD5Init(&ctx);
	MD5Update(&ctx, data, p - data);
	MD5Final((void *)hash, &ctx);
	bcopy(hash, md->md_hash, sizeof(md->md_hash));
	if (bcmp(md->md_hash, p, 16) != 0)
		return (EINVAL);
	return (0);
}
static __inline int
luks_metadata_decode(const u_char *data, struct g_luks_metadata *md)
{
	int error;

	bcopy(data, md->md_magic, sizeof(md->md_magic));
	if (strcmp(md->md_magic, G_LUKS_MAGIC) != 0)
		return (EINVAL);
	md->md_version = le16dec(data + sizeof(md->md_magic));
	switch (md->md_version) {
	case G_LUKS_VERSION_01:
		error = luks_metadata_decode_v1v2v3v4v5v6v7(data, md);
		break;
	default:
		error = EOPNOTSUPP;
		break;
	}
	return (error);
}
#endif	/* !_OpenSSL */

static __inline u_int
g_luks_str2ealgo(const char *name)
{

	if (strcasecmp("null", name) == 0)
		return (CRYPTO_NULL_CBC);
	else if (strcasecmp("null-cbc", name) == 0)
		return (CRYPTO_NULL_CBC);
	else if (strcasecmp("aes", name) == 0)
		return (CRYPTO_AES_XTS);
	else if (strcasecmp("aes-cbc", name) == 0)
		return (CRYPTO_AES_CBC);
	else if (strcasecmp("aes-xts", name) == 0)
		return (CRYPTO_AES_XTS);
	else if (strcasecmp("blowfish", name) == 0)
		return (CRYPTO_BLF_CBC);
	else if (strcasecmp("blowfish-cbc", name) == 0)
		return (CRYPTO_BLF_CBC);
	else if (strcasecmp("camellia", name) == 0)
		return (CRYPTO_CAMELLIA_CBC);
	else if (strcasecmp("camellia-cbc", name) == 0)
		return (CRYPTO_CAMELLIA_CBC);
	else if (strcasecmp("3des", name) == 0)
		return (CRYPTO_3DES_CBC);
	else if (strcasecmp("3des-cbc", name) == 0)
		return (CRYPTO_3DES_CBC);
	return (CRYPTO_ALGORITHM_MIN - 1);
}

static __inline u_int
g_luks_str2aalgo(const char *name)
{

	if (strcasecmp("hmac/md5", name) == 0)
		return (CRYPTO_MD5_HMAC);
	else if (strcasecmp("hmac/sha1", name) == 0)
		return (CRYPTO_SHA1_HMAC);
	else if (strcasecmp("hmac/ripemd160", name) == 0)
		return (CRYPTO_RIPEMD160_HMAC);
	else if (strcasecmp("hmac/sha256", name) == 0)
		return (CRYPTO_SHA2_256_HMAC);
	else if (strcasecmp("hmac/sha384", name) == 0)
		return (CRYPTO_SHA2_384_HMAC);
	else if (strcasecmp("hmac/sha512", name) == 0)
		return (CRYPTO_SHA2_512_HMAC);
	return (CRYPTO_ALGORITHM_MIN - 1);
}

static __inline const char *
g_luks_algo2str(u_int algo)
{

	switch (algo) {
	case CRYPTO_NULL_CBC:
		return ("NULL");
	case CRYPTO_AES_CBC:
		return ("AES-CBC");
	case CRYPTO_AES_XTS:
		return ("AES-XTS");
	case CRYPTO_BLF_CBC:
		return ("Blowfish-CBC");
	case CRYPTO_CAMELLIA_CBC:
		return ("CAMELLIA-CBC");
	case CRYPTO_3DES_CBC:
		return ("3DES-CBC");
	case CRYPTO_MD5_HMAC:
		return ("HMAC/MD5");
	case CRYPTO_SHA1_HMAC:
		return ("HMAC/SHA1");
	case CRYPTO_RIPEMD160_HMAC:
		return ("HMAC/RIPEMD160");
	case CRYPTO_SHA2_256_HMAC:
		return ("HMAC/SHA256");
	case CRYPTO_SHA2_384_HMAC:
		return ("HMAC/SHA384");
	case CRYPTO_SHA2_512_HMAC:
		return ("HMAC/SHA512");
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
	printf("     ealgo: %s\n", g_luks_algo2str(md->md_ealgo));
	printf("    keylen: %u\n", (u_int)md->md_keylen);
	printf("  provsize: %ju\n", (uintmax_t)md->md_provsize);
	printf("sectorsize: %u\n", (u_int)md->md_sectorsize);
	printf("      keys: 0x%02x\n", (u_int)md->md_keys);
	printf("iterations: %d\n", (int)md->md_iterations);
	bzero(str, sizeof(str));
	for (i = 0; i < sizeof(md->md_salt); i++) {
		str[i * 2] = hex[md->md_salt[i] >> 4];
		str[i * 2 + 1] = hex[md->md_salt[i] & 0x0f];
	}
	printf("      Salt: %s\n", str);
	bzero(str, sizeof(str));
	for (i = 0; i < sizeof(md->md_mkeys); i++) {
		str[i * 2] = hex[md->md_mkeys[i] >> 4];
		str[i * 2 + 1] = hex[md->md_mkeys[i] & 0x0f];
	}
	printf("Master Key: %s\n", str);
	bzero(str, sizeof(str));
	for (i = 0; i < 16; i++) {
		str[i * 2] = hex[md->md_hash[i] >> 4];
		str[i * 2 + 1] = hex[md->md_hash[i] & 0x0f];
	}
	printf("  MD5 hash: %s\n", str);
}

static __inline u_int
g_luks_keylen(u_int algo, u_int keylen)
{

	switch (algo) {
	case CRYPTO_NULL_CBC:
		if (keylen == 0)
			keylen = 64 * 8;
		else {
			if (keylen > 64 * 8)
				keylen = 0;
		}
		return (keylen);
	case CRYPTO_AES_CBC:
	case CRYPTO_CAMELLIA_CBC:
		switch (keylen) {
		case 0:
			return (128);
		case 128:
		case 192:
		case 256:
			return (keylen);
		default:
			return (0);
		}
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
	case CRYPTO_BLF_CBC:
		if (keylen == 0)
			return (128);
		if (keylen < 128 || keylen > 448)
			return (0);
		if ((keylen % 32) != 0)
			return (0);
		return (keylen);
	case CRYPTO_3DES_CBC:
		if (keylen == 0 || keylen == 192)
			return (192);
		return (0);
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
	/* Backward compatibility. */
	sc->sc_ealgo = md->md_ealgo;

	sc->sc_sectorsize = md->md_sectorsize;
	sc->sc_mediasize = mediasize;
	if (!(sc->sc_flags & G_LUKS_FLAG_ONETIME))
		sc->sc_mediasize -= sectorsize;

	sc->sc_mediasize /= sc->sc_bytes_per_sector;
	sc->sc_mediasize *= sc->sc_sectorsize;
	sc->sc_ekeylen = md->md_keylen;
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
