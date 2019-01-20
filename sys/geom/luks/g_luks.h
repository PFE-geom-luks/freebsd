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
#include <crypto/sha1.h>
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
#include <sys/types.h>
#include <sha.h>
#include <strings.h>
#include <stdlib.h>
#include <malloc_np.h>
#endif
#include <sys/queue.h>
#include <sys/tree.h>
#ifndef _OpenSSL_
#include <sys/md5.h>
#endif

#define	G_LUKS_CLASS_NAME	"LUKS"
#define	G_LUKS_MAGIC		"LUKS\xba\xbe"
#define	G_LUKS_SUFFIX		".luks"

/*
 * Version history:
 * 0 - Initial version number.
 * 1 - Added data authentication support (md_aalgo field and
 *     G_LUKS_FLAG_AUTH flag).
 * 2 - Added G_LUKS_FLAG_READONLY.
 * 3 - Added 'configure' subcommand.
 * 4 - IV is generated from offset converted to little-endian
 *     (the G_LUKS_FLAG_NATIVE_BYTE_ORDER flag will be set for older versions).
 * 5 - Added multiple encrypton keys and AES-XTS support.
 * 6 - Fixed usage of multiple keys for authenticated providers (the
 *     G_LUKS_FLAG_FIRST_KEY flag will be set for older versions).
 * 7 - Encryption keys are now generated from the Data Key and not from the
 *     IV Key (the G_LUKS_FLAG_ENC_IVKEY flag will be set for older versions).
 */
#define	G_LUKS_VERSION_00	0
#define	G_LUKS_VERSION_01	1
#define	G_LUKS_VERSION_02	2
#define	G_LUKS_VERSION_03	3
#define	G_LUKS_VERSION_04	4
#define	G_LUKS_VERSION_05	5
#define	G_LUKS_VERSION_06	6
#define	G_LUKS_VERSION_07	7
#define	G_LUKS_VERSION		G_LUKS_VERSION_07

/* ON DISK FLAGS. */
/* Use random, onetime keys. */
#define	G_LUKS_FLAG_ONETIME		0x00000001
/* Ask for the passphrase from the kernel, before mounting root. */
#define	G_LUKS_FLAG_BOOT			0x00000002
/* Detach on last close, if we were open for writing. */
#define	G_LUKS_FLAG_WO_DETACH		0x00000004
/* Detach on last close. */
#define	G_LUKS_FLAG_RW_DETACH		0x00000008
/* Provide data authentication. */
#define	G_LUKS_FLAG_AUTH			0x00000010
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
/* Provider uses native byte-order for IV generation. */
#define	G_LUKS_FLAG_NATIVE_BYTE_ORDER	0x00040000
/* Provider uses single encryption key. */
#define	G_LUKS_FLAG_SINGLE_KEY		0x00080000
/* Device suspended. */
#define	G_LUKS_FLAG_SUSPEND		0x00100000
/* Provider uses first encryption key. */
#define	G_LUKS_FLAG_FIRST_KEY		0x00200000
/* Provider uses IV-Key for encryption key generation. */
#define	G_LUKS_FLAG_ENC_IVKEY		0x00400000

#define	G_LUKS_NEW_BIO	255

#define SHA256_MDLEN		32
#define SHA1_MDLEN		20
#define RIPEMD160_MDLEN		20
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

#define	G_LUKS_CRYPTO_PLAIN64		1
#define	G_LUKS_CRYPTO_PLAIN		2
#define	G_LUKS_CRYPTO_ESSIV_SHA256	3

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
#if (MAX_KEY_BYTES < G_LUKS_DATAIVKEYLEN)
#error "MAX_KEY_BYTES is less than G_LUKS_DATAKEYLEN"
#endif


#ifdef _KERNEL
MALLOC_DECLARE(M_LUKS);
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
	off_t		 sc_offset;
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
	char		md_magic[16];	/* Magic value. */
	uint32_t	md_version;	/* Version number. */
	uint32_t	md_flags;	/* Additional flags. */
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
luks_metadata_encode_v0(struct g_luks_metadata *md, u_char **datap)
{
	u_char *p;

	p = *datap;
	le32enc(p, md->md_flags);	p += sizeof(md->md_flags);
	le16enc(p, md->md_ealgo);	p += sizeof(md->md_ealgo);
	le16enc(p, md->md_keylen);	p += sizeof(md->md_keylen);
	le64enc(p, md->md_provsize);	p += sizeof(md->md_provsize);
	le32enc(p, md->md_sectorsize);	p += sizeof(md->md_sectorsize);
	*p = md->md_keys;		p += sizeof(md->md_keys);
	le32enc(p, md->md_iterations);	p += sizeof(md->md_iterations);
	bcopy(md->md_salt, p, sizeof(md->md_salt)); p += sizeof(md->md_salt);
	bcopy(md->md_mkeys, p, sizeof(md->md_mkeys)); p += sizeof(md->md_mkeys);
	*datap = p;
}
static __inline void
luks_metadata_encode_v1v2v3v4v5v6v7(struct g_luks_metadata *md, u_char **datap)
{
	u_char *p;

	p = *datap;
	le32enc(p, md->md_flags);	p += sizeof(md->md_flags);
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
	le32enc(p, md->md_version);
	p += sizeof(md->md_version);
	switch (md->md_version) {
	case G_LUKS_VERSION_00:
		luks_metadata_encode_v0(md, &p);
		break;
	case G_LUKS_VERSION_01:
	case G_LUKS_VERSION_02:
	case G_LUKS_VERSION_03:
	case G_LUKS_VERSION_04:
	case G_LUKS_VERSION_05:
	case G_LUKS_VERSION_06:
	case G_LUKS_VERSION_07:
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
luks_metadata_decode_v0(const u_char *data, struct g_luks_metadata *md)
{
	uint32_t hash[4];
	MD5_CTX ctx;
	const u_char *p;

	p = data + sizeof(md->md_magic) + sizeof(md->md_version);
	md->md_flags = le32dec(p);	p += sizeof(md->md_flags);
	md->md_ealgo = le16dec(p);	p += sizeof(md->md_ealgo);
	md->md_keylen = le16dec(p);	p += sizeof(md->md_keylen);
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
luks_metadata_decode_v1v2v3v4v5v6v7(const u_char *data, struct g_luks_metadata *md)
{
	uint32_t hash[4];
	MD5_CTX ctx;
	const u_char *p;

	p = data + sizeof(md->md_magic) + sizeof(md->md_version);
	md->md_flags = le32dec(p);	p += sizeof(md->md_flags);
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
	md->md_version = le32dec(data + sizeof(md->md_magic));
	switch (md->md_version) {
	case G_LUKS_VERSION_00:
		error = luks_metadata_decode_v0(data, md);
		break;
	case G_LUKS_VERSION_01:
	case G_LUKS_VERSION_02:
	case G_LUKS_VERSION_03:
	case G_LUKS_VERSION_04:
	case G_LUKS_VERSION_05:
	case G_LUKS_VERSION_06:
	case G_LUKS_VERSION_07:
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
	printf("     flags: 0x%x\n", (u_int)md->md_flags);
	printf("     ealgo: %s\n", g_luks_algo2str(md->md_ealgo));
	printf("    keylen: %u\n", (u_int)md->md_keylen);
	if (md->md_flags & G_LUKS_FLAG_AUTH)
		printf("     aalgo: %s\n", g_luks_algo2str(md->md_aalgo));
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
	sc->sc_flags = md->md_flags;
	/* Backward compatibility. */
	if (md->md_version < G_LUKS_VERSION_04)
		sc->sc_flags |= G_LUKS_FLAG_NATIVE_BYTE_ORDER;
	if (md->md_version < G_LUKS_VERSION_05)
		sc->sc_flags |= G_LUKS_FLAG_SINGLE_KEY;
	if (md->md_version < G_LUKS_VERSION_06 &&
	    (sc->sc_flags & G_LUKS_FLAG_AUTH) != 0) {
		sc->sc_flags |= G_LUKS_FLAG_FIRST_KEY;
	}
	if (md->md_version < G_LUKS_VERSION_07)
		sc->sc_flags |= G_LUKS_FLAG_ENC_IVKEY;
	sc->sc_ealgo = md->md_ealgo;
	sc->sc_aalgo = md->md_aalgo;

	if (sc->sc_flags & G_LUKS_FLAG_AUTH) {
		sc->sc_akeylen = sizeof(sc->sc_akey) * 8;
		sc->sc_alen = g_luks_hashlen(sc->sc_aalgo);

		sc->sc_data_per_sector = sectorsize - sc->sc_alen;
		/*
		 * Some hash functions (like SHA1 and RIPEMD160) generates hash
		 * which length is not multiple of 128 bits, but we want data
		 * length to be multiple of 128, so we can encrypt without
		 * padding. The line below rounds down data length to multiple
		 * of 128 bits.
		 */
		sc->sc_data_per_sector -= sc->sc_data_per_sector % 16;

		sc->sc_bytes_per_sector =
		    (md->md_sectorsize - 1) / sc->sc_data_per_sector + 1;
		sc->sc_bytes_per_sector *= sectorsize;
	}
	sc->sc_sectorsize = md->md_sectorsize;
	sc->sc_mediasize = mediasize;
	if (!(sc->sc_flags & G_LUKS_FLAG_ONETIME))
		sc->sc_mediasize -= sectorsize;
	if (!(sc->sc_flags & G_LUKS_FLAG_AUTH))
		sc->sc_mediasize -= (sc->sc_mediasize % sc->sc_sectorsize);
	else {
		sc->sc_mediasize /= sc->sc_bytes_per_sector;
		sc->sc_mediasize *= sc->sc_sectorsize;
	}
	sc->sc_ekeylen = md->md_keylen;
}

#ifdef _KERNEL
int g_luks_read_keymaterial(struct g_class *mp, struct g_provider *pp,
    int start_sector, size_t splitted_key_size, char *keymaterial);
struct g_geom *g_luks_create(struct gctl_req *req, struct g_class *mp,
    struct g_provider *bpp, const struct g_luks_metadata *md, const struct g_luks_metadata_raw *md_raw,
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

void g_luks_crypto_ivgen_aalgo(u_int algo, off_t offset, u_char *iv,size_t size);
void g_luks_mkey_hmac(unsigned char *mkey, const unsigned char *key);
int g_luks_mkey_decrypt(const struct g_luks_metadata *md,
    const unsigned char *key, unsigned char *mkey, unsigned *nkeyp);
int g_luks_mkey_encrypt(unsigned algo, const unsigned char *key, unsigned keylen,
    unsigned char *mkey);
#ifdef _KERNEL
void g_luks_mkey_propagate(struct g_luks_softc *sc, const unsigned char *mkey);
int g_luks_crypto_decrypt_iv(u_int ealgo, u_int aalgo, u_char *data, size_t datasize,
    const u_char *key, uint64_t sector, size_t keysize);
#endif

int g_luks_crypto_encrypt(u_int algo, u_char *data, size_t datasize,
    const u_char *key, size_t keysize);
int g_luks_crypto_decrypt(u_int algo, u_char *data, size_t datasize,
    const u_char *key, size_t keysize);

struct hmac_ctx {
	SHA512_CTX	innerctx;
	SHA512_CTX	outerctx;
};

struct hmac_sha1_ctx {
#ifdef _KERNEL
	SHA1_CTX	innerctx;
	SHA1_CTX	outerctx;
#else
	SHA_CTX	innerctx;
	SHA_CTX	outerctx;
#endif
};
struct hmac_sha256_ctx {
	SHA256_CTX	innerctx;
	SHA256_CTX	outerctx;
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
		if (strncasecmp("xts", mode, 3) == 0)
			return (CRYPTO_AES_XTS);
		else if (strncasecmp("cbc", mode, 3) == 0)
			return (CRYPTO_AES_CBC);
	}
	else if (strcasecmp("cast5", name) == 0) {
		return (CRYPTO_CAST_CBC);
	}
	return (CRYPTO_ALGORITHM_MIN - 1);
}

static __inline u_int
g_luks_cipher2aalgo(const char *mode)
{
	if (strcasecmp("xts-plain64", mode) == 0)
		return (G_LUKS_CRYPTO_PLAIN64);
	else if (strcasecmp("cbc-plain", mode) == 0)
		return (G_LUKS_CRYPTO_PLAIN);
	else if (strcasecmp("cbc-essiv:sha256", mode) == 0)
		return (G_LUKS_CRYPTO_ESSIV_SHA256);

	return G_LUKS_CRYPTO_UNKNOWN;
}

static __inline void
luks_metadata_raw_to_md(const struct g_luks_metadata_raw *md_raw, struct g_luks_metadata *md)
{
	uint8_t keys = 0;

	bcopy(md_raw->md_magic,md->md_magic,sizeof(md->md_magic));
	md->md_version = G_LUKS_VERSION_04;
	md->md_ealgo = g_luks_cipher2ealgo(md_raw->md_ciphername, md_raw->md_ciphermode);
	md->md_aalgo = g_luks_cipher2aalgo(md_raw->md_ciphermode);
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

static __inline void
luks_hash(const uint8_t *data, char *digest, uint32_t iv, size_t length, const char *hashspec)
{

	char *iv_char = (char *)&iv;
	iv = htobe32(iv);

	if(strcasecmp("sha256",hashspec)==0){
		SHA256_CTX lctx;
		SHA256_Init(&lctx);
		SHA256_Update(&lctx,iv_char,sizeof(uint32_t));
		SHA256_Update(&lctx,data,length);
		SHA256_Final(digest,&lctx);
	}else if (strcasecmp("sha512",hashspec)==0){
		SHA512_CTX lctx;
		SHA512_Init(&lctx);
		SHA512_Update(&lctx,iv_char,sizeof(uint32_t));
		SHA512_Update(&lctx,data,length);
		SHA512_Final(digest,&lctx);
	}else if (strcasecmp("sha1",hashspec)==0){
		SHA1_CTX lctx;
#ifdef _KERNEL
		SHA1Init(&lctx);
		SHA1Update(&lctx,iv_char,sizeof(uint32_t));
		SHA1Update(&lctx,data,length);
		SHA1Final(digest,&lctx);
#else
		SHA1_Init(&lctx);
		SHA1_Update(&lctx,iv_char,sizeof(uint32_t));
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
	unsigned int i, j, blocks, padding;
	int hash_size = g_luks_hashlen_hmac(g_luks_hashstr2aalgo(hashspec));
	blocks = length / hash_size;
	padding = length % hash_size;
#ifdef _KERNEL
	char *lastblock = malloc(length, M_LUKS, M_WAITOK | M_ZERO);
	bzero(lastblock,length);
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



		for (j = 0; j < blocks; j++)
		{
			luks_hash(lastblock + hash_size * j,
				    lastblock + hash_size * j,
				    j, (size_t)hash_size, hashspec);
		}
		if(padding)
			luks_hash(lastblock + hash_size * j,
				    lastblock + hash_size * j,
				    j, (size_t)padding, hashspec);
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
	unsigned int i, j, blocks, padding;
	int hash_size = g_luks_hashlen_hmac(g_luks_hashstr2aalgo(hashspec));
	blocks = length / hash_size;
	padding = length % hash_size;
#ifdef _KERNEL
	char *lastblock = malloc(length, M_LUKS, M_WAITOK | M_ZERO);
	bzero(lastblock,length);
	G_LUKS_DEBUG(1,"blocks : %u , length : %zu , hash size : %d",blocks,length,hash_size);
#else
	char *lastblock = calloc(length,1);
#endif

	for (i=0;i<stripes-1;i++){
		xor_af(material+(i*length),lastblock,lastblock,length);
		for (j = 0; j < blocks; j++)
		{
			luks_hash(lastblock + hash_size * j,
				    lastblock + hash_size * j,
				    j, (size_t)hash_size, hashspec);
		}
		if(padding)
			luks_hash(lastblock + hash_size * j,
				    lastblock + hash_size * j,
				    j, (size_t)padding, hashspec);
	}
	xor_af(material+(i*length),lastblock,dst,length);
#ifdef _KERNEL
	free(lastblock,M_LUKS);
#else
	free(lastblock);
#endif
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


#endif	/* !_G_LUKS_H_ */
