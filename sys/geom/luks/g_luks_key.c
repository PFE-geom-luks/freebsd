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
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#ifdef _KERNEL
#include <sys/malloc.h>
#include <sys/systm.h>
#include <geom/geom.h>
#else
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#endif

#include <geom/luks/g_luks.h>
#include <geom/luks/pkcs5v2.h>

#ifdef _KERNEL
MALLOC_DECLARE(M_LUKS);
#endif

/*
 * Verify if the given 'key' is correct.
 * Return 1 if it is correct and 0 otherwise.
 */
static int
g_luks_mkey_verify(const unsigned char *mkey, const unsigned char *key)
{
	const unsigned char *odhmac;	/* On-disk HMAC. */
	unsigned char chmac[SHA512_MDLEN];	/* Calculated HMAC. */
	unsigned char hmkey[SHA512_MDLEN];	/* Key for HMAC. */

	/*
	 * The key for HMAC calculations is: hmkey = HMAC_SHA512(Derived-Key, 0)
	 */
	g_luks_crypto_hmac(key, G_LUKS_USERKEYLEN, "\x00", 1, hmkey, 0);

	odhmac = mkey + G_LUKS_DATAIVKEYLEN;

	/* Calculate HMAC from Data-Key and IV-Key. */
	g_luks_crypto_hmac(hmkey, sizeof(hmkey), mkey, G_LUKS_DATAIVKEYLEN,
	    chmac, 0);

	bzero(hmkey, sizeof(hmkey));

	/*
	 * Compare calculated HMAC with HMAC from metadata.
	 * If two HMACs are equal, 'key' is correct.
	 */
	return (!bcmp(odhmac, chmac, SHA512_MDLEN));
}

/*
 * Calculate HMAC from Data-Key and IV-Key.
 */
void
g_luks_mkey_hmac(unsigned char *mkey, const unsigned char *key)
{
	unsigned char hmkey[SHA512_MDLEN];	/* Key for HMAC. */
	unsigned char *odhmac;	/* On-disk HMAC. */

	/*
	 * The key for HMAC calculations is: hmkey = HMAC_SHA512(Derived-Key, 0)
	 */
	g_luks_crypto_hmac(key, G_LUKS_USERKEYLEN, "\x00", 1, hmkey, 0);

	odhmac = mkey + G_LUKS_DATAIVKEYLEN;
	/* Calculate HMAC from Data-Key and IV-Key. */
	g_luks_crypto_hmac(hmkey, sizeof(hmkey), mkey, G_LUKS_DATAIVKEYLEN,
	    odhmac, 0);

	bzero(hmkey, sizeof(hmkey));
}

/*
 * Find and decrypt Master Key encrypted with 'key'.
 * Return decrypted Master Key number in 'nkeyp' if not NULL.
 * Return 0 on success, > 0 on failure, -1 on bad key.
 */
int
g_luks_mkey_decrypt(const struct g_luks_metadata *md, const unsigned char *key,
    unsigned char *mkey, unsigned *nkeyp)
{
	unsigned char tmpmkey[G_LUKS_MKEYLEN];
	unsigned char enckey[SHA512_MDLEN];	/* Key for encryption. */
	const unsigned char *mmkey;
	int bit, error, nkey;

	if (nkeyp != NULL)
		*nkeyp = -1;

	/*
	 * The key for encryption is: enckey = HMAC_SHA512(Derived-Key, 1)
	 */
	g_luks_crypto_hmac(key, G_LUKS_USERKEYLEN, "\x01", 1, enckey, 0);

	mmkey = md->md_mkeys;
	for (nkey = 0; nkey < G_LUKS_MAXMKEYS; nkey++, mmkey += G_LUKS_MKEYLEN) {
		bit = (1 << nkey);
		if (!(md->md_keys & bit))
			continue;
		bcopy(mmkey, tmpmkey, G_LUKS_MKEYLEN);
		error = g_luks_crypto_decrypt(md->md_ealgo, tmpmkey,
		    G_LUKS_MKEYLEN, enckey, md->md_keylen);
		if (error != 0) {
			bzero(tmpmkey, sizeof(tmpmkey));
			bzero(enckey, sizeof(enckey));
			return (error);
		}
		if (g_luks_mkey_verify(tmpmkey, key)) {
			bcopy(tmpmkey, mkey, G_LUKS_DATAIVKEYLEN);
			bzero(tmpmkey, sizeof(tmpmkey));
			bzero(enckey, sizeof(enckey));
			if (nkeyp != NULL)
				*nkeyp = nkey;
			return (0);
		}
	}
	bzero(enckey, sizeof(enckey));
	bzero(tmpmkey, sizeof(tmpmkey));
	return (-1);
}

#ifdef _KERNEL
int
g_luks_mkey_decrypt_raw(const struct g_luks_metadata_raw *md_raw,
	const struct g_luks_metadata *md, unsigned char *keymaterial, const unsigned char *passphrase,
	unsigned char *mkey, unsigned int nkey )
{

	int error = 0;
	size_t i;

	size_t keymaterial_blocks = af_splitted_size(md_raw->md_keybytes,md_raw->md_keyslot[nkey].stripes);
	size_t keymaterial_size = keymaterial_blocks*LUKS_SECTOR_SIZE;

#ifdef _KERNEL
	char *dkey = malloc(md_raw->md_keybytes, M_LUKS, M_WAITOK | M_ZERO);
	char *digest = malloc(SHA512_MDLEN,M_LUKS,M_WAITOK);
#else
	unsigned char *dkey = malloc(md_raw->md_keybytes);
	char *digest = malloc(SHA512_MDLEN);
#endif
	switch(g_luks_hashstr2aalgo(md_raw->md_hashspec)){
	case CRYPTO_SHA1_HMAC:

		pkcs5v2_genkey_sha1(dkey,md_raw->md_keybytes,md_raw->md_keyslot[nkey].salt,LUKS_SALTSIZE,passphrase,md_raw->md_keyslot[nkey].iterations);

		error = g_luks_crypto_decrypt(md->md_ealgo, keymaterial,
		   keymaterial_size, dkey, md_raw->md_keybytes*8);
		bzero(dkey,md_raw->md_keybytes);
		if (error != 0) {
			return (error);
		}

		af_merge(keymaterial,dkey,md_raw->md_keybytes,md_raw->md_keyslot[nkey].stripes,
				md_raw->md_hashspec);


		pkcs5v2_genkey_sha1(digest,LUKS_DIGESTSIZE,md_raw->md_mkdigestsalt,LUKS_SALTSIZE,dkey,md_raw->md_iterations);

		if (memcmp(digest,md_raw->md_mkdigest,LUKS_DIGESTSIZE) != 0){
			error = -1;
		}else{
			bcopy(dkey,mkey,md_raw->md_keybytes);
		}



	case CRYPTO_RIPEMD160_HMAC:
	case CRYPTO_SHA2_256_HMAC:
		pkcs5v2_genkey_sha256(dkey,md_raw->md_keybytes,md_raw->md_keyslot[nkey].salt,LUKS_SALTSIZE,passphrase,md_raw->md_keyslot[nkey].iterations);

		for (i=0;i<keymaterial_blocks;i++)
		{
			SHA256_CTX *ivctx;
			uint8_t    ivkey[G_LUKS_IVKEYLEN];

			bcopy(mkey, ivkey, sizeof(ivkey));
			ivctx = malloc(sizeof(*ivkey), M_LUKS, M_WAITOK | M_ZERO);

			/*
			 * Precalculate SHA256 for IV generation.
			 * This is expensive operation and we can do it only once now or for
			 * every access to sector, so now will be much better.
			 */
			if (md->md_aalgo == G_LUKS_CRYPTO_ESSIV_SHA256) {
				SHA256_Init(ivctx);
				SHA256_Update(ivctx, ivkey, sizeof(ivkey));
			}

			error = g_luks_crypto_decrypt_iv(md->md_ealgo, md->md_aalgo, ivctx, keymaterial+i*LUKS_SECTOR_SIZE,LUKS_SECTOR_SIZE, dkey, i, md_raw->md_keybytes*8);

			bzero(ivctx, sizeof(*ivctx));
			free(ivctx, M_LUKS);

			if (error != 0) {
				return (error);
			}
		}
		bzero(dkey,md_raw->md_keybytes);

		af_merge(keymaterial,dkey,md_raw->md_keybytes,md_raw->md_keyslot[nkey].stripes,md_raw->md_hashspec);

		pkcs5v2_genkey_sha256(digest,SHA512_MDLEN,md_raw->md_mkdigestsalt,LUKS_SALTSIZE,dkey,md_raw->md_iterations);
		if (memcmp(digest,md_raw->md_mkdigest,LUKS_DIGESTSIZE) != 0){
			error = -1;
		}else{
			bcopy(dkey,mkey,md_raw->md_keybytes);
		}
	case CRYPTO_SHA2_512_HMAC:
		pkcs5v2_genkey(dkey,sizeof(*dkey),md_raw->md_keyslot[nkey].salt,LUKS_SALTSIZE,passphrase,md_raw->md_keyslot[nkey].iterations);
	}

	//bzero(dkey,sizeof(*dkey));
	bzero(digest,sizeof(*digest));

#ifdef _KERNEL
	//free(dkey,M_LUKS);
	free(digest,M_LUKS);
#else
	//free(dkey);
	free(digest);
#endif
	return error;
}
#endif
/*
 * Encrypt the Master-Key and calculate HMAC to be able to verify it in the
 * future.
 */
int
g_luks_mkey_encrypt(unsigned algo, const unsigned char *key, unsigned keylen,
    unsigned char *mkey)
{
	unsigned char enckey[SHA512_MDLEN];	/* Key for encryption. */
	int error;

	/*
	 * To calculate HMAC, the whole key (G_LUKS_USERKEYLEN bytes long) will
	 * be used.
	 */
	g_luks_mkey_hmac(mkey, key);
	/*
	 * The key for encryption is: enckey = HMAC_SHA512(Derived-Key, 1)
	 */
	g_luks_crypto_hmac(key, G_LUKS_USERKEYLEN, "\x01", 1, enckey, 0);
	/*
	 * Encrypt the Master-Key and HMAC() result with the given key (this
	 * time only 'keylen' bits from the key are used).
	 */
	error = g_luks_crypto_encrypt(algo, mkey, G_LUKS_MKEYLEN, enckey, keylen);

	bzero(enckey, sizeof(enckey));

	return (error);
}

#ifdef _KERNEL
/*
 * When doing encryption only, copy IV key and encryption key.
 * When doing encryption and authentication, copy IV key, generate encryption
 * key and generate authentication key.
 */
void
g_luks_mkey_propagate(struct g_luks_softc *sc, const unsigned char *mkey)
{

	/* Remember the Master Key. */
	bcopy(mkey, sc->sc_mkey, sizeof(sc->sc_mkey));

	bcopy(mkey, sc->sc_ivkey, sizeof(sc->sc_ivkey));
	mkey += sizeof(sc->sc_ivkey);

	/*
	 * The authentication key is: akey = HMAC_SHA512(Data-Key, 0x11)
	 */
	if ((sc->sc_flags & G_LUKS_FLAG_AUTH) != 0) {
		g_luks_crypto_hmac(mkey, G_LUKS_MAXKEYLEN, "\x11", 1,
		    sc->sc_akey, 0);
	} else {
		arc4rand(sc->sc_akey, sizeof(sc->sc_akey), 0);
	}

	/* Initialize encryption keys. */
	g_luks_key_init(sc);

	if ((sc->sc_flags & G_LUKS_FLAG_AUTH) != 0) {
		/*
		 * Precalculate SHA256 for HMAC key generation.
		 * This is expensive operation and we can do it only once now or
		 * for every access to sector, so now will be much better.
		 */
		SHA256_Init(&sc->sc_akeyctx);
		SHA256_Update(&sc->sc_akeyctx, sc->sc_akey,
		    sizeof(sc->sc_akey));
	}
	/*
	 * Precalculate SHA256 for IV generation.
	 * This is expensive operation and we can do it only once now or for
	 * every access to sector, so now will be much better.
	 */
	switch (sc->sc_ealgo) {
	case CRYPTO_AES_XTS:
		break;
	default:
		SHA256_Init(&sc->sc_ivctx);
		SHA256_Update(&sc->sc_ivctx, sc->sc_ivkey,
		    sizeof(sc->sc_ivkey));
		break;
	}
}
#endif
