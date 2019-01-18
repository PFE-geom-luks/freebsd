/*-
 * Copyright (c) 2005-2010 Pawel Jakub Dawidek <pjd@FreeBSD.org>
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
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#elif defined(_STANDALONE)
#include "stand.h"
#else
#include <stdint.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <assert.h>
#include <openssl/evp.h>
#define	_OpenSSL_
#endif
#include <geom/luks/g_luks.h>


#ifdef _KERNEL

void
g_luks_crypto_hmac_init_sha1(struct hmac_sha1_ctx *ctx, const uint8_t *hkey,
    size_t hkeylen)
{
	u_char k_ipad[64], k_opad[64], key[64];
	SHA1_CTX lctx;
	u_int i;

	bzero(key, sizeof(key));
	if (hkeylen == 0)
		; /* do nothing */
	else if (hkeylen <= 64)
		bcopy(hkey, key, hkeylen);
	else {
		/* If key is longer than 64 bytes reset it to key = SHA1(key). */
		SHA1Init(&lctx);
		SHA1Update(&lctx, hkey, hkeylen);
		SHA1Final(key, &lctx);
	}

	/* XOR key with ipad and opad values. */
	for (i = 0; i < sizeof(key); i++) {
		k_ipad[i] = key[i] ^ 0x36;
		k_opad[i] = key[i] ^ 0x5c;
	}
	explicit_bzero(key, sizeof(key));
	/* Start inner SHA1. */
	SHA1Init(&ctx->innerctx);
	SHA1Update(&ctx->innerctx, k_ipad, sizeof(k_ipad));
	explicit_bzero(k_ipad, sizeof(k_ipad));
	/* Start outer SHA1. */
	SHA1Init(&ctx->outerctx);
	SHA1Update(&ctx->outerctx, k_opad, sizeof(k_opad));
	explicit_bzero(k_opad, sizeof(k_opad));
}

void
g_luks_crypto_hmac_update_sha1(struct hmac_sha1_ctx *ctx, const uint8_t *data,
    size_t datasize)
{

	SHA1Update(&ctx->innerctx, data, datasize);
}

void
g_luks_crypto_hmac_final_sha1(struct hmac_sha1_ctx *ctx, uint8_t *md, size_t mdsize)
{
	u_char digest[SHA1_MDLEN];

	/* Complete inner hash */
	SHA1Final(digest, &ctx->innerctx);
	
	/* Complete outer hash */
	SHA1Update(&ctx->outerctx, digest, sizeof(digest));
	SHA1Final(digest, &ctx->outerctx);
	
	explicit_bzero(ctx, sizeof(*ctx));
	/* mdsize == 0 means "Give me the whole hash!" */
	if (mdsize == 0)
		mdsize = SHA1_MDLEN;
	bcopy(digest, md, mdsize);
	explicit_bzero(digest, sizeof(digest));
}


#else

void
g_luks_crypto_hmac_init_sha1(struct hmac_sha1_ctx *ctx, const uint8_t *hkey,
    size_t hkeylen)
{
	u_char k_ipad[64], k_opad[64], key[64];
	SHA_CTX lctx;
	u_int i;

	bzero(key, sizeof(key));
	if (hkeylen == 0)
		; /* do nothing */
	else if (hkeylen <= 64)
		bcopy(hkey, key, hkeylen);
	else {
		/* If key is longer than 64 bytes reset it to key = SHA1(key). */
		SHA1_Init(&lctx);
		SHA1_Update(&lctx, hkey, hkeylen);
		SHA1_Final(key, &lctx);
	}

	/* XOR key with ipad and opad values. */
	for (i = 0; i < sizeof(key); i++) {
		k_ipad[i] = key[i] ^ 0x36;
		k_opad[i] = key[i] ^ 0x5c;
	}
	explicit_bzero(key, sizeof(key));
	/* Start inner SHA1. */
	SHA1_Init(&ctx->innerctx);
	SHA1_Update(&ctx->innerctx, k_ipad, sizeof(k_ipad));
	explicit_bzero(k_ipad, sizeof(k_ipad));
	/* Start outer SHA1. */
	SHA1_Init(&ctx->outerctx);
	SHA1_Update(&ctx->outerctx, k_opad, sizeof(k_opad));
	explicit_bzero(k_opad, sizeof(k_opad));
}

void
g_luks_crypto_hmac_update_sha1(struct hmac_sha1_ctx *ctx, const uint8_t *data,
    size_t datasize)
{

	SHA1_Update(&ctx->innerctx, data, datasize);
}

void
g_luks_crypto_hmac_final_sha1(struct hmac_sha1_ctx *ctx, uint8_t *md, size_t mdsize)
{
	u_char digest[SHA1_MDLEN];

	/* Complete inner hash */
	SHA1_Final(digest, &ctx->innerctx);

	/* Complete outer hash */
	SHA1_Update(&ctx->outerctx, digest, sizeof(digest));
	SHA1_Final(digest, &ctx->outerctx);

	explicit_bzero(ctx, sizeof(*ctx));
	/* mdsize == 0 means "Give me the whole hash!" */
	if (mdsize == 0)
		mdsize = SHA1_MDLEN;
	bcopy(digest, md, mdsize);
	explicit_bzero(digest, sizeof(digest));
}

#endif

void
g_luks_crypto_hmac_sha1(const uint8_t *hkey, size_t hkeysize, const uint8_t *data,
    size_t datasize, uint8_t *md, size_t mdsize)
{
	struct hmac_sha1_ctx ctx;

	g_luks_crypto_hmac_init_sha1(&ctx, hkey, hkeysize);
	g_luks_crypto_hmac_update_sha1(&ctx, data, datasize);
	g_luks_crypto_hmac_final_sha1(&ctx, md, mdsize);
}

