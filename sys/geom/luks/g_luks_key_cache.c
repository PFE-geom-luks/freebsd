/*-
 * Copyright (c) 2011 Pawel Jakub Dawidek <pawel@dawidek.net>
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
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/sysctl.h>
#include <sys/systm.h>
#endif /* _KERNEL */
#include <sys/queue.h>
#include <sys/tree.h>

#include <geom/geom.h>

#include <geom/luks/g_luks.h>

#ifdef _KERNEL
MALLOC_DECLARE(M_LUKS);

SYSCTL_DECL(_kern_geom_luks);
/*
 * The default limit (8192 keys) will allow to cache all keys for 4TB
 * provider with 512 bytes sectors and will take around 1MB of memory.
 */
static u_int g_luks_key_cache_limit = 8192;
SYSCTL_UINT(_kern_geom_luks, OID_AUTO, key_cache_limit, CTLFLAG_RDTUN,
    &g_luks_key_cache_limit, 0, "Maximum number of encryption keys to cache");
static uint64_t g_luks_key_cache_hits;
SYSCTL_UQUAD(_kern_geom_luks, OID_AUTO, key_cache_hits, CTLFLAG_RW,
    &g_luks_key_cache_hits, 0, "Key cache hits");
static uint64_t g_luks_key_cache_misses;
SYSCTL_UQUAD(_kern_geom_luks, OID_AUTO, key_cache_misses, CTLFLAG_RW,
    &g_luks_key_cache_misses, 0, "Key cache misses");

#endif /* _KERNEL */

static int
g_luks_key_cmp(const struct g_luks_key *a, const struct g_luks_key *b)
{

	if (a->gek_keyno > b->gek_keyno)
		return (1);
	else if (a->gek_keyno < b->gek_keyno)
		return (-1);
	return (0);
}

void
g_luks_key_fill(struct g_luks_softc *sc, struct g_luks_key *key, uint64_t keyno)
{
	const uint8_t *ekey;
	struct {
		char magic[4];
		uint8_t keyno[8];
	} __packed hmacdata;

	ekey = sc->sc_ekey;

	bcopy("ekey", hmacdata.magic, 4);
	le64enc(hmacdata.keyno, keyno);
	g_luks_crypto_hmac(ekey, G_LUKS_MAXKEYLEN, (uint8_t *)&hmacdata,
	    sizeof(hmacdata), key->gek_key, 0);
	key->gek_keyno = keyno;
	key->gek_count = 0;
	key->gek_magic = G_LUKS_KEY_MAGIC;
}

#ifdef _KERNEL
RB_PROTOTYPE(g_luks_key_tree, g_luks_key, gek_link, g_luks_key_cmp);
RB_GENERATE(g_luks_key_tree, g_luks_key, gek_link, g_luks_key_cmp);

static struct g_luks_key *
g_luks_key_allocate(struct g_luks_softc *sc, uint64_t keyno)
{
	struct g_luks_key *key, *ekey, keysearch;

	mtx_assert(&sc->sc_ekeys_lock, MA_OWNED);
	mtx_unlock(&sc->sc_ekeys_lock);

	key = malloc(sizeof(*key), M_LUKS, M_WAITOK);
	g_luks_key_fill(sc, key, keyno);

	mtx_lock(&sc->sc_ekeys_lock);
	/*
	 * Recheck if the key wasn't added while we weren't holding the lock.
	 */
	keysearch.gek_keyno = keyno;
	ekey = RB_FIND(g_luks_key_tree, &sc->sc_ekeys_tree, &keysearch);
	if (ekey != NULL) {
		bzero(key, sizeof(*key));
		free(key, M_LUKS);
		key = ekey;
		TAILQ_REMOVE(&sc->sc_ekeys_queue, key, gek_next);
	} else {
		RB_INSERT(g_luks_key_tree, &sc->sc_ekeys_tree, key);
		sc->sc_ekeys_allocated++;
	}
	TAILQ_INSERT_TAIL(&sc->sc_ekeys_queue, key, gek_next);

	return (key);
}

static struct g_luks_key *
g_luks_key_find_last(struct g_luks_softc *sc)
{
	struct g_luks_key *key;

	mtx_assert(&sc->sc_ekeys_lock, MA_OWNED);

	TAILQ_FOREACH(key, &sc->sc_ekeys_queue, gek_next) {
		if (key->gek_count == 0)
			break;
	}

	return (key);
}

static void
g_luks_key_replace(struct g_luks_softc *sc, struct g_luks_key *key, uint64_t keyno)
{

	mtx_assert(&sc->sc_ekeys_lock, MA_OWNED);
	KASSERT(key->gek_magic == G_LUKS_KEY_MAGIC, ("Invalid magic."));

	RB_REMOVE(g_luks_key_tree, &sc->sc_ekeys_tree, key);
	TAILQ_REMOVE(&sc->sc_ekeys_queue, key, gek_next);

	KASSERT(key->gek_count == 0, ("gek_count=%d", key->gek_count));

	g_luks_key_fill(sc, key, keyno);

	RB_INSERT(g_luks_key_tree, &sc->sc_ekeys_tree, key);
	TAILQ_INSERT_TAIL(&sc->sc_ekeys_queue, key, gek_next);
}

static void
g_luks_key_remove(struct g_luks_softc *sc, struct g_luks_key *key)
{

	mtx_assert(&sc->sc_ekeys_lock, MA_OWNED);
	KASSERT(key->gek_magic == G_LUKS_KEY_MAGIC, ("Invalid magic."));
	KASSERT(key->gek_count == 0, ("gek_count=%d", key->gek_count));

	RB_REMOVE(g_luks_key_tree, &sc->sc_ekeys_tree, key);
	TAILQ_REMOVE(&sc->sc_ekeys_queue, key, gek_next);
	sc->sc_ekeys_allocated--;
	bzero(key, sizeof(*key));
	free(key, M_LUKS);
}

void
g_luks_key_init(struct g_luks_softc *sc)
{
	uint8_t *mkey;

	mtx_lock(&sc->sc_ekeys_lock);

	mkey = sc->sc_mkey + sizeof(sc->sc_ivkey);
	bcopy(mkey, sc->sc_ekey, G_LUKS_DATAKEYLEN);

	sc->sc_ekeys_total = 1;
	sc->sc_ekeys_allocated = 0;
	mtx_unlock(&sc->sc_ekeys_lock);
}

void
g_luks_key_destroy(struct g_luks_softc *sc)
{

	mtx_lock(&sc->sc_ekeys_lock);
	bzero(sc->sc_ekey, sizeof(sc->sc_ekey));
	mtx_unlock(&sc->sc_ekeys_lock);
}

uint8_t *
g_luks_key_hold(struct g_luks_softc *sc, off_t offset, size_t blocksize)
{
	return (sc->sc_ekey);
}

void
g_luks_key_drop(struct g_luks_softc *sc, uint8_t *rawkey)
{
	return;
}
#endif /* _KERNEL */
