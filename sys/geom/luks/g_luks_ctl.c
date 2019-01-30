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
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/bio.h>
#include <sys/sysctl.h>
#include <sys/malloc.h>
#include <sys/kthread.h>
#include <sys/proc.h>
#include <sys/sched.h>
#include <sys/uio.h>

#include <vm/uma.h>

#include <geom/geom.h>
#include <geom/luks/g_luks.h>


MALLOC_DECLARE(M_LUKS);


static void
g_luks_ctl_attach(struct gctl_req *req, struct g_class *mp)
{
	struct g_luks_metadata md;
	struct g_luks_metadata_raw md_raw;
	struct g_provider *pp;
	const char *name;
	u_char *key, mkey[G_LUKS_DATAIVKEYLEN];
	int *nargs, *detach, *readonly;
	int keysize, error;
	u_int nkey=0;

	g_topology_assert();

	nargs = gctl_get_paraml(req, "nargs", sizeof(*nargs));
	if (nargs == NULL) {
		gctl_error(req, "No '%s' argument.", "nargs");
		return;
	}
	if (*nargs != 1) {
		gctl_error(req, "Invalid number of arguments.");
		return;
	}

	detach = gctl_get_paraml(req, "detach", sizeof(*detach));
	if (detach == NULL) {
		gctl_error(req, "No '%s' argument.", "detach");
		return;
	}

	readonly = gctl_get_paraml(req, "readonly", sizeof(*readonly));
	if (readonly == NULL) {
		gctl_error(req, "No '%s' argument.", "readonly");
		return;
	}

	name = gctl_get_asciiparam(req, "arg0");
	if (name == NULL) {
		gctl_error(req, "No 'arg%u' argument.", 0);
		return;
	}
	if (strncmp(name, "/dev/", strlen("/dev/")) == 0)
		name += strlen("/dev/");
	pp = g_provider_by_name(name);
	if (pp == NULL) {
		gctl_error(req, "Provider %s is invalid.", name);
		return;
	}
	error = g_luks_read_metadata(mp, pp, &md_raw);
	if (error != 0) {
		gctl_error(req, "Cannot read metadata from %s (error=%d).",
		    name, error);
		return;
	}
	luks_metadata_raw_to_md(&md_raw,&md);
	if (md.md_keys == 0x00) {
		bzero(&md, sizeof(md));
		gctl_error(req, "No valid keys on %s.", pp->name);
		return;
	}

	key = gctl_get_param(req, "key", &keysize);
	if (key == NULL || keysize != G_LUKS_USERKEYLEN) {
		bzero(&md, sizeof(md));
		gctl_error(req, "No '%s' argument.", "key");
		return;
	}

	error = g_luks_mkey_decrypt(&md, key, mkey, &nkey);
	bzero(key, keysize);
	if (error == -1) {
		bzero(&md, sizeof(md));
		gctl_error(req, "Wrong key for %s.", pp->name);
		return;
	} else if (error > 0) {
		bzero(&md, sizeof(md));
		gctl_error(req, "Cannot decrypt Master Key for %s (error=%d).",
		    pp->name, error);
		return;
	}
	G_LUKS_DEBUG(1, "Using Master Key %u for %s.", nkey, pp->name);

	if (*detach && *readonly) {
		bzero(&md, sizeof(md));
		gctl_error(req, "Options -d and -r are mutually exclusive.");
		return;
	}
	if (*detach)
		md.md_flags |= G_LUKS_FLAG_WO_DETACH;
	if (*readonly)
		md.md_flags |= G_LUKS_FLAG_RO;
	g_luks_create(req, mp, pp, &md, &md_raw, mkey, nkey);
	bzero(mkey, sizeof(mkey));
	bzero(&md, sizeof(md));
	bzero(&md_raw, sizeof(md_raw));
}

static struct g_luks_softc *
g_luks_find_device(struct g_class *mp, const char *prov)
{
	struct g_luks_softc *sc;
	struct g_geom *gp;
	struct g_provider *pp;
	struct g_consumer *cp;

	if (strncmp(prov, "/dev/", strlen("/dev/")) == 0)
		prov += strlen("/dev/");
	LIST_FOREACH(gp, &mp->geom, geom) {
		sc = gp->softc;
		if (sc == NULL)
			continue;
		pp = LIST_FIRST(&gp->provider);
		if (pp != NULL && strcmp(pp->name, prov) == 0)
			return (sc);
		cp = LIST_FIRST(&gp->consumer);
		if (cp != NULL && cp->provider != NULL &&
		    strcmp(cp->provider->name, prov) == 0) {
			return (sc);
		}
	}
	return (NULL);
}

static void
g_luks_ctl_detach(struct gctl_req *req, struct g_class *mp)
{
	struct g_luks_softc *sc;
	int *force, *last, *nargs, error;
	const char *prov;
	char param[16];
	int i;

	g_topology_assert();

	nargs = gctl_get_paraml(req, "nargs", sizeof(*nargs));
	if (nargs == NULL) {
		gctl_error(req, "No '%s' argument.", "nargs");
		return;
	}
	if (*nargs <= 0) {
		gctl_error(req, "Missing device(s).");
		return;
	}
	force = gctl_get_paraml(req, "force", sizeof(*force));
	if (force == NULL) {
		gctl_error(req, "No '%s' argument.", "force");
		return;
	}
	last = gctl_get_paraml(req, "last", sizeof(*last));
	if (last == NULL) {
		gctl_error(req, "No '%s' argument.", "last");
		return;
	}

	for (i = 0; i < *nargs; i++) {
		snprintf(param, sizeof(param), "arg%d", i);
		prov = gctl_get_asciiparam(req, param);
		if (prov == NULL) {
			gctl_error(req, "No 'arg%d' argument.", i);
			return;
		}
		sc = g_luks_find_device(mp, prov);
		if (sc == NULL) {
			gctl_error(req, "No such device: %s.", prov);
			return;
		}
		if (*last) {
			sc->sc_flags |= G_LUKS_FLAG_RW_DETACH;
			sc->sc_geom->access = g_luks_access;
		} else {
			error = g_luks_destroy(sc, *force ? TRUE : FALSE);
			if (error != 0) {
				gctl_error(req,
				    "Cannot destroy device %s (error=%d).",
				    sc->sc_name, error);
				return;
			}
		}
	}
}

static void
g_luks_ctl_onetime(struct gctl_req *req, struct g_class *mp)
{
	struct g_luks_metadata md;
	struct g_luks_metadata_raw md_raw;
	struct g_provider *pp;
	const char *name;
	intmax_t *keylen, *sectorsize;
	u_char mkey[G_LUKS_DATAIVKEYLEN];
	int *nargs, *detach, *notrim;

	g_topology_assert();
	bzero(&md, sizeof(md));

	nargs = gctl_get_paraml(req, "nargs", sizeof(*nargs));
	if (nargs == NULL) {
		gctl_error(req, "No '%s' argument.", "nargs");
		return;
	}
	if (*nargs != 1) {
		gctl_error(req, "Invalid number of arguments.");
		return;
	}

	strlcpy(md.md_magic, G_LUKS_MAGIC, sizeof(md.md_magic));
	md.md_version = G_LUKS_VERSION;
	md.md_flags |= G_LUKS_FLAG_ONETIME;

	detach = gctl_get_paraml(req, "detach", sizeof(*detach));
	if (detach != NULL && *detach)
		md.md_flags |= G_LUKS_FLAG_WO_DETACH;
	notrim = gctl_get_paraml(req, "notrim", sizeof(*notrim));
	if (notrim != NULL && *notrim)
		md.md_flags |= G_LUKS_FLAG_NODELETE;

	md.md_ealgo = CRYPTO_ALGORITHM_MIN - 1;
	name = gctl_get_asciiparam(req, "aalgo");
	if (name == NULL) {
		gctl_error(req, "No '%s' argument.", "aalgo");
		return;
	}
	if (*name != '\0') {
		md.md_aalgo = g_luks_str2aalgo(name);
		if (md.md_aalgo >= CRYPTO_ALGORITHM_MIN &&
		    md.md_aalgo <= CRYPTO_ALGORITHM_MAX) {
			md.md_flags |= G_LUKS_FLAG_AUTH;
		} else {
			/*
			 * For backward compatibility, check if the -a option
			 * was used to provide encryption algorithm.
			 */
			md.md_ealgo = g_luks_str2ealgo(name);
			if (md.md_ealgo < CRYPTO_ALGORITHM_MIN ||
			    md.md_ealgo > CRYPTO_ALGORITHM_MAX) {
				gctl_error(req,
				    "Invalid authentication algorithm.");
				return;
			} else {
				gctl_error(req, "warning: The -e option, not "
				    "the -a option is now used to specify "
				    "encryption algorithm to use.");
			}
		}
	}

	if (md.md_ealgo < CRYPTO_ALGORITHM_MIN ||
	    md.md_ealgo > CRYPTO_ALGORITHM_MAX) {
		name = gctl_get_asciiparam(req, "ealgo");
		if (name == NULL) {
			gctl_error(req, "No '%s' argument.", "ealgo");
			return;
		}
		md.md_ealgo = g_luks_str2ealgo(name);
		if (md.md_ealgo < CRYPTO_ALGORITHM_MIN ||
		    md.md_ealgo > CRYPTO_ALGORITHM_MAX) {
			gctl_error(req, "Invalid encryption algorithm.");
			return;
		}
	}

	keylen = gctl_get_paraml(req, "keylen", sizeof(*keylen));
	if (keylen == NULL) {
		gctl_error(req, "No '%s' argument.", "keylen");
		return;
	}
	md.md_keylen = g_luks_keylen(md.md_ealgo, *keylen);
	if (md.md_keylen == 0) {
		gctl_error(req, "Invalid '%s' argument.", "keylen");
		return;
	}

	/* Not important here. */
	md.md_provsize = 0;
	/* Not important here. */
	bzero(md.md_salt, sizeof(md.md_salt));

	md.md_keys = 0x01;
	arc4rand(mkey, sizeof(mkey), 0);

	/* Not important here. */
	bzero(md.md_hash, sizeof(md.md_hash));

	name = gctl_get_asciiparam(req, "arg0");
	if (name == NULL) {
		gctl_error(req, "No 'arg%u' argument.", 0);
		return;
	}
	if (strncmp(name, "/dev/", strlen("/dev/")) == 0)
		name += strlen("/dev/");
	pp = g_provider_by_name(name);
	if (pp == NULL) {
		gctl_error(req, "Provider %s is invalid.", name);
		return;
	}

	sectorsize = gctl_get_paraml(req, "sectorsize", sizeof(*sectorsize));
	if (sectorsize == NULL) {
		gctl_error(req, "No '%s' argument.", "sectorsize");
		return;
	}
	if (*sectorsize == 0)
		md.md_sectorsize = pp->sectorsize;
	else {
		if (*sectorsize < 0 || (*sectorsize % pp->sectorsize) != 0) {
			gctl_error(req, "Invalid sector size.");
			return;
		}
		if (*sectorsize > PAGE_SIZE) {
			gctl_error(req, "warning: Using sectorsize bigger than "
			    "the page size!");
		}
		md.md_sectorsize = *sectorsize;
	}

	g_luks_create(req, mp, pp, &md, &md_raw, mkey, -1);
	bzero(mkey, sizeof(mkey));
	bzero(&md, sizeof(md));
	bzero(&md_raw, sizeof(md_raw));
}

static void
g_luks_ctl_configure(struct gctl_req *req, struct g_class *mp)
{
	struct g_luks_softc *sc;
	struct g_luks_metadata_raw md_raw;
	struct g_luks_metadata md;
	struct g_provider *pp;
	struct g_consumer *cp;
	char param[16];
	const char *prov;
	u_char *sector;
	int *nargs, *boot, *noboot, *trim, *notrim, *gluksboot, *nogluksboot;
	int *displaypass, *nodisplaypass;
	int zero, error, changed;
	u_int i;

	g_topology_assert();

	changed = 0;
	zero = 0;

	nargs = gctl_get_paraml(req, "nargs", sizeof(*nargs));
	if (nargs == NULL) {
		gctl_error(req, "No '%s' argument.", "nargs");
		return;
	}
	if (*nargs <= 0) {
		gctl_error(req, "Missing device(s).");
		return;
	}

	boot = gctl_get_paraml(req, "boot", sizeof(*boot));
	if (boot == NULL)
		boot = &zero;
	noboot = gctl_get_paraml(req, "noboot", sizeof(*noboot));
	if (noboot == NULL)
		noboot = &zero;
	if (*boot && *noboot) {
		gctl_error(req, "Options -b and -B are mutually exclusive.");
		return;
	}
	if (*boot || *noboot)
		changed = 1;

	trim = gctl_get_paraml(req, "trim", sizeof(*trim));
	if (trim == NULL)
		trim = &zero;
	notrim = gctl_get_paraml(req, "notrim", sizeof(*notrim));
	if (notrim == NULL)
		notrim = &zero;
	if (*trim && *notrim) {
		gctl_error(req, "Options -t and -T are mutually exclusive.");
		return;
	}
	if (*trim || *notrim)
		changed = 1;

	gluksboot = gctl_get_paraml(req, "gluksboot", sizeof(*gluksboot));
	if (gluksboot == NULL)
		gluksboot = &zero;
	nogluksboot = gctl_get_paraml(req, "nogluksboot", sizeof(*nogluksboot));
	if (nogluksboot == NULL)
		nogluksboot = &zero;
	if (*gluksboot && *nogluksboot) {
		gctl_error(req, "Options -g and -G are mutually exclusive.");
		return;
	}
	if (*gluksboot || *nogluksboot)
		changed = 1;

	displaypass = gctl_get_paraml(req, "displaypass", sizeof(*displaypass));
	if (displaypass == NULL)
		displaypass = &zero;
	nodisplaypass = gctl_get_paraml(req, "nodisplaypass", sizeof(*nodisplaypass));
	if (nodisplaypass == NULL)
		nodisplaypass = &zero;
	if (*displaypass && *nodisplaypass) {
		gctl_error(req, "Options -d and -D are mutually exclusive.");
		return;
	}
	if (*displaypass || *nodisplaypass)
		changed = 1;

	if (!changed) {
		gctl_error(req, "No option given.");
		return;
	}

	for (i = 0; i < *nargs; i++) {
		snprintf(param, sizeof(param), "arg%d", i);
		prov = gctl_get_asciiparam(req, param);
		if (prov == NULL) {
			gctl_error(req, "No 'arg%d' argument.", i);
			return;
		}
		sc = g_luks_find_device(mp, prov);
		if (sc == NULL) {
			/*
			 * We ignore not attached providers, userland part will
			 * take care of them.
			 */
			G_LUKS_DEBUG(1, "Skipping configuration of not attached "
			    "provider %s.", prov);
			continue;
		}
		if (sc->sc_flags & G_LUKS_FLAG_RO) {
			gctl_error(req, "Cannot change configuration of "
			    "read-only provider %s.", prov);
			continue;
		}

		if (*boot && (sc->sc_flags & G_LUKS_FLAG_BOOT)) {
			G_LUKS_DEBUG(1, "BOOT flag already configured for %s.",
			    prov);
			continue;
		} else if (*noboot && !(sc->sc_flags & G_LUKS_FLAG_BOOT)) {
			G_LUKS_DEBUG(1, "BOOT flag not configured for %s.",
			    prov);
			continue;
		}

		if (*notrim && (sc->sc_flags & G_LUKS_FLAG_NODELETE)) {
			G_LUKS_DEBUG(1, "TRIM disable flag already configured for %s.",
			    prov);
			continue;
		} else if (*trim && !(sc->sc_flags & G_LUKS_FLAG_NODELETE)) {
			G_LUKS_DEBUG(1, "TRIM disable flag not configured for %s.",
			    prov);
			continue;
		}

		if (*gluksboot && (sc->sc_flags & G_LUKS_FLAG_GLUKSBOOT)) {
			G_LUKS_DEBUG(1, "GLUKSBOOT flag already configured for %s.",
			    prov);
			continue;
		} else if (*nogluksboot && !(sc->sc_flags & G_LUKS_FLAG_GLUKSBOOT)) {
			G_LUKS_DEBUG(1, "GLUKSBOOT flag not configured for %s.",
			    prov);
			continue;
		}

		if (*displaypass && (sc->sc_flags & G_LUKS_FLAG_GLUKSDISPLAYPASS)) {
			G_LUKS_DEBUG(1, "GLUKSDISPLAYPASS flag already configured for %s.",
			    prov);
			continue;
		} else if (*nodisplaypass &&
		    !(sc->sc_flags & G_LUKS_FLAG_GLUKSDISPLAYPASS)) {
			G_LUKS_DEBUG(1, "GLUKSDISPLAYPASS flag not configured for %s.",
			    prov);
			continue;
		}

		if (!(sc->sc_flags & G_LUKS_FLAG_ONETIME)) {
			/*
			 * ONETIME providers don't write metadata to
			 * disk, so don't try reading it.  This means
			 * we're bit-flipping uninitialized memory in md
			 * below, but that's OK; we don't do anything
			 * with it later.
			 */
			cp = LIST_FIRST(&sc->sc_geom->consumer);
			pp = cp->provider;
			error = g_luks_read_metadata(mp, pp, &md_raw);
			if (error != 0) {
			    gctl_error(req,
				"Cannot read metadata from %s (error=%d).",
				prov, error);
			    continue;
			}
			luks_metadata_raw_to_md(&md_raw,&md);
		}

		if (*boot) {
			md.md_flags |= G_LUKS_FLAG_BOOT;
			sc->sc_flags |= G_LUKS_FLAG_BOOT;
		} else if (*noboot) {
			md.md_flags &= ~G_LUKS_FLAG_BOOT;
			sc->sc_flags &= ~G_LUKS_FLAG_BOOT;
		}

		if (*notrim) {
			md.md_flags |= G_LUKS_FLAG_NODELETE;
			sc->sc_flags |= G_LUKS_FLAG_NODELETE;
		} else if (*trim) {
			md.md_flags &= ~G_LUKS_FLAG_NODELETE;
			sc->sc_flags &= ~G_LUKS_FLAG_NODELETE;
		}

		if (*gluksboot) {
			md.md_flags |= G_LUKS_FLAG_GLUKSBOOT;
			sc->sc_flags |= G_LUKS_FLAG_GLUKSBOOT;
		} else if (*nogluksboot) {
			md.md_flags &= ~G_LUKS_FLAG_GLUKSBOOT;
			sc->sc_flags &= ~G_LUKS_FLAG_GLUKSBOOT;
		}

		if (*displaypass) {
			md.md_flags |= G_LUKS_FLAG_GLUKSDISPLAYPASS;
			sc->sc_flags |= G_LUKS_FLAG_GLUKSDISPLAYPASS;
		} else if (*nodisplaypass) {
			md.md_flags &= ~G_LUKS_FLAG_GLUKSDISPLAYPASS;
			sc->sc_flags &= ~G_LUKS_FLAG_GLUKSDISPLAYPASS;
		}

		if (sc->sc_flags & G_LUKS_FLAG_ONETIME) {
			/* There's no metadata on disk so we are done here. */
			continue;
		}

		sector = malloc(pp->sectorsize, M_LUKS, M_WAITOK | M_ZERO);
		luks_metadata_encode(&md, sector);
//		error = g_write_data(cp, pp->mediasize - pp->sectorsize, sector,
//		    pp->sectorsize);
		// LUKS metadata is at the beginning of the disk
		error = g_write_data(cp, 0, sector, pp->sectorsize);
		if (error != 0) {
			gctl_error(req,
			    "Cannot store metadata on %s (error=%d).",
			    prov, error);
		}
		bzero(&md, sizeof(md));
		bzero(sector, pp->sectorsize);
		free(sector, M_LUKS);
	}
}

static void
g_luks_ctl_setkey(struct gctl_req *req, struct g_class *mp)
{
	struct g_luks_softc *sc;
	struct g_luks_metadata_raw md_raw;
	struct g_luks_metadata md;
	struct g_provider *pp;
	struct g_consumer *cp;
	const char *name;
	u_char *key, *mkeydst, *sector;
	intmax_t *valp;
	int keysize, nkey, error;

	g_topology_assert();

	name = gctl_get_asciiparam(req, "arg0");
	if (name == NULL) {
		gctl_error(req, "No 'arg%u' argument.", 0);
		return;
	}
	sc = g_luks_find_device(mp, name);
	if (sc == NULL) {
		gctl_error(req, "Provider %s is invalid.", name);
		return;
	}
	if (sc->sc_flags & G_LUKS_FLAG_RO) {
		gctl_error(req, "Cannot change keys for read-only provider.");
		return;
	}
	cp = LIST_FIRST(&sc->sc_geom->consumer);
	pp = cp->provider;

	error = g_luks_read_metadata(mp, pp, &md_raw);
	if (error != 0) {
		gctl_error(req, "Cannot read metadata from %s (error=%d).",
		    name, error);
		return;
	}
	luks_metadata_raw_to_md(&md_raw,&md);

	valp = gctl_get_paraml(req, "keyno", sizeof(*valp));
	if (valp == NULL) {
		gctl_error(req, "No '%s' argument.", "keyno");
		return;
	}
	if (*valp != -1)
		nkey = *valp;
	else
		nkey = sc->sc_nkey;
	if (nkey < 0 || nkey >= G_LUKS_MAXMKEYS) {
		gctl_error(req, "Invalid '%s' argument.", "keyno");
		return;
	}

	valp = gctl_get_paraml(req, "iterations", sizeof(*valp));
	if (valp == NULL) {
		gctl_error(req, "No '%s' argument.", "iterations");
		return;
	}
	/* Check if iterations number should and can be changed. */
	if (*valp != -1 && md.md_iterations == -1) {
		md.md_iterations = *valp;
	} else if (*valp != -1 && *valp != md.md_iterations) {
		if (bitcount32(md.md_keys) != 1) {
			gctl_error(req, "To be able to use '-i' option, only "
			    "one key can be defined.");
			return;
		}
		if (md.md_keys != (1 << nkey)) {
			gctl_error(req, "Only already defined key can be "
			    "changed when '-i' option is used.");
			return;
		}
		md.md_iterations = *valp;
	}

	key = gctl_get_param(req, "key", &keysize);
	if (key == NULL || keysize != G_LUKS_USERKEYLEN) {
		bzero(&md, sizeof(md));
		gctl_error(req, "No '%s' argument.", "key");
		return;
	}

	mkeydst = md.md_mkeys + nkey * G_LUKS_MKEYLEN;
	md.md_keys |= (1 << nkey);

	bcopy(sc->sc_mkey, mkeydst, sizeof(sc->sc_mkey));

	/* Encrypt Master Key with the new key. */
	error = g_luks_mkey_encrypt(md.md_ealgo, key, md.md_keylen, mkeydst);
	bzero(key, keysize);
	if (error != 0) {
		bzero(&md, sizeof(md));
		gctl_error(req, "Cannot encrypt Master Key (error=%d).", error);
		return;
	}

	sector = malloc(pp->sectorsize, M_LUKS, M_WAITOK | M_ZERO);
	/* Store metadata with fresh key. */
	luks_metadata_encode(&md, sector);
	bzero(&md, sizeof(md));
//	error = g_write_data(cp, pp->mediasize - pp->sectorsize, sector,
//	    pp->sectorsize);
	// LUKS metadata is at the beginning of the disk
	error = g_write_data(cp, 0, sector, pp->sectorsize);
	bzero(sector, pp->sectorsize);
	free(sector, M_LUKS);
	if (error != 0) {
		gctl_error(req, "Cannot store metadata on %s (error=%d).",
		    pp->name, error);
		return;
	}
	G_LUKS_DEBUG(1, "Key %u changed on %s.", nkey, pp->name);
}

static void
g_luks_ctl_delkey(struct gctl_req *req, struct g_class *mp)
{
	struct g_luks_softc *sc;
	struct g_luks_metadata_raw md_raw;
	struct g_luks_metadata md;
	struct g_provider *pp;
	struct g_consumer *cp;
	const char *name;
	u_char *mkeydst, *sector;
	intmax_t *valp;
	size_t keysize;
	int error, nkey, *all, *force;
	u_int i;

	g_topology_assert();

	nkey = 0;	/* fixes causeless gcc warning */

	name = gctl_get_asciiparam(req, "arg0");
	if (name == NULL) {
		gctl_error(req, "No 'arg%u' argument.", 0);
		return;
	}
	sc = g_luks_find_device(mp, name);
	if (sc == NULL) {
		gctl_error(req, "Provider %s is invalid.", name);
		return;
	}
	if (sc->sc_flags & G_LUKS_FLAG_RO) {
		gctl_error(req, "Cannot delete keys for read-only provider.");
		return;
	}
	cp = LIST_FIRST(&sc->sc_geom->consumer);
	pp = cp->provider;

	error = g_luks_read_metadata(mp, pp, &md_raw);
	if (error != 0) {
		gctl_error(req, "Cannot read metadata from %s (error=%d).",
		    name, error);
		return;
	}
	luks_metadata_raw_to_md(&md_raw,&md);

	all = gctl_get_paraml(req, "all", sizeof(*all));
	if (all == NULL) {
		gctl_error(req, "No '%s' argument.", "all");
		return;
	}

	if (*all) {
		mkeydst = md.md_mkeys;
		keysize = sizeof(md.md_mkeys);
	} else {
		force = gctl_get_paraml(req, "force", sizeof(*force));
		if (force == NULL) {
			gctl_error(req, "No '%s' argument.", "force");
			return;
		}

		valp = gctl_get_paraml(req, "keyno", sizeof(*valp));
		if (valp == NULL) {
			gctl_error(req, "No '%s' argument.", "keyno");
			return;
		}
		if (*valp != -1)
			nkey = *valp;
		else
			nkey = sc->sc_nkey;
		if (nkey < 0 || nkey >= G_LUKS_MAXMKEYS) {
			gctl_error(req, "Invalid '%s' argument.", "keyno");
			return;
		}
		if (!(md.md_keys & (1 << nkey)) && !*force) {
			gctl_error(req, "Master Key %u is not set.", nkey);
			return;
		}
		md.md_keys &= ~(1 << nkey);
		if (md.md_keys == 0 && !*force) {
			gctl_error(req, "This is the last Master Key. Use '-f' "
			    "flag if you really want to remove it.");
			return;
		}
		mkeydst = md.md_mkeys + nkey * G_LUKS_MKEYLEN;
		keysize = G_LUKS_MKEYLEN;
	}

	sector = malloc(pp->sectorsize, M_LUKS, M_WAITOK | M_ZERO);
	for (i = 0; i <= g_luks_overwrites; i++) {
		if (i == g_luks_overwrites)
			bzero(mkeydst, keysize);
		else
			arc4rand(mkeydst, keysize, 0);
		/* Store metadata with destroyed key. */
		luks_metadata_encode(&md, sector);
//		error = g_write_data(cp, pp->mediasize - pp->sectorsize, sector,
//		    pp->sectorsize);
		// LUKS metadata is at the beginning of the disk
		error = g_write_data(cp, 0, sector, pp->sectorsize);
		if (error != 0) {
			G_LUKS_DEBUG(0, "Cannot store metadata on %s "
			    "(error=%d).", pp->name, error);
		}
		/*
		 * Flush write cache so we don't overwrite data N times in cache
		 * and only once on disk.
		 */
		(void)g_io_flush(cp);
	}
	bzero(&md, sizeof(md));
	bzero(sector, pp->sectorsize);
	free(sector, M_LUKS);
	if (*all)
		G_LUKS_DEBUG(1, "All keys removed from %s.", pp->name);
	else
		G_LUKS_DEBUG(1, "Key %d removed from %s.", nkey, pp->name);
}

static void
g_luks_suspend_one(struct g_luks_softc *sc, struct gctl_req *req)
{
	struct g_luks_worker *wr;

	g_topology_assert();

	KASSERT(sc != NULL, ("NULL sc"));

	if (sc->sc_flags & G_LUKS_FLAG_ONETIME) {
		gctl_error(req,
		    "Device %s is using one-time key, suspend not supported.",
		    sc->sc_name);
		return;
	}

	mtx_lock(&sc->sc_queue_mtx);
	if (sc->sc_flags & G_LUKS_FLAG_SUSPEND) {
		mtx_unlock(&sc->sc_queue_mtx);
		gctl_error(req, "Device %s already suspended.",
		    sc->sc_name);
		return;
	}
	sc->sc_flags |= G_LUKS_FLAG_SUSPEND;
	wakeup(sc);
	for (;;) {
		LIST_FOREACH(wr, &sc->sc_workers, w_next) {
			if (wr->w_active)
				break;
		}
		if (wr == NULL)
			break;
		/* Not all threads suspended. */
		msleep(&sc->sc_workers, &sc->sc_queue_mtx, PRIBIO,
		    "gluks:suspend", 0);
	}
	/*
	 * Clear sensitive data on suspend, they will be recovered on resume.
	 */
	bzero(sc->sc_mkey, sizeof(sc->sc_mkey));
	g_luks_key_destroy(sc);
	bzero(sc->sc_akey, sizeof(sc->sc_akey));
	bzero(&sc->sc_akeyctx, sizeof(sc->sc_akeyctx));
	bzero(sc->sc_ivkey, sizeof(sc->sc_ivkey));
	bzero(&sc->sc_ivctx, sizeof(sc->sc_ivctx));
	mtx_unlock(&sc->sc_queue_mtx);
	G_LUKS_DEBUG(0, "Device %s has been suspended.", sc->sc_name);
}

static void
g_luks_ctl_suspend(struct gctl_req *req, struct g_class *mp)
{
	struct g_luks_softc *sc;
	int *all, *nargs;

	g_topology_assert();

	nargs = gctl_get_paraml(req, "nargs", sizeof(*nargs));
	if (nargs == NULL) {
		gctl_error(req, "No '%s' argument.", "nargs");
		return;
	}
	all = gctl_get_paraml(req, "all", sizeof(*all));
	if (all == NULL) {
		gctl_error(req, "No '%s' argument.", "all");
		return;
	}
	if (!*all && *nargs == 0) {
		gctl_error(req, "Too few arguments.");
		return;
	}

	if (*all) {
		struct g_geom *gp, *gp2;

		LIST_FOREACH_SAFE(gp, &mp->geom, geom, gp2) {
			sc = gp->softc;
			if (sc->sc_flags & G_LUKS_FLAG_ONETIME) {
				G_LUKS_DEBUG(0,
				    "Device %s is using one-time key, suspend not supported, skipping.",
				    sc->sc_name);
				continue;
			}
			g_luks_suspend_one(sc, req);
		}
	} else {
		const char *prov;
		char param[16];
		int i;

		for (i = 0; i < *nargs; i++) {
			snprintf(param, sizeof(param), "arg%d", i);
			prov = gctl_get_asciiparam(req, param);
			if (prov == NULL) {
				G_LUKS_DEBUG(0, "No 'arg%d' argument.", i);
				continue;
			}

			sc = g_luks_find_device(mp, prov);
			if (sc == NULL) {
				G_LUKS_DEBUG(0, "No such provider: %s.", prov);
				continue;
			}
			g_luks_suspend_one(sc, req);
		}
	}
}

static void
g_luks_ctl_resume(struct gctl_req *req, struct g_class *mp)
{
	struct g_luks_metadata_raw md_raw;
	struct g_luks_metadata md;
	struct g_luks_softc *sc;
	struct g_provider *pp;
	struct g_consumer *cp;
	const char *name;
	u_char *key, mkey[G_LUKS_DATAIVKEYLEN];
	int *nargs, keysize, error;
	u_int nkey;

	g_topology_assert();

	nargs = gctl_get_paraml(req, "nargs", sizeof(*nargs));
	if (nargs == NULL) {
		gctl_error(req, "No '%s' argument.", "nargs");
		return;
	}
	if (*nargs != 1) {
		gctl_error(req, "Invalid number of arguments.");
		return;
	}

	name = gctl_get_asciiparam(req, "arg0");
	if (name == NULL) {
		gctl_error(req, "No 'arg%u' argument.", 0);
		return;
	}
	sc = g_luks_find_device(mp, name);
	if (sc == NULL) {
		gctl_error(req, "Provider %s is invalid.", name);
		return;
	}
	cp = LIST_FIRST(&sc->sc_geom->consumer);
	pp = cp->provider;
	error = g_luks_read_metadata(mp, pp, &md_raw);
	if (error != 0) {
		gctl_error(req, "Cannot read metadata from %s (error=%d).",
		    name, error);
		return;
	}
	
	luks_metadata_raw_to_md(&md_raw,&md);

	if (md.md_keys == 0x00) {
		bzero(&md, sizeof(md));
		gctl_error(req, "No valid keys on %s.", pp->name);
		return;
	}

	key = gctl_get_param(req, "key", &keysize);
	if (key == NULL || keysize != G_LUKS_USERKEYLEN) {
		bzero(&md, sizeof(md));
		gctl_error(req, "No '%s' argument.", "key");
		return;
	}

	error = g_luks_mkey_decrypt(&md, key, mkey, &nkey);
	bzero(key, keysize);
	if (error == -1) {
		bzero(&md, sizeof(md));
		gctl_error(req, "Wrong key for %s.", pp->name);
		return;
	} else if (error > 0) {
		bzero(&md, sizeof(md));
		gctl_error(req, "Cannot decrypt Master Key for %s (error=%d).",
		    pp->name, error);
		return;
	}
	G_LUKS_DEBUG(1, "Using Master Key %u for %s.", nkey, pp->name);

	mtx_lock(&sc->sc_queue_mtx);
	if (!(sc->sc_flags & G_LUKS_FLAG_SUSPEND))
		gctl_error(req, "Device %s is not suspended.", name);
	else {
		/* Restore sc_mkey, sc_ekeys, sc_akey and sc_ivkey. */
		g_luks_mkey_propagate(sc, mkey);
		sc->sc_flags &= ~G_LUKS_FLAG_SUSPEND;
		G_LUKS_DEBUG(1, "Resumed %s.", pp->name);
		wakeup(sc);
	}
	mtx_unlock(&sc->sc_queue_mtx);
	bzero(mkey, sizeof(mkey));
	bzero(&md, sizeof(md));
}

static int
g_luks_kill_one(struct g_luks_softc *sc)
{
	struct g_provider *pp;
	struct g_consumer *cp;
	int error = 0;

	g_topology_assert();

	if (sc == NULL)
		return (ENOENT);

	pp = LIST_FIRST(&sc->sc_geom->provider);
	g_error_provider(pp, ENXIO);

	cp = LIST_FIRST(&sc->sc_geom->consumer);
	pp = cp->provider;

	if (sc->sc_flags & G_LUKS_FLAG_RO) {
		G_LUKS_DEBUG(0, "WARNING: Metadata won't be erased on read-only "
		    "provider: %s.", pp->name);
	} else {
		u_char *sector;
		u_int i;
		int err;

		sector = malloc(pp->sectorsize, M_LUKS, M_WAITOK);
		for (i = 0; i <= g_luks_overwrites; i++) {
			if (i == g_luks_overwrites)
				bzero(sector, pp->sectorsize);
			else
				arc4rand(sector, pp->sectorsize, 0);
//			err = g_write_data(cp, pp->mediasize - pp->sectorsize,
//			    sector, pp->sectorsize);
			// LUKS metadata is at the beginning of the disk
			err = g_write_data(cp, 0, sector, pp->sectorsize);
			if (err != 0) {
				G_LUKS_DEBUG(0, "Cannot erase metadata on %s "
				    "(error=%d).", pp->name, err);
				if (error == 0)
					error = err;
			}
			/*
			 * Flush write cache so we don't overwrite data N times
			 * in cache and only once on disk.
			 */
			(void)g_io_flush(cp);
		}
		free(sector, M_LUKS);
	}
	if (error == 0)
		G_LUKS_DEBUG(0, "%s has been killed.", pp->name);
	g_luks_destroy(sc, TRUE);
	return (error);
}

static void
g_luks_ctl_kill(struct gctl_req *req, struct g_class *mp)
{
	int *all, *nargs;
	int error;

	g_topology_assert();

	nargs = gctl_get_paraml(req, "nargs", sizeof(*nargs));
	if (nargs == NULL) {
		gctl_error(req, "No '%s' argument.", "nargs");
		return;
	}
	all = gctl_get_paraml(req, "all", sizeof(*all));
	if (all == NULL) {
		gctl_error(req, "No '%s' argument.", "all");
		return;
	}
	if (!*all && *nargs == 0) {
		gctl_error(req, "Too few arguments.");
		return;
	}

	if (*all) {
		struct g_geom *gp, *gp2;

		LIST_FOREACH_SAFE(gp, &mp->geom, geom, gp2) {
			error = g_luks_kill_one(gp->softc);
			if (error != 0)
				gctl_error(req, "Not fully done.");
		}
	} else {
		struct g_luks_softc *sc;
		const char *prov;
		char param[16];
		int i;

		for (i = 0; i < *nargs; i++) {
			snprintf(param, sizeof(param), "arg%d", i);
			prov = gctl_get_asciiparam(req, param);
			if (prov == NULL) {
				G_LUKS_DEBUG(0, "No 'arg%d' argument.", i);
				continue;
			}

			sc = g_luks_find_device(mp, prov);
			if (sc == NULL) {
				G_LUKS_DEBUG(0, "No such provider: %s.", prov);
				continue;
			}
			error = g_luks_kill_one(sc);
			if (error != 0)
				gctl_error(req, "Not fully done.");
		}
	}
}



static void
g_luks_ctl_test_passphrase(struct gctl_req *req, struct g_class *mp)
{
	struct g_luks_metadata_raw md_raw;
	struct g_luks_metadata md;
	struct g_provider *pp;
	const char *name;
	u_char *passphrase, mkey[G_LUKS_MAXKEYLEN];
	int *nargs, *detach, *readonly;
	int passsize, error, i;
	size_t splitted_key_length;
	u_int nkey = 0;

	g_topology_assert();

	nargs = gctl_get_paraml(req, "nargs", sizeof(*nargs));
	if (nargs == NULL) {
		gctl_error(req, "No '%s' argument.", "nargs");
		return;
	}
	if (*nargs != 1) {
		gctl_error(req, "Invalid number of arguments.");
		return;
	}

	detach = gctl_get_paraml(req, "detach", sizeof(*detach));
	if (detach == NULL) {
		gctl_error(req, "No '%s' argument.", "detach");
		return;
	}

	readonly = gctl_get_paraml(req, "readonly", sizeof(*readonly));
	if (readonly == NULL) {
		gctl_error(req, "No '%s' argument.", "readonly");
		return;
	}

	name = gctl_get_asciiparam(req, "arg0");
	if (name == NULL) {
		gctl_error(req, "No 'arg%u' argument.", 0);
		return;
	}
	if (strncmp(name, "/dev/", strlen("/dev/")) == 0)
		name += strlen("/dev/");
	pp = g_provider_by_name(name);
	if (pp == NULL) {
		gctl_error(req, "Provider %s is invalid.", name);
		return;
	}
	error = g_luks_read_metadata(mp, pp, &md_raw);
	if (error != 0) {
		gctl_error(req, "Cannot read metadata from %s (error=%d).",
		    name, error);
		return;
	}

	luks_metadata_raw_to_md(&md_raw,&md);

	for (i=0;i<LUKS_NUMKEYS;i++) {
		if(md_raw.md_keyslot[i].active	== LUKS_KEY_ENABLED) {
			nkey++;
		}
	}

	if (nkey == 0) {
		bzero(&md_raw, sizeof(md_raw));
		gctl_error(req, "No valid keys on %s.", pp->name);
		return;
	}

	passphrase = gctl_get_param(req, "passphrase", &passsize);
	if (passphrase == NULL || passsize != G_LUKS_PASSLEN) {
		bzero(&md_raw, sizeof(md_raw));
		gctl_error(req, "No '%s' argument.", "passphrase");
		return;
	}
	nkey=0;
	error=-1;
	while (nkey<LUKS_NUMKEYS && error != 0){

		if(md_raw.md_keyslot[nkey].active == LUKS_KEY_ENABLED){

			splitted_key_length = af_splitted_size(md_raw.md_keybytes,md_raw.md_keyslot[nkey].stripes) * pp->sectorsize;

			char *keymaterial = malloc(splitted_key_length,M_LUKS,M_WAITOK);
			error = g_luks_read_keymaterial(mp,pp,md_raw.md_keyslot[nkey].keymaterialoffset,splitted_key_length,keymaterial);
			if (error != 0) {
				free(keymaterial,M_LUKS);
				gctl_error(req, "Cannot read material from %s (error=%d).",
				    name, error);
				return;
			}

			error = g_luks_mkey_decrypt_raw(&md_raw, &md, keymaterial, passphrase, mkey, nkey);

			if (error > 0) {
				bzero(&md_raw, sizeof(md_raw));
				free(keymaterial,M_LUKS);
				gctl_error(req, "Cannot decrypt Master Key for %s (error=%d).",pp->name, error);
				return;
			}
			bzero(keymaterial, sizeof(*keymaterial));
			free(keymaterial,M_LUKS);
		}
		nkey++;
	}
	nkey--;
	bzero(passphrase, sizeof(*passphrase));
	if (error == -1) {
		bzero(&md_raw, sizeof(md_raw));
		gctl_error(req, "Wrong passphrase for %s.", pp->name);
		return;
	}
	G_LUKS_DEBUG(1, "Using Master Key %u for %s.", nkey , pp->name);

	if (*detach && *readonly) {
		bzero(&md_raw, sizeof(md_raw));
		gctl_error(req, "Options -d and -r are mutually exclusive.");
		return;
	}
	if (*detach)
		md.md_flags |= G_LUKS_FLAG_WO_DETACH;
	if (*readonly)
		md.md_flags |= G_LUKS_FLAG_RO;
	
	g_luks_create(req, mp, pp, &md, &md_raw, mkey, nkey);
	
//	bzero(mkey, md_raw.md_keybytes);
//	free(mkey,M_LUKS);
	bzero(&md_raw, sizeof(md_raw));
	bzero(&md, sizeof(md));

}

void
g_luks_config(struct gctl_req *req, struct g_class *mp, const char *verb)
{
	uint32_t *version;

	g_topology_assert();

	version = gctl_get_paraml(req, "version", sizeof(*version));
	if (version == NULL) {
		gctl_error(req, "No '%s' argument.", "version");
		return;
	}
	while (*version != G_LUKS_VERSION) {
		if (G_LUKS_VERSION == G_LUKS_VERSION_06 &&
		    *version == G_LUKS_VERSION_05) {
			/* Compatible. */
			break;
		}
		if (G_LUKS_VERSION == G_LUKS_VERSION_07 &&
		    (*version == G_LUKS_VERSION_05 ||
		     *version == G_LUKS_VERSION_06)) {
			/* Compatible. */
			break;
		}
		gctl_error(req, "Userland and kernel parts are out of sync.");
		return;
	}

	if (strcmp(verb, "attach") == 0)
		g_luks_ctl_attach(req, mp);
	else if (strcmp(verb, "detach") == 0 || strcmp(verb, "stop") == 0)
		g_luks_ctl_detach(req, mp);
	else if (strcmp(verb, "onetime") == 0)
		g_luks_ctl_onetime(req, mp);
	else if (strcmp(verb, "configure") == 0)
		g_luks_ctl_configure(req, mp);
	else if (strcmp(verb, "setkey") == 0)
		g_luks_ctl_setkey(req, mp);
	else if (strcmp(verb, "delkey") == 0)
		g_luks_ctl_delkey(req, mp);
	else if (strcmp(verb, "suspend") == 0)
		g_luks_ctl_suspend(req, mp);
	else if (strcmp(verb, "resume") == 0)
		g_luks_ctl_resume(req, mp);
	else if (strcmp(verb, "kill") == 0)
		g_luks_ctl_kill(req, mp);
	else if (strcmp(verb,"test_passphrase") == 0)
		g_luks_ctl_test_passphrase(req, mp);
	else
		gctl_error(req, "Unknown verb.");
}
