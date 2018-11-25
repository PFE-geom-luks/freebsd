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
#include <sys/sbuf.h>
#include <sys/sysctl.h>
#include <sys/malloc.h>
#include <sys/endian.h>
#include <geom/geom.h>
#include <geom/pfe/g_pfe.h>


SYSCTL_DECL(_kern_geom);
MALLOC_DEFINE(M_PFE, "pfe data", "GEOM_PFE Data");
static SYSCTL_NODE(_kern_geom, OID_AUTO, pfe, CTLFLAG_RW, 0, "GEOM_PFE stuff");
static u_int g_pfe_debug = 0;
SYSCTL_UINT(_kern_geom_pfe, OID_AUTO, debug, CTLFLAG_RW, &g_pfe_debug, 0,
    "Debug level");

static int g_pfe_destroy(struct g_geom *gp, boolean_t force);
static int g_pfe_destroy_geom(struct gctl_req *req, struct g_class *mp,
    struct g_geom *gp);
static void g_pfe_config(struct gctl_req *req, struct g_class *mp,
    const char *verb);
static void g_pfe_dumpconf(struct sbuf *sb, const char *indent,
    struct g_geom *gp, struct g_consumer *cp, struct g_provider *pp);

struct g_class g_pfe_class = {
	.name = G_PFE_CLASS_NAME,
	.version = G_VERSION,
	.ctlreq = g_pfe_config,
	.destroy_geom = g_pfe_destroy_geom
};

static void
g_pfe_orphan_spoil_assert(struct g_consumer *cp)
{

	panic("Function %s() called for %s.", __func__, cp->geom->name);
}


static void
g_pfe_orphan(struct g_consumer *cp)
{
	g_topology_assert();
	g_pfe_destroy(cp->geom, 1);
}

static void
g_pfe_start(struct bio *bp)
{
	struct g_pfe_softc *sc;
	struct g_geom *gp;
	struct g_provider *pp;
	struct bio *cbp;
	u_int failprob = 0;
	int error = 0;

	gp = bp->bio_to->geom;
	sc = gp->softc;
	G_PFE_LOGREQ(bp, "Request received.");
	if (failprob > 0) {
		u_int rval;
		rval = arc4random() % 100;
		if (rval < failprob) {
			G_PFE_LOGREQLVL(1, bp, "Returning error=%d.", error);
			g_io_deliver(bp, error);
			return;
		}
	}
	cbp = g_clone_bio(bp);
	if (cbp == NULL) {
		g_io_deliver(bp, ENOMEM);
		return;
	}
	cbp->bio_done = g_std_done;
	cbp->bio_offset = bp->bio_offset;
	pp = LIST_FIRST(&gp->provider);
	KASSERT(pp != NULL, ("NULL pp"));
	cbp->bio_to = pp;
	G_PFE_LOGREQ(cbp, "Sending request.");
	g_io_request(cbp, LIST_FIRST(&gp->consumer));
}

static int
g_pfe_access(struct g_provider *pp, int dr, int dw, int de)
{
	struct g_geom *gp;
	struct g_consumer *cp;
	int error;

	gp = pp->geom;
	cp = LIST_FIRST(&gp->consumer);
	error = g_access(cp, dr, dw, de);

	return (error);
}


struct g_geom *
g_pfe_create(struct gctl_req *req, struct g_class *mp, struct g_provider *bpp,
    const struct g_pfe_metadata *md)
{
	struct g_pfe_softc *sc;
	struct g_geom *gp;
	struct g_provider *pp;
	struct g_consumer *cp;
	int error;

	G_PFE_DEBUG(1, "Creating device %s%s.", bpp->name, G_PFE_SUFFIX);

	gp = g_new_geomf(mp, "%s%s", bpp->name, G_PFE_SUFFIX);
	sc = malloc(sizeof(*sc), M_PFE, M_WAITOK | M_ZERO);
	gp->start = g_pfe_start;
	/*
	 * Spoiling can happen even though we have the provider open
	 * exclusively, e.g. through media change events.
	 */
	gp->spoiled = g_pfe_orphan;
	gp->orphan = g_pfe_orphan;
	gp->dumpconf = g_pfe_dumpconf;

	pfe_metadata_softc(sc, md);
	gp->softc = sc;
	sc->sc_geom = gp;

	
	pp = NULL;
	cp = g_new_consumer(gp);
	error = g_attach(cp, bpp);
	if (error != 0) {
		if (req != NULL) {
			gctl_error(req, "Cannot attach to %s (error=%d).",
			    bpp->name, error);
		} else {
			G_PFE_DEBUG(1, "Cannot attach to %s (error=%d).",
			    bpp->name, error);
		}
		goto failed;
	}

	error = g_access(cp, 1, 1, 1);
	if (error != 0) {
		if (req != NULL) {
			gctl_error(req, "Cannot access %s (error=%d).",
			    bpp->name, error);
		} else {
			G_PFE_DEBUG(1, "Cannot access %s (error=%d).",
			    bpp->name, error);
		}
		goto failed;
	}


	pp = g_new_providerf(gp, "%s%s", bpp->name, G_PFE_SUFFIX);
	g_error_provider(pp, 0);

	G_PFE_DEBUG(0, "Device %s created.", pp->name);
	return (gp);
failed:
	if (cp->provider != NULL)
		g_detach(cp);
	g_destroy_consumer(cp);
	g_destroy_provider(pp);
	g_free(gp->softc);
	g_destroy_geom(gp);
	return (NULL);
}

static int
g_pfe_destroy(struct g_geom *gp, boolean_t force)
{
	struct g_pfe_softc *sc;
	struct g_provider *pp;

	g_topology_assert();
	sc = gp->softc;
	if (sc == NULL)
		return (ENXIO);
	pp = LIST_FIRST(&gp->provider);
	if (pp != NULL && (pp->acr != 0 || pp->acw != 0 || pp->ace != 0)) {
		if (force) {
			G_PFE_DEBUG(0, "Device %s is still open, so it "
			    "can't be definitely removed.", pp->name);
		} else {
			G_PFE_DEBUG(1, "Device %s is still open (r%dw%de%d).",
			    pp->name, pp->acr, pp->acw, pp->ace);
			return (EBUSY);
		}
	} else {
		G_PFE_DEBUG(0, "Device %s removed.", gp->name);
	}
	gp->softc = NULL;
	g_free(sc);
	g_wither_geom(gp, ENXIO);
	return (0);
}

static int
g_pfe_destroy_geom(struct gctl_req *req, struct g_class *mp, struct g_geom *gp)
{

	return (g_pfe_destroy(gp, 0));
}

static void
g_pfe_ctl_create(struct gctl_req *req, struct g_class *mp)
{
	struct g_provider *pp;
	struct g_pfe_metadata *md;
	int i, *nargs;
	intmax_t *error;
	char param[16];
	const char *name;

	g_topology_assert();

	nargs = gctl_get_paraml(req, "nargs", sizeof(*nargs));
	if (nargs == NULL) {
		gctl_error(req, "No '%s' argument", "nargs");
		return;
	}
	if (*nargs <= 0) {
		gctl_error(req, "Missing device(s).");
		return;
	}
	error = gctl_get_paraml(req, "error", sizeof(*error));
	if (error == NULL) {
		gctl_error(req, "No '%s' argument", "error");
		return;
	}
	for (i = 0; i < *nargs; i++) {
		snprintf(param, sizeof(param), "arg%d", i);
		name = gctl_get_asciiparam(req, param);
		if (name == NULL) {
			gctl_error(req, "No 'arg%d' argument", i);
			return;
		}
		if (strncmp(name, "/dev/", strlen("/dev/")) == 0)
			name += strlen("/dev/");
		pp = g_provider_by_name(name);
		if (pp == NULL) {
			G_PFE_DEBUG(1, "Provider %s is invalid.", name);
			gctl_error(req, "Provider %s is invalid.", name);
			return;
		}
		if (g_pfe_create(req, mp, pp, md) != 0) {
			return;
		}
	}
}

static void
g_pfe_ctl_configure(struct gctl_req *req, struct g_class *mp)
{
	struct g_pfe_softc *sc;
	struct g_provider *pp;
	int i, *nargs;
	char param[16];
	intmax_t *error;
	const char *name;

	g_topology_assert();

	nargs = gctl_get_paraml(req, "nargs", sizeof(*nargs));
	if (nargs == NULL) {
		gctl_error(req, "No '%s' argument", "nargs");
		return;
	}
	if (*nargs <= 0) {
		gctl_error(req, "Missing device(s).");
		return;
	}
	error = gctl_get_paraml(req, "error", sizeof(*error));
	if (error == NULL) {
		gctl_error(req, "No '%s' argument", "error");
		return;
	}

	for (i = 0; i < *nargs; i++) {
		snprintf(param, sizeof(param), "arg%d", i);
		name = gctl_get_asciiparam(req, param);
		if (name == NULL) {
			gctl_error(req, "No 'arg%d' argument", i);
			return;
		}
		if (strncmp(name, "/dev/", strlen("/dev/")) == 0)
			name += strlen("/dev/");
		pp = g_provider_by_name(name);
		if (pp == NULL || pp->geom->class != mp) {
			G_PFE_DEBUG(1, "Provider %s is invalid.", name);
			gctl_error(req, "Provider %s is invalid.", name);
			return;
		}
		sc = pp->geom->softc;
	}
}

static struct g_geom *
g_pfe_find_geom(struct g_class *mp, const char *name)
{
	struct g_geom *gp;

	LIST_FOREACH(gp, &mp->geom, geom) {
		if (strcmp(gp->name, name) == 0)
			return (gp);
	}
	return (NULL);
}

static void
g_pfe_ctl_destroy(struct gctl_req *req, struct g_class *mp)
{
	int *nargs, *force, error, i;
	struct g_geom *gp;
	const char *name;
	char param[16];

	g_topology_assert();

	nargs = gctl_get_paraml(req, "nargs", sizeof(*nargs));
	if (nargs == NULL) {
		gctl_error(req, "No '%s' argument", "nargs");
		return;
	}
	if (*nargs <= 0) {
		gctl_error(req, "Missing device(s).");
		return;
	}
	force = gctl_get_paraml(req, "force", sizeof(*force));
	if (force == NULL) {
		gctl_error(req, "No 'force' argument");
		return;
	}

	for (i = 0; i < *nargs; i++) {
		snprintf(param, sizeof(param), "arg%d", i);
		name = gctl_get_asciiparam(req, param);
		if (name == NULL) {
			gctl_error(req, "No 'arg%d' argument", i);
			return;
		}
		if (strncmp(name, "/dev/", strlen("/dev/")) == 0)
			name += strlen("/dev/");
		gp = g_pfe_find_geom(mp, name);
		if (gp == NULL) {
			G_PFE_DEBUG(1, "Device %s is invalid.", name);
			gctl_error(req, "Device %s is invalid.", name);
			return;
		}
		error = g_pfe_destroy(gp, *force);
		if (error != 0) {
			gctl_error(req, "Cannot destroy device %s (error=%d).",
			    gp->name, error);
			return;
		}
	}
}

static void
g_pfe_config(struct gctl_req *req, struct g_class *mp, const char *verb)
{
	uint32_t *version;

	g_topology_assert();

	version = gctl_get_paraml(req, "version", sizeof(*version));
	if (version == NULL) {
		gctl_error(req, "No '%s' argument.", "version");
		return;
	}
	if (*version != G_PFE_VERSION) {
		gctl_error(req, "Userland and kernel parts are out of sync.");
		return;
	}

	if (strcmp(verb, "create") == 0) {
		g_pfe_ctl_create(req, mp);
		return;
	} else if (strcmp(verb, "configure") == 0) {
		g_pfe_ctl_configure(req, mp);
		return;
	} else if (strcmp(verb, "destroy") == 0) {
		g_pfe_ctl_destroy(req, mp);
		return;
	}

	gctl_error(req, "Unknown verb.");
}

static void
g_pfe_dumpconf(struct sbuf *sb, const char *indent, struct g_geom *gp,
    struct g_consumer *cp, struct g_provider *pp)
{
	struct g_pfe_softc *sc;

	if (pp != NULL || cp != NULL)
		return;
	sc = gp->softc;
	sbuf_printf(sb, "%s<magic>%s</magic>\n", indent,
	    sc->sc_magic);
	sbuf_printf(sb, "%s<version>%hu</version>\n", indent,sc->sc_version);
}


int
g_pfe_read_metadata(struct g_class *mp, struct g_provider *pp,
    struct g_pfe_metadata *md)
{
	struct g_geom *gp;
	struct g_consumer *cp;
	u_char *buf = NULL;
	int error;

	g_topology_assert();

	gp = g_new_geomf(mp, "pfe:taste");
	gp->start = g_pfe_start;
	gp->access = g_std_access;
	/*
	 * g_pfe_read_metadata() is always called from the event thread.
	 * Our geom is created and destroyed in the same event, so there
	 * could be no orphan nor spoil event in the meantime.
	 */
	gp->orphan = g_pfe_orphan_spoil_assert;
	gp->spoiled = g_pfe_orphan_spoil_assert;
	cp = g_new_consumer(gp);
	error = g_attach(cp, pp);
	if (error != 0)
		goto end;
	error = g_access(cp, 1, 0, 0);
	if (error != 0)
		goto end;
	g_topology_unlock();
	buf = g_read_data(cp, 0, pp->sectorsize,
	    &error);
	g_topology_lock();
	if (buf == NULL)
		goto end;
	error = pfe_metadata_decode(buf, md);
	if (error != 0)
		goto end;
	/* Metadata was read and decoded successfully. */
end:
	if (buf != NULL)
		g_free(buf);
	if (cp->provider != NULL) {
		if (cp->acr == 1)
			g_access(cp, -1, 0, 0);
		g_detach(cp);
	}
	g_destroy_consumer(cp);
	g_destroy_geom(gp);
	return (error);
}



DECLARE_GEOM_CLASS(g_pfe_class, g_pfe);
MODULE_VERSION(geom_pfe, 0);
