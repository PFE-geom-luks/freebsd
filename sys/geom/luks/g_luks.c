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
#include <sys/cons.h>
#include <sys/kernel.h>
#include <sys/linker.h>
#include <sys/module.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/bio.h>
#include <sys/sbuf.h>
#include <sys/sysctl.h>
#include <sys/malloc.h>
#include <sys/eventhandler.h>
#include <sys/kthread.h>
#include <sys/proc.h>
#include <sys/sched.h>
#include <sys/smp.h>
#include <sys/uio.h>
#include <sys/vnode.h>

#include <vm/uma.h>

#include <geom/geom.h>
#include <geom/luks/g_luks.h>
#include <geom/luks/pkcs5v2.h>

#include <crypto/intake.h>

FEATURE(geom_luks, "GEOM crypto module");

MALLOC_DEFINE(M_LUKS, "luks data", "GEOM_LUKS Data");

SYSCTL_DECL(_kern_geom);
SYSCTL_NODE(_kern_geom, OID_AUTO, luks, CTLFLAG_RW, 0, "GEOM_LUKS stuff");
static int g_luks_version = G_LUKS_VERSION;
SYSCTL_INT(_kern_geom_luks, OID_AUTO, version, CTLFLAG_RD, &g_luks_version, 0,
    "GLUKS version");
int g_luks_debug = 0;
SYSCTL_INT(_kern_geom_luks, OID_AUTO, debug, CTLFLAG_RWTUN, &g_luks_debug, 0,
    "Debug level");
static u_int g_luks_tries = 3;
SYSCTL_UINT(_kern_geom_luks, OID_AUTO, tries, CTLFLAG_RWTUN, &g_luks_tries, 0,
    "Number of tries for entering the passphrase");
static u_int g_luks_visible_passphrase = GETS_NOECHO;
SYSCTL_UINT(_kern_geom_luks, OID_AUTO, visible_passphrase, CTLFLAG_RWTUN,
    &g_luks_visible_passphrase, 0,
    "Visibility of passphrase prompt (0 = invisible, 1 = visible, 2 = asterisk)");
u_int g_luks_overwrites = G_LUKS_OVERWRITES;
SYSCTL_UINT(_kern_geom_luks, OID_AUTO, overwrites, CTLFLAG_RWTUN, &g_luks_overwrites,
    0, "Number of times on-disk keys should be overwritten when destroying them");
static u_int g_luks_threads = 0;
SYSCTL_UINT(_kern_geom_luks, OID_AUTO, threads, CTLFLAG_RWTUN, &g_luks_threads, 0,
    "Number of threads doing crypto work");
u_int g_luks_batch = 0;
SYSCTL_UINT(_kern_geom_luks, OID_AUTO, batch, CTLFLAG_RWTUN, &g_luks_batch, 0,
    "Use crypto operations batching");

/*
 * Passphrase cached during boot, in order to be more user-friendly if
 * there are multiple providers using the same passphrase.
 */
static char cached_passphrase[256];
static u_int g_luks_boot_passcache = 1;
TUNABLE_INT("kern.geom.luks.boot_passcache", &g_luks_boot_passcache);
SYSCTL_UINT(_kern_geom_luks, OID_AUTO, boot_passcache, CTLFLAG_RD,
    &g_luks_boot_passcache, 0,
    "Passphrases are cached during boot process for possible reuse");
static void
fetch_loader_passphrase(void * dummy)
{
	char * env_passphrase;

	KASSERT(dynamic_kenv, ("need dynamic kenv"));

	if ((env_passphrase = kern_getenv("kern.geom.luks.passphrase")) != NULL) {
		/* Extract passphrase from the environment. */
		strlcpy(cached_passphrase, env_passphrase,
		    sizeof(cached_passphrase));
		freeenv(env_passphrase);

		/* Wipe the passphrase from the environment. */
		kern_unsetenv("kern.geom.luks.passphrase");
	}
}
SYSINIT(gluks_fetch_loader_passphrase, SI_SUB_KMEM + 1, SI_ORDER_ANY,
    fetch_loader_passphrase, NULL);

static void
zero_boot_passcache(void)
{

        explicit_bzero(cached_passphrase, sizeof(cached_passphrase));
}

static void
zero_gluks_intake_keys(void)
{
        struct keybuf *keybuf;
        int i;

        if ((keybuf = get_keybuf()) != NULL) {
                /* Scan the key buffer, clear all GLUKS keys. */
                for (i = 0; i < keybuf->kb_nents; i++) {
                         if (keybuf->kb_ents[i].ke_type == KEYBUF_TYPE_GLUKS) {
                                 explicit_bzero(keybuf->kb_ents[i].ke_data,
                                     sizeof(keybuf->kb_ents[i].ke_data));
                                 keybuf->kb_ents[i].ke_type = KEYBUF_TYPE_NONE;
                         }
                }
        }
}

static void
zero_intake_passcache(void *dummy)
{
        zero_boot_passcache();
        zero_gluks_intake_keys();
}
EVENTHANDLER_DEFINE(mountroot, zero_intake_passcache, NULL, 0);

static eventhandler_tag g_luks_pre_sync = NULL;

static int g_luks_destroy_geom(struct gctl_req *req, struct g_class *mp,
    struct g_geom *gp);
static void g_luks_init(struct g_class *mp);
static void g_luks_fini(struct g_class *mp);

static g_taste_t g_luks_taste;
static g_dumpconf_t g_luks_dumpconf;

struct g_class g_luks_class = {
	.name = G_LUKS_CLASS_NAME,
	.version = G_VERSION,
	.ctlreq = g_luks_config,
	.taste = g_luks_taste,
	.destroy_geom = g_luks_destroy_geom,
	.init = g_luks_init,
	.fini = g_luks_fini
};


/*
 * Code paths:
 * BIO_READ:
 *	g_luks_start -> g_luks_crypto_read -> g_io_request -> g_luks_read_done -> g_luks_crypto_run -> g_luks_crypto_read_done -> g_io_deliver
 * BIO_WRITE:
 *	g_luks_start -> g_luks_crypto_run -> g_luks_crypto_write_done -> g_io_request -> g_luks_write_done -> g_io_deliver
 */


/*
 * EAGAIN from crypto(9) means, that we were probably balanced to another crypto
 * accelerator or something like this.
 * The function updates the SID and rerun the operation.
 */
int
g_luks_crypto_rerun(struct cryptop *crp)
{
	struct g_luks_softc *sc;
	struct g_luks_worker *wr;
	struct bio *bp;
	int error;

	bp = (struct bio *)crp->crp_opaque;
	sc = bp->bio_to->geom->softc;
	LIST_FOREACH(wr, &sc->sc_workers, w_next) {
		if (wr->w_number == bp->bio_pflags)
			break;
	}
	KASSERT(wr != NULL, ("Invalid worker (%u).", bp->bio_pflags));
	G_LUKS_DEBUG(1, "Rerunning crypto %s request (sid: %ju -> %ju).",
	    bp->bio_cmd == BIO_READ ? "READ" : "WRITE", (uintmax_t)wr->w_sid,
	    (uintmax_t)crp->crp_sid);
	wr->w_sid = crp->crp_sid;
	crp->crp_etype = 0;
	error = crypto_dispatch(crp);
	if (error == 0)
		return (0);
	G_LUKS_DEBUG(1, "%s: crypto_dispatch() returned %d.", __func__, error);
	crp->crp_etype = error;
	return (error);
}

static void
g_luks_getattr_done(struct bio *bp)
{
	if (bp->bio_error == 0 && 
	    !strcmp(bp->bio_attribute, "GEOM::physpath")) {
		strlcat(bp->bio_data, "/luks", bp->bio_length);
	}
	g_std_done(bp);
}

/*
 * The function is called afer reading encrypted data from the provider.
 *
 * g_luks_start -> g_luks_crypto_read -> g_io_request -> G_LUKS_READ_DONE -> g_luks_crypto_run -> g_luks_crypto_read_done -> g_io_deliver
 */
void
g_luks_read_done(struct bio *bp)
{
	struct g_luks_softc *sc;
	struct bio *pbp;

	G_LUKS_LOGREQ(2, bp, "Request done.");
	pbp = bp->bio_parent;
	if (pbp->bio_error == 0 && bp->bio_error != 0)
		pbp->bio_error = bp->bio_error;
	g_destroy_bio(bp);
	/*
	 * Do we have all sectors already?
	 */
	pbp->bio_inbed++;
	if (pbp->bio_inbed < pbp->bio_children)
		return;
	sc = pbp->bio_to->geom->softc;
	if (pbp->bio_error != 0) {
		G_LUKS_LOGREQ(0, pbp, "%s() failed (error=%d)", __func__,
		    pbp->bio_error);
		pbp->bio_completed = 0;
		if (pbp->bio_driver2 != NULL) {
			free(pbp->bio_driver2, M_LUKS);
			pbp->bio_driver2 = NULL;
		}
		g_io_deliver(pbp, pbp->bio_error);
		atomic_subtract_int(&sc->sc_inflight, 1);
		return;
	}
	mtx_lock(&sc->sc_queue_mtx);
	bioq_insert_tail(&sc->sc_queue, pbp);
	mtx_unlock(&sc->sc_queue_mtx);
	wakeup(sc);
}

/*
 * The function is called after we encrypt and write data.
 *
 * g_luks_start -> g_luks_crypto_run -> g_luks_crypto_write_done -> g_io_request -> G_LUKS_WRITE_DONE -> g_io_deliver
 */
void
g_luks_write_done(struct bio *bp)
{
	struct g_luks_softc *sc;
	struct bio *pbp;

	G_LUKS_LOGREQ(2, bp, "Request done.");
	pbp = bp->bio_parent;
	if (pbp->bio_error == 0 && bp->bio_error != 0)
		pbp->bio_error = bp->bio_error;
	g_destroy_bio(bp);
	/*
	 * Do we have all sectors already?
	 */
	pbp->bio_inbed++;
	if (pbp->bio_inbed < pbp->bio_children)
		return;
	free(pbp->bio_driver2, M_LUKS);
	pbp->bio_driver2 = NULL;
	if (pbp->bio_error != 0) {
		G_LUKS_LOGREQ(0, pbp, "%s() failed (error=%d)", __func__,
		    pbp->bio_error);
		pbp->bio_completed = 0;
	} else
		pbp->bio_completed = pbp->bio_length;

	/*
	 * Write is finished, send it up.
	 */
	sc = pbp->bio_to->geom->softc;
	g_io_deliver(pbp, pbp->bio_error);
	atomic_subtract_int(&sc->sc_inflight, 1);
}

/*
 * This function should never be called, but GEOM made as it set ->orphan()
 * method for every geom.
 */
static void
g_luks_orphan_spoil_assert(struct g_consumer *cp)
{

	panic("Function %s() called for %s.", __func__, cp->geom->name);
}

static void
g_luks_orphan(struct g_consumer *cp)
{
	struct g_luks_softc *sc;

	g_topology_assert();
	sc = cp->geom->softc;
	if (sc == NULL)
		return;
	g_luks_destroy(sc, TRUE);
}

/*
 * BIO_READ:
 *	G_LUKS_START -> g_luks_crypto_read -> g_io_request -> g_luks_read_done -> g_luks_crypto_run -> g_luks_crypto_read_done -> g_io_deliver
 * BIO_WRITE:
 *	G_LUKS_START -> g_luks_crypto_run -> g_luks_crypto_write_done -> g_io_request -> g_luks_write_done -> g_io_deliver
 */
static void
g_luks_start(struct bio *bp)
{
	struct g_luks_softc *sc;
	struct g_consumer *cp;
	struct bio *cbp;

	sc = bp->bio_to->geom->softc;
	KASSERT(sc != NULL,
	    ("Provider's error should be set (error=%d)(device=%s).",
	    bp->bio_to->error, bp->bio_to->name));
	G_LUKS_LOGREQ(2, bp, "Request received.");

	switch (bp->bio_cmd) {
	case BIO_READ:
	case BIO_WRITE:
	case BIO_GETATTR:
	case BIO_FLUSH:
	case BIO_ZONE:
		break;
	case BIO_DELETE:
		/*
		 * If the user hasn't set the NODELETE flag, we just pass
		 * it down the stack and let the layers beneath us do (or
		 * not) whatever they do with it.  If they have, we
		 * reject it.  A possible extension would be an
		 * additional flag to take it as a hint to shred the data
		 * with [multiple?] overwrites.
		 */
		if (!(sc->sc_flags & G_LUKS_FLAG_NODELETE))
			break;
	default:
		g_io_deliver(bp, EOPNOTSUPP);
		return;
	}
	cbp = g_clone_bio(bp);
	if (cbp == NULL) {
		g_io_deliver(bp, ENOMEM);
		return;
	}
	bp->bio_driver1 = cbp;
	bp->bio_pflags = G_LUKS_NEW_BIO;
	switch (bp->bio_cmd) {
	case BIO_READ:
		g_luks_crypto_read(sc, bp, 0);
		break;
	case BIO_WRITE:
		mtx_lock(&sc->sc_queue_mtx);
		bioq_insert_tail(&sc->sc_queue, bp);
		mtx_unlock(&sc->sc_queue_mtx);
		wakeup(sc);
		break;
	case BIO_GETATTR:
	case BIO_FLUSH:
	case BIO_DELETE:
	case BIO_ZONE:
		if (bp->bio_cmd == BIO_GETATTR)
			cbp->bio_done = g_luks_getattr_done;
		else
			cbp->bio_done = g_std_done;
		cp = LIST_FIRST(&sc->sc_geom->consumer);
		cbp->bio_to = cp->provider;
		G_LUKS_LOGREQ(2, cbp, "Sending request.");
		g_io_request(cbp, cp);
		break;
	}
}

static int
g_luks_newsession(struct g_luks_worker *wr)
{
	struct g_luks_softc *sc;
	struct cryptoini crie;
	int error;

	sc = wr->w_softc;

	bzero(&crie, sizeof(crie));
	crie.cri_alg = sc->sc_ealgo;
	crie.cri_klen = sc->sc_ekeylen;
	if (sc->sc_ealgo == CRYPTO_AES_XTS)
		crie.cri_klen <<= 1;
	if ((sc->sc_flags & G_LUKS_FLAG_FIRST_KEY) != 0) {
		crie.cri_key = g_luks_key_hold(sc, 0,
		    LIST_FIRST(&sc->sc_geom->consumer)->provider->sectorsize);
	} else {
		crie.cri_key = sc->sc_ekey;
	}
	switch (sc->sc_crypto) {
	case G_LUKS_CRYPTO_SW:
		error = crypto_newsession(&wr->w_sid, &crie,
		    CRYPTOCAP_F_SOFTWARE);
		break;
	case G_LUKS_CRYPTO_HW:
		error = crypto_newsession(&wr->w_sid, &crie,
		    CRYPTOCAP_F_HARDWARE);
		break;
	case G_LUKS_CRYPTO_UNKNOWN:
		error = crypto_newsession(&wr->w_sid, &crie,
		    CRYPTOCAP_F_HARDWARE);
		if (error == 0) {
			mtx_lock(&sc->sc_queue_mtx);
			if (sc->sc_crypto == G_LUKS_CRYPTO_UNKNOWN)
				sc->sc_crypto = G_LUKS_CRYPTO_HW;
			mtx_unlock(&sc->sc_queue_mtx);
		} else {
			error = crypto_newsession(&wr->w_sid, &crie,
			    CRYPTOCAP_F_SOFTWARE);
			mtx_lock(&sc->sc_queue_mtx);
			if (sc->sc_crypto == G_LUKS_CRYPTO_UNKNOWN)
				sc->sc_crypto = G_LUKS_CRYPTO_SW;
			mtx_unlock(&sc->sc_queue_mtx);
		}
		break;
	default:
		panic("%s: invalid condition", __func__);
	}

	if ((sc->sc_flags & G_LUKS_FLAG_FIRST_KEY) != 0)
		g_luks_key_drop(sc, crie.cri_key);

	return (error);
}

static void
g_luks_freesession(struct g_luks_worker *wr)
{

	crypto_freesession(wr->w_sid);
}

static void
g_luks_cancel(struct g_luks_softc *sc)
{
	struct bio *bp;

	mtx_assert(&sc->sc_queue_mtx, MA_OWNED);

	while ((bp = bioq_takefirst(&sc->sc_queue)) != NULL) {
		KASSERT(bp->bio_pflags == G_LUKS_NEW_BIO,
		    ("Not new bio when canceling (bp=%p).", bp));
		g_io_deliver(bp, ENXIO);
	}
}

static struct bio *
g_luks_takefirst(struct g_luks_softc *sc)
{
	struct bio *bp;

	mtx_assert(&sc->sc_queue_mtx, MA_OWNED);

	if (!(sc->sc_flags & G_LUKS_FLAG_SUSPEND))
		return (bioq_takefirst(&sc->sc_queue));
	/*
	 * Device suspended, so we skip new I/O requests.
	 */
	TAILQ_FOREACH(bp, &sc->sc_queue.queue, bio_queue) {
		if (bp->bio_pflags != G_LUKS_NEW_BIO)
			break;
	}
	if (bp != NULL)
		bioq_remove(&sc->sc_queue, bp);
	return (bp);
}

/*
 * This is the main function for kernel worker thread when we don't have
 * hardware acceleration and we have to do cryptography in software.
 * Dedicated thread is needed, so we don't slow down g_up/g_down GEOM
 * threads with crypto work.
 */
static void
g_luks_worker(void *arg)
{
	struct g_luks_softc *sc;
	struct g_luks_worker *wr;
	struct bio *bp;
	int error;

	wr = arg;
	sc = wr->w_softc;
#ifdef EARLY_AP_STARTUP
	MPASS(!sc->sc_cpubind || smp_started);
#elif defined(SMP)
	/* Before sched_bind() to a CPU, wait for all CPUs to go on-line. */
	if (sc->sc_cpubind) {
		while (!smp_started)
			tsleep(wr, 0, "gluks:smp", hz / 4);
	}
#endif
	thread_lock(curthread);
	sched_prio(curthread, PUSER);
	if (sc->sc_cpubind)
		sched_bind(curthread, wr->w_number % mp_ncpus);
	thread_unlock(curthread);

	G_LUKS_DEBUG(1, "Thread %s started.", curthread->td_proc->p_comm);

	for (;;) {
		mtx_lock(&sc->sc_queue_mtx);
again:
		bp = g_luks_takefirst(sc);
		if (bp == NULL) {
			if (sc->sc_flags & G_LUKS_FLAG_DESTROY) {
				g_luks_cancel(sc);
				LIST_REMOVE(wr, w_next);
				g_luks_freesession(wr);
				free(wr, M_LUKS);
				G_LUKS_DEBUG(1, "Thread %s exiting.",
				    curthread->td_proc->p_comm);
				wakeup(&sc->sc_workers);
				mtx_unlock(&sc->sc_queue_mtx);
				kproc_exit(0);
			}
			while (sc->sc_flags & G_LUKS_FLAG_SUSPEND) {
				if (sc->sc_inflight > 0) {
					G_LUKS_DEBUG(0, "inflight=%d",
					    sc->sc_inflight);
					/*
					 * We still have inflight BIOs, so
					 * sleep and retry.
					 */
					msleep(sc, &sc->sc_queue_mtx, PRIBIO,
					    "gluks:inf", hz / 5);
					goto again;
				}
				/*
				 * Suspend requested, mark the worker as
				 * suspended and go to sleep.
				 */
				if (wr->w_active) {
					g_luks_freesession(wr);
					wr->w_active = FALSE;
				}
				wakeup(&sc->sc_workers);
				msleep(sc, &sc->sc_queue_mtx, PRIBIO,
				    "gluks:suspend", 0);
				if (!wr->w_active &&
				    !(sc->sc_flags & G_LUKS_FLAG_SUSPEND)) {
					error = g_luks_newsession(wr);
					KASSERT(error == 0,
					    ("g_luks_newsession() failed on resume (error=%d)",
					    error));
					wr->w_active = TRUE;
				}
				goto again;
			}
			msleep(sc, &sc->sc_queue_mtx, PDROP, "gluks:w", 0);
			continue;
		}
		if (bp->bio_pflags == G_LUKS_NEW_BIO)
			atomic_add_int(&sc->sc_inflight, 1);
		mtx_unlock(&sc->sc_queue_mtx);
		if (bp->bio_pflags == G_LUKS_NEW_BIO) {
			bp->bio_pflags = 0;
			if (bp->bio_cmd == BIO_READ)
				g_luks_crypto_read(sc, bp, 1);
			else
				g_luks_crypto_run(wr, bp);
		} else {
			g_luks_crypto_run(wr, bp);
		}
	}
}

int
g_luks_read_metadata(struct g_class *mp, struct g_provider *pp,
    struct g_luks_metadata *md)
{
	struct g_geom *gp;
	struct g_consumer *cp;
	u_char *buf = NULL;
	int error;

	g_topology_assert();

	gp = g_new_geomf(mp, "luks:taste");
	gp->start = g_luks_start;
	gp->access = g_std_access;
	/*
	 * g_luks_read_metadata() is always called from the event thread.
	 * Our geom is created and destroyed in the same event, so there
	 * could be no orphan nor spoil event in the meantime.
	 */
	gp->orphan = g_luks_orphan_spoil_assert;
	gp->spoiled = g_luks_orphan_spoil_assert;
	cp = g_new_consumer(gp);
	error = g_attach(cp, pp);
	if (error != 0)
		goto end;
	error = g_access(cp, 1, 0, 0);
	if (error != 0)
		goto end;
	g_topology_unlock();
	buf = g_read_data(cp, pp->mediasize - pp->sectorsize, pp->sectorsize,
	    &error);
	g_topology_lock();
	if (buf == NULL)
		goto end;
	error = luks_metadata_decode(buf, md);
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

/*
 * The function is called when we had last close on provider and user requested
 * to close it when this situation occur.
 */
static void
g_luks_last_close(void *arg, int flags __unused)
{
	struct g_geom *gp;
	char gpname[64];
	int error;

	g_topology_assert();
	gp = arg;
	strlcpy(gpname, gp->name, sizeof(gpname));
	error = g_luks_destroy(gp->softc, TRUE);
	KASSERT(error == 0, ("Cannot detach %s on last close (error=%d).",
	    gpname, error));
	G_LUKS_DEBUG(0, "Detached %s on last close.", gpname);
}

int
g_luks_access(struct g_provider *pp, int dr, int dw, int de)
{
	struct g_luks_softc *sc;
	struct g_geom *gp;

	gp = pp->geom;
	sc = gp->softc;

	if (dw > 0) {
		if (sc->sc_flags & G_LUKS_FLAG_RO) {
			/* Deny write attempts. */
			return (EROFS);
		}
		/* Someone is opening us for write, we need to remember that. */
		sc->sc_flags |= G_LUKS_FLAG_WOPEN;
		return (0);
	}
	/* Is this the last close? */
	if (pp->acr + dr > 0 || pp->acw + dw > 0 || pp->ace + de > 0)
		return (0);

	/*
	 * Automatically detach on last close if requested.
	 */
	if ((sc->sc_flags & G_LUKS_FLAG_RW_DETACH) ||
	    (sc->sc_flags & G_LUKS_FLAG_WOPEN)) {
		g_post_event(g_luks_last_close, gp, M_WAITOK, NULL);
	}
	return (0);
}

static int
g_luks_cpu_is_disabled(int cpu)
{
#ifdef SMP
	return (CPU_ISSET(cpu, &hlt_cpus_mask));
#else
	return (0);
#endif
}

struct g_geom *
g_luks_create(struct gctl_req *req, struct g_class *mp, struct g_provider *bpp,
    const struct g_luks_metadata *md, const u_char *mkey, int nkey)
{
	struct g_luks_softc *sc;
	struct g_luks_worker *wr;
	struct g_geom *gp;
	struct g_provider *pp;
	struct g_consumer *cp;
	u_int i, threads;
	int error;

	G_LUKS_DEBUG(1, "Creating device %s%s.", bpp->name, G_LUKS_SUFFIX);

	gp = g_new_geomf(mp, "%s%s", bpp->name, G_LUKS_SUFFIX);
	sc = malloc(sizeof(*sc), M_LUKS, M_WAITOK | M_ZERO);
	gp->start = g_luks_start;
	/*
	 * Spoiling can happen even though we have the provider open
	 * exclusively, e.g. through media change events.
	 */
	gp->spoiled = g_luks_orphan;
	gp->orphan = g_luks_orphan;
	gp->dumpconf = g_luks_dumpconf;
	gp->access = g_std_access;

	luks_metadata_softc(sc, md, bpp->sectorsize, bpp->mediasize);
	sc->sc_nkey = nkey;

	gp->softc = sc;
	sc->sc_geom = gp;

	bioq_init(&sc->sc_queue);
	mtx_init(&sc->sc_queue_mtx, "gluks:queue", NULL, MTX_DEF);
	mtx_init(&sc->sc_ekeys_lock, "gluks:ekeys", NULL, MTX_DEF);

	pp = NULL;
	cp = g_new_consumer(gp);
	error = g_attach(cp, bpp);
	if (error != 0) {
		if (req != NULL) {
			gctl_error(req, "Cannot attach to %s (error=%d).",
			    bpp->name, error);
		} else {
			G_LUKS_DEBUG(1, "Cannot attach to %s (error=%d).",
			    bpp->name, error);
		}
		goto failed;
	}
	/*
	 * Keep provider open all the time, so we can run critical tasks,
	 * like Master Keys deletion, without wondering if we can open
	 * provider or not.
	 * We don't open provider for writing only when user requested read-only
	 * access.
	 */
	if (sc->sc_flags & G_LUKS_FLAG_RO)
		error = g_access(cp, 1, 0, 1);
	else
		error = g_access(cp, 1, 1, 1);
	if (error != 0) {
		if (req != NULL) {
			gctl_error(req, "Cannot access %s (error=%d).",
			    bpp->name, error);
		} else {
			G_LUKS_DEBUG(1, "Cannot access %s (error=%d).",
			    bpp->name, error);
		}
		goto failed;
	}

	/*
	 * Remember the keys in our softc structure.
	 */
	g_luks_mkey_propagate(sc, mkey);

	LIST_INIT(&sc->sc_workers);

	threads = g_luks_threads;
	if (threads == 0)
		threads = mp_ncpus;
	sc->sc_cpubind = (mp_ncpus > 1 && threads == mp_ncpus);
	for (i = 0; i < threads; i++) {
		if (g_luks_cpu_is_disabled(i)) {
			G_LUKS_DEBUG(1, "%s: CPU %u disabled, skipping.",
			    bpp->name, i);
			continue;
		}
		wr = malloc(sizeof(*wr), M_LUKS, M_WAITOK | M_ZERO);
		wr->w_softc = sc;
		wr->w_number = i;
		wr->w_active = TRUE;

		error = g_luks_newsession(wr);
		if (error != 0) {
			free(wr, M_LUKS);
			if (req != NULL) {
				gctl_error(req, "Cannot set up crypto session "
				    "for %s (error=%d).", bpp->name, error);
			} else {
				G_LUKS_DEBUG(1, "Cannot set up crypto session "
				    "for %s (error=%d).", bpp->name, error);
			}
			goto failed;
		}

		error = kproc_create(g_luks_worker, wr, &wr->w_proc, 0, 0,
		    "g_luks[%u] %s", i, bpp->name);
		if (error != 0) {
			g_luks_freesession(wr);
			free(wr, M_LUKS);
			if (req != NULL) {
				gctl_error(req, "Cannot create kernel thread "
				    "for %s (error=%d).", bpp->name, error);
			} else {
				G_LUKS_DEBUG(1, "Cannot create kernel thread "
				    "for %s (error=%d).", bpp->name, error);
			}
			goto failed;
		}
		LIST_INSERT_HEAD(&sc->sc_workers, wr, w_next);
	}

	/*
	 * Create decrypted provider.
	 */
	pp = g_new_providerf(gp, "%s%s", bpp->name, G_LUKS_SUFFIX);
	pp->mediasize = sc->sc_mediasize;
	pp->sectorsize = sc->sc_sectorsize;

	g_error_provider(pp, 0);

	G_LUKS_DEBUG(0, "Device %s created.", pp->name);
	G_LUKS_DEBUG(0, "Encryption: %s %u", g_luks_algo2str(sc->sc_ealgo),
	    sc->sc_ekeylen);
	G_LUKS_DEBUG(0, "    Crypto: %s",
	    sc->sc_crypto == G_LUKS_CRYPTO_SW ? "software" : "hardware");
	return (gp);
failed:
	mtx_lock(&sc->sc_queue_mtx);
	sc->sc_flags |= G_LUKS_FLAG_DESTROY;
	wakeup(sc);
	/*
	 * Wait for kernel threads self destruction.
	 */
	while (!LIST_EMPTY(&sc->sc_workers)) {
		msleep(&sc->sc_workers, &sc->sc_queue_mtx, PRIBIO,
		    "gluks:destroy", 0);
	}
	mtx_destroy(&sc->sc_queue_mtx);
	if (cp->provider != NULL) {
		if (cp->acr == 1)
			g_access(cp, -1, -1, -1);
		g_detach(cp);
	}
	g_destroy_consumer(cp);
	g_destroy_geom(gp);
	g_luks_key_destroy(sc);
	bzero(sc, sizeof(*sc));
	free(sc, M_LUKS);
	return (NULL);
}

int
g_luks_destroy(struct g_luks_softc *sc, boolean_t force)
{
	struct g_geom *gp;
	struct g_provider *pp;

	g_topology_assert();

	if (sc == NULL)
		return (ENXIO);

	gp = sc->sc_geom;
	pp = LIST_FIRST(&gp->provider);
	if (pp != NULL && (pp->acr != 0 || pp->acw != 0 || pp->ace != 0)) {
		if (force) {
			G_LUKS_DEBUG(1, "Device %s is still open, so it "
			    "cannot be definitely removed.", pp->name);
			sc->sc_flags |= G_LUKS_FLAG_RW_DETACH;
			gp->access = g_luks_access;
			g_wither_provider(pp, ENXIO);
			return (EBUSY);
		} else {
			G_LUKS_DEBUG(1,
			    "Device %s is still open (r%dw%de%d).", pp->name,
			    pp->acr, pp->acw, pp->ace);
			return (EBUSY);
		}
	}

	mtx_lock(&sc->sc_queue_mtx);
	sc->sc_flags |= G_LUKS_FLAG_DESTROY;
	wakeup(sc);
	while (!LIST_EMPTY(&sc->sc_workers)) {
		msleep(&sc->sc_workers, &sc->sc_queue_mtx, PRIBIO,
		    "gluks:destroy", 0);
	}
	mtx_destroy(&sc->sc_queue_mtx);
	gp->softc = NULL;
	g_luks_key_destroy(sc);
	bzero(sc, sizeof(*sc));
	free(sc, M_LUKS);

	if (pp == NULL || (pp->acr == 0 && pp->acw == 0 && pp->ace == 0))
		G_LUKS_DEBUG(0, "Device %s destroyed.", gp->name);
	g_wither_geom_close(gp, ENXIO);

	return (0);
}

static int
g_luks_destroy_geom(struct gctl_req *req __unused,
    struct g_class *mp __unused, struct g_geom *gp)
{
	struct g_luks_softc *sc;

	sc = gp->softc;
	return (g_luks_destroy(sc, FALSE));
}

static int
g_luks_keyfiles_load(struct hmac_ctx *ctx, const char *provider)
{
	u_char *keyfile, *data;
	char *file, name[64];
	size_t size;
	int i;

	for (i = 0; ; i++) {
		snprintf(name, sizeof(name), "%s:gluks_keyfile%d", provider, i);
		keyfile = preload_search_by_type(name);
		if (keyfile == NULL && i == 0) {
			/*
			 * If there is only one keyfile, allow simpler name.
			 */
			snprintf(name, sizeof(name), "%s:gluks_keyfile", provider);
			keyfile = preload_search_by_type(name);
		}
		if (keyfile == NULL)
			return (i);	/* Return number of loaded keyfiles. */
		data = preload_fetch_addr(keyfile);
		if (data == NULL) {
			G_LUKS_DEBUG(0, "Cannot find key file data for %s.",
			    name);
			return (0);
		}
		size = preload_fetch_size(keyfile);
		if (size == 0) {
			G_LUKS_DEBUG(0, "Cannot find key file size for %s.",
			    name);
			return (0);
		}
		file = preload_search_info(keyfile, MODINFO_NAME);
		if (file == NULL) {
			G_LUKS_DEBUG(0, "Cannot find key file name for %s.",
			    name);
			return (0);
		}
		G_LUKS_DEBUG(1, "Loaded keyfile %s for %s (type: %s).", file,
		    provider, name);
		g_luks_crypto_hmac_update(ctx, data, size);
	}
}

static void
g_luks_keyfiles_clear(const char *provider)
{
	u_char *keyfile, *data;
	char name[64];
	size_t size;
	int i;

	for (i = 0; ; i++) {
		snprintf(name, sizeof(name), "%s:gluks_keyfile%d", provider, i);
		keyfile = preload_search_by_type(name);
		if (keyfile == NULL)
			return;
		data = preload_fetch_addr(keyfile);
		size = preload_fetch_size(keyfile);
		if (data != NULL && size != 0)
			bzero(data, size);
	}
}

/*
 * Tasting is only made on boot.
 * We detect providers which should be attached before root is mounted.
 */
static struct g_geom *
g_luks_taste(struct g_class *mp, struct g_provider *pp, int flags __unused)
{
	struct g_luks_metadata md;
	struct g_geom *gp;
	struct hmac_ctx ctx;
	char passphrase[256];
	u_char key[G_LUKS_USERKEYLEN], mkey[G_LUKS_DATAIVKEYLEN];
	u_int i, nkey, nkeyfiles, tries, showpass;
	int error;
        struct keybuf *keybuf;

	g_trace(G_T_TOPOLOGY, "%s(%s, %s)", __func__, mp->name, pp->name);
	g_topology_assert();

	if (root_mounted() || g_luks_tries == 0)
		return (NULL);

	G_LUKS_DEBUG(3, "Tasting %s.", pp->name);

	error = g_luks_read_metadata(mp, pp, &md);
	if (error != 0)
		return (NULL);
	gp = NULL;

	if (strcmp(md.md_magic, G_LUKS_MAGIC) != 0)
		return (NULL);
	if (md.md_version > G_LUKS_VERSION) {
		printf("geom_luks.ko module is too old to handle %s.\n",
		    pp->name);
		return (NULL);
	}
	if (md.md_iterations == -1) {
		/* If there is no passphrase, we try only once. */
		tries = 1;
	} else {
		/* Ask for the passphrase no more than g_luks_tries times. */
		tries = g_luks_tries;
	}

        if ((keybuf = get_keybuf()) != NULL) {
                /* Scan the key buffer, try all GLUKS keys. */
                for (i = 0; i < keybuf->kb_nents; i++) {
                         if (keybuf->kb_ents[i].ke_type == KEYBUF_TYPE_GLUKS) {
                                 memcpy(key, keybuf->kb_ents[i].ke_data,
                                     sizeof(key));

                                 if (g_luks_mkey_decrypt(&md, key,
                                     mkey, &nkey) == 0 ) {
                                         explicit_bzero(key, sizeof(key));
                                         goto have_key;
                                 }
                         }
                }
        }

        for (i = 0; i <= tries; i++) {
                g_luks_crypto_hmac_init(&ctx, NULL, 0);

                /*
                 * Load all key files.
                 */
                nkeyfiles = g_luks_keyfiles_load(&ctx, pp->name);

                if (nkeyfiles == 0 && md.md_iterations == -1) {
                        /*
                         * No key files and no passphrase, something is
                         * definitely wrong here.
                         * gluks(8) doesn't allow for such situation, so assume
                         * that there was really no passphrase and in that case
                         * key files are no properly defined in loader.conf.
                         */
                        G_LUKS_DEBUG(0,
                            "Found no key files in loader.conf for %s.",
                            pp->name);
                        return (NULL);
                }

                /* Ask for the passphrase if defined. */
                if (md.md_iterations >= 0) {
                        /* Try first with cached passphrase. */
                        if (i == 0) {
                                if (!g_luks_boot_passcache)
                                        continue;
                                memcpy(passphrase, cached_passphrase,
                                    sizeof(passphrase));
                        } else {
                                printf("Enter passphrase for %s: ", pp->name);
				showpass = g_luks_visible_passphrase;
                                cngets(passphrase, sizeof(passphrase),
				    showpass);
                                memcpy(cached_passphrase, passphrase,
                                    sizeof(passphrase));
                        }
                }

                /*
                 * Prepare Derived-Key from the user passphrase.
                 */
                if (md.md_iterations == 0) {
                        g_luks_crypto_hmac_update(&ctx, md.md_mkdigestsalt,
                            sizeof(md.md_mkdigestsalt));
                        g_luks_crypto_hmac_update(&ctx, passphrase,
                            strlen(passphrase));
                        explicit_bzero(passphrase, sizeof(passphrase));
                } else if (md.md_iterations > 0) {
                        u_char dkey[G_LUKS_USERKEYLEN];

                        pkcs5v2_genkey(dkey, sizeof(dkey), md.md_mkdigestsalt,
                            sizeof(md.md_mkdigestsalt), passphrase, md.md_iterations);
                        bzero(passphrase, sizeof(passphrase));
                        g_luks_crypto_hmac_update(&ctx, dkey, sizeof(dkey));
                        explicit_bzero(dkey, sizeof(dkey));
                }

                g_luks_crypto_hmac_final(&ctx, key, 0);

                /*
                 * Decrypt Master-Key.
                 */
                error = g_luks_mkey_decrypt(&md, key, mkey, &nkey);
                bzero(key, sizeof(key));
                if (error == -1) {
                        if (i == tries) {
                                G_LUKS_DEBUG(0,
                                    "Wrong key for %s. No tries left.",
                                    pp->name);
                                g_luks_keyfiles_clear(pp->name);
                                return (NULL);
                        }
                        if (i > 0) {
                                G_LUKS_DEBUG(0,
                                    "Wrong key for %s. Tries left: %u.",
                                    pp->name, tries - i);
                        }
                        /* Try again. */
                        continue;
                } else if (error > 0) {
                        G_LUKS_DEBUG(0,
                            "Cannot decrypt Master Key for %s (error=%d).",
                            pp->name, error);
                        g_luks_keyfiles_clear(pp->name);
                        return (NULL);
                }
                g_luks_keyfiles_clear(pp->name);
                G_LUKS_DEBUG(1, "Using Master Key %u for %s.", nkey, pp->name);
                break;
        }
have_key:

	/*
	 * We have correct key, let's attach provider.
	 */
	gp = g_luks_create(NULL, mp, pp, &md, mkey, nkey);
	bzero(mkey, sizeof(mkey));
	bzero(&md, sizeof(md));
	if (gp == NULL) {
		G_LUKS_DEBUG(0, "Cannot create device %s%s.", pp->name,
		    G_LUKS_SUFFIX);
		return (NULL);
	}
	return (gp);
}

static void
g_luks_dumpconf(struct sbuf *sb, const char *indent, struct g_geom *gp,
    struct g_consumer *cp, struct g_provider *pp)
{
	struct g_luks_softc *sc;

	g_topology_assert();
	sc = gp->softc;
	if (sc == NULL)
		return;
	if (pp != NULL || cp != NULL)
		return;	/* Nothing here. */

	sbuf_printf(sb, "%s<KeysTotal>%ju</KeysTotal>\n", indent,
	    (uintmax_t)sc->sc_ekeys_total);
	sbuf_printf(sb, "%s<KeysAllocated>%ju</KeysAllocated>\n", indent,
	    (uintmax_t)sc->sc_ekeys_allocated);
	sbuf_printf(sb, "%s<Flags>", indent);
	if (sc->sc_flags == 0)
		sbuf_printf(sb, "NONE");
	else {
		int first = 1;

#define ADD_FLAG(flag, name)	do {					\
	if (sc->sc_flags & (flag)) {					\
		if (!first)						\
			sbuf_printf(sb, ", ");				\
		else							\
			first = 0;					\
		sbuf_printf(sb, name);					\
	}								\
} while (0)
		ADD_FLAG(G_LUKS_FLAG_SUSPEND, "SUSPEND");
		ADD_FLAG(G_LUKS_FLAG_ONETIME, "ONETIME");
		ADD_FLAG(G_LUKS_FLAG_BOOT, "BOOT");
		ADD_FLAG(G_LUKS_FLAG_WO_DETACH, "W-DETACH");
		ADD_FLAG(G_LUKS_FLAG_RW_DETACH, "RW-DETACH");
		ADD_FLAG(G_LUKS_FLAG_WOPEN, "W-OPEN");
		ADD_FLAG(G_LUKS_FLAG_DESTROY, "DESTROY");
		ADD_FLAG(G_LUKS_FLAG_RO, "READ-ONLY");
		ADD_FLAG(G_LUKS_FLAG_NODELETE, "NODELETE");
		ADD_FLAG(G_LUKS_FLAG_GLUKSBOOT, "GLUKSBOOT");
		ADD_FLAG(G_LUKS_FLAG_GLUKSDISPLAYPASS, "GLUKSDISPLAYPASS");
#undef  ADD_FLAG
	}
	sbuf_printf(sb, "</Flags>\n");

	if (!(sc->sc_flags & G_LUKS_FLAG_ONETIME)) {
		sbuf_printf(sb, "%s<UsedKey>%u</UsedKey>\n", indent,
		    sc->sc_nkey);
	}
	sbuf_printf(sb, "%s<Version>%u</Version>\n", indent, sc->sc_version);
	sbuf_printf(sb, "%s<Crypto>", indent);
	switch (sc->sc_crypto) {
	case G_LUKS_CRYPTO_HW:
		sbuf_printf(sb, "hardware");
		break;
	case G_LUKS_CRYPTO_SW:
		sbuf_printf(sb, "software");
		break;
	default:
		sbuf_printf(sb, "UNKNOWN");
		break;
	}
	sbuf_printf(sb, "</Crypto>\n");
	sbuf_printf(sb, "%s<KeyLength>%u</KeyLength>\n", indent,
	    sc->sc_ekeylen);
	sbuf_printf(sb, "%s<EncryptionAlgorithm>%s</EncryptionAlgorithm>\n",
	    indent, g_luks_algo2str(sc->sc_ealgo));
	sbuf_printf(sb, "%s<State>%s</State>\n", indent,
	    (sc->sc_flags & G_LUKS_FLAG_SUSPEND) ? "SUSPENDED" : "ACTIVE");
}

static void
g_luks_shutdown_pre_sync(void *arg, int howto)
{
	struct g_class *mp;
	struct g_geom *gp, *gp2;
	struct g_provider *pp;
	struct g_luks_softc *sc;
	int error;

	mp = arg;
	g_topology_lock();
	LIST_FOREACH_SAFE(gp, &mp->geom, geom, gp2) {
		sc = gp->softc;
		if (sc == NULL)
			continue;
		pp = LIST_FIRST(&gp->provider);
		KASSERT(pp != NULL, ("No provider? gp=%p (%s)", gp, gp->name));
		if (pp->acr + pp->acw + pp->ace == 0)
			error = g_luks_destroy(sc, TRUE);
		else {
			sc->sc_flags |= G_LUKS_FLAG_RW_DETACH;
			gp->access = g_luks_access;
		}
	}
	g_topology_unlock();
}

static void
g_luks_init(struct g_class *mp)
{

	g_luks_pre_sync = EVENTHANDLER_REGISTER(shutdown_pre_sync,
	    g_luks_shutdown_pre_sync, mp, SHUTDOWN_PRI_FIRST);
	if (g_luks_pre_sync == NULL)
		G_LUKS_DEBUG(0, "Warning! Cannot register shutdown event.");
}

static void
g_luks_fini(struct g_class *mp)
{

	if (g_luks_pre_sync != NULL)
		EVENTHANDLER_DEREGISTER(shutdown_pre_sync, g_luks_pre_sync);
}

DECLARE_GEOM_CLASS(g_luks_class, g_luks);
MODULE_DEPEND(g_luks, crypto, 1, 1, 1);
MODULE_VERSION(geom_luks, 0);
