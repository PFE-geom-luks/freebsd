#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/mman.h>
#include <sys/sysctl.h>
#include <sys/resource.h>
#include <opencrypto/cryptodev.h>

#include <assert.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <libgeom.h>
#include <paths.h>
#include <readpassphrase.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#include <geom/pfe/g_pfe.h>

#include "core/geom.h"
#include "misc/subr.h"


uint32_t lib_version = G_LIB_VERSION;
uint32_t version = G_PFE_VERSION;

#define	GLUKS_BACKUP_DIR "/var/backups/"
#define	GLUKS_ENC_ALGO   "aes"

static void luks_main(struct gctl_req *req, unsigned flags);
static void luks_dump(struct gctl_req *req);

/*
 * Available commands:
 *
 * init [-bdgPTv] [-a aalgo] [-B backupfile] [-e ealgo] [-i iterations] [-l keylen] [-J newpassfile] [-K newkeyfile] [-s sectorsize] [-V version] prov
 * label - alias for 'init'
 * attach [-dprv] [-j passfile] [-k keyfile] prov
 * detach [-fl] prov ...
 * stop - alias for 'detach'
 * onetime [-d] [-a aalgo] [-e ealgo] [-l keylen] prov
 * configure [-bBgGtT] prov ...
 * setkey [-pPv] [-n keyno] [-j passfile] [-J newpassfile] [-k keyfile] [-K newkeyfile] prov
 * delkey [-afv] [-n keyno] prov
 * suspend [-v] -a | prov ...
 * resume [-pv] [-j passfile] [-k keyfile] prov
 * kill [-av] [prov ...]
 * backup [-v] prov file
 * restore [-fv] file prov
 * resize [-v] -s oldsize prov
 * version [prov ...]
 * clear [-v] prov ...
 * dump [-v] prov ...
 */
struct g_command class_commands[] = {
	{ "dump", G_FLAG_VERBOSE, luks_main, G_NULL_OPTS,
	    "[-v] prov ..."
	},
	G_CMD_SENTINEL
};

static int verbose = 0;

#define	BUFSIZE	1024

static int
luks_protect(struct gctl_req *req)
{
	struct rlimit rl;

	/* Disable core dumps. */
	rl.rlim_cur = 0;
	rl.rlim_max = 0;
	if (setrlimit(RLIMIT_CORE, &rl) == -1) {
		gctl_error(req, "Cannot disable core dumps: %s.",
		    strerror(errno));
		return (-1);
	}
	/* Disable swapping. */
	if (mlockall(MCL_FUTURE) == -1) {
		gctl_error(req, "Cannot lock memory: %s.", strerror(errno));
		return (-1);
	}
	return (0);
}

static void
luks_main(struct gctl_req *req, unsigned int flags)
{
	const char *name;

	if (luks_protect(req) == -1)
		return;

	if ((flags & G_FLAG_VERBOSE) != 0)
		verbose = 1;

	name = gctl_get_ascii(req, "verb");
	if (name == NULL) {
		gctl_error(req, "No '%s' argument.", "verb");
		return;
	}
	if (strcmp(name, "dump") == 0)
		luks_dump(req);
	else
		gctl_error(req, "Unknown command: %s.", name);
}

static int
luks_metadata_read(struct gctl_req *req, const char *prov,
    struct g_pfe_metadata *md)
{
	unsigned char sector[sizeof(struct g_pfe_metadata)];
	int error;

	if (g_get_sectorsize(prov) == 0) {
		int fd;

		/* This is a file probably. */
		fd = open(prov, O_RDONLY);
		if (fd == -1) {
			gctl_error(req, "Cannot open %s: %s.", prov,
			    strerror(errno));
			return (-1);
		}
		if (read(fd, sector, sizeof(sector)) != sizeof(sector)) {
			gctl_error(req, "Cannot read metadata from %s: %s.",
			    prov, strerror(errno));
			close(fd);
			return (-1);
		}
		close(fd);
	} else {
		/* This is a GEOM provider. */
		error = g_metadata_read(prov, sector, sizeof(sector),
		    LUKS_MAGIC_L);
		if (error != 0) {
			gctl_error(req, "Cannot read metadata from %s: %s.",
			    prov, strerror(error));
			return (-1);
		}
	}
	error = pfe_metadata_decode(sector, md);
	switch (error) {
	case 0:
		break;
	case EOPNOTSUPP:
		gctl_error(req,
		    "Provider's %s metadata version %u is too new.\n"
		    "gluks: The highest supported version is %u.",
		    prov, (unsigned int)md->md_version, G_PFE_VERSION);
		return (-1);
	case EINVAL:
		gctl_error(req, "Inconsistent provider's %s metadata.", prov);
		return (-1);
	default:
		gctl_error(req,
		    "Unexpected error while decoding provider's %s metadata: %s.",
		    prov, strerror(error));
		return (-1);
	}
	return (0);
}

static void
luks_dump(struct gctl_req *req)
{
	struct g_pfe_metadata md;
	const char *name;
	int i, nargs;

	nargs = gctl_get_int(req, "nargs");
	if (nargs < 1) {
		gctl_error(req, "Too few arguments.");
		return;
	}

	for (i = 0; i < nargs; i++) {
		name = gctl_get_ascii(req, "arg%d", i);
		if (luks_metadata_read(NULL, name, &md) == -1) {
			gctl_error(req, "Not fully done.");
			continue;
		}
		printf("Metadata on %s:\n", name);
		pfe_metadata_dump(&md);
		printf("\n");
	}
}
