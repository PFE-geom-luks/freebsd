# $FreeBSD$

.PATH: ${SRCTOP}/sys/geom/luks

KMOD=	geom_luks
SRCS=	g_luks.c
SRCS+=	g_luks_crypto.c
SRCS+=	g_luks_ctl.c
SRCS+=	g_luks_hmac.c
SRCS+=	g_luks_key.c
SRCS+=	g_luks_key_cache.c
SRCS+=	g_luks_privacy.c
SRCS+=	pkcs5v2.c
SRCS+=	vnode_if.h

.include <bsd.kmod.mk>
