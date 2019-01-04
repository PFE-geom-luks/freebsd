# $FreeBSD$

PACKAGE=runtime
.PATH: ${.CURDIR:H:H}/misc ${SRCTOP}/sys/geom/luks ${SRCTOP}/sys/crypto/sha2

GEOM_CLASS=	luks
SRCS=	g_luks_crypto.c
SRCS+=	g_luks_hmac.c
SRCS+=	g_luks_hmac_sha1.c
SRCS+=	g_luks_hmac_sha256.c
SRCS+=	g_luks_key.c
SRCS+=	pkcs5v2.c
SRCS+=	sha256c.c
SRCS+=	sha512c.c

LIBADD=	md crypto

WARNS?=	3

CFLAGS+=-I${SRCTOP}/sys

.include <bsd.lib.mk>
