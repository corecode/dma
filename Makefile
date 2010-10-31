#
# Depending on your operating system, you might want to influence
# the conditional inclusion of some helper functions:
#
# Define HAVE_* (in caps) if your system already provides:
#   reallocf
#   strlcpy
#   getprogname
#

version=	$(shell sh get-version.sh)
debversion=	$(shell sh get-version.sh | sed -Ee 's/^v//;s/[.]([[:digit:]]+)[.](g[[:xdigit:]]+)$$/+\1+\2/')

CC?=		gcc
CFLAGS?=	-O -pipe
LDADD?=		-lssl -lcrypto -lresolv

CFLAGS+=	-Wall -DDMA_VERSION='"${version}"' -DLIBEXEC_PATH='"${LIBEXEC}"'

INSTALL?=	install -p
CHGRP?=		chgrp
CHMOD?=		chmod

PREFIX?=	/usr/local
SBIN?=		${PREFIX}/sbin
LIBEXEC?=	${PREFIX}/lib
CONFDIR?=	/etc
MAN?=		${PREFIX}/share/man
VAR?=		/var
DMASPOOL?=	${VAR}/spool/dma
VARMAIL?=	${VAR}/mail

YACC?=		yacc
LEX?=		lex

OBJS=	aliases_parse.o aliases_scan.o base64.o conf.o crypto.o
OBJS+=	dma.o dns.o local.o mail.o net.o spool.o util.o
OBJS+=	dfcompat.o

all: dma dma-mbox-create

clean:
	-rm -f .depend dma dma-mbox-create *.[do]
	-rm -f aliases_parse.[ch] aliases_scan.c
 
install: all
	${INSTALL} -d ${DESTDIR}${SBIN} ${DESTDIR}${CONFDIR}
	${INSTALL} -d ${DESTDIR}${MAN}/man8 ${DESTDIR}${LIBEXEC}
	${INSTALL} -m 2755 -o root -g mail dma ${DESTDIR}${SBIN}
	${INSTALL} -m 4754 -o root -g mail dma-mbox-create ${DESTDIR}${LIBEXEC}
	${INSTALL} -m 0644 dma.8 ${DESTDIR}${MAN}/man8/
	${INSTALL} -d -m 2775 -o root -g mail ${DESTDIR}${DMASPOOL}
	${INSTALL} -d -m 2775 -o root -g mail ${DESTDIR}${VARMAIL}

permissions:
	-${CHGRP} mail ${DESTDIR}${VARMAIL}/*
	-${CHMOD} g+w ${DESTDIR}${VARMAIL}/*

aliases_parse.c: aliases_parse.y
	${YACC} -d -o aliases_parse.c aliases_parse.y

aliases_scan.c: aliases_scan.l
	${LEX} -t aliases_scan.l > aliases_scan.c

.SUFFIXES: .c .o

.c.o:
	${CC} ${CFLAGS} ${CPPFLAGS} -include dfcompat.h -o $@ -c $<

dma: ${OBJS}
	${CC} ${LDFLAGS} ${LDADD} -o $@ ${OBJS}


dch:
	dch --release-heuristic changelog -v ${debversion}


ppa:
	@if [ -z '${DEB_DIST}' ]; then echo "please set DEB_DIST to build"; exit 1; fi
	dch -v "${debversion}~${DEB_DIST}" -D ${DEB_DIST} "${DEB_DIST} build"
	debuild -S -sa
	ver=$$(dpkg-parsechangelog -n1 | awk '$$1 == "Version:" { print $$2 }'); \
	dput ppa:corecode/dma ../$${ver}_source.changes
