# $DragonFly: src/libexec/dma/Makefile,v 1.5 2008/09/19 00:36:57 corecode Exp $
#

version!=       sh ../../get-version.sh ../../VERSION

CFLAGS+= -I${.CURDIR}/../..
CFLAGS+= -DHAVE_REALLOCF -DHAVE_STRLCPY -DHAVE_GETPROGNAME
CFLAGS+= -DLIBEXEC_PATH='"${LIBEXEC}"' -DDMA_VERSION='"${version}"'
CFLAGS+= -DCONF_PATH='"${CONFDIR}"'

DPADD=  ${LIBSSL} ${LIBCRYPTO}
LDADD=  -lssl -lcrypto

YACCFLAGS+=	-d

.PATH: ${.CURDIR}/../..
PATHTOYACCFILES=${.CURDIR}/../..
MAN=    dma.8

PREFIX?=        /usr/local
LIBEXEC?=       ${PREFIX}/libexec
CONFDIR?=       ${PREFIX}/etc/dma

YACC?=		yacc
LEX?=		lex

OBJS=   aliases_parse.o aliases_scan.o base64.o conf.o crypto.o
OBJS+=  dma.o dns.o local.o mail.o net.o spool.o util.o
OBJS+=  conf_parse.o conf_scan.o auth_parse.o auth_scan.o

all:	dma

aliases_parse.c: aliases_parse.y
	${YACC} ${YACCFLAGS} -o aliases_parse.c ${PATHTOYACCFILES}/aliases_parse.y

aliases_scan.c: aliases_scan.l
	${LEX} -t ${PATHTOYACCFILES}/aliases_scan.l > aliases_scan.c

auth_parse.c: auth_parse.y
	${YACC} ${YACCFLAGS} -p auth_ -b auth_ -o auth_parse.c ${PATHTOYACCFILES}/auth_parse.y

auth_scan.c: auth_scan.l
	${LEX} -t ${PATHTOYACCFILES}/auth_scan.l > auth_scan.c

conf_parse.c: conf_parse.y
	${YACC} ${YACCFLAGS} -p conf_ -b conf_ -o conf_parse.c ${PATHTOYACCFILES}/conf_parse.y

conf_scan.c: conf_scan.l
	${LEX} -t ${PATHTOYACCFILES}/conf_scan.l > conf_scan.c

.SUFFIXES: .c .o

.c.o:
	${CC} ${CFLAGS} ${CPPFLAGS} -o $@ -c $<

dma:	${OBJS}
	${CC} ${LDFLAGS} -o $@ ${OBJS} ${LDADD}
	
clean:
	-rm -f .depend dma dma-mbox-create *.[do]
	-rm -f aliases_parse.[ch] aliases_scan.c
	-rm -f auth_parse.[ch] auth_scan.c
	-rm -f conf_parse.[ch] conf_scan.c
	
BINOWN= root
BINGRP= mail
BINMODE=2555
WARNS?= 5

install:
	install  -s -o ${BINOWN} -g ${BINGRP} -m ${BINMODE}   dma ${LIBEXEC}
	install  -o root -g wheel -m 444 dma.8.gz  /usr/share/man/man8/

.include <bsd.prog.mk>

