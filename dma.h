/*
 * Copyright (c) 2008-2014, Simon Schubert <2@0x2c.org>.
 * Copyright (c) 2008 The DragonFly Project.  All rights reserved.
 *
 * This code is derived from software contributed to The DragonFly Project
 * by Simon Schubert <2@0x2c.org> and
 * Matthias Schmidt <matthias@dragonflybsd.org>.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 * 3. Neither the name of The DragonFly Project nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific, prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE
 * COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef DMA_H
#define DMA_H

#include <sys/types.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <arpa/nameser.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <netdb.h>
#include <sysexits.h>
#include <stdbool.h>

#define VERSION	"DragonFly Mail Agent " DMA_VERSION

/* Defaults */

#define BUF_SIZE	        2048
#define ERRMSG_SIZE	        1024
#define USERNAME_SIZE	        50
#define EHLO_RESPONSE_SIZE      BUF_SIZE
#define MIN_RETRY	        300			/* 5 minutes */
#define MAX_RETRY	        (3*60*60)		/* retry at least every 3 hours */
#define MAX_TIMEOUT	        (5*24*60*60)	        /* give up after 5 days */
#define SLEEP_TIMEOUT	        30			/* check for queue flush every 30 seconds */
#ifndef PATH_MAX
#define PATH_MAX	        1024			/* Max path len */
#endif
#define	SMTP_PORT	        25			/* Default SMTP port */
#define SMTP_PORT_STRING        "25"                    /* as above, as string */
#define CON_TIMEOUT	        (5*60)			/* Connection timeout per RFC5321 */
#define DEFAULT_ALIASES_PATH    "/etc/aliases"
#define DEFAULT_SPOOLDIR	"/var/spool/dma"
#ifndef HOST_NAME_MAX
#define HOST_NAME_MAX           255
#endif

/* String constants representing the configuration settings */

#define CONF_STARTTLS		"STARTTLS"
#define CONF_SECURETRANSFER	"SECURETRANSFER"
#define CONF_DEFER		"DEFER"
#define CONF_INSECURE		"INSECURE"
#define CONF_FULLBOUNCE		"FULLBOUNCE"
#define CONF_NULLCLIENT		"NULLCLIENT"
#define CONF_TLS_OPP		"OPPORTUNISTIC_TLS"
#define CONF_FINGERPRINT	"FINGERPRINT"
#define CONF_MASQUERADE		"MASQUERADE"
#define CONF_MAILNAME		"MAILNAME"
#define CONF_CERTFILE		"CERTFILE"
#define CONF_AUTHPATH		"AUTHPATH"
#define CONF_SPOOLDIR		"SPOOLDIR"
#define CONF_ALIASES		"ALIASES"
#define CONF_PORT		"PORT"
#define CONF_SMARTHOST		"SMARTHOST"

#ifndef CONF_PATH
#error Please define CONF_PATH
#endif

#ifndef LIBEXEC_PATH
#error Please define LIBEXEC_PATH
#endif

#define SPOOL_FLUSHFILE         "flush"

#ifndef DMA_ROOT_USER
#define DMA_ROOT_USER   	"mail"
#endif
#ifndef DMA_GROUP
#define DMA_GROUP	        "mail"
#endif

#ifndef MBOX_STRICT
#define MBOX_STRICT	        0
#endif


struct stritem {
	SLIST_ENTRY(stritem) next;
	char *str;
};
SLIST_HEAD(strlist, stritem);

struct alias {
	LIST_ENTRY(alias) next;
	char *alias;
	struct strlist dests;
};
LIST_HEAD(aliases, alias);

struct qitem {
	LIST_ENTRY(qitem) next;
	const char *sender;
	char *addr;
	char *queuefn;
	char *mailfn;
	char *queueid;
	FILE *queuef;
	FILE *mailf;
	int remote;
};
LIST_HEAD(queueh, qitem);

struct queue {
	struct queueh queue;
	char *id;
	FILE *mailf;
	char *tmpf;
	const char *sender;
};

struct masquerade_config_t {
	char *host;
	char *user;
};

struct mx_hostentry {
	char		host[MAXDNAME];
	char		addr[INET6_ADDRSTRLEN];
	int		pref;
	struct addrinfo	ai;
	struct sockaddr_storage	sa;
};

struct smtp_auth_mechanisms {
	int cram_md5;
	int login;
};

struct smtp_features {
	struct smtp_auth_mechanisms auth;
	int starttls;
};

struct auth_details_t {
	char *login;
	char *password;
};

/* global variables */
extern struct aliases aliases;
extern bool no_ssl_flag;
extern struct strlist tmpfs;
extern char username[USERNAME_SIZE];
extern uid_t useruid;
extern SSL *ssl_state;
extern const char *logident_base;

extern char neterr[ERRMSG_SIZE];
extern char errmsg[ERRMSG_SIZE];

/* aliases_parse.y */
int yyparse(void);
int yywrap(void);
int yylex(void);
extern FILE *yyin;

/* auth_parse.y */
extern FILE *auth_in;
int auth_parse(void);

/* conf.c */
/* "Public" functions */
struct auth_details_t *get_auth_details_for_host(const char *);
struct masquerade_config_t *extract_masquerade_settings(const char *);
const char *get_configuration_value(const char *);
const struct masquerade_config_t *get_masquerade_settings(void);
bool is_configuration_setting_enabled(const char *);
void parse_authfile(const char *);
void parse_conf(const char *);
void initialize_all_configuration_settings(void);
void trim_line(char *);
int try_to_set_configuration_setting(char *, char *);
int add_auth_entry(char *, char *, char *);

/* conf_parse.y */
extern FILE *conf_in;
int conf_parse(void);

/* crypto.c */
void hmac_md5(unsigned char *, int, unsigned char *, int, unsigned char *);
int smtp_auth_md5(int, char *, char *);
int smtp_init_crypto(int, struct smtp_features*);
int verify_server_fingerprint(const X509 *);

/* dns.c */
int dns_get_mx_list(const char *, int, struct mx_hostentry **, int);

/* net.c */
char *ssl_errstr(void);
int read_remote(int, int, char *);
ssize_t send_remote_command(int, const char*, ...)  __attribute__((__nonnull__(2), __format__ (__printf__, 2, 3)));
int perform_server_greeting(int, struct smtp_features*);
int deliver_remote(struct qitem *);

/* base64.c */
int base64_encode(const void *, int, char **);
int base64_decode(const char *, void *);

/* dma.c */
#define EXPAND_ADDR	1
#define EXPAND_WILDCARD	2
int add_recp(struct queue *, const char *, int);
void run_queue(struct queue *);

/* spool.c */
int newspoolf(struct queue *);
int linkspool(struct queue *);
int load_queue(struct queue *);
void delqueue(struct qitem *);
int acquirespool(struct qitem *);
void dropspool(struct queue *, struct qitem *);
int flushqueue_since(unsigned int);
int flushqueue_signal(void);

/* local.c */
int deliver_local(struct qitem *);

/* mail.c */
void bounce(struct qitem *, const char *);
int readmail(struct queue *, int, int);

/* util.c */
const char *hostname(void);
void setlogident(const char *, ...) __attribute__((__format__ (__printf__, 1, 2)));
void errlog(int, const char *, ...) __attribute__((__format__ (__printf__, 2, 3)));
void errlogx(int, const char *, ...) __attribute__((__format__ (__printf__, 2, 3)));
void free_auth_details(struct auth_details_t *);
void free_masquerade_settings(struct masquerade_config_t *);
void log_warning(const char *fmt, ...) __attribute__((__format__ (__printf__, 1, 2)));;
void set_username(void);
void deltmp(void);
int do_timeout(int, int);
int open_locked(const char *, int, ...);
char *rfc822date(void);
int strprefixcmp(const char *, const char *);
void init_random(void);

#endif
