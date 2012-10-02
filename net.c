/*
 * Copyright (c) 2008 The DragonFly Project.  All rights reserved.
 *
 * This code is derived from software contributed to The DragonFly Project
 * by Matthias Schmidt <matthias@dragonflybsd.org>, University of Marburg,
 * Germany.
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

#include "dfcompat.h"

#include <sys/param.h>
#include <sys/queue.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <netdb.h>
#include <setjmp.h>
#include <signal.h>
#include <syslog.h>
#include <unistd.h>

#include "dma.h"

char neterr[ERRMSG_SIZE];

char *
ssl_errstr(void)
{
	long oerr, nerr;

	oerr = 0;
	while ((nerr = ERR_get_error()) != 0)
		oerr = nerr;

	return (ERR_error_string(oerr, NULL));
}

ssize_t
send_remote_command(int fd, const char* fmt, ...)
{
	va_list va;
	char cmd[4096];
	size_t len, pos;
	int s;
	ssize_t n;

	va_start(va, fmt);
	s = vsnprintf(cmd, sizeof(cmd) - 2, fmt, va);
	va_end(va);
	if (s == sizeof(cmd) - 2 || s < 0) {
		strcpy(neterr, "Internal error: oversized command string");
		return (-1);
	}

	/* We *know* there are at least two more bytes available */
	strcat(cmd, "\r\n");
	len = strlen(cmd);

	if ((config.features & USESSL) != 0) {
		while ((s = SSL_write(config.ssl, (const char*)cmd, len)) <= 0) {
			s = SSL_get_error(config.ssl, s);
			if (s != SSL_ERROR_WANT_READ &&
			    s != SSL_ERROR_WANT_WRITE) {
				strncpy(neterr, ssl_errstr(), sizeof(neterr));
				return (-1);
			}
		}
	}
	else {
		pos = 0;
		while (pos < len) {
			n = write(fd, cmd + pos, len - pos);
			if (n < 0)
				return (-1);
			pos += n;
		}
	}

	return (len);
}

int
read_remote(int fd, size_t *extbufsize, char *extbuf)
{
	ssize_t rlen = 0;
	size_t pos, len, copysize, ebufpos = 0, ebuflen = 0;
	char buff[BUF_SIZE];
	long status = 0;
	int done = 0;

	if (do_timeout(CON_TIMEOUT, 1) != 0) {
		snprintf(neterr, sizeof(neterr), "Timeout reached");
		return (-1);
	}
	
	if (extbuf && extbufsize) {
		ebuflen = *extbufsize;
	}
	
	/*
	 * Remote reading code from femail.c written by Henning Brauer of
	 * OpenBSD and released under a BSD style license.
	 */
	pos = 0;
	len = 0;
	neterr[0] = 0;
	do {
		if (memchr(buff + pos, '\n', len - pos) == NULL) {
			rlen = 0;
		      
			/* Move away already parsed data */
			memmove(buff, buff + pos, len - pos);
			len -= pos;
			pos = 0;
		      
			/* Read the next bytes */
			if ((config.features & USESSL) != 0) {
				if ((rlen = SSL_read(config.ssl, buff + len, sizeof(buff) - len)) == -1) {
				      strncpy(neterr, ssl_errstr(), sizeof(neterr));
				      goto error;
				}
			} else {
				if ((rlen = read(fd, buff + len, sizeof(buff) - len)) == -1) {
					strncpy(neterr, strerror(errno), sizeof(neterr));
					goto error;
				}
			}
			      
			if (rlen == 0) {
				strncpy(neterr, "unexpected connection end", sizeof(neterr));
				goto error;
			}
		      
			/* If an external buffer is available, copy data over there */
			if (ebuflen > 0) {
				/* Do not write over the buffer bounds */
				ssize_t copysiz = rlen;
			      
				if (ebufpos + copysiz > ebuflen) {
					copysiz = ebuflen - ebufpos;
				}
			      
				if (copysiz > 0) {
				    memcpy(extbuf + ebufpos, buff + len, copysiz);
				}
			      
				/* Add rlen to ebufpos, so the caller
				 * can know if the provided buffer was too small.
				 */
				ebufpos += rlen;
			}
		}

		for (; pos < len && isdigit(buff[pos]); pos++)
			; /* Skip over status number */

		if (pos == len) {
			/* We need more data from the server */
			continue;
		}

		if (buff[pos] == ' ') {
			done = 1;
		} else if (buff[pos] == '-') {

			while (buff[pos++] != '\n')
				; /*skip*/

		} else {
			strncpy(neterr, "invalid syntax in reply from server", sizeof(neterr));
			goto error;
		}
		
	} while (!done);

	status = strtol(buff, NULL, 10);
	if (status < 100 || status > 999) {
		strncpy(neterr, "error reading status, out of range value", sizeof(neterr));
		goto error;
	}

	do_timeout(0, 0);

	if (extbufsize)
		*extbufsize = ebufpos;
	
	syslog(LOG_DEBUG, "<<< status %d", (int)status);
	return ((int)status);

error:
	/* Ensure neterr '\0' ending byte*/
	neterr[sizeof(neterr) - 1] = '\0';
	
	/* Chop off trailing newlines */
	while (neterr[0] != 0 && strchr("\r\n", neterr[strlen(neterr) - 1]) != 0)
		neterr[strlen(neterr) - 1] = 0;
	
	do_timeout(0, 0);
	return (-1);
}

/*
 * Handle SMTP authentication
 */
static int
smtp_login(int fd, char *login, char* password)
{
	char *temp;
	int len, res = 0;

	res = smtp_auth_md5(fd, login, password);
	if (res == 0) {
		return (0);
	} else if (res == -2) {
	/*
	 * If the return code is -2, then then the login attempt failed, 
	 * do not try other login mechanisms
	 */
		return (1);
	}

	if ((config.features & INSECURE) != 0 ||
	    (config.features & SECURETRANS) != 0) {
		/* Send AUTH command according to RFC 2554 */
		send_remote_command(fd, "AUTH LOGIN");
		if (read_remote(fd, NULL, NULL) != 334) {
			syslog(LOG_NOTICE, "remote delivery deferred:"
					" AUTH login not available: %s",
					neterr);
			return (1);
		}

		len = base64_encode(login, strlen(login), &temp);
		if (len < 0) {
encerr:
			syslog(LOG_ERR, "can not encode auth reply: %m");
			return (1);
		}

		send_remote_command(fd, "%s", temp);
		free(temp);
		res = read_remote(fd, NULL, NULL);
		if (res != 334) {
			syslog(LOG_NOTICE, "remote delivery %s: AUTH login failed: %s",
			       res == 503 ? "failed" : "deferred", neterr);
			return (res == 503 ? -1 : 1);
		}

		len = base64_encode(password, strlen(password), &temp);
		if (len < 0)
			goto encerr;

		send_remote_command(fd, "%s", temp);
		free(temp);
		res = read_remote(fd, NULL, NULL);
		if (res != 235) {
			syslog(LOG_NOTICE, "remote delivery %s: Authentication failed: %s",
					res == 503 ? "failed" : "deferred", neterr);
			return (res == 503 ? -1 : 1);
		}
	} else {
		syslog(LOG_WARNING, "non-encrypted SMTP login is disabled in config, so skipping it. ");
		return (1);
	}

	return (0);
}

static int
open_connection(struct mx_hostentry *h)
{
	int fd;

	syslog(LOG_INFO, "trying remote delivery to %s [%s] pref %d",
	       h->host, h->addr, h->pref);

	fd = socket(h->ai.ai_family, h->ai.ai_socktype, h->ai.ai_protocol);
	if (fd < 0) {
		syslog(LOG_INFO, "socket for %s [%s] failed: %m",
		       h->host, h->addr);
		return (-1);
	}

	if (connect(fd, (struct sockaddr *)&h->sa, h->ai.ai_addrlen) < 0) {
		syslog(LOG_INFO, "connect to %s [%s] failed: %m",
		       h->host, h->addr);
		close(fd);
		return (-1);
	}

	return (fd);
}

static void
close_connection(int fd)
{
	if (config.ssl != NULL) {
		if (((config.features & SECURETRANS) != 0) &&
		    ((config.features & USESSL) != 0))
			SSL_shutdown(config.ssl);
		SSL_free(config.ssl);
	}

	close(fd);
}

static int
deliver_to_host(struct qitem *it, struct mx_hostentry *host)
{
	struct authuser *a;
	char line[1000];
	size_t linelen;
	int fd, error = 0, do_auth = 0, res = 0;

	if (fseek(it->mailf, 0, SEEK_SET) != 0) {
		snprintf(errmsg, sizeof(errmsg), "can not seek: %s", strerror(errno));
		return (-1);
	}

	fd = open_connection(host);
	if (fd < 0)
		return (1);

#define READ_REMOTE_CHECK(c, exp)	\
	res = read_remote(fd, NULL, NULL); \
	if (res == 500 || res == 502) { \
		syslog(LOG_ERR, "remote delivery to %s [%s] failed after %s: %s", \
		       host->host, host->addr, c, neterr); \
		snprintf(errmsg, sizeof(errmsg), "%s [%s] did not like our %s:\n%s", \
			 host->host, host->addr, c, neterr); \
		return (-1); \
	} else if (res != exp) { \
		syslog(LOG_NOTICE, "remote delivery deferred: %s [%s] failed after %s: %s", \
		       host->host, host->addr, c, neterr); \
		return (1); \
	}

	/* Check first reply from remote host */
	if ((config.features & SECURETRANS) == 0 ||
	    (config.features & STARTTLS) != 0) {
		READ_REMOTE_CHECK("connect", 220);
	}

	if ((config.features & SECURETRANS) != 0) {
		error = smtp_init_crypto(fd, config.features);
		if (error == 0)
			syslog(LOG_DEBUG, "SSL initialization successful");
		else
			goto out;

		if ((config.features & STARTTLS) == 0)
			READ_REMOTE_CHECK("connect", 250);
	}

	/* XXX allow HELO fallback */
	/* XXX record ESMTP keywords */
	send_remote_command(fd, "EHLO %s", hostname());
	READ_REMOTE_CHECK("EHLO", 250);

	/*
	 * Use SMTP authentication if the user defined an entry for the remote
	 * or smarthost
	 */
	SLIST_FOREACH(a, &authusers, next) {
		if (strcmp(a->host, host->host) == 0) {
			do_auth = 1;
			break;
		}
	}

	if (do_auth == 1) {
		/*
		 * Check if the user wants plain text login without using
		 * encryption.
		 */
		syslog(LOG_INFO, "using SMTP authentication for user %s", a->login);
		error = smtp_login(fd, a->login, a->password);
		if (error < 0) {
			syslog(LOG_ERR, "remote delivery failed:"
					" SMTP login failed: %m");
			snprintf(errmsg, sizeof(errmsg), "SMTP login to %s failed", host->host);
			return (-1);
		}
		/* SMTP login is not available, so try without */
		else if (error > 0) {
			syslog(LOG_WARNING, "SMTP login not available. Trying without.");
		}
	}

	/* XXX send ESMTP ENVID, RET (FULL/HDRS) and 8BITMIME */
	send_remote_command(fd, "MAIL FROM:<%s>", it->sender);
	READ_REMOTE_CHECK("MAIL FROM", 250);

	/* XXX send ESMTP ORCPT */
	send_remote_command(fd, "RCPT TO:<%s>", it->addr);
	READ_REMOTE_CHECK("RCPT TO", 250);

	send_remote_command(fd, "DATA");
	READ_REMOTE_CHECK("DATA", 354);

	error = 0;
	while (!feof(it->mailf)) {
		if (fgets(line, sizeof(line), it->mailf) == NULL)
			break;
		linelen = strlen(line);
		if (linelen == 0 || line[linelen - 1] != '\n') {
			syslog(LOG_CRIT, "remote delivery failed: corrupted queue file");
			snprintf(errmsg, sizeof(errmsg), "corrupted queue file");
			error = -1;
			goto out;
		}

		/* Remove trailing \n's and escape leading dots */
		trim_line(line);

		/*
		 * If the first character is a dot, we escape it so the line
		 * length increases
		*/
		if (line[0] == '.')
			linelen++;

		if (send_remote_command(fd, "%s", line) != (ssize_t)linelen+1) {
			syslog(LOG_NOTICE, "remote delivery deferred: write error");
			error = 1;
			goto out;
		}
	}

	send_remote_command(fd, ".");
	READ_REMOTE_CHECK("final DATA", 250);

	send_remote_command(fd, "QUIT");
	if (read_remote(fd, NULL, NULL) != 221)
		syslog(LOG_INFO, "remote delivery succeeded but QUIT failed: %s", neterr);
out:

	close_connection(fd);
	return (error);
}

int
deliver_remote(struct qitem *it)
{
	struct mx_hostentry *hosts, *h;
	const char *host;
	int port;
	int error = 1, smarthost = 0;

	host = strrchr(it->addr, '@');
	/* Should not happen */
	if (host == NULL) {
		snprintf(errmsg, sizeof(errmsg), "Internal error: badly formed address %s",
		    it->addr);
		return(-1);
	} else {
		/* Step over the @ */
		host++;
	}

	port = SMTP_PORT;

	/* Smarthost support? */
	if (config.smarthost != NULL) {
		host = config.smarthost;
		port = config.port;
		syslog(LOG_INFO, "using smarthost (%s:%i)", host, port);
		smarthost = 1;
	}

	error = dns_get_mx_list(host, port, &hosts, smarthost);
	if (error) {
		snprintf(errmsg, sizeof(errmsg), "DNS lookup failure: host %s not found", host);
		syslog(LOG_NOTICE, "remote delivery %s: DNS lookup failure: host %s not found",
		       error < 0 ? "failed" : "deferred",
		       host);
		return (error);
	}

	for (h = hosts; *h->host != 0; h++) {
		switch (deliver_to_host(it, h)) {
		case 0:
			/* success */
			error = 0;
			goto out;
		case 1:
			/* temp failure */
			error = 1;
			break;
		default:
			/* perm failure */
			error = -1;
			goto out;
		}
	}
out:
	free(hosts);

	return (error);
}
