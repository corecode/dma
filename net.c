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

	if (config.features & VERBOSE)
		syslog(LOG_DEBUG, ">>> %s", cmd);
	
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
			if (n < 0) {
				if (errno == EINTR)
					continue;
				
				return (-1);
			}
			
			pos += n;
		}
	}

	return (len);
}

int
read_remote(int fd, size_t *extbufsize, char *extbuf)
{
	ssize_t pos = 0, len = 0, copysize = 0;
	size_t ebufpos = 0, ebufmax = 0;
	char buff[BUF_SIZE];
	int statnum = 0, currstatnum = 0, done = 0;
	enum { PARSE_STATNUM, PARSE_DASH, PARSE_REST } parse = PARSE_STATNUM;
	
	if (do_timeout(CON_TIMEOUT, 1) != 0) {
		strncpy(neterr, "timeout reached", sizeof(neterr));
		statnum = -1;
		goto timeout;
	}
	
	if (extbufsize) {
		/*if no extbuf is provided interpret the call as a "peek" to the size*/
		if (extbuf) {
			ebufmax = *extbufsize;
		}
		/*always leave room for ending null byte*/
		if (ebufmax) {
			ebufmax--;
		}
	}
	
	/*
	 * Remote reading code from femail.c written by Henning Brauer of
	 * OpenBSD and released under a BSD style license.
	 */
	neterr[0] = 0;
	do {
		if (pos == len) {
			/* no more data in buffer, read the next chunk */
			pos = 0;
		      
			/* Read the next bytes */
			if ((config.features & USESSL) != 0) {
				if ((len = SSL_read(config.ssl, buff, sizeof(buff))) == -1) {
				      strncpy(neterr, ssl_errstr(), sizeof(neterr));
				      goto error;
				}
			} else {
				if ((len = read(fd, buff, sizeof(buff))) == -1) {
					strncpy(neterr, strerror(errno), sizeof(neterr));
					goto error;
				}
			}
			      
			if (len == 0) {
				strncpy(neterr, "unexpected connection end", sizeof(neterr));
				statnum = -1;
				goto error;
			}
			
			/* Copy (at least partially) contents to an error buffer*/
			copysize = sizeof(neterr) - strlen(neterr) - 1;
			if (copysize > len)
				copysize = len;
			
			strncat(neterr, buff, copysize);
			
			/* If an external buffer is available, copy data over there */
			if (ebufmax > 0) {
				/* Do not write over the buffer bounds */
				copysize = len;
			      
				if (ebufpos + copysize > ebufmax) {
					copysize = ebufmax - ebufpos;
				}
			      
				if (copysize > 0) {
					memcpy(extbuf + ebufpos, buff, copysize);
					extbuf[ebufpos + copysize] = 0;
				}
			}
			
			/* Add len to ebufpos, so the caller
			 * can know if the provided buffer was too small.
			 */
			ebufpos += len;
		}
		
		/* since rlen can't be zero, we're sure that there is at least one character*/
		switch (parse) {
		default:
			/* shouldn't happen */
			syslog(LOG_CRIT, "reached dead code");
			statnum = -1;
			goto error;
		case PARSE_STATNUM:
			/* parse status number*/
			for (; pos < len; pos++) {
				if (isdigit(buff[pos])) {
					currstatnum = currstatnum * 10 + (buff[pos] - '0');
				} else {
					/* verify and store status */
					if (currstatnum < 100 || currstatnum > 999) {
						strncpy(neterr, "error reading status, out of range value", sizeof(neterr));
						statnum = -1;
						goto error;
					}
					
					statnum = currstatnum;
					currstatnum = 0;
					parse = PARSE_DASH;
					break;
				}
			}
			
			break;
		case PARSE_DASH:
			/* parse dash, if space then we're done*/
			if (buff[pos] == ' ') {
				  done = 1;
			} else if (buff[pos] == '-') {
				  /* ignore */
				  /* XXX read capabilities */
			} else {
				strncpy(neterr, "invalid syntax in reply from server", sizeof(neterr));
				statnum = -1;
				goto error;
			}
			
			pos++;
			parse = PARSE_REST;
			break;
		case PARSE_REST:
			/* parse to newline */
			for (; pos < len; pos++) {
				if (buff[pos] == '\n') {
					/* Skip the newline and expect a status number */
					pos++;
					parse = PARSE_STATNUM;
					break;
				}
			}
			
			break;
		}
		
	} while (!done);
	
	if (config.features & VERBOSE)
		syslog(LOG_DEBUG, "<<< %d", statnum);

error:
	/* Disable timeout */
	do_timeout(0, 0);

timeout:
	/* Ensure neterr null-termination*/
	neterr[sizeof(neterr) - 1] = 0;
	/* Chop off trailing newlines */
	while (neterr[0] != 0 && strchr("\r\n", neterr[strlen(neterr) - 1]) != 0)
		neterr[strlen(neterr) - 1] = 0;

	if (extbufsize)
		*extbufsize = ebufpos;
	
	return (statnum);
}

/*
 * Handle SMTP authentication
 */
static int
smtp_login(int fd, char *login, char* password)
{
	char *temp;
	int len, res = 0;

	if ((config.features & AUTHCRAMMD5) != 0) {
		/* Use CRAM-MD5 authentication if available*/
		return smtp_auth_md5(fd, login, password);
	}
	
	/* Try non-encrypted logins */
	if ((config.features & USESSL) == 0 && (config.features & INSECURE) == 0) {
		syslog(LOG_WARNING, "non-encrypted SMTP login is disabled in config, so skipping it");
		return (1);
	}
	
	if ((config.features & AUTHLOGIN) != 0) {
		/* Send AUTH command according to RFC 2554 */
		send_remote_command(fd, "AUTH LOGIN");
		if (read_remote(fd, NULL, NULL) != 334) {
			syslog(LOG_NOTICE, "remote delivery deferred:"
					" AUTH LOGIN was refused: %s",
					neterr);
			return (1);
		}

		len = base64_encode(login, strlen(login), &temp);
		if (len < 0) {
			syslog(LOG_ERR, "can not encode auth reply: %m");
			return (1);
		}

		send_remote_command(fd, "%s", temp);
		free(temp);
		res = read_remote(fd, NULL, NULL);
		if (res != 334) {
			syslog(LOG_NOTICE, "remote delivery %s: AUTH LOGIN failed: %s",
			      res == 503 ? "failed" : "deferred", neterr);
			return (res == 503 ? -1 : 1);
		}

		len = base64_encode(password, strlen(password), &temp);
		if (len < 0) {
			syslog(LOG_ERR, "can not encode auth reply: %m");
			return (1); 
		}

		send_remote_command(fd, "%s", temp);
		free(temp);
		res = read_remote(fd, NULL, NULL);
		if (res != 235) {
			syslog(LOG_NOTICE, "remote delivery %s: authentication failed: %s",
					res == 503 ? "failed" : "deferred", neterr);
			return (res == 503 ? -1 : 1);
		}
		
		return (0);
	} else if ((config.features & AUTHPLAIN) != 0) {
		/* PLAIN login (single string with authority, authetication and password,
		 * if no authority is provided the SMTP server will derive it from authentication.
		 */
		char *buff;
		 
		len = strlen(login) + strlen(password) + 2;
		buff = calloc(len, 1);
		if (!buff) {
			syslog(LOG_NOTICE, "remote delivery deferred: memory allocation failure");
			return (1);
		}
		
		strcpy(buff, login);
		strcpy(buff + strlen(login) + 1, password);
		
		len = base64_encode(buff, len, &temp);
		free(buff);
		
		if (len < 0) {
			syslog(LOG_ERR, "can not encode auth reply: %m");
			return (1);
		}
		
		send_remote_command(fd, "%s", temp);
		free(temp);
		res = read_remote(fd, NULL, NULL);
		if (res != 235) {
			syslog(LOG_NOTICE, "remote delivery deferred: authentication failed: %s",
			       neterr);
			return (1);
		}
		
		return (0);
	} else {
		/* No supported authentication method */
		syslog(LOG_ERR, "no supported authentication method for remote host");
		return (1);
	}
}

static int
esmtp_nextline(char **buff, int skip)
{
	char *line = *buff;
	long status;
	
	if (skip) {
		/* Allow skipping to the next line,
		 * possible scenarios are:
		 * - the parser is already on a newline
		 *   when it deleted '\r' and is currently over
		 *   a '\n' character.
		 * - the parser is in a token inside a line,
		 *   happens when it deleted ' ' and is over
		 *   the next token of a line.
		 */
		while (*line != '\0' && *line != '\n')
			line++;
		
		if (*line == '\n') {
			line++;
		}
	}
	
	/* now we expect the status number*/
	status = strtol(line, &line, 10);
	if (status != 250) {
		/*invalid status*/
		return -1;
	}
	
	if (*line == ' ') {
		/* signal end of parse with a positive number */
		*buff = line;
		return 1;
	}
	
	if (*line != '-') {
		/*invalid syntax*/
		return -1;
	}
	
	/* success */
	line++;
	*buff = line;
	return 0;
}

static char *
esmtp_nexttoken(char **buff)
{
	char *line = *buff;
	char *tok = line;
	
	if (*line == '\n' || *line == '\0') {
		/* No more tokens available,
		 * we are on the next line of the ESMTP response.
		 */
		return NULL;
	}
	
	/* make the line uppercase to honour RFC
	 * (tokens are parsed regardless their case)
	 */
	while (*line != '\0' && *line != '\r' && *line != ' ') {
		*line = toupper(*line);
		line++;
	}
	
	/* null terminate and update the parser */
	if (*line == '\r') {
	    *line++ = 0;
	}
	if (*line == ' ') {
	  *line++ = 0;
	}
	
	*buff = line;
	return tok;
}

static int
esmtp_response(int fd)
{
	char buff[ESMTPBUF_SIZE];
	size_t buffsize = sizeof(buff);
	char **parse;
	char *esmtp;
	char *tok;
	int error;
	int res;
  
	res = read_remote(fd, &buffsize, buff);
	if (res != 250) {
		return res;
	}
	
	if (buffsize > sizeof(buff)) {
		/*oversized or invalid buffer*/
		return -1;
	}
	
	/* initialize ESMTP parsing */
	esmtp = buff;
	parse = &esmtp;
	error = esmtp_nextline(parse, 0);
	while (error == 0) {
		tok = esmtp_nexttoken(parse);
		if (!tok) {
			/* shouldn't happen, return parse error */
			return -1;
		}
		
		if ((config.features & VERBOSE) != 0)
		      syslog(LOG_DEBUG, "ESMTP got %s", tok);
		
		if (strcmp(tok, "STARTTLS") == 0) {
			/* STARTTLS is supported */
			config.features |= HASSTARTTLS;
		} else if (strcmp(tok, "AUTH") == 0) {
			/* retrieve supported authentication methods */
			while ((tok = esmtp_nexttoken(parse)) != NULL) {
				if (strcmp(tok, "CRAM-MD5") == 0)
					config.features |= AUTHCRAMMD5;
				else if (strcmp(tok, "LOGIN") == 0)
					config.features |= AUTHLOGIN;
				else if (strcmp(tok, "PLAIN") == 0)
					config.features |= AUTHPLAIN;
			}
			
		}
		
		/*position over next line*/
		error = esmtp_nextline(parse, 1);
		
	}
	
	/*return a negative number on parsing error*/
	if (error < 0)
	    res = -1;
	
	return res;
}

static int
expect_response(int fd, const char *when, int exp)
{
	int res = read_remote(fd, NULL, NULL);
      
	if (res == 500 || res == 502) {
		syslog(LOG_NOTICE, "remote delivery deferred: failed after %s: %s", when, neterr);
		return (1);
	}
      
	if (res != exp) {
		syslog(LOG_ERR, "remote delivery failed after %s: %s", when, neterr);
		snprintf(errmsg, sizeof(errmsg), "remote host did not like our %s:\n%s", when, neterr);
		return (-1);
	}
	
	return 0;
}

static int
open_connection(struct mx_hostentry *h, int ehlo)
{
	int fd;
	int res;

	syslog(LOG_INFO, "trying remote delivery to %s [%s] pref %d using %s",
	       h->host, h->addr, h->pref, ehlo? "EHLO" : "HELO");

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
	
	/* Check first reply from remote host */
	res = read_remote(fd, NULL, NULL);
	if (res != 220) {
		switch(res) {
		case 421:
			syslog(LOG_INFO, "connection rejected temporarily by remote host");
			break;
		case 554:
			syslog(LOG_INFO, "connection failed, remote host requires QUIT");
			send_remote_command(fd, "QUIT");
			break;
		default:
			syslog(LOG_INFO, "connection failed, remote host greeted us with %d", res);
			break;
		}
		
		close(fd);
		return (-2);
	}
	
	syslog(LOG_DEBUG, "connection accepted");
	if (ehlo) {
		/* Try EHLO */
		send_remote_command(fd, "EHLO %s", hostname());
		res = esmtp_response(fd);
	} else {
		send_remote_command(fd, "HELO %s", hostname());
		res = read_remote(fd, NULL, NULL);
	}

	if (res != 250) {
		if (res < 0) {
			syslog(LOG_INFO, "connection failed, malformed response by remote host");
		} else {
			syslog(LOG_INFO, "connection failed, remote host refused our greeting");
		}
		
		close(fd);
		return -2;
	}
	
	return (fd);
}

static void
close_connection(int fd)
{
	if (config.ssl != NULL) {
		if ((config.features & USESSL) != 0)
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

	fd = open_connection(host, 1);
	if (fd == -2) {
		/* fallback to HELO if possible */
		if ((config.features & NOHELO) != 0) {
			/* HELO disabled in config file */
			syslog(LOG_NOTICE, "remote delivery deferred:"
			      " EHLO unsupported by remote host and HELO fallback is disabled");
			return (1);
		}
		
		if (do_auth) {
			/* cannot fallback to HELO, authentication is required */
			syslog(LOG_NOTICE, "remote delivery deferred:"
			       " EHLO unsupported by remote host and authentication is required");
			return (1);
		}
		
		if ((config.features & SECURETRANS) != 0 && (config.features & INSECURE) == 0) {
			/* cannot fallback to HELO if secure connection is required */
			syslog(LOG_NOTICE, "remote delivery deferred:"
				" ESMTP unsupported by remote host and secure connection is required");
			return (1);
		}
		
		if ((config.features & STARTTLS) != 0 && (config.features & TLS_OPP) == 0) {
			/* cannot fallback to HELO if STARTTLS is mandatory */
			syslog(LOG_NOTICE, "remote delivery deferred:"
				" ESMTP unsupported by remote host and STARTTLS is required");
			return (1);
		  
		}
	
		/*disable any security*/
		config.features &= ~(SECURETRANS | STARTTLS);
		fd = open_connection(host, 0);
	}
	
	if (fd < 0) {
	      /*connection failed*/
	      return (1);
	}
	
	if ((config.features & HASSTARTTLS) == 0 && (config.features & STARTTLS) != 0) {
		  if ((config.features & TLS_OPP) != 0) {
			/* disable STARTTLS, opportunistic mode */
			syslog(LOG_INFO, "in opportunistic TLS mode, STARTTLS not available");
			config.features &= ~STARTTLS;
		  } else {
			/* remote has no STARTTLS but user required it */
			syslog(LOG_ERR, "remote delivery deferred: STARTTLS not available");
			error = 1;
			goto out;
		  }
	}

	if ((config.features & SECURETRANS) != 0) {
		/* initialize secure transaction */
		error = smtp_init_crypto(fd, config.features);
		if (error == 0)
			syslog(LOG_DEBUG, "SSL initialization successful");
		else
			goto out;
		
		/* refresh supported ESMTP features if STARTTLS was used*/
		if ((config.features & STARTTLS) != 0) {
			config.features &= ~ESMTPMASK;
			send_remote_command(fd, "EHLO %s", hostname());
			res = esmtp_response(fd);
			if (res != 250) {
				/* shouldn't happen */
				syslog(LOG_NOTICE, "remote delivery deferred: EHLO after STARTTLS failed: %s", neterr);
				error = 1;
				goto out;
			}
		}
	}

	if (do_auth) {
		/*
		 * Check if the user wants plain text login without using
		 * encryption.
		 */
		syslog(LOG_INFO, "using SMTP authentication for user %s", a->login);
		error = smtp_login(fd, a->login, a->password);
		if (error) {
			syslog(LOG_ERR, "remote delivery failed:"
					" SMTP login failed: %m");
			snprintf(errmsg, sizeof(errmsg), "SMTP login to %s failed", host->host);
			goto out;
		}
	}

	/* XXX send ESMTP ENVID, RET (FULL/HDRS) and 8BITMIME */
	send_remote_command(fd, "MAIL FROM:<%s>", it->sender);
	error = expect_response(fd, "MAIL FROM", 250);
	if (error)
		goto out;

	/* XXX send ESMTP ORCPT */
	send_remote_command(fd, "RCPT TO:<%s>", it->addr);
	error = expect_response(fd, "RCPT TO", 250);
	if (error)
		goto out;

	send_remote_command(fd, "DATA");
	error = expect_response(fd, "DATA", 354);
	if (error)
		goto out;

	error = 0;
	while (fgets(line, sizeof(line), it->mailf)) {
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
	
	if (ferror(it->mailf)) {
		syslog(LOG_NOTICE, "remote delivery deferred: I/O read error, %m");
		error = 1;
		goto out;
	}

	send_remote_command(fd, ".");
	error = expect_response(fd, "final DATA", 250);
	if (error)
		goto out;

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
	unsigned int port;
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
