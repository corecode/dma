/*
 * Copyright (c) 2010-2015, Simon Schubert <2@0x2c.org>.
 * Copyright (c) 2008 The DragonFly Project.  All rights reserved.
 *
 * This code is derived from software contributed to The DragonFly Project
 * by Antonio Huete Jimenez <tuxillo@quantumachine.net>
 * by Simon Schubert <2@0x2c.org>.
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

#include <sys/param.h>
#include <sys/stat.h>

#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <paths.h>
#include <pwd.h>
#include <stdio.h>
#include <syslog.h>
#include <stdlib.h>
#include <unistd.h>

#include "dma.h"

void
logfail(const char *fmt, ...)
{
	int oerrno = errno;
	va_list ap;
	char outs[1024];

	outs[0] = 0;
	if (fmt != NULL) {
		va_start(ap, fmt);
		vsnprintf(outs, sizeof(outs), fmt, ap);
		va_end(ap);
	}

	errno = oerrno;
	if (*outs != 0)
		syslog(LOG_ERR, errno ? "%s: %m" : "%s", outs);
	else
		syslog(LOG_ERR, errno ? "%m" : "unknown error");

	exit(1);
}

gid_t
dma_drop_grpriv(void)
{
	struct group *gr;
	gid_t mail_gid;

	gr = getgrnam(DMA_GROUP);
	if (!gr)
		logfail("cannot find dma group `%s'", DMA_GROUP);

	mail_gid = gr->gr_gid;

	if (setgid(mail_gid) != 0)
		logfail("cannot set gid to %d (%s)", mail_gid, DMA_GROUP);
	if (getegid() != mail_gid)
		logfail("cannot set gid to %d (%s), still at %d", mail_gid,
		    DMA_GROUP, getegid());

	endgrent();

	return mail_gid;
}

uid_t
dma_getuser(const char *user)
{
	struct passwd *pw;
	uid_t uid;

	/* the username may not contain a pathname separator */
	if (strchr(user, '/')) {
		errno = 0;
		logfail("path separator in username `%s'", user);
		exit(1);
	}

	/* verify the user exists */
	errno = 0;
	pw = getpwnam(user);
	if (!pw)
		logfail("cannot find user `%s'", user);

	uid = pw->pw_uid;
	endpwent();

	return uid;
}

/* caller is responsible of freeing dir */
void
dma_gethome(const char *user, char **dir)
{
	struct passwd *pw;

	/* verify the user exists */
	pw = getpwnam(user);
	if (!pw)
		logfail("cannot find user `%s'", user);

	if (pw->pw_dir)
		asprintf(dir, "%s", pw->pw_dir);
	else
		logfail("cannot get %s home directory", user);

}
