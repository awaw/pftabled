/* $Id: pftabled.c,v 1.7 2004/04/24 23:12:01 armin Exp $ */
/*
 * Copyright (c) 2003, 2004 Armin Wolfermann.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/queue.h>

#include <net/if.h>
#include <net/pfvar.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <pwd.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include "pftabled.h"

#define PFDEV "/dev/pf"
static int pfdev = -1;

static struct syslog_data sdata = SYSLOG_DATA_INIT;

static int timeout = 0;

TAILQ_HEAD(pftimeout_head, pftimeout) timeouts;
struct pftimeout {
	TAILQ_ENTRY(pftimeout) queue;
	struct in_addr ip;
	time_t timeout;
};

static void
logit(int level, const char *fmt, ...)
{
	va_list ap;
	extern char *__progname;

	va_start(ap, fmt);

	if (sdata.opened) {
		vsyslog_r(level, &sdata, fmt, ap);
	} else {
		fprintf(stderr, "%s: ", __progname);
		vfprintf(stderr, fmt, ap);
		if (strchr(fmt, '\n') == NULL)
			fprintf(stderr, "\n");
	}

	va_end(ap);
}

static void
add(char *tname, struct in_addr *ip)
{
	struct pfioc_table io;
	struct pfr_table table;
	struct pfr_addr addr;
	struct pftimeout *t;

	bzero(&io, sizeof io);
	bzero(&table, sizeof(table));
	bzero(&addr, sizeof(addr));

	strncpy(table.pfrt_name, tname, sizeof(table.pfrt_name));

	bcopy(ip, &addr.pfra_ip4addr, 4);
	addr.pfra_af = AF_INET;
	addr.pfra_net = 32;

	io.pfrio_table = table;
	io.pfrio_buffer = &addr;
	io.pfrio_esize = sizeof(addr);
	io.pfrio_size = 1;

	if (ioctl(pfdev, DIOCRADDADDRS, &io))
		err(1, "ioctl");

	if (timeout) {
		if ((t = malloc(sizeof(struct pftimeout))) == NULL)
			err(1, "malloc");
		t->timeout = time(NULL) + timeout;
		t->ip = *ip;
		TAILQ_INSERT_HEAD(&timeouts, t, queue);
	}
}

static void
del(char *tname, struct in_addr *ip)
{
	struct pfioc_table io;
	struct pfr_table table;
	struct pfr_addr addr;

	bzero(&io, sizeof(io));
	bzero(&table, sizeof(table));
	bzero(&addr, sizeof(addr));

	strncpy(table.pfrt_name, tname, sizeof(table.pfrt_name));

	bcopy(ip, &addr.pfra_ip4addr, 4);
	addr.pfra_af = AF_INET;
	addr.pfra_net = 32;

	io.pfrio_table = table;
	io.pfrio_buffer = &addr;
	io.pfrio_esize = sizeof(addr);
	io.pfrio_size = 1;

	if (ioctl(pfdev, DIOCRDELADDRS, &io))
		err(1, "ioctl");
}

static void
flush(char *tname)
{
	struct pfioc_table io;
	struct pfr_table table;

	bzero(&io, sizeof io);
	bzero(&table, sizeof(table));

	strncpy(table.pfrt_name, tname, sizeof(table.pfrt_name));

	io.pfrio_table = table;

	if (ioctl(pfdev, DIOCRCLRADDRS, &io))
		err(1, "ioctl");
}

static void
usage(int code)
{
	fprintf(stderr, "%d\n", sizeof(struct pftimeout));
	fprintf(stderr,
	    "Usage: pftabled [-dv] [-a address] [-p port] [-t timeout] table\n"
	    "-d          Run as daemon in the background\n"
	    "-v          Log all received packets\n"
	    "-a address  Bind to this address (default: 0.0.0.0)\n"
	    "-p port     Bind to this port (default: 56789)\n"
	    "-t timeout  Remove IPs from table after timeout seconds\n");
	if (code)
		exit(code);
}

int
main(int argc, char *argv[])
{
	struct sockaddr_in laddr;
	struct sockaddr_in raddr;
	socklen_t socklen = sizeof(struct sockaddr_in);
	struct passwd *pw;
	struct pftabled_msg msg;
	int ch, n, s;
	struct timeval tv;
	struct pftimeout *t;

	/* Options and their defaults */
	char *address = NULL;
	int daemonize = 0;
	int port = 56789;
	char *table = NULL;
	int verbose = 0;

	/* Process commandline arguments */
	while ((ch = getopt(argc, argv, "a:dp:t:vh")) != -1) {
		switch (ch) {
		case 'a':
			address = optarg;
			break;
		case 'd':
			daemonize = 1;
			break;
		case 'p':
			port = strtol(optarg, NULL, 10);
			break;
		case 't':
			timeout = strtol(optarg, NULL, 10);
			break;
		case 'v':
			verbose = 1;
			break;
		case 'h':
		default:
			usage(1);
		}
	}

	/* Check table argument */
	if ((table = argv[optind]) == NULL)
		usage(1);

	if (strlen(table) >= PF_TABLE_NAME_SIZE)
		err(1, "table name too long");

	/* Prepare and bind our socket */
	bzero((char *)&laddr, sizeof(struct sockaddr_in));
	laddr.sin_family = AF_INET;
	laddr.sin_addr.s_addr = inet_addr(address ? address : "0.0.0.0");
	laddr.sin_port = htons(port);

	if ((s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1)
		err(1, "socket");

	if (bind(s, (struct sockaddr *)&laddr, socklen) == -1)
		err(1, "bind");

	/* Set receive timeout on socket if using timeouts */
	if (timeout) {
		tv.tv_sec = 1;
		tv.tv_usec = 0;
		if (setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)))
			err(1, "setsockopt");
	}

	/* Open PF device while we are root */
	pfdev = open(PFDEV, O_RDWR);
	if (pfdev == -1)
		err(1, "open " PFDEV);

	/* Daemonize if requested */
	if (daemonize) {
		tzset();
		openlog_r("pftabled", LOG_PID|LOG_NDELAY, LOG_DAEMON, &sdata);

		if (daemon(0, 0) == -1)
			err(1, "daemon");
	}

	/* Find less privileged user */
	pw = getpwnam("pftabled");
	if (!pw)
		pw = getpwnam("nobody");

	/* Chroot to /var/empty */
	if (chroot("/var/empty") == -1 || chdir("/") == -1) {
		logit(LOG_ERR, "unable to chroot to /var/empty");
		exit(1);
	}

	/* Drop privileges */
	if (pw) {
		if ((setgroups(1, &pw->pw_gid) == -1) ||
		    (setegid(pw->pw_gid) == -1) ||
		    (setgid(pw->pw_gid) == -1) ||
		    (seteuid(pw->pw_uid) == -1) ||
		    (setuid(pw->pw_uid) == -1)) {
			logit(LOG_ERR, "unable to drop privileges");
			exit(1);
		}
	}

	/* Main loop: receive packets */
	for(;;) {

		n = recvfrom(s, &msg, sizeof(msg), 0,
		    (struct sockaddr *)&raddr, &socklen);

		/* Check for timeouts */
		if (timeout) {
			time_t now = time(NULL);

			while (!TAILQ_EMPTY(&timeouts)) {
				t = TAILQ_LAST(&timeouts, pftimeout_head);
				if (now < t->timeout)
					break;

				del(table, &t->ip);
				if (verbose)
					logit(LOG_ERR, "<%s> del %s\n", table,
					    inet_ntoa(t->ip));

				TAILQ_REMOVE(&timeouts, t, queue);
				free(t);
			}
		}

		/* Drop short packets */
		if (n != sizeof(msg))
			continue;

		/* Dispatch commands */
		switch (ntohl(msg.cmd)) {
		case CMD_ADD:
			add(table, &msg.addr);
			if (verbose)
				logit(LOG_ERR, "<%s> add %s\n", table,
				    inet_ntoa(msg.addr));
			break;
		case CMD_DEL:
			del(table, &msg.addr);
			if (verbose)
				logit(LOG_ERR, "<%s> del %s\n", table,
				    inet_ntoa(msg.addr));
			break;
		case CMD_FLUSH:
			flush(table);
			if (verbose)
				logit(LOG_ERR, "<%s> flush\n", table);
			break;
		default:
			logit(LOG_ERR, "received unkown command\n");
			break;
		}
	}

	return (0);
}
