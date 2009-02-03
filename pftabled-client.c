/* $Id: pftabled-client.c,v 1.15 2009/02/04 12:05:10 armin Exp $ */
/*
 * Copyright (c) 2003, 2004, 2005, 2006, 2009 Armin Wolfermann. All rights
 * reserved.
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

#include "pftabled.h"

#include <sys/socket.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static void
fatal(char *text, char *arg)
{
	fprintf(stderr, "pftabled-client: ");
	fprintf(stderr, text, arg);
	exit(1);
}

static void
usage(int code)
{
	fprintf(stderr, "\nUsage: "
	    "pftabled-client [-k keyfile] host port table cmd [ip[/mask]]\n"
	    "\n"
	    "host      Host where pftabled is running\n"
	    "port      Port number at host\n"
	    "table     Name of table\n"
	    "cmd       One of: add, del or flush.\n"
	    "ip[/mask] IP or network to add or delete from table\n"
	    "keyfile   Name of file to read key from\n\n");
	if (code)
		exit(code);
}

int
main(int argc, char *argv[])
{
	struct sockaddr_in src;
	struct sockaddr_in dst;
	struct hostent *host;
	struct pftabled_msg msg;
	char key[SHA1_DIGEST_LENGTH];
	char *slash;
	int keyfile;
	int use_key = 0;
	int s, ch;

	while ((ch = getopt(argc, argv, "k:h")) != -1) {
		switch (ch) {
		case 'k':
			use_key = 1;
			keyfile = open(optarg, O_RDONLY, 0);
			if (read(keyfile, key, sizeof(key)) != sizeof(key))
				fatal("unable to read key file\n", NULL);
			close(keyfile);
			break;
		case 'h':
		default:
			usage(1);
		}
	}
	argc -= optind;
	argv += optind;

	if (argc < 4)
		usage(1);

	if ((s = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
		fatal("Error creating socket\n", NULL);

	memset(&src, 0, sizeof(src));
	src.sin_family = AF_INET;

	if (bind(s, (struct sockaddr *)&src, sizeof(src)) == -1)
		fatal("Error binding socket\n", NULL);

	memset(&dst, 0, sizeof(dst));
	dst.sin_family = AF_INET;

	if ((host = gethostbyname(*argv)) == NULL)
		fatal("Unable to resolve '%s'\n", *argv);

	memcpy(&dst.sin_addr, host->h_addr, host->h_length);
	--argc, ++argv;

	dst.sin_port = htons(atoi(*argv));
	--argc, ++argv;

	memset(&msg, 0, sizeof(msg));
	msg.version = PFTABLED_MSG_VERSION;
	msg.timestamp = htonl(time(NULL));

	if (strlen(*argv) > sizeof(msg.table))
		fatal("Table name '%s' too long\n", *argv);

	strncpy(msg.table, *argv, strlen(*argv));
	--argc, ++argv;

	if (!strcmp(*argv, "add"))
		msg.cmd = PFTABLED_CMD_ADD;
	else if (!strcmp(*argv, "del"))
		msg.cmd = PFTABLED_CMD_DEL;
	else if (!strcmp(*argv, "flush"))
		msg.cmd = PFTABLED_CMD_FLUSH;
	else
		fatal("Unknown command '%s'\n", *argv);
	--argc, ++argv;

	if (msg.cmd != PFTABLED_CMD_FLUSH) {
		if (!argc)
			usage(1);

		if ((slash = strchr(*argv, '/')) != NULL) {
			msg.mask = (uint8_t)atoi(slash+1);
			if (msg.mask < 1 || msg.mask > 32)
				fatal("Invalid network mask '%s'\n", slash);
			*slash = '\0';
		} else
			msg.mask = 32;

		if (inet_pton(AF_INET, *argv, &msg.addr) != 1)
			fatal("Unable to parse '%s'\n", *argv);
	}

	if (use_key)
		hmac(key, &msg, sizeof(msg) - sizeof(msg.digest), msg.digest);

	if (sendto(s, &msg, sizeof(msg), 0, (struct sockaddr *)&dst,
		    sizeof(dst)) == -1)
		fatal("Unable to send message\n", NULL);

	return 0;
}
