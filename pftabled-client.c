/* $Id: pftabled-client.c,v 1.11 2004/09/12 15:53:22 armin Exp $ */
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

void
fatal(char *text, char *arg)
{
	fprintf(stderr, "pftabled-client: ");
	fprintf(stderr, text, arg);
	exit(1);
}

int
main(int argc, char *argv[])
{
	struct sockaddr_in src;
	struct sockaddr_in dst;
	struct hostent *host;
	struct pftabled_msg msg;
	char key[SHA1_DIGEST_LENGTH];
	int keyfile;
	int s;

	if (argc != 7) {
		fprintf(stderr,
		    "Usage: pftabled-client host port cmd ip table keyfile\n\n"
		    "host    Host where pftabled is running\n"
		    "port    Port number at host\n"
		    "cmd     One of: add, del or flush.\n"
		    "ip      IP to add or delete from table\n"
		    "table   Name of table\n"
		    "keyfile Name of file to read key from\n\n");
		exit(1);
	}

	if ((s = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
		fatal("Error creating socket\n", NULL);

	memset(&src, 0, sizeof(src));
	src.sin_family = AF_INET;

	if (bind(s, (struct sockaddr *)&src, sizeof(src)) == -1)
		fatal("Error binding socket\n", NULL);

	memset(&dst, 0, sizeof(dst));
	dst.sin_family = AF_INET;

	if ((host = gethostbyname(argv[1])) == NULL)
		fatal("Unable to resolve '%s'\n", argv[1]);

	memcpy(&dst.sin_addr, host->h_addr, host->h_length);

	dst.sin_port = htons(atoi(argv[2]));

	memset(&msg, 0, sizeof(msg));
	msg.version = PFTABLED_MSG_VERSION;
	msg.timestamp = htonl(time(NULL));

	if (!strcmp(argv[3], "add"))
		msg.cmd = PFTABLED_CMD_ADD;
	else if (!strcmp(argv[3], "del"))
		msg.cmd = PFTABLED_CMD_DEL;
	else if (!strcmp(argv[3], "flush"))
		msg.cmd = PFTABLED_CMD_FLUSH;
	else
		fatal("Unknown command '%s'\n", argv[3]);

	if (inet_pton(AF_INET, argv[4], &msg.addr) != 1)
		fatal("Unable to parse '%s'\n", argv[4]);

	if (strlen(argv[5]) > sizeof(msg.table))
		fatal("Table name '%s' too long\n", argv[5]);

	strncpy(msg.table, argv[5], strlen(argv[5]));

	keyfile = open(argv[6], O_RDONLY, 0);
	if (read(keyfile, key, sizeof(key)) != sizeof(key))
		fatal("Unable to read key from file '%s'\n", argv[6]);
	close(keyfile);

	hmac(key, &msg, sizeof(msg) - sizeof(msg.digest), msg.digest);

	if (sendto(s, &msg, sizeof(msg), 0, (struct sockaddr *)&dst,
		    sizeof(dst)) == -1)
		fatal("Unable to send message\n", NULL);

	return 0;
}
