/* $Id: pftabled-client.c,v 1.5 2004/04/24 17:49:17 armin Exp $ */
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
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <netdb.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "pftabled.h"

int
main(int argc, char *argv[])
{
	struct sockaddr_in src;
	struct sockaddr_in dst;
	struct hostent *host;
	struct pftabled_msg msg;
	int s;

	if (argc != 5) {
		fprintf(stderr,
		    "Usage: pftabled-client host port cmd ip\n\n"
		    "host  Host where pftabled is running\n"
		    "port  Port number at host\n"
		    "cmd   One of: add, del or flush.\n"
		    "ip    IP to add or delete from table\n\n");
		exit(1);
	}

	if ((s = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
		fprintf(stderr, "Error creating socket\n");
		exit(1);
	}

	memset(&src, 0, sizeof(src));
	src.sin_family = AF_INET;

	if (bind(s, (struct sockaddr *)&src, sizeof(src)) == -1) {
		fprintf(stderr, "Error binding socket\n");
		exit(1);
	}

	memset(&dst, 0, sizeof dst);
	dst.sin_family = AF_INET;

	host = gethostbyname(argv[1]);
	if (host == NULL) {
		fprintf(stderr, "Unable to resolve '%s'\n", argv[1]);
		exit(1);
	}
	memcpy(&dst.sin_addr, host->h_addr, host->h_length);

	dst.sin_port = htons(atoi(argv[2]));

	if (!strcmp(argv[3], "add"))
		msg.cmd = htonl(CMD_ADD);
	else if (!strcmp(argv[3], "del"))
		msg.cmd = htonl(CMD_DEL);
	else if (!strcmp(argv[3], "flush"))
		msg.cmd = htonl(CMD_FLUSH);
	else {
		fprintf(stderr, "Unknown command '%s'\n", argv[3]);
		exit(1);
	}

	if (inet_pton(AF_INET, argv[4], &msg.addr) != 1) {
		fprintf(stderr, "Unable to parse '%s'\n", argv[4]);
		exit(1);
	}

	if (sendto(s, &msg, sizeof(msg), 0, (struct sockaddr *)&dst,
		    sizeof(dst)) == -1) {
		fprintf(stderr, "Unable to send message\n");
		exit(1);
	}

	return 0;
}
