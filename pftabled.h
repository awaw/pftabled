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

#include "config.h"

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#else
#ifdef HAVE_STDINT_H
#include <stdint.h>
#else
#ifdef HAVE_INTTYPES_H
#include <inttypes.h>
#endif
#endif
#endif
#include <netinet/in.h>
#include "sha1.h"

#ifdef DEBUG
#define DPRINTF(x) do { printf x ; } while (0)
#else
#define DPRINTF(x)
#endif

#define cleanmask(ip, mask) { \
	uint8_t *b = (uint8_t *)ip; \
	if (mask < 32) b[3] &= (0xFF << (32 - mask)); \
	if (mask < 24) b[2] &= (0xFF << (24 - mask)); \
	if (mask < 16) b[1] &= (0xFF << (16 - mask)); \
	if (mask <  8) b[0] &= (0xFF << ( 8 - mask)); \
}

#ifndef PF_TABLE_NAME_SIZE
#define PF_TABLE_NAME_SIZE 32	/* Needs to be defined for non-OpenBSD */
#endif

#define CLOCKDIFF 60	/* Maximum clock difference plus network delay in
			   seconds between server and client. Server drops
			   packet if exceeded. */

#define PFTABLED_MSG_VERSION 0x02

#define PFTABLED_CMD_ADD   0x01
#define PFTABLED_CMD_DEL   0x02
#define PFTABLED_CMD_FLUSH 0x03

struct pftabled_msg {
	uint8_t		version;
	uint8_t		cmd;
	uint8_t		reserved;
	uint8_t		mask;
	struct in_addr	addr;
	char		table[PF_TABLE_NAME_SIZE];
	uint32_t	timestamp;
	uint8_t		digest[SHA1_DIGEST_LENGTH];
};

/* hmac.c */
void hmac(uint8_t *, void *, int, uint8_t *);
int hmac_verify(uint8_t *, void *, int, uint8_t *);

