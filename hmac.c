/*
 * Copyright (c) 2004 Armin Wolfermann.  All rights reserved.
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
#include <string.h>
#include "pftabled.h"
#include "sha1.h"

void
hmac(uint8_t *key, void *data, int datalen, uint8_t *md)
{
	SHA1_CTX ctx;
	unsigned char pad[SHA1_BLOCK_LENGTH];
	unsigned int i;

	/* compute ipad from key */
	memset((void *)&pad, 0, sizeof(pad));
	(void)memcpy(pad, key, SHA1_DIGEST_LENGTH);
	for (i = 0; i < sizeof(pad); i++)
		pad[i] ^= 0x36;

	/* compute inner hash */
	SHA1Init(&ctx);
	SHA1Update(&ctx, pad, sizeof(pad));
	SHA1Update(&ctx, data, datalen);
	SHA1Final(md, &ctx);

	/* convert ipad to opad */
	for (i = 0; i < sizeof(pad); i++)
		pad[i] ^= 0x36 ^ 0x5c;

	/* compute outer hash */
	SHA1Init(&ctx);
	SHA1Update(&ctx, pad, sizeof(pad));
	SHA1Update(&ctx, md, SHA1_DIGEST_LENGTH);
	SHA1Final(md, &ctx);
}

int
hmac_verify(uint8_t *key, void *data, int datalen, uint8_t *md)
{
	uint8_t md2[SHA1_DIGEST_LENGTH];

	hmac(key, data, datalen, md2);

	return (memcmp(md, md2, SHA1_DIGEST_LENGTH));
}
