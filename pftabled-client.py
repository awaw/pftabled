#!/usr/local/bin/python
#
# Copyright (c) 2010 Armin Wolfermann <armin@wolfermann.org>
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
#
import hmac
import re
import sha
import socket
import struct
import sys
import time

if len(sys.argv) < 5:
    print "usage: pftabled-client.py host port table cmd [ip] [key]"
    sys.exit(1)

host = sys.argv[1]
port = int(sys.argv[2])
table = sys.argv[3]
command = { 'add': 1, 'del': 2, 'flush': 3 }.get(sys.argv[4], 0)

addr = '0.0.0.0'
netmask = 32
if len(sys.argv) > 5:
    addr = sys.argv[5]
    m = re.search('([\d\.]+)/(\d+)', addr)
    if m:
        addr = m.group(1)
	netmask = int(m.group(2))

key = ''
if len(sys.argv) > 6:
    key = sys.argv[6]

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
msg = struct.pack("BBxB4s32sI", 2, command, netmask, socket.inet_aton(addr), table, socket.htonl(int(time.time())) & 0xFFFFFFFF)
msg = msg + hmac.new(key, msg, digestmod=sha).digest()
s.sendto(msg, (host, port))
s.close()

