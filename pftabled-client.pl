#!/usr/bin/perl
#
# Copyright (c) 2009 Armin Wolfermann <armin@wolfermann.org>
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
use strict;
use warnings;
use IO::Socket::INET;
use Digest::HMAC_SHA1 qw(hmac_sha1);

use constant PFTABLED_MSG_VERSION => 2;
use constant PFTABLED_CMD_ADD => 1;
use constant PFTABLED_CMD_DEL => 2;
use constant PFTABLED_CMD_FLUSH => 3;

use constant SHA1_DIGEST_LENGTH => 20;
use constant PF_TABLE_NAME_SIZE => 32;

my $usage = <<USAGE;
pftabled-client host port table cmd [ip[/mask]] [keyfile]

host      Host where pftabled is running
port      Port number at host
table     Name of table
cmd       One of: add, del or flush
ip[/mask] IP or network to add or delete from table
keyfile   Name of file to read key from
USAGE

my ($host, $port, $table, $cmd, $target, $key) = @ARGV;

unless ($host && $port && $table && $cmd =~ /^(add|del|flush)$/) {
	print STDERR $usage;
	exit 1;
}

my @ip = (0, 0, 0, 0);
my $mask = 32;
if ($target) {
	if ($target !~ /^(\d+)\.(\d+)\.(\d+)\.(\d+)(?:\/)?(\d+)?$/) {
		print STDERR $usage;
		exit 1;
	}
	@ip = ($1, $2, $3, $4);
	$mask = $5 if $5;
}

if ($key) {
	if (! -r $key) {
		print STDERR $usage;
		exit 1;
	}
	open(KEY, "<$key");
	sysread KEY, $key, SHA1_DIGEST_LENGTH;
	close KEY;
}

my $sock = new IO::Socket::INET->new(
	Proto    => 'udp',
	PeerPort => $port,
	PeerAddr => $host) or die "Can't create socket: $@\n";

my $msg = pack("C", PFTABLED_MSG_VERSION);

if ($cmd eq 'add') {
	$msg .= pack("C", PFTABLED_CMD_ADD);
} elsif ($cmd eq 'del') {
	$msg .= pack("C", PFTABLED_CMD_DEL);
} elsif ($cmd eq 'flush') {
	$msg .= pack("C", PFTABLED_CMD_FLUSH);
}

$msg .= pack("x");

$msg .= pack("C", $mask);
$msg .= pack("C4", @ip);

$msg .= pack("Z" . PF_TABLE_NAME_SIZE, $table);
$msg .= pack("N", time());

$msg .= hmac_sha1($msg, $key);

$sock->send($msg) or die "send: $!";

