#!/usr/bin/env perl

use strict;
use warnings;
use autodie;

use Test::More;
use Test::FailWarnings;

use Socket;

use FindBin;
use lib "$FindBin::Bin/../lib";

use Linux::PacketFilter ();

socketpair my $a, my $b, AF_UNIX(), SOCK_DGRAM(), 0;

# For any packet whose 2nd byte is 'e', return only the first 2 bytes;
# otherwise return the whole thing.
my $filter = Linux::PacketFilter->new(
    [ 'ld b abs', 1 ],
    [ 'jmp jeq k', ord('e'), 0, 1 ],
    [ 'ret k', 2 ],
    [ 'ret k', 0xffffffff ],
);

$filter->attach($b);

send( $a, "Hello.\n", 0 );
send( $a, "There.\n", 0 );
close $a;

recv( $b, my $buf1, 512, 0 );
recv( $b, my $buf2, 512, 0 );

is( $buf1, 'He', 'filtered as intended' );
is( $buf2, "There.$/", 'ignored as intended' );

done_testing();
