#!/usr/bin/env perl

use strict;
use warnings;
use autodie;

use Test::More;
use Test::FailWarnings;

use Socket;

use FindBin;
use lib "$FindBin::Bin/../lib";

use Text::Control;

use Linux::PacketFilter ();

sub _do_test {
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

    recv( $b, my $buf1, 512, 0 );
    recv( $b, my $buf2, 512, 0 );

    is( $buf1, 'He', 'filtered as intended' );
    is( $buf2, "There.$/", 'ignored as intended' );

    #----------------------------------------------------------------------

    # Accept every packet whose first 2 bytes (network order) are > 256.
    # Trim all others down to 1 byte.
    my $filter2 = Linux::PacketFilter->new(
        [ 'ld h abs', 0 ],
        [ 'jmp jgt kn', 256, 0, 1 ],
        [ 'ret k', 0xffffffff ],
        [ 'ret k', 1 ],
    );

    $filter2->attach($b);

    send( $a, pack('n a*', 123, 'shortened'), 0 );
    send( $a, pack('n a*', 255, 'shortened'), 0 );
    send( $a, pack('n a*', 256, 'full'), 0 );
    send( $a, pack('n a*', 65534, 'full'), 0 );

    my @vals = map { recv($b, my $b, 512, 0); $b } 1 .. 4;
    is_deeply(
        \@vals,
        [
            pack('n a*', 123, 's'),
            pack('n a*', 255, 's'),
            pack('n a*', 256, 'full'),
            pack('n a*', 65534, 'full'),
        ],
        '16-bit host/network order',
    ) or diag [ map { Text::Control::to_hex($_) } @vals ];
}

SKIP: {
    skip 'This test only runs in Linux.' if $^O ne 'linux';

    _do_test();
}

done_testing();
