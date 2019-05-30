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

    # This seems strange .. the filter takes numbers in host order but
    # applies them in network order. That seems inconsistent with Netlink
    # sockets, where the filter takes numbers in network order.
    my $filter2 = Linux::PacketFilter->new(
        [ 'ld h abs', 0 ],
        [ 'jmp jeq k', 256, 0, 1 ],
        [ 'ret k', 0xffffffff ],
        [ 'ret k', 3 ],
    );

    $filter2->attach($b);

    send( $a, pack('n a*', 123, 'shortened'), 0 );
    send( $a, pack('n a*', 256, 'full'), 0 );
    send( $a, pack('n a*', 257, 'shortened'), 0 );
    send( $a, pack('n a*', 65534, 'shortened'), 0 );

    my @vals = map { recv($b, my $b, 512, 0); $b } 1 .. 4;
    is_deeply(
        \@vals,
        [
            pack('n a*', 123, 's'),
            pack('n a*', 256, 'full'),
            pack('n a*', 257, 's'),
            pack('n a*', 65534, 's'),
        ],
        '16-bit host/network order',
    ) or diag explain [ map { Text::Control::to_hex($_) } @vals ];

    #----------------------------------------------------------------------

    {
        my $filter3 = Linux::PacketFilter->new(
            [ 'ld w abs', 0 ],
            [ 'jmp jeq k_N', 256, 0, 1 ],
            [ 'ret k', 0xffffffff ],
            [ 'ret k', 5 ],
        );

        $filter3->attach($b);

        send( $a, pack('L a*', 123, 'shortened'), 0 );
        send( $a, pack('L a*', 256, 'full'), 0 );
        send( $a, pack('L a*', 257, 'shortened'), 0 );
        send( $a, pack('L a*', 65534, 'shortened'), 0 );

        my @vals = map { recv($b, my $b, 512, 0); $b } 1 .. 4;
        is_deeply(
            \@vals,
            [
                pack('L a*', 123, 's'),
                pack('L a*', 256, 'full'),
                pack('L a*', 257, 's'),
                pack('L a*', 65534, 's'),
            ],
            '32-bit host/network order',
        ) or diag explain [ map { Text::Control::to_hex($_) } @vals ];
    }
}

SKIP: {
    skip 'This test only runs in Linux.' if $^O ne 'linux';

    _do_test();
}

done_testing();
