package Linux::PacketFilter;

use strict;
use warnings;

=encoding utf-8

=head1 NAME

Linux::PacketFilter - Simple interface to Linux packet filtering

=head1 SYNOPSIS

    # Reject any packet that starts with a period:
    my $filter = Linux::PacketFilter->new(

        # Load the accumulator with the 1st byte in the packet:
        [ 'ld b abs', 0 ],

        # If the accumulator value is an ASCII period, continue;
        # otherwise, skip a line.
        [ 'jmp jeq', ord('.'), 0, 1 ],

        # If we continued, we’ll get here and thus reject the packet.
        [ ret => 0 ],

        # If we get here, we skipped a line above. That means
        # the packet’s first byte wasn’t an ASCII period,
        # so we'll return the full packet.
        [ ret => 0xffffffff ],
    );

=head1 DESCRIPTION

This module is a simple, small, pure-Perl compiler for Linux’s
Berkeley Packet Filter (BPF) implementation.

=head1 HOW DO I USE THIS?

If you’re familiar with BPF already, the SYNOPSIS above probably makes
sense “out-of-the-box”. If you’re new to BPF, though, take heart; it’s
fairly straightforward.

The best source I have found for learning about BPF itself is
L<bpf(4) in the BSD man pages|; see the section entitled B<FILTER MACHINE>.

Linux-specific implementation notes are available in the kernel
source tree at L</Documentation/networking/filter.txt|https://www.kernel.org/doc/Documentation/networking/filter.txt>. This contains a lot of detail
about uses for BPF that don't pertain to packet filtering, though.

L<Here is another helpful guide.|https://web.archive.org/web/20130125231050/http://netsplit.com/2011/02/09/the-proc-connector-and-socket-filters/> Take
especial note of the need to convert between network and host byte order.
(See below for a convenience that this module provides for this conversion.)

You might also take interest in L<the original BPF white paper|http://www.tcpdump.org/papers/bpf-usenix93.pdf>.

=cut

our %BPF;

BEGIN {
    %BPF = (
        w => 0x00,      # 32-bit word
        h => 0x08,      # 16-bit half-word
        b => 0x10,      # 8-bit byte
        # dw => 0x18,     # 64-bit double word

        k => 0x00,      # given constant
        x => 0x08,      # index register

        # Conveniences:
        kn => 0x00,
        kN => 0x00,
    );

    # ld = to accumulator
    # ldx = to index
    # st = accumulator to scratch[k]
    # stx = index to scratch[k]
    my @inst = qw( ld ldx st stx alu jmp ret misc );
    for my $i ( 0 .. $#inst ) {
        $BPF{ $inst[$i] } = $i;
    }

    # Load accumulator:
    # imm = k
    # abs = offset into packet
    # ind = index + k
    # mem = scratch[k]
    # len = packet length
    # msh = IP header length (hack ..)
    my @code = qw( imm abs ind mem len msh );
    for my $i ( 0 .. $#code ) {
        $BPF{ $code[$i] } = ( $i << 5 );
    }

    my @alu = qw( add sub mul div or and lsh rsh neg mod xor );
    for my $i ( 0 .. $#alu ) {
        $BPF{ $alu[$i] } = ( $i << 4 );
    }

    # ja = move forward k
    # jeq = move (A == k) ? jt : jf
    # jset = (A & k)
    my @j = qw( ja jeq jgt jge jset );
    for my $i ( 0 .. $#j ) {
        $BPF{ $j[$i] } = ( $i << 4 );
    }
}

=head1 METHODS

=head2 $obj = I<CLASS>->new( @filters )

Creates an object that represents an array of instructions for
the BPF filter machine. Each @filters member is an array reference
that represents a single instruction and has either 2 or 4 members,
which correspond with the BPF_STMT and BPF_JUMP macros, respectively.

The first member of each array reference is, rather than a number,
a space-separated string of options, lower-cased and without the
leading C<BPF_>. So where in C you would write:

    BPF_LD | BPF_W | BPF_ABS

... in this module you write:

    'ld w abs'

Note that, in Linux anyway, the C<ld>, C<w>, C<imm>, C<add>, C<ja>, and C<k>
options are all numerically 0, so strictly speaking, you do not need to give
these; thus, you could write the above as just:

    'abs'

For clarity's sake, though, you should probably avoid being quite so terse.
:) I find it reasonable to omit C<w> and C<k> but to include everything else
(so C<'ld abs'> for the above).

=head3 Byte order conversion

Pass your “k” values as scalar references to tell Linux::PacketFilter to
do a 16-bit or 32-bit byte
conversion. So, for example, the following:

    [ 'jmp jeq', 'n0x80000000', 1, 0 ]

… will skip a line if the accumulator matches 0x80000000 in network byte
order.

=cut

use constant {
    _INSTR_PACK => 'S CC L',

    _INSTR_PACK_n => (pack('n', 1) eq pack('S', 1)) ? 'S CC N' : 'S CC n xx',
    _INSTR_PACK_N => 'S CC N',

    _ARRAY_PACK => 'S x![P] P',
};

use constant _INSTR_LEN => length( pack _INSTR_PACK() );

sub new {
    my $class = shift;

    my $buf = ("\0" x (_INSTR_LEN() * @_));

    my $f = 0;

    for my $filter (@_) {
        my $code = 0;

        my $tmpl;

        for my $piece ( split m<\s+>, $filter->[0] ) {
            $code |= ($BPF{$piece} // die "Unknown BPF: $piece");

            if ($piece eq 'kn') {
                $tmpl = _INSTR_PACK_n();
            }
            elsif ($piece eq 'kN') {
                $tmpl = _INSTR_PACK_N();
            }
        }

        substr(
            $buf, $f, _INSTR_LEN(),
            pack(
                ( $tmpl || _INSTR_PACK() ),
                $code,
                (@$filter == 2) ? (0, 0, $filter->[1]) : @{$filter}[2, 3, 1],
            ),
        );

        $f += _INSTR_LEN();
    }

    return bless [ pack(_ARRAY_PACK(), 0 + @_, $buf), $buf ], $class;
}

=head2 I<OBJ>->attach( $SOCKET )

Attaches the filter instructions to the socket.

Note that this class purposely omits public access to the value that
is given to the underlying C<setsockopt(2)> system call. This is because
that value contains a pointer to a Perl string. That pointer is only valid
during this object's lifetime, and bad stuff (e.g., segmentation faults)
can happen when you start using pointers to strings that Perl has already
deleted.

=cut

sub attach {
    my ($self, $socket) = @_;

    do {
        local ($@, $!);
        require Socket;
    };

    setsockopt $socket, Socket::SOL_SOCKET(), Socket::SO_ATTACH_FILTER(), $self->[0] or die "attach filter: $!";

    return;
}

1;
