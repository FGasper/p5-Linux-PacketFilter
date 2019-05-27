package Linux::PacketFilter;

our %BPF;

BEGIN {
    %BPF = (
        w => 0x00,
        h => 0x08,
        b => 0x10,
        dw => 0x18,

        k => 0x00,
        x => 0x08,
    );

    my @inst = qw( ld ldx st stx alu jmp ret misc );
    for my $i ( 0 .. $#inst ) {
        $BPF{ $inst[$i] } = $i;
    }

    my @code = qw( imm abs ind mem len msh );
    for my $i ( 0 .. $#code ) {
        $BPF{ $code[$i] } = ( $i << 5 );
    }

    my @alu = qw( add sub mul div or and lsh rsh neg mod xor );
    for my $i ( 0 .. $#alu ) {
        $BPF{ $alu[$i] } = ( $i << 4 );
    }

    my @j = qw( ja jeq jgt jge jset );
    for my $i ( 0 .. $#j ) {
        $BPF{ $j[$i] } = ( $i << 4 );
    }
}

sub new {
    my $class = shift;

    my $buf = ("\0" x (8 * @_));

    my $f = 0;

    for my $filter (@_) {
        my $code = 0;
        for my $piece ( split m<\s+>, $filter->[0] ) {
            $piece =~ tr<A-Z><a-z>;

            $code |= ($BPF{$piece} // die "Unknown BPF: $piece");
        }

        substr(
            $buf, $f, 8,
            pack(
                'S CC L',
                $code,
                (@$filter == 2) ? (0, 0, $filter->[1]) : @{$filter}[2, 3, 1],
            ),
        );

        $f += 8;
    }

    return bless [ pack('S x![P] P', 0 + @_, $buf), $buf ], $class;
}

sub attach {
    my ($self, $socket) = @_;

    do {
        local ($@, $!);
        require Socket;
    };

    setsockopt $socket, Socket::SOL_SOCKET(), Socket::SO_ATTACH_FILTER(), $self->[0] or die "attach filter: $!";
}

1;
