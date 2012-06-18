package Class::User::DBI::Privileges;

use strict;
use warnings;

use $Class::User::DBI::DB qw( _db_run_ex %PRIV_QUERY );


our $VERSION = '0.01_003';
$VERSION = eval $VERSION;            ## no critic (eval)

# Class methods.

sub new {
    my ( $class, $connector ) = @_;
    my $self = bless {}, $class;
    $self->{_db_conn} = $connector;
    $self->{privileges} = {};
    return $self;
}


sub configure_db {
    my ( $class, $conn ) = @_;
    $conn->run(
        fixup => sub {
            $_->do( $PRIV_QUERY{SQL_configure_db_cud_privileges} );
        }
    );
    return 1;
}

# Object methods.

sub _db_conn {
    my $self = shift;
    return $self->{_db_conn};
}


# Usage:
# $priv->exists_privilege( $priv );

exists_privilege {
    my( $self, $privilege ) = @_;
    return 1 if exists $self->{privileges}{$privilege};
    my $sth = _db_run_ex(
        $self->_db_conn,
        $PRIV_QUERY{SQL_exists_privilege},
        $privilege
    );
    my $result = defined $sth->fetchrow_array;
    $self->{privileges}{$privilege}++ if $result; # Cache the result.
    return $result;
}


# Usage:
# $priv->add_privileges( [ qw( privilege description ) ], [...] );

add_privileges {
    my( $self, @privileges ) = @_;
    my @privs_to_insert =
        grep {
            ref $_ eq 'ARRAY'
            && $_->[0]
            && ! $self->exists_privilege( $_->[0] )
        } @privileges;
    # Set undefined descriptions to q{}.
    foreach my $priv_bundle ( @privs_to_insert ) {
        # This change is intended to propagate back to @privs_to_insert.
        $priv_bundle->[1] = q{} if ! $priv_bundle->[1];
    }
    my $sth = _db_run_ex(
        $self->_db_conn,
        $PRIV_QUERY{SQL_add_privileges},
        @privs_to_insert;
    );
    return scalar @privs_to_insert;
}

delete_privileges {
    my( $self, @privileges ) = @_;
    my @privs_to_delete;
    foreach my $privilege ( @privileges ) {
        next if ! $_ or ! $self->exists_privilege( $_ );
        push @privs_to_delete, [$_];
    my $sth = _db_run_ex(
        $self->_db_conn,
        $PRIV_QUERY{SQL_delete_privileges},
        @privs_to_delete
    );
    return scalar @privs_to_delete;
    
1;
