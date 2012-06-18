package Class::User::DBI::Privileges;

use strict;
use warnings;

use Carp;

use Class::User::DBI::DB qw( _db_run_ex  %PRIV_QUERY );

our $VERSION = '0.01_003';
$VERSION = eval $VERSION;    ## no critic (eval)

# Class methods.

sub new {
    my ( $class, $conn ) = @_;
    my $self = bless {}, $class;
    croak 'Constructor called without a DBIx::Connector object.'
      if !ref $conn || !$conn->isa('DBIx::Connector');
    $self->{_db_conn}   = $conn;
    $self->{privileges} = {};
    return $self;
}

sub configure_db {
    my ( $class, $conn ) = @_;
    croak 'Must provide a valid constructor object.'
      if !ref $conn || !$conn->isa('DBIx::Connector');
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
# returns 0 or 1.
sub exists_privilege {
    my ( $self, $privilege ) = @_;
    croak "Must pass a defined value in privilege test."
      if !defined $privilege;
    croak "Must pass a non-empty value in privilege test."
      if !length $privilege;
    return 1 if exists $self->{privileges}{$privilege};
    my $sth =
      _db_run_ex( $self->_db_conn, $PRIV_QUERY{SQL_exists_privilege},
        $privilege );
    my $result = defined $sth->fetchrow_array;
    $self->{privileges}{$privilege}++ if $result;    # Cache the result.
    return $result;
}

# Usage:
# $priv->add_privileges( [ qw( privilege description ) ], [...] );
# Returns the number of privs actually added.

sub add_privileges {
    my ( $self, @privileges ) = @_;
    my @privs_to_insert =
      grep {
             ref $_ eq 'ARRAY'
          && $_->[0]
          && !$self->exists_privilege( $_->[0] )
      } @privileges;

    # Set undefined descriptions to q{}.
    foreach my $priv_bundle (@privs_to_insert) {

        # This change is intended to propagate back to @privs_to_insert.
        $priv_bundle->[1] = q{} if !$priv_bundle->[1];
    }
    my $sth = _db_run_ex( $self->_db_conn, $PRIV_QUERY{SQL_add_privileges},
        @privs_to_insert );
    return scalar @privs_to_insert;
}

# Deletes all privileges in @privileges (if they exist).
# Silent if non-existent. Returns the number of privs actually deleted.
sub delete_privileges {
    my ( $self, @privileges ) = @_;
    my @privs_to_delete;
    foreach my $privilege (@privileges) {
        next if !$privilege or !$self->exists_privilege($privilege);
        push @privs_to_delete, [$privilege];
        delete $self->{privileges}{$privilege};  # Remove it from the cache too.
    }
    my $sth = _db_run_ex( $self->_db_conn, $PRIV_QUERY{SQL_delete_privileges},
        @privs_to_delete );
    return scalar @privs_to_delete;
}

# Gets the description for a single privilege.  Must specify a valid privilege.
sub get_privilege_description {
    my ( $self, $privilege ) = @_;
    croak 'Must specify a privilege.'
      if !defined $privilege;
    croak 'Specified privilege must exist.'
      if !$self->exists_privilege($privilege);
    my $sth =
      _db_run_ex( $self->_db_conn, $PRIV_QUERY{SQL_get_privilege_description},
        $privilege );
    return ( $sth->fetchrow_array )[0];
}

# Pass a privilege and a new description.  All parameters required.  Description
# of q{} deletes the description.
sub update_privilege_description {
    my ( $self, $privilege, $description ) = @_;
    croak 'Must specify a privilege.'
      if !defined $privilege;
    croak 'Specified privilege doesn\'t exist.'
      if !$self->exists_privilege($privilege);
    croak 'Must specify a description (q{} is ok too).'
      if !defined $description;
    my $sth =
      _db_run_ex( $self->_db_conn,
        $PRIV_QUERY{SQL_update_privilege_description},
        $description, $privilege );
    return 1;
}

# Returns an array of pairs (AoA).  Pairs are [ privilege, description ],...
sub fetch_privileges {
    my $self = shift;
    my $sth = _db_run_ex( $self->_db_conn, $PRIV_QUERY{SQL_list_privileges} );
    my @privileges = @{ $sth->fetchall_arrayref };
    return @privileges;
}

1;

__END__
